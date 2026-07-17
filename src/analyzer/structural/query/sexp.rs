use super::ir::{CodeQuery, CodeQueryResultDetail};
use super::schema::{RqlForm, RqlFormClass, RqlProperty, resolve_rql_schema_version};
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::{NormalizedKind, Role, RoleValueShape};
use crate::schema_version::SchemaVersionResolution;
#[cfg(test)]
use crate::sexp::MAX_SEXP_DEPTH;
use crate::sexp::{Expr, ExprKind, ParseError, ParsedSexp, parse_sexp};
use serde_json::{Map, Number, Value, json};
use std::fmt;
use std::ops::Range;

const MAX_SEXP_INPUT_BYTES: usize = 64 * 1024;

impl CodeQuery {
    pub fn from_sexp(input: &str) -> Result<Self, String> {
        let expr = parse_query_expr(input)?;
        let version = resolve_rql_schema_version(None)
            .expect("the RQL registry always resolves an omitted schema version");
        code_query_from_expr(&expr, version).map_err(QueryExprError::into_rql_message)
    }
}

pub fn sexp_to_json(input: &str) -> Result<Value, String> {
    let expr = parse_query_expr(input)?;
    query_expr_to_json(&expr).map_err(|error| error.message)
}

fn parse_query_expr(input: &str) -> Result<Expr, String> {
    if input.len() > MAX_SEXP_INPUT_BYTES {
        return Err(format!(
            "S-expression query is too large: {} bytes exceeds {}",
            input.len(),
            MAX_SEXP_INPUT_BYTES
        ));
    }
    let parsed = parse_query_sexp(input).map_err(parse_error_message)?;
    if let Some(error) = parsed.incomplete {
        return Err(error.message);
    }
    let expr = parsed
        .expr
        .ok_or_else(|| "expected expression, found end of input".to_string())?;
    Ok(expr)
}

fn parse_error_message(error: ParseError) -> String {
    error.message
}

pub(super) fn parse_query_sexp(input: &str) -> Result<ParsedSexp, ParseError> {
    parse_sexp(input).map_err(|mut error| {
        if error.message == "unexpected input after the expression" {
            error.message = "unexpected input after the query".to_string();
        }
        error
    })
}

/// An error lowering one already-parsed RQL subtree.
///
/// `range` always points into the original enclosing S-expression source, so
/// RQLP can surface a nested selector error without rendering and reparsing
/// the selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueryExprError {
    pub(crate) path: String,
    pub(crate) range: Range<usize>,
    pub(crate) message: String,
    kind: QueryExprErrorKind,
}

#[derive(Debug)]
pub(super) struct QueryLowerError {
    pub(super) range: Range<usize>,
    pub(super) message: String,
}

type LowerResult<T> = Result<T, QueryLowerError>;

trait LocateLoweringError<T> {
    fn at(self, expr: &Expr) -> LowerResult<T>;
}

impl<T> LocateLoweringError<T> for Result<T, String> {
    fn at(self, expr: &Expr) -> LowerResult<T> {
        self.map_err(|message| QueryLowerError {
            range: expr.range.clone(),
            message,
        })
    }
}

fn lower_error(expr: &Expr, message: impl Into<String>) -> QueryLowerError {
    QueryLowerError {
        range: expr.range.clone(),
        message: message.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryExprErrorKind {
    Lowering,
    Semantic,
}

impl QueryExprError {
    fn into_rql_message(self) -> String {
        match self.kind {
            QueryExprErrorKind::Lowering => self.message,
            QueryExprErrorKind::Semantic => self.to_string(),
        }
    }
}

impl fmt::Display for QueryExprError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            formatter.write_str(&self.message)
        } else {
            write!(
                formatter,
                "invalid query at {}: {}",
                self.path, self.message
            )
        }
    }
}

impl std::error::Error for QueryExprError {}

/// Lower an already-parsed RQL subtree to the canonical query JSON shape.
pub(crate) fn query_expr_to_json(expr: &Expr) -> Result<Value, QueryExprError> {
    query_to_json(expr).map_err(|error| {
        let path = super::source::query_expr_path_for_range(expr, &error.range)
            .unwrap_or_else(|| "match".to_string());
        QueryExprError {
            path,
            range: error.range,
            message: error.message,
            kind: QueryExprErrorKind::Lowering,
        }
    })
}

/// Lower and validate an already-parsed RQL subtree exactly once.
///
/// The caller supplies the independently resolved RQL schema version. Inline
/// policy selectors therefore do not need a source-text reconstruction step.
pub(crate) fn code_query_from_expr(
    expr: &Expr,
    schema: SchemaVersionResolution,
) -> Result<CodeQuery, QueryExprError> {
    let mut value = query_expr_to_json(expr)?;
    let object = value
        .as_object_mut()
        .expect("RQL lowering always produces a query object");
    object.insert("schema_version".to_string(), json!(schema.version));
    CodeQuery::from_json(&value).map_err(|error| {
        let range = super::source::query_expr_range_for_path(expr, &error.path);
        QueryExprError {
            path: error.path,
            range,
            message: error.message,
            kind: QueryExprErrorKind::Semantic,
        }
    })
}

/// Reject query output controls that an embedding must own itself.
///
/// Policy evaluation fixes its result detail and finding budget independently
/// of authored selectors. Keeping this check beside the RQL form registry
/// prevents the policy frontend from growing a second list of query keywords.
pub(crate) fn validate_policy_selector_expr(expr: &Expr) -> Result<(), QueryExprError> {
    let mut stack = vec![expr];
    while let Some(current) = stack.pop() {
        let items = match &current.kind {
            ExprKind::List(items) | ExprKind::Vector(items) => items,
            ExprKind::String(_) | ExprKind::Symbol(_) | ExprKind::Number(_) => continue,
        };
        if matches!(&current.kind, ExprKind::List(_))
            && let Some(head) = items.first()
            && let Some(label) = head.as_symbol()
            && let Some(form @ (RqlForm::Limit | RqlForm::ResultDetail)) =
                RqlForm::from_label(label)
        {
            let (path, authored_label) = match form {
                RqlForm::Limit => ("limit", "limit"),
                RqlForm::ResultDetail => ("result_detail", "result-detail"),
                _ => unreachable!("output-control forms were filtered above"),
            };
            return Err(QueryExprError {
                path: path.to_string(),
                range: head.range.clone(),
                message: format!(
                    "policy selectors cannot author `{authored_label}`; policy evaluation owns query output controls"
                ),
                kind: QueryExprErrorKind::Semantic,
            });
        }
        stack.extend(items.iter().rev());
    }
    Ok(())
}

pub(super) fn query_to_json(expr: &Expr) -> LowerResult<Value> {
    if let Some(value) = wrapper_query_to_json(expr)? {
        return Ok(value);
    }
    Ok(json!({ "match": pattern_to_json(expr)? }))
}

fn wrapper_query_to_json(expr: &Expr) -> LowerResult<Option<Value>> {
    let Some(items) = expr.as_list() else {
        return Ok(None);
    };
    let Some(head) = head_symbol(items)? else {
        return Ok(None);
    };
    let Some(form) = RqlForm::from_label(head) else {
        return Ok(None);
    };
    if form.class() != RqlFormClass::Wrapper {
        return Ok(None);
    }
    match form {
        RqlForm::Where => {
            if items.len() < 3 {
                return Err(lower_error(
                    expr,
                    "(where ...) requires at least one glob and a query",
                ));
            }
            let mut query = query_object(&items[items.len() - 1])?;
            let globs = items[1..items.len() - 1]
                .iter()
                .map(string_arg)
                .collect::<Result<Vec<_>, _>>()?;
            insert_unique(&mut query, "where", array_of_strings(globs)).at(expr)?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Language => {
            if items.len() < 3 {
                return Err(lower_error(
                    expr,
                    "(language ...) requires at least one label and a query",
                ));
            }
            let mut query = query_object(&items[items.len() - 1])?;
            let labels = items[1..items.len() - 1]
                .iter()
                .map(language_arg)
                .collect::<Result<Vec<_>, _>>()?;
            insert_unique(&mut query, "languages", array_of_strings(labels)).at(expr)?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Limit => {
            expect_len(expr, items, 3, "limit")?;
            let mut query = query_object(&items[2])?;
            insert_unique(&mut query, "limit", number_value(&items[1], "limit")?).at(expr)?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::ResultDetail => {
            expect_len(expr, items, 3, head)?;
            let mut query = query_object(&items[2])?;
            insert_unique(
                &mut query,
                "result_detail",
                Value::String(result_detail_arg(&items[1])?),
            )
            .at(expr)?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Inside | RqlForm::NotInside => {
            expect_len(expr, items, 3, head)?;
            let mut query = query_object(&items[2])?;
            let field = if form == RqlForm::Inside {
                "inside"
            } else {
                "not_inside"
            };
            insert_unique(&mut query, field, pattern_to_json(&items[1])?).at(expr)?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Union | RqlForm::Intersect | RqlForm::Except => {
            if items.len() < 3 {
                return Err(lower_error(
                    expr,
                    format!("({head} ...) requires at least two queries"),
                ));
            }
            let branches = items[1..]
                .iter()
                .map(query_to_json)
                .collect::<Result<Vec<_>, _>>()?;
            let mut query = Map::new();
            query.insert(head.to_string(), Value::Array(branches));
            Ok(Some(Value::Object(query)))
        }
        RqlForm::EnclosingDecl
        | RqlForm::FileOf
        | RqlForm::ImportsOf
        | RqlForm::ImportersOf
        | RqlForm::Members
        | RqlForm::Owner => {
            expect_len(expr, items, 2, head)?;
            let mut query = query_object(&items[1])?;
            let steps = query
                .entry("steps".to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| lower_error(expr, "internal error: steps must be an array"))?;
            let op = match form {
                RqlForm::EnclosingDecl => "enclosing_decl",
                RqlForm::FileOf => "file_of",
                RqlForm::ImportsOf => "imports_of",
                RqlForm::ImportersOf => "importers_of",
                RqlForm::Members => "members",
                RqlForm::Owner => "owner",
                _ => unreachable!("typed pipeline wrapper filtered above"),
            };
            steps.push(json!({ "op": op }));
            Ok(Some(Value::Object(query)))
        }
        RqlForm::ReferencesOf | RqlForm::UsedBy | RqlForm::Uses => {
            if items.len() < 2 || !(items.len() - 2).is_multiple_of(2) {
                return Err(lower_error(
                    expr,
                    format!("({head} ...) expects option/value pairs followed by a query"),
                ));
            }
            let query_expr = items.last().expect("reference wrapper has a query");
            let mut query = query_object(query_expr)?;
            let op = match form {
                RqlForm::ReferencesOf => "references_of",
                RqlForm::UsedBy => "used_by",
                RqlForm::Uses => "uses",
                _ => unreachable!("reference wrapper filtered above"),
            };
            let mut step = Map::new();
            step.insert("op".to_string(), Value::String(op.to_string()));
            for pair in items[1..items.len() - 1].chunks_exact(2) {
                let key = pair[0].as_symbol().ok_or_else(|| {
                    lower_error(
                        &pair[0],
                        format!("({head} ...) option names must be symbols"),
                    )
                })?;
                let (field, value) = match key {
                    ":reference-kinds" => {
                        let values = pair[1].as_sequence().ok_or_else(|| {
                            lower_error(
                                &pair[1],
                                format!("({head} :reference-kinds ...) requires a vector"),
                            )
                        })?;
                        let labels = values
                            .iter()
                            .map(symbol_or_string)
                            .collect::<Result<Vec<_>, _>>()?
                            .into_iter()
                            .map(|label| label.replace('-', "_"))
                            .collect();
                        ("reference_kinds", array_of_strings(labels))
                    }
                    ":proof" => (
                        "proof",
                        Value::String(symbol_or_string(&pair[1])?.replace('-', "_")),
                    ),
                    ":surface" => (
                        "surface",
                        Value::String(symbol_or_string(&pair[1])?.replace('-', "_")),
                    ),
                    _ => {
                        return Err(lower_error(
                            &pair[0],
                            format!(
                                "({head} ...) accepts only :reference-kinds, :proof, and :surface"
                            ),
                        ));
                    }
                };
                if step.insert(field.to_string(), value).is_some() {
                    return Err(lower_error(
                        &pair[0],
                        format!("({head} ...) repeats option {key}"),
                    ));
                }
            }
            query
                .entry("steps".to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| lower_error(expr, "internal error: steps must be an array"))?
                .push(Value::Object(step));
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Callers | RqlForm::Callees | RqlForm::CallSitesTo | RqlForm::CallSitesFrom => {
            if items.len() < 2 || !(items.len() - 2).is_multiple_of(2) {
                return Err(lower_error(
                    expr,
                    format!("({head} ...) expects option/value pairs followed by a query"),
                ));
            }
            let query_expr = items.last().expect("call wrapper has a query");
            let mut query = query_object(query_expr)?;
            let op = match form {
                RqlForm::Callers => "callers",
                RqlForm::Callees => "callees",
                RqlForm::CallSitesTo => "call_sites_to",
                RqlForm::CallSitesFrom => "call_sites_from",
                _ => unreachable!("call wrapper filtered above"),
            };
            let mut step = Map::new();
            step.insert("op".to_string(), Value::String(op.to_string()));
            for pair in items[1..items.len() - 1].chunks_exact(2) {
                let key = pair[0].as_symbol().ok_or_else(|| {
                    lower_error(
                        &pair[0],
                        format!("({head} ...) option names must be symbols"),
                    )
                })?;
                let (field, value) = match key {
                    ":depth" if matches!(form, RqlForm::Callers | RqlForm::Callees) => {
                        ("depth", number_value(&pair[1], head)?)
                    }
                    ":proof" => (
                        "proof",
                        Value::String(symbol_or_string(&pair[1])?.replace('-', "_")),
                    ),
                    _ => {
                        return Err(lower_error(
                            &pair[0],
                            format!(
                                "({head} ...) accepts :proof{}",
                                if matches!(form, RqlForm::Callers | RqlForm::Callees) {
                                    " and :depth"
                                } else {
                                    ""
                                }
                            ),
                        ));
                    }
                };
                if step.insert(field.to_string(), value).is_some() {
                    return Err(lower_error(
                        &pair[0],
                        format!("({head} ...) repeats option {key}"),
                    ));
                }
            }
            query
                .entry("steps".to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| lower_error(expr, "internal error: steps must be an array"))?
                .push(Value::Object(step));
            Ok(Some(Value::Object(query)))
        }
        RqlForm::CallInput => {
            if items.len() != 4 {
                return Err(lower_error(
                    expr,
                    format!("({head} ...) expects one selector option followed by a query"),
                ));
            }
            let key = items[1].as_symbol().ok_or_else(|| {
                lower_error(&items[1], format!("({head} ...) selector must be a symbol"))
            })?;
            let (field, value) = match key {
                ":receiver" if items[2].as_symbol() == Some("true") => {
                    ("receiver", Value::Bool(true))
                }
                ":receiver" => {
                    return Err(lower_error(
                        &items[2],
                        format!("({head} :receiver ...) requires true"),
                    ));
                }
                ":parameter-index" => ("parameter_index", number_value(&items[2], head)?),
                ":parameter-name" => (
                    "parameter_name",
                    Value::String(symbol_or_string(&items[2])?),
                ),
                _ => {
                    return Err(lower_error(
                        &items[1],
                        format!(
                            "({head} ...) requires :receiver, :parameter-index, or :parameter-name"
                        ),
                    ));
                }
            };
            let mut query = query_object(&items[3])?;
            let mut step = Map::new();
            step.insert("op".to_string(), Value::String("call_input".to_string()));
            step.insert(field.to_string(), value);
            query
                .entry("steps".to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| lower_error(expr, "internal error: steps must be an array"))?
                .push(Value::Object(step));
            Ok(Some(Value::Object(query)))
        }
        RqlForm::ReceiverTargets | RqlForm::PointsTo | RqlForm::MemberTargets => {
            let (query_expr, capture) = match items.len() {
                2 => (&items[1], None),
                4 if items[1].as_symbol() == Some(":capture") => {
                    (&items[3], Some(symbol_or_string(&items[2])?))
                }
                _ => {
                    return Err(lower_error(
                        expr,
                        format!(
                            "({head} ...) expects an optional :capture name followed by a query"
                        ),
                    ));
                }
            };
            let op = match form {
                RqlForm::ReceiverTargets => "receiver_targets",
                RqlForm::PointsTo => "points_to",
                RqlForm::MemberTargets => "member_targets",
                _ => unreachable!("receiver wrapper filtered above"),
            };
            let mut query = query_object(query_expr)?;
            let mut step = Map::new();
            step.insert("op".to_string(), Value::String(op.to_string()));
            if let Some(capture) = capture {
                step.insert("capture".to_string(), Value::String(capture));
            }
            query
                .entry("steps".to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| lower_error(expr, "internal error: steps must be an array"))?
                .push(Value::Object(step));
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Supertypes | RqlForm::Subtypes => {
            let (query_expr, option) = match items.len() {
                2 => (&items[1], None),
                4 => (&items[3], Some((&items[1], &items[2]))),
                _ => {
                    return Err(lower_error(
                        expr,
                        format!(
                            "({head} ...) expects a query, optionally preceded by :depth count or :transitive true"
                        ),
                    ));
                }
            };
            let mut query = query_object(query_expr)?;
            let op = if form == RqlForm::Supertypes {
                "supertypes"
            } else {
                "subtypes"
            };
            let mut step = Map::new();
            step.insert("op".to_string(), Value::String(op.to_string()));
            if let Some((key, value)) = option {
                match key.as_symbol() {
                    Some(":depth") => {
                        step.insert("depth".to_string(), number_value(value, head)?);
                    }
                    Some(":transitive") => {
                        if value.as_symbol() != Some("true") {
                            return Err(lower_error(
                                value,
                                format!("({head} :transitive ...) requires true"),
                            ));
                        }
                        step.insert("transitive".to_string(), Value::Bool(true));
                    }
                    _ => {
                        return Err(lower_error(
                            key,
                            format!("({head} ...) accepts only :depth count or :transitive true"),
                        ));
                    }
                }
            }
            query
                .entry("steps".to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| lower_error(expr, "internal error: steps must be an array"))?
                .push(Value::Object(step));
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Name
        | RqlForm::NameRegex
        | RqlForm::TextRegex
        | RqlForm::Capture
        | RqlForm::Has
        | RqlForm::NotHas
        | RqlForm::NotKind => unreachable!("predicate filtered above"),
    }
}

fn query_object(expr: &Expr) -> LowerResult<Map<String, Value>> {
    match query_to_json(expr)? {
        Value::Object(object) => Ok(object),
        _ => unreachable!("query_to_json always returns an object"),
    }
}

fn pattern_to_json(expr: &Expr) -> LowerResult<Value> {
    let Some(items) = expr.as_list() else {
        return Err(lower_error(expr, "pattern must be an S-expression list"));
    };
    let Some(head) = head_symbol(items)? else {
        return Err(lower_error(expr, "pattern list must not be empty"));
    };

    let mut object = Map::new();
    if NormalizedKind::from_label(head).is_some() {
        insert_unique(&mut object, "kind", Value::String(head.to_string())).at(&items[0])?;
        parse_pattern_tail(&mut object, &items[1..])?;
        return Ok(Value::Object(object));
    }

    let Some(form) = RqlForm::from_label(head) else {
        return Err(lower_error(
            &items[0],
            format!("unknown S-expression form `{head}`"),
        ));
    };
    if form.class() != RqlFormClass::Predicate {
        return Err(lower_error(
            &items[0],
            format!("S-expression wrapper `{head}` is not a pattern"),
        ));
    }
    match form {
        RqlForm::Name => {
            expect_len(expr, items, 2, "name")?;
            insert_unique(&mut object, "name", Value::String(string_arg(&items[1])?)).at(expr)?;
        }
        RqlForm::NameRegex => {
            expect_len(expr, items, 2, "name/regex")?;
            insert_unique(
                &mut object,
                "name".to_string(),
                json!({ "regex": string_arg(&items[1])? }),
            )
            .at(expr)?;
        }
        RqlForm::TextRegex => {
            expect_len(expr, items, 2, "text/regex")?;
            insert_unique(
                &mut object,
                "text".to_string(),
                json!({ "regex": string_arg(&items[1])? }),
            )
            .at(expr)?;
        }
        RqlForm::Capture => {
            expect_len(expr, items, 2, "capture")?;
            insert_unique(
                &mut object,
                "capture",
                Value::String(string_arg(&items[1])?),
            )
            .at(expr)?;
        }
        RqlForm::Has | RqlForm::NotHas => {
            expect_len(expr, items, 2, head)?;
            insert_unique(
                &mut object,
                if form == RqlForm::Has {
                    "has"
                } else {
                    "not_has"
                }
                .to_string(),
                pattern_to_json(&items[1])?,
            )
            .at(expr)?;
        }
        RqlForm::NotKind => {
            expect_len(expr, items, 2, "not-kind")?;
            insert_unique(&mut object, "not_kind", kind_value(&items[1])?).at(expr)?;
        }
        RqlForm::Where
        | RqlForm::Language
        | RqlForm::Limit
        | RqlForm::ResultDetail
        | RqlForm::Inside
        | RqlForm::NotInside
        | RqlForm::Union
        | RqlForm::Intersect
        | RqlForm::Except
        | RqlForm::EnclosingDecl
        | RqlForm::FileOf
        | RqlForm::ImportsOf
        | RqlForm::ImportersOf
        | RqlForm::Supertypes
        | RqlForm::Subtypes
        | RqlForm::Members
        | RqlForm::Owner
        | RqlForm::ReferencesOf
        | RqlForm::UsedBy
        | RqlForm::Uses
        | RqlForm::Callers
        | RqlForm::Callees
        | RqlForm::CallSitesTo
        | RqlForm::CallSitesFrom
        | RqlForm::CallInput
        | RqlForm::ReceiverTargets
        | RqlForm::PointsTo
        | RqlForm::MemberTargets => unreachable!("wrapper filtered above"),
    }
    Ok(Value::Object(object))
}

fn parse_pattern_tail(object: &mut Map<String, Value>, tail: &[Expr]) -> LowerResult<()> {
    let mut index = 0;
    while index < tail.len() {
        match &tail[index].kind {
            ExprKind::Symbol(keyword) if keyword.starts_with(':') => {
                if index + 1 >= tail.len() {
                    return Err(lower_error(
                        &tail[index],
                        format!("keyword `{keyword}` requires a value"),
                    ));
                }
                insert_keyword(object, &tail[index], &keyword[1..], &tail[index + 1])?;
                index += 2;
            }
            ExprKind::List(_) => {
                merge_pattern_fragment(object, pattern_to_json(&tail[index])?, &tail[index])?;
                index += 1;
            }
            _ => {
                return Err(lower_error(
                    &tail[index],
                    format!(
                        "unexpected pattern argument {}; use :field value or a predicate form",
                        describe_expr(&tail[index])
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn insert_keyword(
    object: &mut Map<String, Value>,
    key_expr: &Expr,
    key: &str,
    value: &Expr,
) -> LowerResult<()> {
    if let Some(property) = RqlProperty::from_label(key) {
        return match property {
            RqlProperty::Name => {
                insert_unique(object, "name", Value::String(string_arg(value)?)).at(key_expr)
            }
            RqlProperty::NameRegex => {
                insert_unique(object, "name", json!({ "regex": string_arg(value)? })).at(key_expr)
            }
            RqlProperty::TextRegex => {
                insert_unique(object, "text", json!({ "regex": string_arg(value)? })).at(key_expr)
            }
            RqlProperty::Capture => {
                insert_unique(object, "capture", Value::String(string_arg(value)?)).at(key_expr)
            }
            RqlProperty::NotKind => {
                insert_unique(object, "not_kind", kind_value(value)?).at(key_expr)
            }
            RqlProperty::Has => insert_unique(object, "has", pattern_to_json(value)?).at(key_expr),
            RqlProperty::NotHas => {
                insert_unique(object, "not_has", pattern_to_json(value)?).at(key_expr)
            }
        };
    }
    let Some(role) = Role::from_label(key) else {
        return Err(lower_error(
            key_expr,
            format!("unknown pattern field `:{key}`"),
        ));
    };
    match role.value_shape() {
        RoleValueShape::Pattern => {
            insert_unique(object, role.label(), single_role_value(value)?).at(key_expr)
        }
        RoleValueShape::PatternList => {
            insert_unique(object, role.label(), pattern_array(value)?).at(key_expr)
        }
        RoleValueShape::PatternMap => {
            insert_unique(object, role.label(), kwargs_object(value)?).at(key_expr)
        }
    }
}

fn merge_pattern_fragment(
    object: &mut Map<String, Value>,
    fragment: Value,
    origin: &Expr,
) -> LowerResult<()> {
    let Value::Object(fragment) = fragment else {
        return Err(lower_error(
            origin,
            "pattern fragment must lower to an object",
        ));
    };
    for (key, value) in fragment {
        insert_unique(object, key, value).at(origin)?;
    }
    Ok(())
}

fn insert_unique(
    object: &mut Map<String, Value>,
    key: impl Into<String>,
    value: Value,
) -> Result<(), String> {
    let key = key.into();
    if object.contains_key(&key) {
        Err(format!("duplicate S-expression field `{key}`"))
    } else {
        object.insert(key, value);
        Ok(())
    }
}

fn single_role_value(expr: &Expr) -> LowerResult<Value> {
    match expr.as_string() {
        Some(value) => Ok(json!({ "name": value })),
        None => pattern_to_json(expr),
    }
}

fn pattern_array(expr: &Expr) -> LowerResult<Value> {
    let items = expr
        .as_sequence()
        .ok_or_else(|| lower_error(expr, "expected a list/vector of patterns"))?;
    items
        .iter()
        .map(pattern_to_json)
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

fn kwargs_object(expr: &Expr) -> LowerResult<Value> {
    let pairs = expr
        .as_sequence()
        .ok_or_else(|| lower_error(expr, "expected a list/vector of keyword argument pairs"))?;
    let mut object = Map::new();
    for pair in pairs {
        let Some(items) = pair.as_list() else {
            return Err(lower_error(pair, "keyword argument entry must be a list"));
        };
        expect_len(pair, items, 2, "kwargs entry")?;
        let key = symbol_or_string(&items[0])?;
        insert_unique(&mut object, key, pattern_to_json(&items[1])?).at(&items[0])?;
    }
    Ok(Value::Object(object))
}

fn kind_value(expr: &Expr) -> LowerResult<Value> {
    match expr.as_sequence() {
        Some(items) => items
            .iter()
            .map(kind_label)
            .collect::<Result<Vec<_>, _>>()
            .map(array_of_strings),
        None => Ok(Value::String(kind_label(expr)?)),
    }
}

fn kind_label(expr: &Expr) -> LowerResult<String> {
    let label = symbol_or_string(expr)?;
    if NormalizedKind::from_label(&label).is_some() {
        Ok(label)
    } else {
        Err(lower_error(
            expr,
            format!("unknown normalized kind `{label}`"),
        ))
    }
}

fn language_arg(expr: &Expr) -> LowerResult<String> {
    let label = symbol_or_string(expr)?;
    Language::from_config_label(&label)
        .map(|language| language.config_label().to_string())
        .ok_or_else(|| lower_error(expr, format!("unknown language label `{label}`")))
}

fn result_detail_arg(expr: &Expr) -> LowerResult<String> {
    let label = symbol_or_string(expr)?;
    CodeQueryResultDetail::from_label(&label)
        .map(|detail| detail.label().to_string())
        .ok_or_else(|| lower_error(expr, format!("unknown result detail `{label}`")))
}

fn string_arg(expr: &Expr) -> LowerResult<String> {
    expr.as_string().map(str::to_string).ok_or_else(|| {
        lower_error(
            expr,
            format!("expected string, got {}", describe_expr(expr)),
        )
    })
}

fn symbol_or_string(expr: &Expr) -> LowerResult<String> {
    expr.as_string()
        .or_else(|| expr.as_symbol())
        .map(str::to_string)
        .ok_or_else(|| {
            lower_error(
                expr,
                format!("expected symbol or string, got {}", describe_expr(expr)),
            )
        })
}

fn number_value(expr: &Expr, context: &str) -> LowerResult<Value> {
    expr.as_number()
        .map(|value| Value::Number(Number::from(value)))
        .ok_or_else(|| lower_error(expr, format!("({context} ...) requires a number")))
}

fn array_of_strings(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}

fn head_symbol(items: &[Expr]) -> LowerResult<Option<&str>> {
    match items.first() {
        Some(expr) if expr.as_symbol().is_some() => Ok(expr.as_symbol()),
        Some(other) => Err(lower_error(
            other,
            format!(
                "S-expression head must be a symbol, got {}",
                describe_expr(other)
            ),
        )),
        None => Ok(None),
    }
}

fn expect_len(expr: &Expr, items: &[Expr], len: usize, form: &str) -> LowerResult<()> {
    if items.len() == len {
        Ok(())
    } else {
        Err(lower_error(
            expr,
            format!(
                "({form} ...) expects {} argument{}",
                len - 1,
                if len == 2 { "" } else { "s" }
            ),
        ))
    }
}

fn describe_expr(expr: &Expr) -> &'static str {
    match &expr.kind {
        ExprKind::List(_) => "a list",
        ExprKind::Vector(_) => "a vector",
        ExprKind::String(_) => "a string",
        ExprKind::Symbol(_) => "a symbol",
        ExprKind::Number(_) => "a number",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canonical(input: &str) -> Value {
        CodeQuery::from_sexp(input).unwrap().to_canonical_json()
    }

    fn canonical_json(value: Value) -> Value {
        CodeQuery::from_json(&value).unwrap().to_canonical_json()
    }

    fn rql_schema_resolution() -> SchemaVersionResolution {
        resolve_rql_schema_version(None).unwrap()
    }

    #[test]
    fn policy_selector_validation_rejects_output_controls_at_their_head() {
        for (source, expected) in [
            ("(limit 10 (call))", "limit"),
            (
                "(union (call) (result-detail full (call)))",
                "result-detail",
            ),
        ] {
            let expr = parse_query_expr(source).unwrap();
            let error = validate_policy_selector_expr(&expr).unwrap_err();
            assert_eq!(&source[error.range], expected);
        }

        let expr = parse_query_expr(r#"(call :callee (name "limit"))"#).unwrap();
        validate_policy_selector_expr(&expr).unwrap();
    }

    #[test]
    fn parsed_subtree_lowers_without_source_reconstruction() {
        let source = r#"(policy :selector (call :callee (name "eval")))"#;
        let parsed = parse_sexp(source).unwrap();
        let document = parsed.expr.unwrap();
        let selector = document
            .as_list()
            .and_then(|items| items.last())
            .expect("selector subtree");

        let query = code_query_from_expr(selector, rql_schema_resolution()).unwrap();

        assert_eq!(
            query.to_canonical_json(),
            canonical_json(json!({
                "match": { "kind": "call", "callee": { "name": "eval" } }
            }))
        );
        assert_eq!(
            &source[selector.range.clone()],
            r#"(call :callee (name "eval"))"#
        );
    }

    #[test]
    fn parsed_subtree_error_retains_semantic_path_and_original_range() {
        let source = "(policy :selector (limit 0 (call)))";
        let parsed = parse_sexp(source).unwrap();
        let document = parsed.expr.unwrap();
        let selector = document
            .as_list()
            .and_then(|items| items.last())
            .expect("selector subtree");

        let error = code_query_from_expr(selector, rql_schema_resolution())
            .expect_err("zero limit must fail");

        assert_eq!(error.path, "limit");
        assert_eq!(&source[error.range], "0");
    }

    #[test]
    fn nested_set_semantic_error_retains_canonical_path_and_absolute_leaf_range() {
        let invalid_name = "x".repeat(super::super::MAX_STRING_PREDICATE_LENGTH + 1);
        let source = format!(
            r#"(policy :selector (union (call) (intersect (call) (call :name "{invalid_name}"))))"#
        );
        let parsed = parse_sexp(&source).unwrap();
        let document = parsed.expr.unwrap();
        let selector = document
            .as_list()
            .and_then(|items| items.last())
            .expect("selector subtree");

        let error = code_query_from_expr(selector, rql_schema_resolution())
            .expect_err("oversized nested name must fail");

        assert_eq!(error.path, "union[1].intersect[1].match.name");
        assert_eq!(&source[error.range], format!(r#""{invalid_name}""#));
    }

    #[test]
    fn nested_wrapper_semantic_error_retains_canonical_path_and_absolute_leaf_range() {
        let source = r#"(policy :selector (union (call) (intersect (where "[" (call)) (call))))"#;
        let parsed = parse_sexp(source).unwrap();
        let document = parsed.expr.unwrap();
        let selector = document
            .as_list()
            .and_then(|items| items.last())
            .expect("selector subtree");

        let error = code_query_from_expr(selector, rql_schema_resolution())
            .expect_err("invalid nested glob must fail");

        assert_eq!(error.path, "union[1].intersect[0].where[0]");
        assert_eq!(&source[error.range], r#""[""#);
    }

    #[test]
    fn parsed_subtree_lowering_error_retains_narrow_original_range() {
        let source = r#"(policy :selector (call :unknown "value"))"#;
        let parsed = parse_sexp(source).unwrap();
        let document = parsed.expr.unwrap();
        let selector = document
            .as_list()
            .and_then(|items| items.last())
            .expect("selector subtree");

        let error = code_query_from_expr(selector, rql_schema_resolution())
            .expect_err("unknown field must fail");

        assert_eq!(error.path, "match");
        assert_eq!(&source[error.range], ":unknown");
    }

    #[test]
    fn parsed_subtree_incomplete_property_error_retains_keyword_range() {
        let source = "(policy :selector (call :callee))";
        let parsed = parse_sexp(source).unwrap();
        let document = parsed.expr.unwrap();
        let selector = document
            .as_list()
            .and_then(|items| items.last())
            .expect("selector subtree");

        let error = code_query_from_expr(selector, rql_schema_resolution())
            .expect_err("missing property value must fail");

        assert_eq!(error.path, "match");
        assert_eq!(&source[error.range], ":callee");
    }

    #[test]
    fn parsed_subtree_lowering_range_follows_first_failing_branch() {
        for source in [
            "(policy :selector (union (call :callee) (call :receiver)))",
            r#"(policy :selector (union (call :callee) (call :unknown "value")))"#,
        ] {
            let parsed = parse_sexp(source).unwrap();
            let document = parsed.expr.unwrap();
            let selector = document
                .as_list()
                .and_then(|items| items.last())
                .expect("selector subtree");

            let error = code_query_from_expr(selector, rql_schema_resolution())
                .expect_err("first malformed branch must fail");

            assert!(error.message.contains("requires a value"), "{error}");
            assert_eq!(&source[error.range], ":callee", "{source}");
        }
    }

    #[test]
    fn lowering_range_ignores_earlier_decoder_only_diagnostic() {
        let source = r#"(policy :selector (assignment :callee (name "run") :unknown "value"))"#;
        let parsed = parse_sexp(source).unwrap();
        let document = parsed.expr.unwrap();
        let selector = document
            .as_list()
            .and_then(|items| items.last())
            .expect("selector subtree");

        let error = code_query_from_expr(selector, rql_schema_resolution())
            .expect_err("unknown field must fail during lowering");

        assert!(error.message.contains("unknown pattern field"), "{error}");
        assert_eq!(&source[error.range], ":unknown");
    }

    #[test]
    fn standalone_rql_preserves_query_specific_trailing_input_wording() {
        let error = CodeQuery::from_sexp("(call) (call)").unwrap_err();

        assert_eq!(error, "unexpected input after the query");
    }

    #[test]
    fn structural_query_sexp_lowers_call_with_callee_and_capture() {
        assert_eq!(
            canonical(r#"(call :callee (name "eval") :args [(capture "arg")])"#),
            canonical_json(json!({
                "match": {
                    "kind": "call",
                    "callee": { "name": "eval" },
                    "args": [{ "capture": "arg" }]
                }
            }))
        );
    }

    #[test]
    fn structural_query_sexp_lowers_wrappers() {
        assert_eq!(
            canonical(
                r#"(where "src/**/*.py" (language python (limit 25 (call :callee (name "eval")))))"#
            ),
            canonical_json(json!({
                "where": ["src/**/*.py"],
                "languages": ["python"],
                "limit": 25,
                "match": { "kind": "call", "callee": { "name": "eval" } }
            }))
        );
    }

    #[test]
    fn structural_query_sexp_lowers_result_detail_wrapper() {
        assert_eq!(
            canonical(r#"(result-detail full (call :callee (name "eval")))"#),
            canonical_json(json!({
                "result_detail": "full",
                "match": { "kind": "call", "callee": { "name": "eval" } }
            }))
        );
    }

    #[test]
    fn structural_query_sexp_lowers_typed_steps_in_execution_order() {
        assert_eq!(
            canonical(r#"(imports-of (file-of (call :callee (name "load"))))"#),
            canonical_json(json!({
                "match": { "kind": "call", "callee": { "name": "load" } },
                "steps": [
                    { "op": "file_of" },
                    { "op": "imports_of" }
                ]
            }))
        );
    }

    #[test]
    fn reference_traversal_options_lower_in_any_order() {
        assert_eq!(
            canonical(
                r#"(references-of :surface external-usages :proof proven :reference-kinds [field-write method-call] (enclosing-decl (class :name "Target")))"#,
            ),
            canonical_json(json!({
                "match": { "kind": "class", "name": "Target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    {
                        "op": "references_of",
                        "reference_kinds": ["field_write", "method_call"],
                        "proof": "proven"
                    }
                ]
            }))
        );
    }

    #[test]
    fn structural_query_sexp_lowers_hierarchy_options_and_members() {
        assert_eq!(
            canonical(
                r#"(owner (members (subtypes :transitive true (supertypes :depth 2 (enclosing-decl (class :name "Service"))))))"#
            ),
            canonical_json(json!({
                "match": { "kind": "class", "name": "Service" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "supertypes", "depth": 2 },
                    { "op": "subtypes", "transitive": true },
                    { "op": "members" },
                    { "op": "owner" }
                ]
            }))
        );

        for invalid in [
            r#"(supertypes :depth 0 (enclosing-decl (class)))"#,
            r#"(subtypes :transitive false (enclosing-decl (class)))"#,
            r#"(subtypes :transitive "true" (enclosing-decl (class)))"#,
            r#"(supertypes :unknown 2 (enclosing-decl (class)))"#,
        ] {
            assert!(CodeQuery::from_sexp(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn structural_query_sexp_rejects_result_detail_as_pattern_field() {
        let error = CodeQuery::from_sexp(r#"(call :callee (name "eval") :result-detail full)"#)
            .unwrap_err();
        assert!(
            error.contains("unknown pattern field `:result-detail`"),
            "{error}"
        );
    }

    #[test]
    fn structural_query_sexp_lowers_string_role_shorthand() {
        assert_eq!(
            canonical(r#"(import :module "os")"#),
            canonical_json(json!({
                "match": {
                    "kind": "import",
                    "module": { "name": "os" }
                }
            }))
        );
    }

    #[test]
    fn structural_query_sexp_lowers_containment() {
        assert_eq!(
            canonical(r#"(inside (function :name "handler") (call :callee (name "eval")))"#),
            canonical_json(json!({
                "inside": { "kind": "function", "name": "handler" },
                "match": { "kind": "call", "callee": { "name": "eval" } }
            }))
        );
    }

    #[test]
    fn structural_query_sexp_reports_parser_errors() {
        let error = CodeQuery::from_sexp(r#"(call :callee (name "eval")"#).unwrap_err();
        assert!(error.contains("missing `)`"), "{error}");
    }

    #[test]
    fn structural_query_sexp_reports_unknown_forms() {
        let error = CodeQuery::from_sexp("(banana)").unwrap_err();
        assert!(
            error.contains("unknown S-expression form `banana`"),
            "{error}"
        );
    }

    #[test]
    fn structural_query_sexp_reports_bad_language() {
        let error = CodeQuery::from_sexp("(language klingon (call))").unwrap_err();
        assert!(
            error.contains("unknown language label `klingon`"),
            "{error}"
        );
    }

    #[test]
    fn structural_query_sexp_reports_duplicate_keyword_fields() {
        let error = CodeQuery::from_sexp(r#"(class :name "A" :name "B")"#).unwrap_err();
        assert!(
            error.contains("duplicate S-expression field `name`"),
            "{error}"
        );
    }

    #[test]
    fn structural_query_sexp_reports_excessive_parser_depth() {
        let mut input = String::new();
        for _ in 0..=MAX_SEXP_DEPTH + 1 {
            input.push('(');
        }
        input.push_str("call");
        for _ in 0..=MAX_SEXP_DEPTH + 1 {
            input.push(')');
        }
        let error = CodeQuery::from_sexp(&input).unwrap_err();
        assert!(
            error.contains("S-expression nesting exceeds maximum depth"),
            "{error}"
        );
    }

    #[test]
    fn structural_query_sexp_preserves_pathful_validation_errors() {
        let error = CodeQuery::from_sexp("(assignment :callee (name \"run\"))").unwrap_err();
        assert!(error.contains("match.callee"), "{error}");
    }
}
