use super::ir::{CodeQuery, CodeQueryResultDetail};
use super::schema::{RqlForm, RqlFormClass, RqlProperty};
#[cfg(test)]
use super::syntax::MAX_RQL_DEPTH;
use super::syntax::{Expr, ExprKind, parse_rql};
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::{NormalizedKind, Role, RoleValueShape};
use serde_json::{Map, Number, Value, json};

const MAX_SEXP_INPUT_BYTES: usize = 64 * 1024;

impl CodeQuery {
    pub fn from_sexp(input: &str) -> Result<Self, String> {
        let value = sexp_to_json(input)?;
        Self::from_json(&value).map_err(|error| error.to_string())
    }
}

pub fn sexp_to_json(input: &str) -> Result<Value, String> {
    if input.len() > MAX_SEXP_INPUT_BYTES {
        return Err(format!(
            "S-expression query is too large: {} bytes exceeds {}",
            input.len(),
            MAX_SEXP_INPUT_BYTES
        ));
    }
    let parsed = parse_rql(input).map_err(|error| error.message)?;
    if let Some(error) = parsed.incomplete {
        return Err(error.message);
    }
    let expr = parsed
        .expr
        .ok_or_else(|| "expected expression, found end of input".to_string())?;
    query_to_json(&expr)
}

pub(crate) fn query_to_json(expr: &Expr) -> Result<Value, String> {
    if let Some(value) = wrapper_query_to_json(expr)? {
        return Ok(value);
    }
    Ok(json!({ "match": pattern_to_json(expr)? }))
}

fn wrapper_query_to_json(expr: &Expr) -> Result<Option<Value>, String> {
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
                return Err("(where ...) requires at least one glob and a query".to_string());
            }
            let mut query = query_object(&items[items.len() - 1])?;
            let globs = items[1..items.len() - 1]
                .iter()
                .map(string_arg)
                .collect::<Result<Vec<_>, _>>()?;
            insert_unique(&mut query, "where", array_of_strings(globs))?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Language => {
            if items.len() < 3 {
                return Err("(language ...) requires at least one label and a query".to_string());
            }
            let mut query = query_object(&items[items.len() - 1])?;
            let labels = items[1..items.len() - 1]
                .iter()
                .map(language_arg)
                .collect::<Result<Vec<_>, _>>()?;
            insert_unique(&mut query, "languages", array_of_strings(labels))?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Limit => {
            expect_len(items, 3, "limit")?;
            let mut query = query_object(&items[2])?;
            insert_unique(&mut query, "limit", number_value(&items[1], "limit")?)?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::ResultDetail => {
            expect_len(items, 3, head)?;
            let mut query = query_object(&items[2])?;
            insert_unique(
                &mut query,
                "result_detail",
                Value::String(result_detail_arg(&items[1])?),
            )?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::Inside | RqlForm::NotInside => {
            expect_len(items, 3, head)?;
            let mut query = query_object(&items[2])?;
            let field = if form == RqlForm::Inside {
                "inside"
            } else {
                "not_inside"
            };
            insert_unique(&mut query, field, pattern_to_json(&items[1])?)?;
            Ok(Some(Value::Object(query)))
        }
        RqlForm::EnclosingDecl
        | RqlForm::FileOf
        | RqlForm::ImportsOf
        | RqlForm::ImportersOf
        | RqlForm::Members
        | RqlForm::Owner => {
            expect_len(items, 2, head)?;
            let mut query = query_object(&items[1])?;
            let steps = query
                .entry("steps".to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| "internal error: steps must be an array".to_string())?;
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
        RqlForm::Supertypes | RqlForm::Subtypes => {
            let (query_expr, option) = match items.len() {
                2 => (&items[1], None),
                4 => (&items[3], Some((&items[1], &items[2]))),
                _ => {
                    return Err(format!(
                        "({head} ...) expects a query, optionally preceded by :depth count or :transitive true"
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
                        if symbol_or_string(value)?.as_str() != "true" {
                            return Err(format!("({head} :transitive ...) requires true"));
                        }
                        step.insert("transitive".to_string(), Value::Bool(true));
                    }
                    _ => {
                        return Err(format!(
                            "({head} ...) accepts only :depth count or :transitive true"
                        ));
                    }
                }
            }
            query
                .entry("steps".to_string())
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| "internal error: steps must be an array".to_string())?
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

fn query_object(expr: &Expr) -> Result<Map<String, Value>, String> {
    match query_to_json(expr)? {
        Value::Object(object) => Ok(object),
        _ => unreachable!("query_to_json always returns an object"),
    }
}

fn pattern_to_json(expr: &Expr) -> Result<Value, String> {
    let Some(items) = expr.as_list() else {
        return Err("pattern must be an S-expression list".to_string());
    };
    let Some(head) = head_symbol(items)? else {
        return Err("pattern list must not be empty".to_string());
    };

    let mut object = Map::new();
    if NormalizedKind::from_label(head).is_some() {
        insert_unique(&mut object, "kind", Value::String(head.to_string()))?;
        parse_pattern_tail(&mut object, &items[1..])?;
        return Ok(Value::Object(object));
    }

    let Some(form) = RqlForm::from_label(head) else {
        return Err(format!("unknown S-expression form `{head}`"));
    };
    if form.class() != RqlFormClass::Predicate {
        return Err(format!("S-expression wrapper `{head}` is not a pattern"));
    }
    match form {
        RqlForm::Name => {
            expect_len(items, 2, "name")?;
            insert_unique(&mut object, "name", Value::String(string_arg(&items[1])?))?;
        }
        RqlForm::NameRegex => {
            expect_len(items, 2, "name/regex")?;
            insert_unique(
                &mut object,
                "name".to_string(),
                json!({ "regex": string_arg(&items[1])? }),
            )?;
        }
        RqlForm::TextRegex => {
            expect_len(items, 2, "text/regex")?;
            insert_unique(
                &mut object,
                "text".to_string(),
                json!({ "regex": string_arg(&items[1])? }),
            )?;
        }
        RqlForm::Capture => {
            expect_len(items, 2, "capture")?;
            insert_unique(
                &mut object,
                "capture",
                Value::String(string_arg(&items[1])?),
            )?;
        }
        RqlForm::Has | RqlForm::NotHas => {
            expect_len(items, 2, head)?;
            insert_unique(
                &mut object,
                if form == RqlForm::Has {
                    "has"
                } else {
                    "not_has"
                }
                .to_string(),
                pattern_to_json(&items[1])?,
            )?;
        }
        RqlForm::NotKind => {
            expect_len(items, 2, "not-kind")?;
            insert_unique(&mut object, "not_kind", kind_value(&items[1])?)?;
        }
        RqlForm::Where
        | RqlForm::Language
        | RqlForm::Limit
        | RqlForm::ResultDetail
        | RqlForm::Inside
        | RqlForm::NotInside
        | RqlForm::EnclosingDecl
        | RqlForm::FileOf
        | RqlForm::ImportsOf
        | RqlForm::ImportersOf
        | RqlForm::Supertypes
        | RqlForm::Subtypes
        | RqlForm::Members
        | RqlForm::Owner => unreachable!("wrapper filtered above"),
    }
    Ok(Value::Object(object))
}

fn parse_pattern_tail(object: &mut Map<String, Value>, tail: &[Expr]) -> Result<(), String> {
    let mut index = 0;
    while index < tail.len() {
        match &tail[index].kind {
            ExprKind::Symbol(keyword) if keyword.starts_with(':') => {
                if index + 1 >= tail.len() {
                    return Err(format!("keyword `{keyword}` requires a value"));
                }
                insert_keyword(object, &keyword[1..], &tail[index + 1])?;
                index += 2;
            }
            ExprKind::List(_) => {
                merge_pattern_fragment(object, pattern_to_json(&tail[index])?)?;
                index += 1;
            }
            _ => {
                return Err(format!(
                    "unexpected pattern argument {}; use :field value or a predicate form",
                    describe_expr(&tail[index])
                ));
            }
        }
    }
    Ok(())
}

fn insert_keyword(object: &mut Map<String, Value>, key: &str, value: &Expr) -> Result<(), String> {
    if let Some(property) = RqlProperty::from_label(key) {
        return match property {
            RqlProperty::Name => insert_unique(object, "name", Value::String(string_arg(value)?)),
            RqlProperty::NameRegex => {
                insert_unique(object, "name", json!({ "regex": string_arg(value)? }))
            }
            RqlProperty::TextRegex => {
                insert_unique(object, "text", json!({ "regex": string_arg(value)? }))
            }
            RqlProperty::Capture => {
                insert_unique(object, "capture", Value::String(string_arg(value)?))
            }
            RqlProperty::NotKind => insert_unique(object, "not_kind", kind_value(value)?),
            RqlProperty::Has => insert_unique(object, "has", pattern_to_json(value)?),
            RqlProperty::NotHas => insert_unique(object, "not_has", pattern_to_json(value)?),
        };
    }
    let Some(role) = Role::from_label(key) else {
        return Err(format!("unknown pattern field `:{key}`"));
    };
    match role.value_shape() {
        RoleValueShape::Pattern => insert_unique(object, role.label(), single_role_value(value)?),
        RoleValueShape::PatternList => insert_unique(object, role.label(), pattern_array(value)?),
        RoleValueShape::PatternMap => insert_unique(object, role.label(), kwargs_object(value)?),
    }
}

fn merge_pattern_fragment(object: &mut Map<String, Value>, fragment: Value) -> Result<(), String> {
    let Value::Object(fragment) = fragment else {
        return Err("pattern fragment must lower to an object".to_string());
    };
    for (key, value) in fragment {
        insert_unique(object, key, value)?;
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

fn single_role_value(expr: &Expr) -> Result<Value, String> {
    match expr.as_string() {
        Some(value) => Ok(json!({ "name": value })),
        None => pattern_to_json(expr),
    }
}

fn pattern_array(expr: &Expr) -> Result<Value, String> {
    let items = expr
        .as_sequence()
        .ok_or_else(|| "expected a list/vector of patterns".to_string())?;
    items
        .iter()
        .map(pattern_to_json)
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

fn kwargs_object(expr: &Expr) -> Result<Value, String> {
    let pairs = expr
        .as_sequence()
        .ok_or_else(|| "expected a list/vector of keyword argument pairs".to_string())?;
    let mut object = Map::new();
    for pair in pairs {
        let Some(items) = pair.as_list() else {
            return Err("keyword argument entry must be a list".to_string());
        };
        expect_len(items, 2, "kwargs entry")?;
        let key = symbol_or_string(&items[0])?;
        insert_unique(&mut object, key, pattern_to_json(&items[1])?)?;
    }
    Ok(Value::Object(object))
}

fn kind_value(expr: &Expr) -> Result<Value, String> {
    match expr.as_sequence() {
        Some(items) => items
            .iter()
            .map(kind_label)
            .collect::<Result<Vec<_>, _>>()
            .map(array_of_strings),
        None => Ok(Value::String(kind_label(expr)?)),
    }
}

fn kind_label(expr: &Expr) -> Result<String, String> {
    let label = symbol_or_string(expr)?;
    if NormalizedKind::from_label(&label).is_some() {
        Ok(label)
    } else {
        Err(format!("unknown normalized kind `{label}`"))
    }
}

fn language_arg(expr: &Expr) -> Result<String, String> {
    let label = symbol_or_string(expr)?;
    Language::from_config_label(&label)
        .map(|language| language.config_label().to_string())
        .ok_or_else(|| format!("unknown language label `{label}`"))
}

fn result_detail_arg(expr: &Expr) -> Result<String, String> {
    let label = symbol_or_string(expr)?;
    CodeQueryResultDetail::from_label(&label)
        .map(|detail| detail.label().to_string())
        .ok_or_else(|| format!("unknown result detail `{label}`"))
}

fn string_arg(expr: &Expr) -> Result<String, String> {
    expr.as_string()
        .map(str::to_string)
        .ok_or_else(|| format!("expected string, got {}", describe_expr(expr)))
}

fn symbol_or_string(expr: &Expr) -> Result<String, String> {
    expr.as_string()
        .or_else(|| expr.as_symbol())
        .map(str::to_string)
        .ok_or_else(|| format!("expected symbol or string, got {}", describe_expr(expr)))
}

fn number_value(expr: &Expr, context: &str) -> Result<Value, String> {
    expr.as_number()
        .map(|value| Value::Number(Number::from(value)))
        .ok_or_else(|| format!("({context} ...) requires a number"))
}

fn array_of_strings(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}

fn head_symbol(items: &[Expr]) -> Result<Option<&str>, String> {
    match items.first() {
        Some(expr) if expr.as_symbol().is_some() => Ok(expr.as_symbol()),
        Some(other) => Err(format!(
            "S-expression head must be a symbol, got {}",
            describe_expr(other)
        )),
        None => Ok(None),
    }
}

fn expect_len(items: &[Expr], len: usize, form: &str) -> Result<(), String> {
    if items.len() == len {
        Ok(())
    } else {
        Err(format!(
            "({form} ...) expects {} argument{}",
            len - 1,
            if len == 2 { "" } else { "s" }
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
        for _ in 0..=MAX_RQL_DEPTH + 1 {
            input.push('(');
        }
        input.push_str("call");
        for _ in 0..=MAX_RQL_DEPTH + 1 {
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
