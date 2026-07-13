//! Source-oriented parsing, validation, and help for unsaved RQL documents.

use super::schema::{
    PatternField, QueryField, RqlForm, RqlFormClass, RqlProperty, StringPredicateField,
};
use super::sexp::sexp_to_json;
use super::{CodeQuery, CodeQueryResultDetail};
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::{NormalizedKind, Role, RoleValueShape};
use json_spanned_value::spanned;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySourceDiagnostic {
    pub range: Range<usize>,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySourceHelp {
    pub range: Range<usize>,
    pub signature: String,
    pub description: String,
}

impl CodeQuery {
    /// Parse RQL or canonical JSON. JSON is selected only when the first
    /// non-whitespace character is an opening brace.
    pub fn from_source(source: &str) -> Result<Self, String> {
        if is_json_source(source) {
            let parsed: spanned::Value =
                json_spanned_value::from_str(source).map_err(|error| error.to_string())?;
            Self::from_json(&spanned_to_json(&parsed)).map_err(|error| error.to_string())
        } else {
            Self::from_sexp(source)
        }
    }
}

pub fn validate_query_source(source: &str) -> Vec<QuerySourceDiagnostic> {
    analyze_source(source).diagnostics
}

pub fn query_source_help_at(source: &str, byte_offset: usize) -> Option<QuerySourceHelp> {
    analyze_source(source)
        .help
        .into_iter()
        .find(|help| help.range.start <= byte_offset && byte_offset < help.range.end)
}

fn is_json_source(source: &str) -> bool {
    source.trim_start().starts_with('{')
}

#[derive(Default)]
struct Analysis {
    diagnostics: Vec<QuerySourceDiagnostic>,
    help: Vec<QuerySourceHelp>,
    paths: HashMap<String, Range<usize>>,
}

impl Analysis {
    fn error(&mut self, range: Range<usize>, code: &'static str, message: impl Into<String>) {
        self.diagnostics.push(QuerySourceDiagnostic {
            range,
            code,
            message: message.into(),
        });
    }

    fn add_help(
        &mut self,
        range: Range<usize>,
        signature: impl Into<String>,
        description: impl Into<String>,
    ) {
        self.help.push(QuerySourceHelp {
            range,
            signature: signature.into(),
            description: description.into(),
        });
    }

    fn path(&mut self, path: impl Into<String>, range: Range<usize>) {
        self.paths.insert(path.into(), range);
    }

    fn semantic_error(&mut self, error: super::QueryError, fallback: Range<usize>) {
        let mut path = error.path.as_str();
        let range = loop {
            if let Some(range) = self.paths.get(path) {
                break range.clone();
            }
            if let Some(index) = path.rfind(['.', '[']) {
                path = &path[..index];
            } else {
                break fallback;
            }
        };
        self.error(range, "invalid-query", error.message);
    }
}

fn analyze_source(source: &str) -> Analysis {
    if is_json_source(source) {
        analyze_json(source)
    } else {
        analyze_rql(source)
    }
}

#[derive(Debug, Clone)]
struct Expr {
    kind: ExprKind,
    range: Range<usize>,
}

#[derive(Debug, Clone)]
enum ExprKind {
    List(Vec<Expr>),
    Vector(Vec<Expr>),
    String,
    Symbol(String),
    Number(u64),
}

#[derive(Debug)]
struct ParseError {
    range: Range<usize>,
    message: String,
    incomplete: bool,
}

struct Parser<'a> {
    source: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self { source, pos: 0 }
    }

    fn parse(mut self) -> Result<Option<Expr>, ParseError> {
        self.skip_trivia();
        if self.pos == self.source.len() {
            return Ok(None);
        }
        let expr = self.expr(0)?;
        self.skip_trivia();
        if self.pos != self.source.len() {
            return Err(self.error_here("unexpected input after the query", false));
        }
        Ok(Some(expr))
    }

    fn expr(&mut self, depth: usize) -> Result<Expr, ParseError> {
        if depth > 128 {
            return Err(self.error_here("RQL nesting exceeds 128 levels", false));
        }
        self.skip_trivia();
        let start = self.pos;
        let Some(byte) = self.peek() else {
            return Err(self.error_here("expected an expression", true));
        };
        match byte {
            b'(' => self.delimited(b')', depth, true),
            b'[' => self.delimited(b']', depth, false),
            b')' | b']' => {
                self.pos += 1;
                Err(ParseError {
                    range: start..self.pos,
                    message: format!("unexpected '{}'", byte as char),
                    incomplete: false,
                })
            }
            b'"' => self.string(),
            b'0'..=b'9' => self.number(),
            _ => self.symbol(),
        }
    }

    fn delimited(&mut self, close: u8, depth: usize, list: bool) -> Result<Expr, ParseError> {
        let start = self.pos;
        self.pos += 1;
        let mut values = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek() {
                Some(byte) if byte == close => {
                    self.pos += 1;
                    return Ok(Expr {
                        kind: if list {
                            ExprKind::List(values)
                        } else {
                            ExprKind::Vector(values)
                        },
                        range: start..self.pos,
                    });
                }
                None => {
                    return Err(ParseError {
                        range: start..self.source.len(),
                        message: format!("missing '{}'", close as char),
                        incomplete: true,
                    });
                }
                _ => values.push(self.expr(depth + 1)?),
            }
        }
    }

    fn string(&mut self) -> Result<Expr, ParseError> {
        let start = self.pos;
        self.pos += 1;
        let mut escaped = false;
        while let Some(byte) = self.peek() {
            self.pos += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return serde_json::from_str::<String>(&self.source[start..self.pos])
                    .map(|_| Expr {
                        kind: ExprKind::String,
                        range: start..self.pos,
                    })
                    .map_err(|error| ParseError {
                        range: start..self.pos,
                        message: format!("invalid string: {error}"),
                        incomplete: false,
                    });
            }
        }
        Err(ParseError {
            range: start..self.source.len(),
            message: "unfinished string".to_string(),
            incomplete: true,
        })
    }

    fn number(&mut self) -> Result<Expr, ParseError> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let number = self.source[start..self.pos]
            .parse()
            .map_err(|error| ParseError {
                range: start..self.pos,
                message: format!("invalid number: {error}"),
                incomplete: false,
            })?;
        Ok(Expr {
            kind: ExprKind::Number(number),
            range: start..self.pos,
        })
    }

    fn symbol(&mut self) -> Result<Expr, ParseError> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || matches!(byte, b'(' | b')' | b'[' | b']' | b';') {
                break;
            }
            self.pos += 1;
        }
        if start == self.pos {
            return Err(self.error_here("expected a symbol", false));
        }
        Ok(Expr {
            kind: ExprKind::Symbol(self.source[start..self.pos].to_string()),
            range: start..self.pos,
        })
    }

    fn skip_trivia(&mut self) {
        loop {
            while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
                self.pos += 1;
            }
            if self.peek() != Some(b';') {
                break;
            }
            while self.peek().is_some_and(|byte| byte != b'\n') {
                self.pos += 1;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.pos).copied()
    }

    fn error_here(&self, message: &str, incomplete: bool) -> ParseError {
        ParseError {
            range: self.pos..self.pos.saturating_add(1).min(self.source.len()),
            message: message.to_string(),
            incomplete,
        }
    }
}

fn analyze_rql(source: &str) -> Analysis {
    let mut analysis = Analysis::default();
    let expr = match Parser::new(source).parse() {
        Ok(Some(expr)) => expr,
        Ok(None) => return analysis,
        Err(error) if error.incomplete => return analysis,
        Err(error) => {
            analysis.error(error.range, "invalid-syntax", error.message);
            return analysis;
        }
    };

    validate_rql_query(&expr, "match", &mut analysis);
    if analysis.diagnostics.is_empty() {
        match sexp_to_json(source) {
            Ok(json) => {
                if let Err(error) = CodeQuery::from_json(&json) {
                    analysis.semantic_error(error, expr.range.clone());
                }
            }
            Err(message) => analysis.error(expr.range.clone(), "invalid-query", message),
        }
    }
    analysis
}

fn list_head(expr: &Expr) -> Option<(&str, Range<usize>, &[Expr])> {
    let ExprKind::List(items) = &expr.kind else {
        return None;
    };
    let first = items.first()?;
    let ExprKind::Symbol(label) = &first.kind else {
        return None;
    };
    Some((label, first.range.clone(), &items[1..]))
}

fn validate_rql_query(expr: &Expr, path: &str, analysis: &mut Analysis) {
    analysis.path(path, expr.range.clone());
    let Some((head, head_range, args)) = list_head(expr) else {
        analysis.error(
            expr.range.clone(),
            "wrong-value-shape",
            "query must be an RQL list",
        );
        return;
    };
    if let Some(form) = RqlForm::from_label(head)
        && form.class() == RqlFormClass::Wrapper
    {
        analysis.add_help(head_range, form.signature(), form.description());
        validate_wrapper(form, args, path, analysis);
    } else {
        validate_rql_pattern(expr, path, analysis);
    }
}

fn validate_wrapper(form: RqlForm, args: &[Expr], path: &str, analysis: &mut Analysis) {
    let Some(query) = args.last() else {
        return;
    };
    match form {
        RqlForm::Where => {
            for arg in &args[..args.len().saturating_sub(1)] {
                require_string(arg, analysis);
            }
        }
        RqlForm::Language => {
            for arg in &args[..args.len().saturating_sub(1)] {
                validate_language(arg, analysis);
            }
        }
        RqlForm::Limit => {
            if args.len() != 2 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "limit expects a count and query",
                );
            } else if !matches!(args[0].kind, ExprKind::Number(value) if value > 0) {
                analysis.error(
                    args[0].range.clone(),
                    "wrong-value-shape",
                    "expected a positive integer",
                );
            }
        }
        RqlForm::ResultDetail => {
            if args.len() != 2 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "result-detail expects a value and query",
                );
            } else {
                validate_result_detail(&args[0], analysis);
            }
        }
        RqlForm::Inside | RqlForm::NotInside => {
            if args.len() != 2 {
                analysis.error(
                    query.range.clone(),
                    "wrong-value-shape",
                    "containment wrapper expects a pattern and query",
                );
            } else {
                let field = if form == RqlForm::Inside {
                    "inside"
                } else {
                    "not_inside"
                };
                validate_rql_pattern(&args[0], field, analysis);
            }
        }
        RqlForm::Name
        | RqlForm::NameRegex
        | RqlForm::TextRegex
        | RqlForm::Capture
        | RqlForm::Has
        | RqlForm::NotHas
        | RqlForm::NotKind => unreachable!("predicate cannot be a query wrapper"),
    }
    validate_rql_query(query, path, analysis);
}

fn validate_rql_pattern(expr: &Expr, path: &str, analysis: &mut Analysis) {
    analysis.path(path, expr.range.clone());
    let Some((head, head_range, args)) = list_head(expr) else {
        analysis.error(
            expr.range.clone(),
            "wrong-value-shape",
            "pattern must be an RQL list",
        );
        return;
    };
    if let Some(kind) = NormalizedKind::from_label(head) {
        analysis.add_help(head_range, kind.signature(), kind.description());
        let mut seen = HashSet::new();
        let mut index = 0;
        while index < args.len() {
            match &args[index].kind {
                ExprKind::Symbol(keyword) if keyword.starts_with(':') => {
                    let label = &keyword[1..];
                    let key_range = (args[index].range.start + 1)..args[index].range.end;
                    if index + 1 == args.len() {
                        return;
                    }
                    validate_rql_property(
                        label,
                        key_range,
                        &args[index + 1],
                        path,
                        &mut seen,
                        analysis,
                    );
                    index += 2;
                }
                ExprKind::List(_) => {
                    validate_predicate_fragment(&args[index], path, &mut seen, analysis);
                    index += 1;
                }
                _ => {
                    analysis.error(
                        args[index].range.clone(),
                        "wrong-value-shape",
                        "expected :property value or a predicate form",
                    );
                    index += 1;
                }
            }
        }
    } else if RqlForm::from_label(head).is_some_and(|form| form.class() == RqlFormClass::Predicate)
    {
        let mut seen = HashSet::new();
        validate_predicate_fragment(expr, path, &mut seen, analysis);
    } else {
        analysis.error(
            head_range,
            "unknown-form",
            format!("unknown RQL form '{head}'"),
        );
    }
}

fn validate_predicate_fragment(
    expr: &Expr,
    path: &str,
    seen: &mut HashSet<String>,
    analysis: &mut Analysis,
) {
    let Some((head, head_range, args)) = list_head(expr) else {
        return;
    };
    let Some(form) = RqlForm::from_label(head) else {
        analysis.error(
            head_range,
            "unknown-form",
            format!("unknown RQL form '{head}'"),
        );
        return;
    };
    if form.class() != RqlFormClass::Predicate {
        analysis.error(
            head_range,
            "wrong-form",
            "query wrapper cannot be nested as a predicate",
        );
        return;
    }
    analysis.add_help(head_range.clone(), form.signature(), form.description());
    if args.len() != 1 {
        analysis.error(
            head_range,
            "wrong-value-shape",
            format!("{} expects one value", form.label()),
        );
        return;
    }
    let property = RqlProperty::from_label(form.label()).expect("predicate has property metadata");
    validate_property_value(property, &args[0], path, analysis);
    record_duplicate(property.label(), head_range, seen, analysis);
}

fn validate_rql_property(
    label: &str,
    range: Range<usize>,
    value: &Expr,
    path: &str,
    seen: &mut HashSet<String>,
    analysis: &mut Analysis,
) {
    if let Some(property) = RqlProperty::from_label(label) {
        analysis.add_help(range.clone(), property.signature(), property.description());
        validate_property_value(property, value, path, analysis);
        record_duplicate(property.label(), range, seen, analysis);
    } else if let Some(role) = Role::from_label(label) {
        analysis.add_help(
            range.clone(),
            format!(":{} {}", role.label(), role.signature()),
            role.description(),
        );
        let child = format!("{path}.{}", role.label());
        analysis.path(&child, value.range.clone());
        match role.value_shape() {
            RoleValueShape::Pattern => validate_rql_pattern(value, &child, analysis),
            RoleValueShape::PatternList => validate_pattern_list(value, &child, analysis),
            RoleValueShape::PatternMap => validate_pattern_map(value, &child, analysis),
        }
        record_duplicate(role.label(), range, seen, analysis);
    } else {
        analysis.error(
            range,
            "unknown-property",
            format!("unknown pattern property ':{label}'"),
        );
    }
}

fn record_duplicate(
    canonical: &str,
    range: Range<usize>,
    seen: &mut HashSet<String>,
    analysis: &mut Analysis,
) {
    if !seen.insert(canonical.to_string()) {
        analysis.error(
            range,
            "duplicate-property",
            format!("duplicate pattern property '{canonical}'"),
        );
    }
}

fn validate_property_value(
    property: RqlProperty,
    value: &Expr,
    path: &str,
    analysis: &mut Analysis,
) {
    let child = format!("{path}.{}", property.label().replace('-', "_"));
    analysis.path(&child, value.range.clone());
    match property {
        RqlProperty::Name
        | RqlProperty::NameRegex
        | RqlProperty::TextRegex
        | RqlProperty::Capture => {
            require_string(value, analysis);
        }
        RqlProperty::NotKind => validate_kind_value(value, analysis),
        RqlProperty::Has | RqlProperty::NotHas => validate_rql_pattern(value, &child, analysis),
    }
}

fn validate_pattern_list(value: &Expr, path: &str, analysis: &mut Analysis) {
    let items = match &value.kind {
        ExprKind::List(items) | ExprKind::Vector(items) => items,
        _ => {
            analysis.error(
                value.range.clone(),
                "wrong-value-shape",
                "expected a list/vector of patterns",
            );
            return;
        }
    };
    for (index, item) in items.iter().enumerate() {
        validate_rql_pattern(item, &format!("{path}[{index}]"), analysis);
    }
}

fn validate_pattern_map(value: &Expr, path: &str, analysis: &mut Analysis) {
    let pairs = match &value.kind {
        ExprKind::List(items) | ExprKind::Vector(items) => items,
        _ => {
            analysis.error(
                value.range.clone(),
                "wrong-value-shape",
                "expected named pattern pairs",
            );
            return;
        }
    };
    for pair in pairs {
        let ExprKind::List(items) = &pair.kind else {
            analysis.error(
                pair.range.clone(),
                "wrong-value-shape",
                "named pattern entry must be a list",
            );
            continue;
        };
        if items.len() != 2 {
            analysis.error(
                pair.range.clone(),
                "wrong-value-shape",
                "named pattern entry expects a name and pattern",
            );
        } else {
            validate_rql_pattern(&items[1], path, analysis);
        }
    }
}

fn require_string(value: &Expr, analysis: &mut Analysis) {
    if !matches!(value.kind, ExprKind::String) {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "expected a string",
        );
    }
}

fn validate_kind_value(value: &Expr, analysis: &mut Analysis) {
    match &value.kind {
        ExprKind::Symbol(label) => {
            if let Some(kind) = NormalizedKind::from_label(label) {
                analysis.add_help(value.range.clone(), kind.signature(), kind.description());
            } else {
                analysis.error(
                    value.range.clone(),
                    "invalid-kind",
                    format!("unknown normalized kind '{label}'"),
                );
            }
        }
        ExprKind::Vector(items) | ExprKind::List(items) => {
            for item in items {
                validate_kind_value(item, analysis);
            }
        }
        ExprKind::String => {}
        _ => analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "expected a kind or list of kinds",
        ),
    }
}

fn validate_language(value: &Expr, analysis: &mut Analysis) {
    match &value.kind {
        ExprKind::Symbol(label) => {
            if let Some(language) = Language::from_config_label(label) {
                analysis.add_help(
                    value.range.clone(),
                    language.config_label(),
                    "Restrict structural matching to this analyzer language.",
                );
            } else {
                analysis.error(
                    value.range.clone(),
                    "invalid-language",
                    format!("unknown language label '{label}'"),
                );
            }
        }
        ExprKind::String => {}
        _ => analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "expected a language label",
        ),
    }
}

fn validate_result_detail(value: &Expr, analysis: &mut Analysis) {
    let ExprKind::Symbol(label) = &value.kind else {
        analysis.error(
            value.range.clone(),
            "wrong-value-shape",
            "expected compact or full",
        );
        return;
    };
    if CodeQueryResultDetail::from_label(label).is_some() {
        analysis.add_help(
            value.range.clone(),
            label,
            if label == "compact" {
                "Return compact match locations."
            } else {
                "Return full capture and source details."
            },
        );
    } else {
        analysis.error(
            value.range.clone(),
            "invalid-result-detail",
            "expected compact or full",
        );
    }
}

fn analyze_json(source: &str) -> Analysis {
    let mut analysis = Analysis::default();
    let parsed: spanned::Value = match json_spanned_value::from_str(source) {
        Ok(value) => value,
        Err(error) if error.classify() == serde_json::error::Category::Eof => return analysis,
        Err(error) => {
            let offset = json_error_offset(source, error.line(), error.column());
            let end = source[offset..]
                .chars()
                .next()
                .map_or(offset, |ch| offset + ch.len_utf8());
            analysis.error(offset..end, "invalid-json", error.to_string());
            return analysis;
        }
    };
    validate_json_query(&parsed, "", &mut analysis);
    if analysis.diagnostics.is_empty()
        && let Err(error) = CodeQuery::from_json(&spanned_to_json(&parsed))
    {
        analysis.semantic_error(error, parsed.range());
    }
    analysis
}

fn validate_json_query(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    analysis.path(path, value.range());
    let Some(object) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "query must be a JSON object",
        );
        return;
    };
    for (key, child) in object {
        let child_path = join_path(path, key.get_ref());
        analysis.path(&child_path, child.range());
        let Some(field) = QueryField::from_label(key.get_ref()) else {
            analysis.error(
                key.range(),
                "unknown-property",
                format!("unknown query property '{key}'"),
            );
            continue;
        };
        analysis.add_help(key.range(), field.signature(), field.description());
        match field {
            QueryField::Where => validate_string_array(child, "where", analysis),
            QueryField::Languages => validate_json_languages(child, analysis),
            QueryField::Match | QueryField::Inside | QueryField::NotInside => {
                validate_json_pattern(child, &child_path, analysis);
            }
            QueryField::Limit => {
                if child
                    .as_number()
                    .and_then(serde_json::Number::as_u64)
                    .is_none_or(|number| number == 0)
                {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "expected a positive integer",
                    );
                }
            }
            QueryField::ResultDetail => validate_json_result_detail(child, analysis),
            QueryField::SchemaVersion => {
                if child.as_number().and_then(serde_json::Number::as_u64) != Some(1) {
                    analysis.error(
                        child.range(),
                        "wrong-value-shape",
                        "expected schema version 1",
                    );
                }
            }
        }
    }
}

fn validate_json_pattern(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    analysis.path(path, value.range());
    let Some(object) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "pattern must be a JSON object",
        );
        return;
    };
    for (key, child) in object {
        let child_path = join_path(path, key.get_ref());
        analysis.path(&child_path, child.range());
        if let Some(field) = PatternField::from_label(key.get_ref()) {
            analysis.add_help(key.range(), field.signature(), field.description());
            match field {
                PatternField::Kind | PatternField::NotKind => validate_json_kinds(child, analysis),
                PatternField::Name | PatternField::Text => {
                    validate_string_predicate(child, analysis)
                }
                PatternField::Capture => require_json_string(child, analysis),
                PatternField::Has | PatternField::NotHas => {
                    validate_json_pattern(child, &child_path, analysis);
                }
            }
        } else if let Some(role) = Role::from_label(key.get_ref()) {
            analysis.add_help(
                key.range(),
                format!("\"{}\": {}", role.label(), role.signature()),
                role.description(),
            );
            match role.value_shape() {
                RoleValueShape::Pattern => validate_json_pattern(child, &child_path, analysis),
                RoleValueShape::PatternList => {
                    validate_json_pattern_array(child, &child_path, analysis);
                }
                RoleValueShape::PatternMap => {
                    validate_json_pattern_map(child, &child_path, analysis);
                }
            }
        } else {
            analysis.error(
                key.range(),
                "unknown-property",
                format!("unknown pattern property '{key}'"),
            );
        }
    }
}

fn validate_json_kinds(value: &spanned::Value, analysis: &mut Analysis) {
    if let Some(label) = value.as_string() {
        if let Some(kind) = NormalizedKind::from_label(label) {
            analysis.add_help(value.range(), kind.signature(), kind.description());
        } else {
            analysis.error(
                value.range(),
                "invalid-kind",
                format!("unknown normalized kind '{label}'"),
            );
        }
    } else if let Some(values) = value.as_array() {
        for value in values {
            validate_json_kinds(value, analysis);
        }
    } else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected a kind string or array of kind strings",
        );
    }
}

fn validate_string_predicate(value: &spanned::Value, analysis: &mut Analysis) {
    if value.is_string() {
        return;
    }
    let Some(object) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected a string or { \"regex\": string }",
        );
        return;
    };
    for (key, value) in object {
        if StringPredicateField::from_label(key.get_ref()).is_none() {
            analysis.error(
                key.range(),
                "unknown-property",
                "string predicate only accepts 'regex'",
            );
        } else {
            analysis.add_help(
                key.range(),
                "\"regex\": \"pattern\"",
                "Match the value with a regular expression.",
            );
            require_json_string(value, analysis);
        }
    }
}

fn validate_json_pattern_array(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    let Some(values) = value.as_array() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected an array of patterns",
        );
        return;
    };
    for (index, value) in values.iter().enumerate() {
        validate_json_pattern(value, &format!("{path}[{index}]"), analysis);
    }
}

fn validate_json_pattern_map(value: &spanned::Value, path: &str, analysis: &mut Analysis) {
    let Some(values) = value.as_object() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected an object mapping names to patterns",
        );
        return;
    };
    for (key, value) in values {
        validate_json_pattern(value, &join_path(path, key.get_ref()), analysis);
    }
}

fn validate_string_array(value: &spanned::Value, label: &str, analysis: &mut Analysis) {
    let Some(values) = value.as_array() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            format!("{label} must be an array of strings"),
        );
        return;
    };
    for value in values {
        require_json_string(value, analysis);
    }
}

fn validate_json_languages(value: &spanned::Value, analysis: &mut Analysis) {
    let Some(values) = value.as_array() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "languages must be an array of strings",
        );
        return;
    };
    for value in values {
        let Some(label) = value.as_string() else {
            analysis.error(
                value.range(),
                "wrong-value-shape",
                "expected a language label string",
            );
            continue;
        };
        if let Some(language) = Language::from_config_label(label) {
            analysis.add_help(
                value.range(),
                language.config_label(),
                "Restrict structural matching to this analyzer language.",
            );
        } else {
            analysis.error(
                value.range(),
                "invalid-language",
                format!("unknown language '{label}'"),
            );
        }
    }
}

fn validate_json_result_detail(value: &spanned::Value, analysis: &mut Analysis) {
    let Some(label) = value.as_string() else {
        analysis.error(
            value.range(),
            "wrong-value-shape",
            "expected compact or full",
        );
        return;
    };
    if CodeQueryResultDetail::from_label(label).is_some() {
        analysis.add_help(
            value.range(),
            label,
            if label == "compact" {
                "Return compact match locations."
            } else {
                "Return full capture and source details."
            },
        );
    } else {
        analysis.error(
            value.range(),
            "invalid-result-detail",
            "expected compact or full",
        );
    }
}

fn require_json_string(value: &spanned::Value, analysis: &mut Analysis) {
    if !value.is_string() {
        analysis.error(value.range(), "wrong-value-shape", "expected a string");
    }
}

fn join_path(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_string()
    } else {
        format!("{path}.{field}")
    }
}

fn spanned_to_json(value: &spanned::Value) -> Value {
    match value.get_ref() {
        json_spanned_value::Value::Null => Value::Null,
        json_spanned_value::Value::Bool(value) => Value::Bool(*value),
        json_spanned_value::Value::Number(value) => Value::Number(value.clone()),
        json_spanned_value::Value::String(value) => Value::String(value.clone()),
        json_spanned_value::Value::Array(values) => {
            Value::Array(values.iter().map(spanned_to_json).collect())
        }
        json_spanned_value::Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.get_ref().clone(), spanned_to_json(value)))
                .collect::<Map<_, _>>(),
        ),
    }
}

fn json_error_offset(source: &str, line: usize, column: usize) -> usize {
    let line_start = source
        .split_inclusive('\n')
        .take(line.saturating_sub(1))
        .map(str::len)
        .sum::<usize>();
    line_start
        + source[line_start..]
            .char_indices()
            .nth(column.saturating_sub(1))
            .map_or_else(
                || source.len().saturating_sub(line_start),
                |(offset, _)| offset,
            )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_for_empty_and_incomplete_sources() {
        for source in [
            "",
            "  ; comment",
            "(call",
            "(call :callee",
            "\"unfinished",
            "{\"match\":",
        ] {
            assert!(validate_query_source(source).is_empty(), "{source:?}");
        }
    }

    #[test]
    fn reports_multiple_rql_errors_at_exact_ranges() {
        let source = "(call :wat 1 :name 2 :also-nope 3)";
        let diagnostics = validate_query_source(source);
        assert_eq!(diagnostics.len(), 3);
        assert_eq!(&source[diagnostics[0].range.clone()], "wat");
        assert_eq!(&source[diagnostics[1].range.clone()], "2");
        assert_eq!(&source[diagnostics[2].range.clone()], "also-nope");
    }

    #[test]
    fn reports_multiple_json_errors_at_key_and_value_ranges() {
        let source = r#"{"oops": 1, "match": {"kind": "banana", "capture": 4}}"#;
        let mut diagnostics = validate_query_source(source);
        diagnostics.sort_by_key(|diagnostic| diagnostic.range.start);
        assert_eq!(diagnostics.len(), 3);
        assert_eq!(&source[diagnostics[0].range.clone()], "\"oops\"");
        assert_eq!(&source[diagnostics[1].range.clone()], "\"banana\"");
        assert_eq!(&source[diagnostics[2].range.clone()], "4");
    }

    #[test]
    fn canonical_json_and_rql_execute_equivalently() {
        let rql = CodeQuery::from_source("(language rust (call :callee (name \"run\")))")
            .expect("RQL query");
        let json = CodeQuery::from_source(
            r#"{"languages":["rust"],"match":{"kind":"call","callee":{"name":"run"}}}"#,
        )
        .expect("JSON query");
        assert_eq!(rql.to_canonical_json(), json.to_canonical_json());
    }

    #[test]
    fn help_covers_forms_properties_roles_kinds_and_values() {
        let source = "(result-detail full (call :callee (name \"run\")))";
        for token in ["result-detail", "full", "call", "callee", "name"] {
            let offset = source.find(token).unwrap();
            let help = query_source_help_at(source, offset)
                .unwrap_or_else(|| panic!("no help for {token}"));
            assert!(!help.description.is_empty());
            assert_eq!(&source[help.range], token);
        }
        assert!(query_source_help_at(source, source.find("run").unwrap()).is_none());
    }

    #[test]
    fn byte_ranges_preserve_utf8_boundaries() {
        let source = "(call :unknown-λ 1)";
        let diagnostic = validate_query_source(source).pop().expect("diagnostic");
        assert_eq!(&source[diagnostic.range], "unknown-λ");
    }
}
