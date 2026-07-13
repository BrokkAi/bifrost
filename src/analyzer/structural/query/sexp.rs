use super::ir::{CodeQuery, CodeQueryResultDetail};
use super::schema::{RqlForm, RqlFormClass, RqlProperty};
use crate::analyzer::Language;
use crate::analyzer::structural::kinds::{NormalizedKind, Role};
use serde_json::{Map, Number, Value, json};

const MAX_SEXP_INPUT_BYTES: usize = 64 * 1024;
const MAX_SEXP_DEPTH: usize = 128;

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
    let mut parser = Parser::new(input);
    let expr = parser.parse_expr()?;
    parser.skip_ws();
    if !parser.is_eof() {
        return Err(format!("unexpected input at byte {}", parser.pos));
    }
    query_to_json(&expr)
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    List(Vec<Expr>),
    Vector(Vec<Expr>),
    String(String),
    Symbol(String),
    Number(u64),
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn parse_expr(&mut self) -> Result<Expr, String> {
        self.parse_expr_at_depth(0)
    }

    fn parse_expr_at_depth(&mut self, depth: usize) -> Result<Expr, String> {
        if depth > MAX_SEXP_DEPTH {
            return Err(format!(
                "S-expression nesting exceeds maximum depth {MAX_SEXP_DEPTH}"
            ));
        }
        self.skip_ws();
        let Some(byte) = self.peek() else {
            return Err("expected expression, found end of input".to_string());
        };
        match byte {
            b'(' => self.parse_delimited(b'(', b')', depth + 1).map(Expr::List),
            b'[' => self
                .parse_delimited(b'[', b']', depth + 1)
                .map(Expr::Vector),
            b'"' => self.parse_string().map(Expr::String),
            b'0'..=b'9' => self.parse_number().map(Expr::Number),
            _ => self.parse_symbol().map(Expr::Symbol),
        }
    }

    fn parse_delimited(&mut self, open: u8, close: u8, depth: usize) -> Result<Vec<Expr>, String> {
        self.expect(open)?;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(close) {
                self.pos += 1;
                return Ok(items);
            }
            if self.is_eof() {
                return Err(format!("missing `{}`", close as char));
            }
            items.push(self.parse_expr_at_depth(depth)?);
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        let start = self.pos;
        self.expect(b'"')?;
        let mut escaped = false;
        while let Some(byte) = self.peek() {
            self.pos += 1;
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'"' => {
                    return serde_json::from_str(&self.input[start..self.pos])
                        .map_err(|error| format!("invalid string at byte {start}: {error}"));
                }
                _ => {}
            }
        }
        Err(format!("unterminated string at byte {start}"))
    }

    fn parse_number(&mut self) -> Result<u64, String> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.input[start..self.pos]
            .parse()
            .map_err(|error| format!("invalid number at byte {start}: {error}"))
    }

    fn parse_symbol(&mut self) -> Result<String, String> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || matches!(byte, b'(' | b')' | b'[' | b']') {
                break;
            }
            self.pos += 1;
        }
        if start == self.pos {
            return Err(format!("expected symbol at byte {start}"));
        }
        Ok(self.input[start..self.pos].to_string())
    }

    fn skip_ws(&mut self) {
        loop {
            while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
                self.pos += 1;
            }
            if self.peek() == Some(b';') {
                while self.peek().is_some_and(|byte| byte != b'\n') {
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), String> {
        match self.peek() {
            Some(byte) if byte == expected => {
                self.pos += 1;
                Ok(())
            }
            Some(byte) => Err(format!(
                "expected `{}`, found `{}` at byte {}",
                expected as char, byte as char, self.pos
            )),
            None => Err(format!(
                "expected `{}`, found end of input",
                expected as char
            )),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }
}

fn query_to_json(expr: &Expr) -> Result<Value, String> {
    if let Some(value) = wrapper_query_to_json(expr)? {
        return Ok(value);
    }
    Ok(json!({ "match": pattern_to_json(expr)? }))
}

fn wrapper_query_to_json(expr: &Expr) -> Result<Option<Value>, String> {
    let Expr::List(items) = expr else {
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
    let Expr::List(items) = expr else {
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
        | RqlForm::NotInside => unreachable!("wrapper filtered above"),
    }
    Ok(Value::Object(object))
}

fn parse_pattern_tail(object: &mut Map<String, Value>, tail: &[Expr]) -> Result<(), String> {
    let mut index = 0;
    while index < tail.len() {
        match &tail[index] {
            Expr::Symbol(keyword) if keyword.starts_with(':') => {
                if index + 1 >= tail.len() {
                    return Err(format!("keyword `{keyword}` requires a value"));
                }
                insert_keyword(object, &keyword[1..], &tail[index + 1])?;
                index += 2;
            }
            Expr::List(_) => {
                merge_pattern_fragment(object, pattern_to_json(&tail[index])?)?;
                index += 1;
            }
            other => {
                return Err(format!(
                    "unexpected pattern argument {}; use :field value or a predicate form",
                    describe_expr(other)
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
    if Role::single_target_roles().contains(&role) {
        insert_unique(object, role.label(), single_role_value(value)?)
    } else if Role::list_target_roles().contains(&role) {
        insert_unique(object, role.label(), pattern_array(value)?)
    } else {
        insert_unique(object, role.label(), kwargs_object(value)?)
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
    match expr {
        Expr::String(value) => Ok(json!({ "name": value })),
        _ => pattern_to_json(expr),
    }
}

fn pattern_array(expr: &Expr) -> Result<Value, String> {
    let items = match expr {
        Expr::Vector(items) | Expr::List(items) => items,
        _ => return Err("expected a list/vector of patterns".to_string()),
    };
    items
        .iter()
        .map(pattern_to_json)
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

fn kwargs_object(expr: &Expr) -> Result<Value, String> {
    let pairs = match expr {
        Expr::Vector(items) | Expr::List(items) => items,
        _ => return Err("expected a list/vector of keyword argument pairs".to_string()),
    };
    let mut object = Map::new();
    for pair in pairs {
        let Expr::List(items) = pair else {
            return Err("keyword argument entry must be a list".to_string());
        };
        expect_len(items, 2, "kwargs entry")?;
        let key = symbol_or_string(&items[0])?;
        insert_unique(&mut object, key, pattern_to_json(&items[1])?)?;
    }
    Ok(Value::Object(object))
}

fn kind_value(expr: &Expr) -> Result<Value, String> {
    match expr {
        Expr::Vector(items) | Expr::List(items) => items
            .iter()
            .map(kind_label)
            .collect::<Result<Vec<_>, _>>()
            .map(array_of_strings),
        _ => Ok(Value::String(kind_label(expr)?)),
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
    match expr {
        Expr::String(value) => Ok(value.clone()),
        _ => Err(format!("expected string, got {}", describe_expr(expr))),
    }
}

fn symbol_or_string(expr: &Expr) -> Result<String, String> {
    match expr {
        Expr::String(value) | Expr::Symbol(value) => Ok(value.clone()),
        _ => Err(format!(
            "expected symbol or string, got {}",
            describe_expr(expr)
        )),
    }
}

fn number_value(expr: &Expr, context: &str) -> Result<Value, String> {
    match expr {
        Expr::Number(value) => Ok(Value::Number(Number::from(*value))),
        _ => Err(format!("({context} ...) requires a number")),
    }
}

fn array_of_strings(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::String).collect())
}

fn head_symbol(items: &[Expr]) -> Result<Option<&str>, String> {
    match items.first() {
        Some(Expr::Symbol(symbol)) => Ok(Some(symbol.as_str())),
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
    match expr {
        Expr::List(_) => "a list",
        Expr::Vector(_) => "a vector",
        Expr::String(_) => "a string",
        Expr::Symbol(_) => "a symbol",
        Expr::Number(_) => "a number",
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
