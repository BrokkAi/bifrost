//! Shared byte-spanned S-expression syntax.

use std::ops::Range;

pub(crate) const MAX_SEXP_DEPTH: usize = 128;

/// Resource limits applied while building an S-expression syntax tree.
///
/// `max_depth` preserves the parser's existing depth convention: the root is
/// at depth zero and each expression nested in a list or vector increments the
/// depth by one. `max_nodes` counts every returned [`Expr`], including list and
/// vector containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SexpParseLimits {
    pub(crate) max_depth: usize,
    pub(crate) max_nodes: usize,
}

impl SexpParseLimits {
    pub(crate) const fn new(max_depth: usize, max_nodes: usize) -> Self {
        Self {
            max_depth,
            max_nodes,
        }
    }
}

impl Default for SexpParseLimits {
    fn default() -> Self {
        Self::new(MAX_SEXP_DEPTH, usize::MAX)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Expr {
    pub(crate) kind: ExprKind,
    pub(crate) range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ExprKind {
    List(Vec<Expr>),
    Vector(Vec<Expr>),
    String(String),
    Symbol(String),
    Number(u64),
}

impl Expr {
    pub(crate) fn as_list(&self) -> Option<&[Expr]> {
        match &self.kind {
            ExprKind::List(items) => Some(items),
            _ => None,
        }
    }

    pub(crate) fn as_sequence(&self) -> Option<&[Expr]> {
        match &self.kind {
            ExprKind::List(items) | ExprKind::Vector(items) => Some(items),
            _ => None,
        }
    }

    pub(crate) fn as_string(&self) -> Option<&str> {
        match &self.kind {
            ExprKind::String(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_symbol(&self) -> Option<&str> {
        match &self.kind {
            ExprKind::Symbol(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_number(&self) -> Option<u64> {
        match self.kind {
            ExprKind::Number(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ParseError {
    pub(crate) range: Range<usize>,
    pub(crate) message: String,
}

pub(crate) struct ParsedSexp {
    pub(crate) expr: Option<Expr>,
    pub(crate) incomplete: Option<ParseError>,
}

pub(crate) struct ParsedSexpDocument {
    pub(crate) exprs: Vec<Expr>,
    pub(crate) incomplete: Option<ParseError>,
}

pub(crate) fn parse_sexp(source: &str) -> Result<ParsedSexp, ParseError> {
    parse_sexp_with_limits(source, SexpParseLimits::default())
}

pub(crate) fn parse_sexp_with_limits(
    source: &str,
    limits: SexpParseLimits,
) -> Result<ParsedSexp, ParseError> {
    Parser::new(source, limits).parse()
}

pub(crate) fn parse_sexp_document_with_limits(
    source: &str,
    limits: SexpParseLimits,
) -> Result<ParsedSexpDocument, ParseError> {
    Parser::new(source, limits).parse_document()
}

struct Parser<'a> {
    source: &'a str,
    pos: usize,
    incomplete: Option<ParseError>,
    limits: SexpParseLimits,
    parsed_nodes: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str, limits: SexpParseLimits) -> Self {
        Self {
            source,
            pos: 0,
            incomplete: None,
            limits,
            parsed_nodes: 0,
        }
    }

    fn parse(mut self) -> Result<ParsedSexp, ParseError> {
        self.skip_trivia();
        if self.pos == self.source.len() {
            return Ok(ParsedSexp {
                expr: None,
                incomplete: None,
            });
        }
        let expr = self.expr(0)?;
        self.skip_trivia();
        if self.pos != self.source.len() {
            return Err(self.error_here("unexpected input after the expression"));
        }
        Ok(ParsedSexp {
            expr: Some(expr),
            incomplete: self.incomplete,
        })
    }

    fn parse_document(mut self) -> Result<ParsedSexpDocument, ParseError> {
        let mut exprs = Vec::new();
        loop {
            self.skip_trivia();
            if self.pos == self.source.len() {
                break;
            }
            exprs.push(self.expr(0)?);
            if self.incomplete.is_some() {
                break;
            }
        }
        Ok(ParsedSexpDocument {
            exprs,
            incomplete: self.incomplete,
        })
    }

    fn expr(&mut self, depth: usize) -> Result<Expr, ParseError> {
        self.skip_trivia();
        if depth > self.limits.max_depth {
            return Err(self.error_here(&format!(
                "S-expression nesting exceeds maximum depth {}",
                self.limits.max_depth
            )));
        }
        let start = self.pos;
        let Some(byte) = self.peek() else {
            return Err(self.error_here("expected an expression"));
        };
        if self.parsed_nodes >= self.limits.max_nodes {
            return Err(self.error_here(&format!(
                "S-expression syntax node count exceeds maximum {}",
                self.limits.max_nodes
            )));
        }
        self.parsed_nodes += 1;
        match byte {
            b'(' => self.delimited(b')', depth, true),
            b'[' => self.delimited(b']', depth, false),
            b')' | b']' => {
                self.pos += 1;
                Err(ParseError {
                    range: start..self.pos,
                    message: format!("unexpected '{}'", byte as char),
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
                    self.mark_incomplete(
                        start..self.source.len(),
                        format!("missing `{}`", close as char),
                    );
                    return Ok(Expr {
                        kind: if list {
                            ExprKind::List(values)
                        } else {
                            ExprKind::Vector(values)
                        },
                        range: start..self.source.len(),
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
                let value = serde_json::from_str::<String>(&self.source[start..self.pos]).map_err(
                    |error| ParseError {
                        range: start..self.pos,
                        message: format!("invalid string: {error}"),
                    },
                )?;
                return Ok(Expr {
                    kind: ExprKind::String(value),
                    range: start..self.pos,
                });
            }
        }
        self.mark_incomplete(
            start..self.source.len(),
            format!("unterminated string at byte {start}"),
        );
        Ok(Expr {
            kind: ExprKind::String(String::new()),
            range: start..self.source.len(),
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
            })?;
        Ok(Expr {
            kind: ExprKind::Number(number),
            range: start..self.pos,
        })
    }

    fn symbol(&mut self) -> Result<Expr, ParseError> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() || matches!(byte, b'(' | b')' | b'[' | b']') {
                break;
            }
            self.pos += 1;
        }
        if start == self.pos {
            return Err(self.error_here("expected a symbol"));
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

    fn mark_incomplete(&mut self, range: Range<usize>, message: String) {
        if self.incomplete.is_none() {
            self.incomplete = Some(ParseError { range, message });
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.pos).copied()
    }

    fn error_here(&self, message: &str) -> ParseError {
        let end = self.source[self.pos..]
            .chars()
            .next()
            .map_or(self.pos, |character| self.pos + character.len_utf8());
        ParseError {
            range: self.pos..end,
            message: message.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_expression_parser_uses_schema_neutral_trailing_input_wording() {
        let error = match parse_sexp("(first) (second)") {
            Ok(_) => panic!("second expression must fail"),
            Err(error) => error,
        };

        assert_eq!(error.message, "unexpected input after the expression");
        assert_eq!(&"(first) (second)"[error.range], "(");
    }

    #[test]
    fn limited_parser_accepts_exact_node_budget_and_rejects_the_next_node() {
        let limits = SexpParseLimits::new(MAX_SEXP_DEPTH, 3);
        let parsed = parse_sexp_with_limits("(first second)", limits).unwrap();

        let expr = parsed.expr.expect("root list");
        assert_eq!(expr.as_list().unwrap().len(), 2);

        let error = match parse_sexp_with_limits("(first second third)", limits) {
            Ok(_) => panic!("fourth syntax node must exceed the budget"),
            Err(error) => error,
        };
        assert_eq!(
            error.message,
            "S-expression syntax node count exceeds maximum 3"
        );
        assert_eq!(&"(first second third)"[error.range], "t");
    }

    #[test]
    fn limited_document_parser_applies_one_budget_across_top_level_forms() {
        let limits = SexpParseLimits::new(MAX_SEXP_DEPTH, 2);
        let parsed = parse_sexp_document_with_limits("first second", limits).unwrap();
        assert_eq!(parsed.exprs.len(), 2);

        let error = match parse_sexp_document_with_limits("first second third", limits) {
            Ok(_) => panic!("third syntax node must exceed the document budget"),
            Err(error) => error,
        };
        assert_eq!(
            error.message,
            "S-expression syntax node count exceeds maximum 2"
        );
        assert_eq!(&"first second third"[error.range], "t");
    }

    #[test]
    fn limited_parser_preserves_incomplete_forms_at_the_budget_boundary() {
        let limits = SexpParseLimits::new(MAX_SEXP_DEPTH, 2);
        let parsed = parse_sexp_with_limits("(first", limits).unwrap();

        assert_eq!(parsed.expr.unwrap().as_list().unwrap().len(), 1);
        let incomplete = parsed.incomplete.expect("missing close delimiter");
        assert_eq!(incomplete.message, "missing `)`");

        let error = match parse_sexp_with_limits("(first second", limits) {
            Ok(_) => panic!("incomplete form must still enforce its node budget"),
            Err(error) => error,
        };
        assert_eq!(
            error.message,
            "S-expression syntax node count exceeds maximum 2"
        );
        assert_eq!(&"(first second"[error.range], "s");
    }

    #[test]
    fn limited_parser_preserves_incomplete_strings_at_the_budget_boundary() {
        let limits = SexpParseLimits::new(MAX_SEXP_DEPTH, 2);
        let parsed = parse_sexp_with_limits("(\"unterminated", limits).unwrap();

        assert_eq!(parsed.expr.unwrap().as_list().unwrap().len(), 1);
        let incomplete = parsed.incomplete.expect("unterminated string");
        assert!(incomplete.message.starts_with("unterminated string"));
    }

    #[test]
    fn limited_parser_uses_the_configured_depth_boundary() {
        let limits = SexpParseLimits::new(1, usize::MAX);
        parse_sexp_with_limits("(())", limits).unwrap();

        let error = match parse_sexp_with_limits("((value))", limits) {
            Ok(_) => panic!("nested value must exceed the configured depth"),
            Err(error) => error,
        };
        assert_eq!(
            error.message,
            "S-expression nesting exceeds maximum depth 1"
        );
        assert_eq!(&"((value))"[error.range], "v");
    }

    #[test]
    fn depth_limit_points_at_multibyte_expression_after_trivia() {
        let source = "(( ; before the nested expression\nβeta))";
        let error = match parse_sexp_with_limits(source, SexpParseLimits::new(1, usize::MAX)) {
            Ok(_) => panic!("nested symbol must exceed the depth budget"),
            Err(error) => error,
        };

        assert_eq!(
            error.message,
            "S-expression nesting exceeds maximum depth 1"
        );
        assert_eq!(&source[error.range], "β");
    }

    #[test]
    fn node_limit_points_at_multibyte_expression_after_trivia() {
        let source = "(first ; before the next node\néclair)";
        let error = match parse_sexp_with_limits(source, SexpParseLimits::new(MAX_SEXP_DEPTH, 2)) {
            Ok(_) => panic!("third syntax node must exceed the node budget"),
            Err(error) => error,
        };

        assert_eq!(
            error.message,
            "S-expression syntax node count exceeds maximum 2"
        );
        assert_eq!(&source[error.range], "é");
    }

    #[test]
    fn default_parser_keeps_its_preexisting_unbounded_node_behavior() {
        let source = std::iter::repeat_n("value", 4_097)
            .collect::<Vec<_>>()
            .join(" ");
        let parsed = crate::sexp::parse_sexp_document(&source).unwrap();

        assert_eq!(parsed.exprs.len(), 4_097);
    }
}
