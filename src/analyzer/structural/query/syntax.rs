//! Shared byte-spanned syntax for the RQL frontend.

use std::ops::Range;

pub(crate) const MAX_RQL_DEPTH: usize = 128;

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

pub(crate) struct ParsedRql {
    pub(crate) expr: Option<Expr>,
    pub(crate) incomplete: Option<ParseError>,
}

pub(crate) struct ParsedRqlDocument {
    pub(crate) exprs: Vec<Expr>,
    pub(crate) incomplete: Option<ParseError>,
}

pub(crate) fn parse_rql(source: &str) -> Result<ParsedRql, ParseError> {
    Parser::new(source).parse()
}

pub(crate) fn parse_rql_document(source: &str) -> Result<ParsedRqlDocument, ParseError> {
    Parser::new(source).parse_document()
}

struct Parser<'a> {
    source: &'a str,
    pos: usize,
    incomplete: Option<ParseError>,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            pos: 0,
            incomplete: None,
        }
    }

    fn parse(mut self) -> Result<ParsedRql, ParseError> {
        self.skip_trivia();
        if self.pos == self.source.len() {
            return Ok(ParsedRql {
                expr: None,
                incomplete: None,
            });
        }
        let expr = self.expr(0)?;
        self.skip_trivia();
        if self.pos != self.source.len() {
            return Err(self.error_here("unexpected input after the query"));
        }
        Ok(ParsedRql {
            expr: Some(expr),
            incomplete: self.incomplete,
        })
    }

    fn parse_document(mut self) -> Result<ParsedRqlDocument, ParseError> {
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
        Ok(ParsedRqlDocument {
            exprs,
            incomplete: self.incomplete,
        })
    }

    fn expr(&mut self, depth: usize) -> Result<Expr, ParseError> {
        if depth > MAX_RQL_DEPTH {
            return Err(self.error_here(&format!(
                "S-expression nesting exceeds maximum depth {MAX_RQL_DEPTH}"
            )));
        }
        self.skip_trivia();
        let start = self.pos;
        let Some(byte) = self.peek() else {
            return Err(self.error_here("expected an expression"));
        };
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
        ParseError {
            range: self.pos..self.pos.saturating_add(1).min(self.source.len()),
            message: message.to_string(),
        }
    }
}
