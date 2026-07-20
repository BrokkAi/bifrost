//! Source-preserving, width-aware formatting for RQLP documents.
//!
//! Formatting intentionally operates on the shared S-expression tree instead
//! of the typed policy model. This lets editors format a syntactically complete
//! buffer while the author is still correcting schema or variant errors.

use std::fmt;
use std::ops::Range;

use crate::sexp::{Expr, ExprKind, SexpParseLimits, parse_sexp_with_limits};

use super::schema::{PolicyRecord, RecordLayout, lookup_field, records_from_label};
use super::source::{
    MAX_RQLP_SEXP_DEPTH, MAX_RQLP_SEXP_NODES, MAX_RQLP_SOURCE_BYTES, PolicySourceDiagnostic,
    PolicySourceDiagnosticSeverity, PolicySourceError,
};

pub const DEFAULT_RQLP_FORMAT_WIDTH: usize = 100;
pub const MIN_RQLP_FORMAT_WIDTH: usize = 80;
pub const MAX_RQLP_FORMAT_WIDTH: usize = 120;

/// Validated formatting controls for one RQLP document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyFormatOptions {
    max_width: usize,
}

impl PolicyFormatOptions {
    pub fn new(max_width: usize) -> Result<Self, PolicyFormatOptionsError> {
        if !(MIN_RQLP_FORMAT_WIDTH..=MAX_RQLP_FORMAT_WIDTH).contains(&max_width) {
            return Err(PolicyFormatOptionsError { max_width });
        }
        Ok(Self { max_width })
    }

    pub fn max_width(self) -> usize {
        self.max_width
    }
}

impl Default for PolicyFormatOptions {
    fn default() -> Self {
        Self {
            max_width: DEFAULT_RQLP_FORMAT_WIDTH,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyFormatOptionsError {
    max_width: usize,
}

impl PolicyFormatOptionsError {
    pub fn max_width(self) -> usize {
        self.max_width
    }
}

impl fmt::Display for PolicyFormatOptionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RQLP format width must be from {MIN_RQLP_FORMAT_WIDTH} through {MAX_RQLP_FORMAT_WIDTH}, found {}",
            self.max_width
        )
    }
}

impl std::error::Error for PolicyFormatOptionsError {}

pub fn format_rqlp_source(source: &str) -> Result<String, PolicySourceError> {
    format_rqlp_source_with_options(source, &PolicyFormatOptions::default())
}

pub fn format_rqlp_source_with_options(
    source: &str,
    options: &PolicyFormatOptions,
) -> Result<String, PolicySourceError> {
    let expr = parse_for_formatting(source)?;
    let formatter = PolicyFormatter {
        source,
        max_width: options.max_width,
    };
    let lines = formatter.render_expr(&expr, 0, 0);
    let line_ending = source_line_ending(source);

    let mut output = String::with_capacity(source.len());
    output.push_str(&source[..expr.range.start]);
    output.push_str(&lines.join(line_ending));
    output.push_str(&source[expr.range.end..]);
    Ok(output)
}

fn source_line_ending(source: &str) -> &'static str {
    let bytes = source.as_bytes();
    let Some(index) = bytes.iter().position(|byte| *byte == b'\n') else {
        return "\n";
    };
    if index > 0 && bytes[index - 1] == b'\r' {
        "\r\n"
    } else {
        "\n"
    }
}

fn parse_for_formatting(source: &str) -> Result<Expr, PolicySourceError> {
    if source.len() > MAX_RQLP_SOURCE_BYTES {
        return Err(format_error(
            "source-too-large",
            0..source.len(),
            format!(
                "RQLP source is too large: {} bytes exceeds {}",
                source.len(),
                MAX_RQLP_SOURCE_BYTES
            ),
        ));
    }

    let parsed = parse_sexp_with_limits(
        source,
        SexpParseLimits::new(MAX_RQLP_SEXP_DEPTH, MAX_RQLP_SEXP_NODES),
    )
    .map_err(|error| format_error("invalid-s-expression", error.range, error.message))?;
    if let Some(error) = parsed.incomplete {
        return Err(format_error(
            "incomplete-s-expression",
            error.range,
            error.message,
        ));
    }
    parsed.expr.ok_or_else(|| {
        format_error(
            "missing-document",
            source.len()..source.len(),
            "expected one `(policy ...)` or `(endpoint ...)` document",
        )
    })
}

fn format_error(
    code: &'static str,
    range: Range<usize>,
    message: impl Into<String>,
) -> PolicySourceError {
    PolicySourceError {
        diagnostic: PolicySourceDiagnostic {
            code,
            severity: PolicySourceDiagnosticSeverity::Error,
            message: message.into(),
            range,
            fix: None,
            related: Vec::new(),
        },
    }
}

struct PolicyFormatter<'a> {
    source: &'a str,
    max_width: usize,
}

impl PolicyFormatter<'_> {
    /// Render an expression at `depth`. `first_line_extra` reserves width for
    /// a field keyword that will be prepended to this expression's first line.
    fn render_expr(&self, expr: &Expr, depth: usize, first_line_extra: usize) -> Vec<String> {
        if let Some(flat) = self.flat(expr)
            && self.indent_width(depth) + first_line_extra + width(&flat) <= self.max_width
        {
            return vec![format!("{}{}", self.indent(depth), flat)];
        }

        match &expr.kind {
            ExprKind::List(items) => self.render_list(expr, items, depth),
            ExprKind::Vector(items) => self.render_vector(expr, items, depth),
            _ => vec![format!(
                "{}{}",
                self.indent(depth),
                &self.source[expr.range.clone()]
            )],
        }
    }

    fn render_list(&self, expr: &Expr, items: &[Expr], depth: usize) -> Vec<String> {
        if items.is_empty() {
            return self.render_empty_container(expr, depth, '(', ')');
        }

        let content_start = expr.range.start + 1;
        let head_is_atom = is_atom(&items[0]);
        let keep_head = head_is_atom
            && self
                .comments_in(content_start..items[0].range.start)
                .is_empty();
        let records = record_candidates(items);
        let mut lines = Vec::new();
        let mut item_index;
        if keep_head {
            lines.push(format!(
                "{}({}",
                self.indent(depth),
                &self.source[items[0].range.clone()]
            ));
            item_index = 1;
        } else {
            lines.push(format!("{}(", self.indent(depth)));
            self.push_comments(&mut lines, content_start..items[0].range.start, depth + 1);
            lines.extend(self.render_expr(&items[0], depth + 1, 0));
            item_index = 1;
        }

        while item_index < items.len() {
            let trivia_start = items[item_index - 1].range.end;
            self.push_comments(
                &mut lines,
                trivia_start..items[item_index].range.start,
                depth + 1,
            );

            match self.group_kind(items, item_index, &records) {
                GroupKind::RegisteredField | GroupKind::GenericKeyword => {
                    let keyword = &items[item_index];
                    let value = &items[item_index + 1];
                    let comments = self.comments_in(keyword.range.end..value.range.start);
                    if comments.is_empty() {
                        lines.extend(self.render_keyword_value(keyword, value, depth + 1));
                    } else {
                        lines.push(format!(
                            "{}{}",
                            self.indent(depth + 1),
                            &self.source[keyword.range.clone()]
                        ));
                        self.push_comment_values(&mut lines, comments, depth + 1);
                        lines.extend(self.render_expr(value, depth + 1, 0));
                    }
                    item_index += 2;
                }
                GroupKind::Single => {
                    lines.extend(self.render_expr(&items[item_index], depth + 1, 0));
                    item_index += 1;
                }
            }
        }

        let trailing_start = items.last().map_or(content_start, |item| item.range.end);
        let closing_start = expr.range.end.saturating_sub(1);
        self.push_comments(&mut lines, trailing_start..closing_start, depth + 1);
        lines.push(format!("{})", self.indent(depth)));
        lines
    }

    fn render_vector(&self, expr: &Expr, items: &[Expr], depth: usize) -> Vec<String> {
        if items.is_empty() {
            return self.render_empty_container(expr, depth, '[', ']');
        }

        let content_start = expr.range.start + 1;
        let mut lines = vec![format!("{}[", self.indent(depth))];
        let mut packed_line: Option<String> = None;

        for (index, item) in items.iter().enumerate() {
            let trivia_start = if index == 0 {
                content_start
            } else {
                items[index - 1].range.end
            };
            let comments = self.comments_in(trivia_start..item.range.start);
            if !comments.is_empty() {
                flush_packed_line(&mut lines, &mut packed_line);
                self.push_comment_values(&mut lines, comments, depth + 1);
            }

            if is_registered_record(item) {
                flush_packed_line(&mut lines, &mut packed_line);
                lines.extend(self.render_expr(item, depth + 1, 0));
            } else if let Some(flat) = self.flat(item) {
                let indent = self.indent(depth + 1);
                let candidate = match &packed_line {
                    Some(line) => format!("{line} {flat}"),
                    None => format!("{indent}{flat}"),
                };
                if packed_line.is_some() && width(&candidate) <= self.max_width {
                    packed_line = Some(candidate);
                } else {
                    flush_packed_line(&mut lines, &mut packed_line);
                    let item_line = format!("{indent}{flat}");
                    if width(&item_line) <= self.max_width || is_atom(item) {
                        packed_line = Some(item_line);
                    } else {
                        lines.extend(self.render_expr(item, depth + 1, 0));
                    }
                }
            } else {
                flush_packed_line(&mut lines, &mut packed_line);
                lines.extend(self.render_expr(item, depth + 1, 0));
            }
        }
        flush_packed_line(&mut lines, &mut packed_line);

        let trailing_start = items.last().map_or(content_start, |item| item.range.end);
        let closing_start = expr.range.end.saturating_sub(1);
        self.push_comments(&mut lines, trailing_start..closing_start, depth + 1);
        lines.push(format!("{}]", self.indent(depth)));
        lines
    }

    fn render_empty_container(
        &self,
        expr: &Expr,
        depth: usize,
        open: char,
        close: char,
    ) -> Vec<String> {
        let content_start = expr.range.start + open.len_utf8();
        let content_end = expr.range.end.saturating_sub(close.len_utf8());
        let comments = self.comments_in(content_start..content_end);
        if comments.is_empty() {
            return vec![format!("{}{open}{close}", self.indent(depth))];
        }

        let mut lines = vec![format!("{}{open}", self.indent(depth))];
        self.push_comment_values(&mut lines, comments, depth + 1);
        lines.push(format!("{}{close}", self.indent(depth)));
        lines
    }

    fn render_keyword_value(&self, keyword: &Expr, value: &Expr, depth: usize) -> Vec<String> {
        let keyword_text = &self.source[keyword.range.clone()];
        let prefix_width = width(keyword_text) + 1;
        let mut value_lines = self.render_expr(value, depth, prefix_width);
        let indent = self.indent(depth);
        let first = value_lines
            .first_mut()
            .expect("rendering one expression always returns a line");
        let value_first = first
            .strip_prefix(&indent)
            .expect("rendered expression begins with its requested indentation")
            .to_string();
        *first = format!("{indent}{keyword_text} {value_first}");
        value_lines
    }

    fn group_kind(&self, items: &[Expr], start: usize, records: &[PolicyRecord]) -> GroupKind {
        let Some(label) = keyword_label(&items[start]) else {
            return GroupKind::Single;
        };
        if start + 1 >= items.len() {
            return GroupKind::Single;
        }
        if records
            .iter()
            .filter(|record| {
                matches!(
                    record.layout(),
                    RecordLayout::KeywordPairs | RecordLayout::Mixed
                )
            })
            .any(|record| lookup_field(*record, label).is_some())
        {
            GroupKind::RegisteredField
        } else {
            // Unknown records and wrong-variant fields remain formattable. A
            // colon-prefixed symbol has the generic keyword/value shape even
            // when the schema registry cannot assign it typed meaning.
            GroupKind::GenericKeyword
        }
    }

    fn flat(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::List(items) => self.flat_sequence(expr, items, '(', ')'),
            ExprKind::Vector(items) => self.flat_sequence(expr, items, '[', ']'),
            _ => Some(self.source[expr.range.clone()].to_string()),
        }
    }

    fn flat_sequence(
        &self,
        expr: &Expr,
        items: &[Expr],
        open: char,
        close: char,
    ) -> Option<String> {
        let mut cursor = expr.range.start + open.len_utf8();
        let mut output = String::new();
        output.push(open);
        for (index, item) in items.iter().enumerate() {
            if !self.comments_in(cursor..item.range.start).is_empty() {
                return None;
            }
            if index > 0 {
                output.push(' ');
            }
            output.push_str(&self.flat(item)?);
            cursor = item.range.end;
        }
        let closing_start = expr.range.end.saturating_sub(close.len_utf8());
        if !self.comments_in(cursor..closing_start).is_empty() {
            return None;
        }
        output.push(close);
        Some(output)
    }

    fn comments_in(&self, range: Range<usize>) -> Vec<&str> {
        self.source[range]
            .lines()
            .filter_map(|line| line.find(';').map(|start| line[start..].trim_end()))
            .collect()
    }

    fn push_comments(&self, lines: &mut Vec<String>, range: Range<usize>, depth: usize) {
        let comments = self.comments_in(range);
        self.push_comment_values(lines, comments, depth);
    }

    fn push_comment_values(&self, lines: &mut Vec<String>, comments: Vec<&str>, depth: usize) {
        let indent = self.indent(depth);
        lines.extend(
            comments
                .into_iter()
                .map(|comment| format!("{indent}{comment}")),
        );
    }

    fn indent(&self, depth: usize) -> String {
        "  ".repeat(depth)
    }

    fn indent_width(&self, depth: usize) -> usize {
        depth.saturating_mul(2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupKind {
    RegisteredField,
    GenericKeyword,
    Single,
}

fn record_candidates(items: &[Expr]) -> Vec<PolicyRecord> {
    items
        .first()
        .and_then(Expr::as_symbol)
        .map(|head| records_from_label(head).collect())
        .unwrap_or_default()
}

fn is_registered_record(expr: &Expr) -> bool {
    expr.as_list()
        .and_then(|items| items.first())
        .and_then(Expr::as_symbol)
        .is_some_and(|head| records_from_label(head).next().is_some())
}

fn keyword_label(expr: &Expr) -> Option<&str> {
    expr.as_symbol()?.strip_prefix(':')
}

fn is_atom(expr: &Expr) -> bool {
    !matches!(expr.kind, ExprKind::List(_) | ExprKind::Vector(_))
}

fn flush_packed_line(lines: &mut Vec<String>, packed_line: &mut Option<String>) {
    if let Some(line) = packed_line.take() {
        lines.push(line);
    }
}

fn width(value: &str) -> usize {
    value.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at_width(source: &str, max_width: usize) -> String {
        format_rqlp_source_with_options(source, &PolicyFormatOptions::new(max_width).unwrap())
            .unwrap()
    }

    #[test]
    fn format_width_is_validated_and_defaults_to_one_hundred() {
        assert_eq!(PolicyFormatOptions::default().max_width(), 100);
        assert_eq!(PolicyFormatOptions::new(80).unwrap().max_width(), 80);
        assert_eq!(PolicyFormatOptions::new(120).unwrap().max_width(), 120);
        assert_eq!(PolicyFormatOptions::new(79).unwrap_err().max_width(), 79);
        assert_eq!(
            PolicyFormatOptions::new(121).unwrap_err().to_string(),
            "RQLP format width must be from 80 through 120, found 121"
        );
    }

    #[test]
    fn exact_width_golds_keep_fields_and_tagged_vector_records_together() {
        let source = "(policy :id \"example.user-controlled-pii\" :name \"User-controlled I/O to sensitive PII\" :message (generated-message :relation can-reach) :severity warning :analysis (analysis :type taint :sources (endpoint-set :entries [(source :id request :display-name \"User-controlled request parameter\" :categories [user-controlled io] :selector (rql (language python (call :callee (name \"request_parameter\")))) :bind return-value :labels [untrusted])]) :sinks (endpoint-set :entries [(sink :id profile :display-name \"Sensitive user PII\" :categories [pii sensitive] :selector (rql (language python (call :callee (name \"store_profile\")))) :dangerous-operand (argument :index 0) :accepts [untrusted])])))";

        let width_80 = r#"(policy
  :id "example.user-controlled-pii"
  :name "User-controlled I/O to sensitive PII"
  :message (generated-message :relation can-reach)
  :severity warning
  :analysis (analysis
    :type taint
    :sources (endpoint-set
      :entries [
        (source
          :id request
          :display-name "User-controlled request parameter"
          :categories [user-controlled io]
          :selector (rql
            (language python (call :callee (name "request_parameter")))
          )
          :bind return-value
          :labels [untrusted]
        )
      ]
    )
    :sinks (endpoint-set
      :entries [
        (sink
          :id profile
          :display-name "Sensitive user PII"
          :categories [pii sensitive]
          :selector (rql
            (language python (call :callee (name "store_profile")))
          )
          :dangerous-operand (argument :index 0)
          :accepts [untrusted]
        )
      ]
    )
  )
)"#;
        let width_100 = "(policy\n  :id \"example.user-controlled-pii\"\n  :name \"User-controlled I/O to sensitive PII\"\n  :message (generated-message :relation can-reach)\n  :severity warning\n  :analysis (analysis\n    :type taint\n    :sources (endpoint-set\n      :entries [\n        (source\n          :id request\n          :display-name \"User-controlled request parameter\"\n          :categories [user-controlled io]\n          :selector (rql (language python (call :callee (name \"request_parameter\"))))\n          :bind return-value\n          :labels [untrusted]\n        )\n      ]\n    )\n    :sinks (endpoint-set\n      :entries [\n        (sink\n          :id profile\n          :display-name \"Sensitive user PII\"\n          :categories [pii sensitive]\n          :selector (rql (language python (call :callee (name \"store_profile\"))))\n          :dangerous-operand (argument :index 0)\n          :accepts [untrusted]\n        )\n      ]\n    )\n  )\n)";
        let width_120 = "(policy\n  :id \"example.user-controlled-pii\"\n  :name \"User-controlled I/O to sensitive PII\"\n  :message (generated-message :relation can-reach)\n  :severity warning\n  :analysis (analysis\n    :type taint\n    :sources (endpoint-set\n      :entries [\n        (source\n          :id request\n          :display-name \"User-controlled request parameter\"\n          :categories [user-controlled io]\n          :selector (rql (language python (call :callee (name \"request_parameter\"))))\n          :bind return-value\n          :labels [untrusted]\n        )\n      ]\n    )\n    :sinks (endpoint-set\n      :entries [\n        (sink\n          :id profile\n          :display-name \"Sensitive user PII\"\n          :categories [pii sensitive]\n          :selector (rql (language python (call :callee (name \"store_profile\"))))\n          :dangerous-operand (argument :index 0)\n          :accepts [untrusted]\n        )\n      ]\n    )\n  )\n)";

        assert_eq!(at_width(source, 80), width_80);
        assert_eq!(at_width(source, 100), width_100);
        assert_eq!(at_width(source, 120), width_120);
        assert_eq!(format_rqlp_source(source).unwrap(), width_100);
    }

    #[test]
    fn formatting_is_idempotent_at_every_supported_gold_width() {
        let source = "(endpoint :id \"bifrost.sources.request-parameter\" :name \"Request parameter\" :display-name \"User-controlled I/O\" :role source :categories [user-controlled input web] :selector (rql (language python (call :callee (name \"request_parameter\")))) :binding return-value ; retained comment\n :unknown-future-field (future-record :value \"preserved\") :taint (source-semantics :labels [untrusted]))";
        for max_width in [80, 100, 120] {
            let once = at_width(source, max_width);
            let twice = at_width(&once, max_width);
            assert_eq!(twice, once, "formatter was not idempotent at {max_width}");
        }
    }

    #[test]
    fn a_broken_vector_places_each_registered_record_on_its_own_line() {
        let source = "(policy :future [(transition :from new :on open :to open) (transition :from open :on close :to closed)])";
        assert_eq!(
            at_width(source, 80),
            "(policy\n  :future [\n    (transition :from new :on open :to open)\n    (transition :from open :on close :to closed)\n  ]\n)"
        );
    }

    #[test]
    fn comments_string_bytes_and_version_omission_are_preserved() {
        let source = "; before\n(policy :id \"example.escape\" :name \"line\\nquote: \\\"\" ; between\n :bogus-endpoint-field \"still formats\" :message \"message\" :severity warning :analysis (analysis :type match :selector (rql (language python (call :callee (name \"eval\"))))))\n; after\n";
        let formatted = at_width(source, 80);
        assert!(formatted.starts_with("; before\n(policy\n"));
        assert!(formatted.contains("\"line\\nquote: \\\"\""));
        assert!(formatted.contains("; between"));
        assert!(!formatted.contains(":schema-version"));
        assert!(formatted.ends_with("\n; after\n"));
    }

    #[test]
    fn comments_inside_otherwise_empty_containers_are_preserved() {
        let source = "(policy :empty-list (; keep list\n) :empty-vector [; keep vector\n])";
        let formatted = at_width(source, 80);
        assert_eq!(
            formatted,
            "(policy\n  :empty-list (\n    ; keep list\n  )\n  :empty-vector [\n    ; keep vector\n  ]\n)"
        );
        assert_eq!(at_width(&formatted, 80), formatted);
    }

    #[test]
    fn comment_between_keyword_and_value_keeps_its_source_order() {
        let source = "(policy :future ; explains the value\n (unknown :value 1))";
        let formatted = at_width(source, 80);
        assert_eq!(
            formatted,
            "(policy\n  :future\n  ; explains the value\n  (unknown :value 1)\n)"
        );
        assert_eq!(at_width(&formatted, 80), formatted);
    }

    #[test]
    fn formatting_requires_one_complete_bounded_form_but_not_a_valid_policy() {
        let invalid = format_rqlp_source("(policy :id @)").unwrap();
        assert_eq!(invalid, "(policy :id @)");

        let incomplete = format_rqlp_source("(policy :id \"example\"").unwrap_err();
        assert_eq!(incomplete.diagnostic.code, "incomplete-s-expression");

        let multiple = format_rqlp_source("(policy) (endpoint)").unwrap_err();
        assert_eq!(multiple.diagnostic.code, "invalid-s-expression");

        let too_many_nodes = format!(
            "(policy :future [{}])",
            std::iter::repeat_n("x", MAX_RQLP_SEXP_NODES)
                .collect::<Vec<_>>()
                .join(" ")
        );
        let error = format_rqlp_source(&too_many_nodes).unwrap_err();
        assert_eq!(error.diagnostic.code, "invalid-s-expression");
        assert!(error.diagnostic.message.contains("node count"));

        let nesting = MAX_RQLP_SEXP_DEPTH + 1;
        let too_deep = format!("{}x{}", "(".repeat(nesting), ")".repeat(nesting));
        let error = format_rqlp_source(&too_deep).unwrap_err();
        assert_eq!(error.diagnostic.code, "invalid-s-expression");
        assert!(error.diagnostic.message.contains("maximum depth"));

        let too_large = "x".repeat(MAX_RQLP_SOURCE_BYTES + 1);
        let error = format_rqlp_source(&too_large).unwrap_err();
        assert_eq!(error.diagnostic.code, "source-too-large");
    }
}
