//! Width-aware formatting for RQL and Rune IR S-expressions.

use std::ops::Range;

use super::syntax::{Expr, ExprKind, parse_rql_document};

pub(crate) const DEFAULT_SEXP_LINE_WIDTH: usize = 120;

#[derive(Clone, Copy)]
pub(crate) struct SexpFormatOptions<'a> {
    pub(crate) line_width: usize,
    pub(crate) indent: &'a str,
}

/// Format every top-level S-expression while preserving top-level comments and
/// blank lines verbatim. Invalid or incomplete input is left to the caller so
/// an editor formatting request never damages a document that is being typed.
pub(crate) fn format_sexp_document(source: &str, options: SexpFormatOptions<'_>) -> Option<String> {
    let parsed = parse_rql_document(source).ok()?;
    if parsed.incomplete.is_some() {
        return None;
    }

    let formatter = Formatter { source, options };
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    for expr in &parsed.exprs {
        output.push_str(&source[cursor..expr.range.start]);
        formatter.render_expr(expr, 0, &mut output);
        cursor = expr.range.end;
    }
    output.push_str(&source[cursor..]);
    Some(output)
}

struct Formatter<'a, 'options> {
    source: &'a str,
    options: SexpFormatOptions<'options>,
}

impl Formatter<'_, '_> {
    fn render_expr(&self, expr: &Expr, depth: usize, output: &mut String) {
        if let Some(flat) = self.flat(expr)
            && self.indent_width(depth) + width(&flat) <= self.options.line_width
        {
            self.push_indent(depth, output);
            output.push_str(&flat);
            return;
        }

        let (items, open, close) = match &expr.kind {
            ExprKind::List(items) => (items.as_slice(), '(', ')'),
            ExprKind::Vector(items) => (items.as_slice(), '[', ']'),
            _ => {
                self.push_indent(depth, output);
                output.push_str(&self.source[expr.range.clone()]);
                return;
            }
        };

        self.push_indent(depth, output);
        output.push(open);
        if items.is_empty() {
            output.push(close);
            return;
        }

        let content_start = expr.range.start + open.len_utf8();
        let keep_head = matches!(expr.kind, ExprKind::List(_))
            && self
                .comments_in(content_start..items[0].range.start)
                .is_empty()
            && is_atom(&items[0]);
        let mut item_index = 0;
        if keep_head {
            output.push_str(&self.source[items[0].range.clone()]);
            item_index = 1;
        }
        output.push('\n');

        while item_index < items.len() {
            let trivia_start = if item_index == 0 {
                content_start
            } else {
                items[item_index - 1].range.end
            };
            self.render_comments(
                trivia_start..items[item_index].range.start,
                depth + 1,
                output,
            );

            let group_end = self.group_end(items, item_index);
            if let Some(flat) = self.flat_group(&items[item_index..group_end])
                && self.indent_width(depth + 1) + width(&flat) <= self.options.line_width
            {
                self.push_indent(depth + 1, output);
                output.push_str(&flat);
                output.push('\n');
            } else {
                for item in &items[item_index..group_end] {
                    self.render_expr(item, depth + 1, output);
                    output.push('\n');
                }
            }
            item_index = group_end;
        }

        let trailing_start = items.last().map_or(content_start, |item| item.range.end);
        let closing_start = expr.range.end.saturating_sub(close.len_utf8());
        self.render_comments(trailing_start..closing_start, depth + 1, output);
        self.push_indent(depth, output);
        output.push(close);
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

    fn flat_group(&self, items: &[Expr]) -> Option<String> {
        let mut output = String::new();
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                let previous = &items[index - 1];
                if !self
                    .comments_in(previous.range.end..item.range.start)
                    .is_empty()
                {
                    return None;
                }
                output.push(' ');
            }
            output.push_str(&self.flat(item)?);
        }
        Some(output)
    }

    fn group_end(&self, items: &[Expr], start: usize) -> usize {
        let next = start + 1;
        if is_keyword(&items[start])
            && next < items.len()
            && self
                .comments_in(items[start].range.end..items[next].range.start)
                .is_empty()
        {
            next + 1
        } else {
            next
        }
    }

    fn comments_in(&self, range: Range<usize>) -> Vec<&str> {
        self.source[range]
            .lines()
            .filter_map(|line| line.find(';').map(|start| line[start..].trim_end()))
            .collect()
    }

    fn render_comments(&self, range: Range<usize>, depth: usize, output: &mut String) {
        for comment in self.comments_in(range) {
            self.push_indent(depth, output);
            output.push_str(comment);
            output.push('\n');
        }
    }

    fn push_indent(&self, depth: usize, output: &mut String) {
        for _ in 0..depth {
            output.push_str(self.options.indent);
        }
    }

    fn indent_width(&self, depth: usize) -> usize {
        depth.saturating_mul(width(self.options.indent))
    }
}

fn is_atom(expr: &Expr) -> bool {
    !matches!(expr.kind, ExprKind::List(_) | ExprKind::Vector(_))
}

fn is_keyword(expr: &Expr) -> bool {
    matches!(&expr.kind, ExprKind::Symbol(value) if value.starts_with(':'))
}

fn width(value: &str) -> usize {
    value.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format(source: &str, line_width: usize) -> Option<String> {
        format_sexp_document(
            source,
            SexpFormatOptions {
                line_width,
                indent: "  ",
            },
        )
    }

    #[test]
    fn compact_forms_stay_on_one_line() {
        assert_eq!(
            format("(call   :callee   (name \"eval\"))", 120).as_deref(),
            Some("(call :callee (name \"eval\"))")
        );
    }

    #[test]
    fn long_forms_break_entries_and_keep_keyword_values_together() {
        let source = format!(
            "(call :name \"{}\" :callee (name \"eval\") :args [(capture \"payload\")])",
            "a".repeat(90)
        );
        let expected = format!(
            "(call\n  :name \"{}\"\n  :callee (name \"eval\")\n  :args [(capture \"payload\")]\n)",
            "a".repeat(90)
        );
        assert_eq!(format(&source, 120), Some(expected));
    }

    #[test]
    fn nested_forms_break_again_when_their_own_line_is_too_wide() {
        let source = format!("(call :args [(capture \"{}\")])", "x".repeat(40));
        assert_eq!(
            format(&source, 32).as_deref(),
            Some(
                "(call\n  :args\n  [\n    (capture\n      \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"\n    )\n  ]\n)"
            )
        );
    }

    #[test]
    fn rune_documents_preserve_top_level_comments_and_multiple_forms() {
        let source = "; Rune IR\n\n(function :range (0 500) :name \"demo\")\n\n; Starter RQL\n(function :name \"demo\")\n";
        assert_eq!(format(source, 120).as_deref(), Some(source));
    }

    #[test]
    fn comments_inside_forms_are_retained() {
        assert_eq!(
            format("(call ; explain\n :name \"demo\")", 120).as_deref(),
            Some("(call\n  ; explain\n  :name \"demo\"\n)")
        );
    }

    #[test]
    fn incomplete_documents_are_not_formatted() {
        assert_eq!(format("(call :name \"demo\"", 120), None);
    }
}
