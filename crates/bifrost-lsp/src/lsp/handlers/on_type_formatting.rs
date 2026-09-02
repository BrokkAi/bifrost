//! `textDocument/onTypeFormatting` for the Bifrost S-expression languages.
//!
//! A trigger arrives on a keystroke, so only the pure, in-process formatters
//! that document formatting already uses are safe here. The external formatter
//! commands that document formatting resolves may build a project and are
//! bounded by a 30 s timeout, so they never run on type. The LSP capability is
//! global, so a trigger in any other document answers with no edits.
//!
//! The edit covers only the top-level form that encloses the trigger, not the
//! whole document, so the client applies a local replacement and the author's
//! cursor stays where they left it.

use std::ops::Range;

use lsp_types::{Position, Range as LspRange, TextEdit};

use crate::lsp::conversion::{byte_offset_to_position, position_to_byte_offset};
use crate::lsp::handlers::formatting::{
    self, FormatterCancellation, is_bifrost_policy_language, is_bifrost_sexp_language,
};
use crate::sexp::{Expr, SexpParseLimits, parse_sexp_document_with_limits};
use crate::text_utils::compute_line_starts;

/// Closing a list is the point at which the form's final shape is known.
pub(crate) const FIRST_TRIGGER_CHARACTER: &str = ")";

/// The vector terminator closes a form the same way, and a newline ends a line
/// whose indentation the enclosing form now determines.
pub(crate) const MORE_TRIGGER_CHARACTERS: [&str; 2] = ["]", "\n"];

/// Whether the in-process formatters cover this document's language.
pub(crate) fn is_supported_language(language_id: &str) -> bool {
    is_bifrost_sexp_language(language_id) || is_bifrost_policy_language(language_id)
}

/// Format the top-level form that encloses `position`, returning at most one
/// edit that replaces exactly that form.
///
/// The result is empty whenever the trigger has nothing safe to do: an
/// unsupported language, a document the S-expression parser rejects, a
/// position outside every complete top-level form, or a form the formatter
/// leaves unchanged.
pub(crate) fn format_on_type(
    language_id: &str,
    text: &str,
    position: &Position,
    cancellation: &FormatterCancellation,
) -> Result<Vec<TextEdit>, String> {
    if !is_supported_language(language_id) {
        return Ok(Vec::new());
    }
    let line_starts = compute_line_starts(text);
    let offset = position_to_byte_offset(text, &line_starts, position);
    let Some(form) = enclosing_top_level_form(text, offset) else {
        return Ok(Vec::new());
    };
    // The request's `FormattingOptions` are ignored, matching document
    // formatting: both S-expression formatters own their indent and line
    // width, so an on-type edit and a whole-document format agree on the
    // bytes they write for the same form.
    let source = &text[form.clone()];
    let prepared = if is_bifrost_policy_language(language_id) {
        formatting::prepare_bifrost_policy(source)
    } else {
        formatting::prepare_bifrost_sexp(source)
    };
    let Some(formatted) = formatting::format_prepared_with_cancellation(&prepared, cancellation)?
    else {
        return Ok(Vec::new());
    };
    let edit_range = LspRange {
        start: byte_offset_to_position(text, &line_starts, form.start),
        end: byte_offset_to_position(text, &line_starts, form.end),
    };
    Ok(vec![TextEdit::new(edit_range, formatted)])
}

/// Byte range of the complete top-level form that encloses `offset`.
///
/// The trigger position sits just after the typed character, so the form a `)`
/// has just closed ends exactly at `offset`. Both ends therefore match.
fn enclosing_top_level_form(text: &str, offset: usize) -> Option<Range<usize>> {
    let parsed = parse_sexp_document_with_limits(text, SexpParseLimits::default()).ok()?;
    // The document parser stops at the first form it could not finish, so only
    // the last form can be the partial one the author is still typing. Its
    // range runs to end of file and its contents are what the parser had to
    // assume, so formatting it would rewrite text that is not there yet.
    let complete: &[Expr] = if parsed.incomplete.is_some() {
        parsed.exprs.split_last()?.1
    } else {
        &parsed.exprs
    };
    complete
        .iter()
        .find(|expr| expr.range.start <= offset && offset <= expr.range.end)
        .map(|expr| expr.range.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(text: &str, offset: usize) -> Position {
        byte_offset_to_position(text, &compute_line_starts(text), offset)
    }

    #[test]
    fn unsupported_languages_are_not_formatted() {
        let text = "(call :name \"demo\")";
        let edits = format_on_type(
            "rust",
            text,
            &position(text, text.len()),
            &FormatterCancellation::new(),
        )
        .expect("rust triggers never fail");
        assert!(edits.is_empty());
    }

    #[test]
    fn only_the_enclosing_top_level_form_is_replaced() {
        let long_name = "a".repeat(90);
        let first = format!(
            "(call   :name \"{long_name}\" :callee (name \"eval\") :args [(capture \"p\")])"
        );
        let text = format!("{first}\n(function :name \"demo\")\n");
        let edits = format_on_type(
            "bifrost-rql",
            &text,
            &position(&text, first.len()),
            &FormatterCancellation::new(),
        )
        .expect("complete RQL formats");
        assert_eq!(edits.len(), 1, "{edits:?}");
        assert_eq!(edits[0].range.start, Position::new(0, 0));
        assert_eq!(edits[0].range.end, Position::new(0, first.len() as u32));
        assert!(edits[0].new_text.starts_with("(call\n  :name"), "{edits:?}");
        assert!(
            !edits[0].new_text.contains("function"),
            "the second top-level form must stay outside the edit: {edits:?}"
        );
    }

    #[test]
    fn an_unfinished_form_is_left_alone() {
        let text = "(policy\n  (analysis :type match)\n";
        let edits = format_on_type(
            "bifrost-rql-policy",
            text,
            &position(text, text.len() - 1),
            &FormatterCancellation::new(),
        )
        .expect("incomplete RQLP never fails");
        assert!(edits.is_empty(), "{edits:?}");
    }

    #[test]
    fn a_trigger_between_forms_is_left_alone() {
        let text = "(function :name \"demo\")\n\n(function :name \"other\")\n";
        let edits = format_on_type(
            "bifrost-rune-ir",
            text,
            &position(text, 24),
            &FormatterCancellation::new(),
        )
        .expect("complete Rune IR formats");
        assert!(edits.is_empty(), "{edits:?}");
    }
}
