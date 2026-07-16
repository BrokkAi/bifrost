use lsp_types::{Position, Range as LspRange, TextDocumentIdentifier};

use crate::analyzer::common::{display_identifier_for_target, language_for_file};
use crate::analyzer::structural::{
    RuneIrLanguage, RuneIrLimits, RuneIrSelection, render_source_rune_ir,
};
use crate::analyzer::{Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::lsp::conversion::{byte_range_to_lsp_range, position_to_byte_offset};
use crate::lsp::handlers::document_symbol::primary_range;
use crate::lsp::handlers::formatting::format_bifrost_sexp;
use crate::lsp::handlers::util::read_document_for_uri;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuneIrParams {
    pub(crate) text_document: TextDocumentIdentifier,
    #[serde(default)]
    pub(crate) position: Option<Position>,
    #[serde(default)]
    pub(crate) range: Option<LspRange>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuneIrResponse {
    pub(crate) code_unit: String,
    pub(crate) source_range: LspRange,
    pub(crate) rune_ir: String,
    pub(crate) starter_rql: String,
    pub(crate) truncated: bool,
    pub(crate) display_text: String,
}

pub(crate) fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: RuneIrParams,
) -> Result<RuneIrResponse, String> {
    let (file, source, line_starts) = read_document_for_uri(project, &params.text_document.uri)
        .ok_or_else(|| {
            format!(
                "cannot read Rune IR source for `{}` from the active workspace overlay",
                params.text_document.uri.as_str()
            )
        })?;
    let requested = requested_byte_range(&source, &line_starts, params.position, params.range)?;
    let analyzer = workspace.analyzer();
    let code_unit = analyzer
        .enclosing_code_unit(&file, &requested)
        .ok_or_else(|| {
            "no indexed code unit encloses the requested cursor or selection; place it inside a function, method, type, field, constructor, or other declaration"
                .to_string()
        })?;
    let code_unit_range = primary_range(analyzer, &code_unit, &source);
    if code_unit_range.start_byte >= code_unit_range.end_byte
        || code_unit_range.end_byte > source.len()
    {
        return Err(format!(
            "indexed code unit `{}` has no usable primary source range in the current overlay",
            display_identifier_for_target(&code_unit)
        ));
    }

    let language = language_for_file(&file);
    let rune_ir_language = RuneIrLanguage::for_path(language, file.rel_path());
    let rendered = render_source_rune_ir(
        rune_ir_language,
        &source,
        RuneIrSelection::ByteRange(code_unit_range.start_byte..code_unit_range.end_byte),
        RuneIrLimits::default(),
    )
    .map_err(|error| format!("failed to render Rune IR: {error}"))?;
    let code_unit_name = display_identifier_for_target(&code_unit);
    let source_range = byte_range_to_lsp_range(&source, &line_starts, &code_unit_range);
    let unformatted_display_text = format!(
        "; Rune IR for {} ({})\n\n{}\n; Starter RQL\n{}\n",
        code_unit_name,
        rune_ir_language.config_label(),
        rendered.rune_ir.trim_end(),
        rendered.starter_rql
    );
    let display_text = format_bifrost_sexp(&unformatted_display_text)
        .ok_or_else(|| "generated Rune IR was not a complete S-expression document".to_string())?;

    Ok(RuneIrResponse {
        code_unit: code_unit_name,
        source_range,
        rune_ir: rendered.rune_ir,
        starter_rql: rendered.starter_rql,
        truncated: rendered.truncated,
        display_text,
    })
}

fn requested_byte_range(
    source: &str,
    line_starts: &[usize],
    position: Option<Position>,
    range: Option<LspRange>,
) -> Result<ByteRange, String> {
    let (start_byte, end_byte) = match (position, range) {
        (Some(_), Some(_)) => {
            return Err(
                "Rune IR request must provide either `position` or `range`, not both".into(),
            );
        }
        (None, None) => {
            return Err("Rune IR request must provide `position` or `range`".into());
        }
        (Some(position), None) => {
            let offset = position_to_byte_offset(source, line_starts, &position);
            nonempty_cursor_range(source, offset)
        }
        (None, Some(range)) => {
            let start = position_to_byte_offset(source, line_starts, &range.start);
            let end = position_to_byte_offset(source, line_starts, &range.end);
            if start > end {
                return Err("Rune IR request range start must not be after its end".into());
            }
            if start == end {
                nonempty_cursor_range(source, start)
            } else {
                (start, end)
            }
        }
    };
    if start_byte == end_byte {
        return Err("cannot select Rune IR from an empty document".to_string());
    }
    Ok(ByteRange {
        start_byte,
        end_byte,
        start_line: 0,
        end_line: 0,
    })
}

fn nonempty_cursor_range(source: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(source.len());
    if offset < source.len() {
        let width = source[offset..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(0);
        return (offset, offset + width);
    }
    let start = source
        .char_indices()
        .next_back()
        .map(|(index, _)| index)
        .unwrap_or(offset);
    (start, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_utils::compute_line_starts;

    #[test]
    fn requested_range_counts_utf16_and_makes_cursor_nonempty() {
        let source = "😀fn demo() {}";
        let starts = compute_line_starts(source);
        let range = requested_byte_range(
            source,
            &starts,
            Some(Position {
                line: 0,
                character: 2,
            }),
            None,
        )
        .unwrap();
        assert_eq!(range.start_byte, "😀".len());
        assert_eq!(range.end_byte, "😀f".len());
    }

    #[test]
    fn requested_range_requires_exactly_one_location_shape() {
        let starts = compute_line_starts("fn demo() {}");
        assert!(requested_byte_range("fn demo() {}", &starts, None, None).is_err());
        assert!(
            requested_byte_range(
                "fn demo() {}",
                &starts,
                Some(Position::new(0, 0)),
                Some(LspRange::new(Position::new(0, 0), Position::new(0, 1)))
            )
            .is_err()
        );
    }
}
