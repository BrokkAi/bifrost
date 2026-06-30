use lsp_types::{DocumentHighlight, DocumentHighlightKind, DocumentHighlightParams};

use crate::analyzer::usages::UsageHit;
use crate::analyzer::{CodeUnit, IAnalyzer, Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::{
    broad_symbol::{broad_symbol_target_at_position, code_unit_declaration_name_range},
    usage_hits::usage_hits_for_candidates_in_file,
    util::identifier_selection_range,
};

/// Resolve `textDocument/documentHighlight`. Scopes the usage scan to the
/// current file via [`UsageFinder::with_file_filter`] — clients fire this
/// request on every cursor movement, so a project-wide scan is too expensive.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &DocumentHighlightParams,
) -> Option<Vec<DocumentHighlight>> {
    let uri = &params.text_document_position_params.text_document.uri;
    let analyzer = workspace.analyzer();
    let target = broad_symbol_target_at_position(
        analyzer,
        project,
        uri,
        &params.text_document_position_params.position,
    )?;

    let mut highlights: Vec<DocumentHighlight> =
        usage_hits_for_candidates_in_file(analyzer, &target.candidates, &target.file)
            .into_iter()
            .map(|hit| usage_hit_to_highlight(&hit, &target.content, &target.line_starts))
            .collect();

    // Include each overload's declaration when it lives in this file — without
    // it, highlighting from the declaration site itself returns nothing on
    // languages where UsageFinder does not emit a hit at the declaration.
    for cu in &target.candidates {
        if cu.source() == &target.file
            && let Some(decl) =
                code_unit_highlight(analyzer, cu, &target.content, &target.line_starts)
        {
            highlights.push(decl);
        }
    }

    // Sort by position, then by descending kind priority so a WRITE
    // declaration outranks a READ usage that shares the same range. dedup_by
    // keeps the first of each consecutive run, so WRITE wins.
    highlights.sort_by(|a, b| {
        a.range
            .start
            .line
            .cmp(&b.range.start.line)
            .then_with(|| a.range.start.character.cmp(&b.range.start.character))
            .then_with(|| kind_priority(b.kind).cmp(&kind_priority(a.kind)))
    });
    highlights.dedup_by(|a, b| a.range == b.range);

    Some(highlights)
}

fn kind_priority(kind: Option<DocumentHighlightKind>) -> u8 {
    match kind {
        Some(DocumentHighlightKind::WRITE) => 2,
        Some(DocumentHighlightKind::READ) => 1,
        _ => 0,
    }
}

fn usage_hit_to_highlight(
    hit: &UsageHit,
    content: &str,
    line_starts: &[usize],
) -> DocumentHighlight {
    let range = ByteRange {
        start_byte: hit.start_offset,
        end_byte: hit.end_offset,
        start_line: hit.line,
        end_line: hit.line,
    };
    DocumentHighlight {
        range: byte_range_to_lsp_range(content, line_starts, &range),
        kind: Some(DocumentHighlightKind::READ),
    }
}

fn code_unit_highlight(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    content: &str,
    line_starts: &[usize],
) -> Option<DocumentHighlight> {
    let range = analyzer.ranges(code_unit).iter().min().copied()?;
    // Scope the declaration highlight to the identifier span — the analyzer's
    // primary range can cover the whole class/function body, which would
    // wash out the editor with a giant highlight on cursor over the name.
    // Fall back to the full range if the identifier can't be located word-
    // bounded inside it (e.g. synthetic units with no recoverable name).
    let lsp_range =
        code_unit_declaration_name_range(analyzer, code_unit.source(), content, code_unit)
            .map(|name_range| byte_range_to_lsp_range(content, line_starts, &name_range))
            .or_else(|| identifier_selection_range(code_unit, content, line_starts, &range))
            .unwrap_or_else(|| byte_range_to_lsp_range(content, line_starts, &range));
    Some(DocumentHighlight {
        range: lsp_range,
        kind: Some(DocumentHighlightKind::WRITE),
    })
}
