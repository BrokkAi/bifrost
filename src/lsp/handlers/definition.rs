use std::path::Path;

use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse, Location, Uri};

use crate::analyzer::{
    CodeUnit, IAnalyzer, Range as ByteRange, WorkspaceAnalyzer,
};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset,
};
use crate::lsp::handlers::util::{identifier_at_offset, project_file_for_uri};
use crate::text_utils::compute_line_starts;

/// Resolve `textDocument/definition`. Strategy:
/// 1. Read the file at `uri` and find the identifier under the cursor.
/// 2. Look up the analyzer's `definitions(fq_name)` for the bare identifier
///    (this hits top-level symbols whose fq_name *is* the identifier).
/// 3. Fall back to `search_definitions(^ident$, false)` for any short-name
///    match anywhere in the workspace.
///
/// This is a best-effort lookup — bifrost is a tree-sitter index, not a type
/// checker, so name shadowing and overload resolution are handled by ranking
/// rather than analysis.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project_root: &Path,
    params: &GotoDefinitionParams,
) -> Option<GotoDefinitionResponse> {
    let uri = &params.text_document_position_params.text_document.uri;
    let project_file = project_file_for_uri(project_root, uri)?;

    let content = project_file.read_to_string().ok()?;
    let line_starts = compute_line_starts(&content);
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let identifier = identifier_at_offset(&content, byte_offset)?;

    let analyzer = workspace.analyzer();
    let candidates = resolve_candidates(analyzer, identifier);
    if candidates.is_empty() {
        return None;
    }

    let mut locations = Vec::with_capacity(candidates.len());
    for cu in candidates {
        if let Some(loc) = code_unit_location(analyzer, &cu) {
            locations.push(loc);
        }
    }
    if locations.is_empty() {
        return None;
    }
    Some(GotoDefinitionResponse::Array(locations))
}

fn resolve_candidates(analyzer: &dyn IAnalyzer, identifier: &str) -> Vec<CodeUnit> {
    let direct: Vec<CodeUnit> = analyzer.get_definitions(identifier);
    if !direct.is_empty() {
        return direct;
    }
    let pattern = format!(r"^{}$", regex::escape(identifier));
    analyzer
        .search_definitions(&pattern, false)
        .into_iter()
        .filter(|cu| cu.identifier() == identifier)
        .collect()
}

fn code_unit_location(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Option<Location> {
    let abs_path = code_unit.source().abs_path();
    let body = std::fs::read_to_string(&abs_path).ok()?;
    let line_starts = compute_line_starts(&body);
    let range = analyzer.ranges(code_unit).iter().min().copied().unwrap_or(ByteRange {
        start_byte: 0,
        end_byte: body.len(),
        start_line: 0,
        end_line: 0,
    });
    let lsp_range = byte_range_to_lsp_range(&body, &line_starts, &range);
    let uri: Uri = path_to_uri_string(&abs_path).parse().ok()?;
    Some(Location {
        uri,
        range: lsp_range,
    })
}
