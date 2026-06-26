use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse};

use crate::analyzer::{Project, WorkspaceAnalyzer};
use crate::lsp::conversion::position_to_byte_offset;
use crate::lsp::handlers::util::{
    code_unit_location, identifier_at_offset, read_document_for_uri, resolve_identifier_candidates,
};

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
    project: &dyn Project,
    params: &GotoDefinitionParams,
) -> Option<GotoDefinitionResponse> {
    let uri = &params.text_document_position_params.text_document.uri;
    let (_, content, line_starts) = read_document_for_uri(project, uri)?;
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let identifier = identifier_at_offset(&content, byte_offset)?;

    let analyzer = workspace.analyzer();
    let candidates = resolve_identifier_candidates(analyzer, identifier);
    if candidates.is_empty() {
        return None;
    }

    let mut locations = Vec::with_capacity(candidates.len());
    for cu in candidates {
        if let Some(loc) = code_unit_location(analyzer, project, &cu) {
            locations.push(loc);
        }
    }
    if locations.is_empty() {
        return None;
    }
    Some(GotoDefinitionResponse::Array(locations))
}
