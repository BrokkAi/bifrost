use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse};

use crate::analyzer::{Project, WorkspaceAnalyzer};
use crate::lsp::handlers::broad_symbol::broad_symbol_target_at_position;
use crate::lsp::handlers::util::code_unit_location;

/// Resolve `textDocument/definition`. Strategy:
/// 1. Read the file at `uri` and find the identifier under the cursor.
/// 2. Accept the cursor only when it selects a real declaration name or a
///    structured reference that analyzer-owned definition lookup resolves.
/// 3. Map the resolved CodeUnits to LSP Locations.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &GotoDefinitionParams,
) -> Option<GotoDefinitionResponse> {
    let uri = &params.text_document_position_params.text_document.uri;
    let analyzer = workspace.analyzer();
    let target = broad_symbol_target_at_position(
        analyzer,
        project,
        uri,
        &params.text_document_position_params.position,
    )?;

    let mut locations = Vec::with_capacity(target.candidates.len());
    for cu in target.candidates {
        if let Some(loc) = code_unit_location(analyzer, project, &cu) {
            locations.push(loc);
        }
    }
    if locations.is_empty() {
        return None;
    }
    Some(GotoDefinitionResponse::Array(locations))
}
