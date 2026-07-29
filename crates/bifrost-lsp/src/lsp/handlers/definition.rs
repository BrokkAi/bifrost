use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse, Location};

use crate::analyzer::{Project, WorkspaceAnalyzer};
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::broad_symbol::navigation_target_at_position;
use crate::lsp::handlers::util::{NavigationLocationCache, navigation_target_location};
use crate::navigation::NavigationOperation;

/// Resolve `textDocument/definition`. Strategy:
/// 1. Read the file at `uri` and find the identifier under the cursor.
/// 2. Accept the cursor only when it selects a real declaration name or a
///    structured reference that analyzer-owned definition lookup resolves.
/// 3. Map the resolved CodeUnits to LSP Locations.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &GotoDefinitionParams,
    operation: NavigationOperation,
) -> Option<GotoDefinitionResponse> {
    let uri = &params.text_document_position_params.text_document.uri;
    let analyzer = workspace.analyzer();
    let target = navigation_target_at_position(
        analyzer,
        project,
        uri,
        &params.text_document_position_params.position,
        operation,
    )?;
    if let Some(definition) = target.lexical_definition {
        let range =
            byte_range_to_lsp_range(&target.content, &target.line_starts, &definition.name_range);
        return Some(GotoDefinitionResponse::Array(vec![Location {
            uri: uri.clone(),
            range,
        }]));
    }
    let mut locations = Vec::with_capacity(target.navigation_targets.len());
    let mut location_cache = NavigationLocationCache::default();
    for navigation_target in target.navigation_targets {
        if let Some(loc) =
            navigation_target_location(analyzer, project, &mut location_cache, &navigation_target)
        {
            locations.push(loc);
        }
    }
    if locations.is_empty() {
        return None;
    }
    Some(GotoDefinitionResponse::Array(locations))
}
