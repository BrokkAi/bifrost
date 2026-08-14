use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse, Location, Position, Range, Uri};

use crate::analyzer::{Project, WorkspaceAnalyzer};
use crate::lsp::conversion::{byte_range_to_lsp_range, path_to_uri_string};
use crate::lsp::handlers::broad_symbol::{
    modeled_symbol_target_at_position, navigation_target_at_position,
};
use crate::lsp::handlers::util::{NavigationLocationCache, navigation_target_location};
use crate::navigation::NavigationOperation;
use crate::text_utils::compute_line_starts;

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
    let Some(target) = navigation_target_at_position(
        analyzer,
        project,
        uri,
        &params.text_document_position_params.position,
        operation,
    ) else {
        return model_definition_at_position(analyzer, project, params);
    };
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
        return model_definition_at_position(analyzer, project, params);
    }
    Some(GotoDefinitionResponse::Array(locations))
}

fn model_definition_at_position(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    project: &dyn Project,
    params: &GotoDefinitionParams,
) -> Option<GotoDefinitionResponse> {
    let uri = &params.text_document_position_params.text_document.uri;
    let modeled = modeled_symbol_target_at_position(
        analyzer,
        project,
        uri,
        &params.text_document_position_params.position,
    )?;
    let symbol = &modeled.symbol;
    let (uri, range): (Uri, Range) = match &symbol.location {
        crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor) => {
            let file = project.file_by_rel_path(std::path::Path::new(&anchor.path))?;
            let source = project.read_source(&file).ok()?;
            let starts = compute_line_starts(&source);
            let range = crate::analyzer::Range {
                start_byte: anchor.range.start_byte,
                end_byte: anchor.range.end_byte,
                start_line: anchor.range.start_line,
                end_line: anchor.range.end_line,
            };
            (
                path_to_uri_string(&file.abs_path()).parse().ok()?,
                byte_range_to_lsp_range(&source, &starts, &range),
            )
        }
        crate::analyzer::semantic_model::SemanticModelLocation::Model(location) => (
            location.uri.parse().ok()?,
            Range {
                start: Position {
                    line: u32::try_from(location.range.start_line.saturating_sub(1))
                        .unwrap_or(u32::MAX),
                    character: 0,
                },
                end: Position {
                    line: u32::try_from(location.range.end_line.saturating_sub(1))
                        .unwrap_or(u32::MAX),
                    character: 0,
                },
            },
        ),
    };
    Some(GotoDefinitionResponse::Array(vec![Location { uri, range }]))
}
