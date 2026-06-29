use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse, Location};

use crate::analyzer::{CodeUnit, Project, WorkspaceAnalyzer};
use crate::hash::HashSet;
use crate::lsp::handlers::type_target::{
    ImplementationTargetKind, TypeTargetEligibility, resolve_type_target,
};
use crate::lsp::handlers::util::code_unit_location;

pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &GotoDefinitionParams,
) -> Option<GotoDefinitionResponse> {
    let analyzer = workspace.analyzer();
    let target = resolve_type_target(
        workspace,
        project,
        &params.text_document_position_params.text_document.uri,
        &params.text_document_position_params.position,
        TypeTargetEligibility::TypeDefinition,
    )?;
    let locations = locations_for_units(analyzer, project, target.units.into_iter());
    if locations.is_empty() {
        return None;
    }
    Some(GotoDefinitionResponse::Array(locations))
}

pub fn implementation(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &GotoDefinitionParams,
) -> Option<GotoDefinitionResponse> {
    let analyzer = workspace.analyzer();
    let provider = analyzer.type_hierarchy_provider()?;
    let target = resolve_type_target(
        workspace,
        project,
        &params.text_document_position_params.text_document.uri,
        &params.text_document_position_params.position,
        TypeTargetEligibility::Implementation,
    )?;

    let mut descendants = Vec::new();
    let mut seen = HashSet::default();
    for type_unit in target.units {
        if !provider.supports_type_hierarchy(&type_unit) {
            continue;
        }
        for descendant in provider.get_descendants(&type_unit) {
            if seen.insert(descendant.clone()) {
                descendants.push(descendant);
            }
        }
    }

    let units: Vec<_> = match target.implementation_kind {
        ImplementationTargetKind::Type => descendants,
        ImplementationTargetKind::Method { name } => descendants
            .into_iter()
            .flat_map(|descendant| analyzer.get_direct_children(&descendant))
            .filter(|child| child.is_function() && child.identifier() == name)
            .collect(),
    };
    let locations = locations_for_units(analyzer, project, units.into_iter());
    if locations.is_empty() {
        return None;
    }
    Some(GotoDefinitionResponse::Array(locations))
}

fn locations_for_units(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    project: &dyn Project,
    units: impl Iterator<Item = CodeUnit>,
) -> Vec<Location> {
    units
        .filter_map(|unit| code_unit_location(analyzer, project, &unit))
        .collect()
}
