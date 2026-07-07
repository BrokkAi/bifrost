use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse, Location};

use crate::analyzer::{CodeUnit, Project, RustAnalyzer, WorkspaceAnalyzer, resolve_analyzer};
use crate::hash::HashSet;
use crate::lsp::handlers::type_target::{
    ImplementationMemberKind, ImplementationTargetKind, TypeTargetEligibility, resolve_type_target,
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

    let target_units = target.units;
    let mut descendants = Vec::new();
    let mut seen = HashSet::default();
    for type_unit in &target_units {
        if !provider.supports_type_hierarchy(type_unit) {
            continue;
        }
        for descendant in provider.get_descendants(type_unit) {
            if seen.insert(descendant.clone()) {
                descendants.push(descendant);
            }
        }
    }

    let units: Vec<_> = match target.implementation_kind {
        ImplementationTargetKind::Type => descendants,
        ImplementationTargetKind::Member {
            declaration,
            name,
            kind,
        } => {
            if let Some(implementations) = rust_trait_member_implementations(
                analyzer,
                &target_units,
                declaration.as_ref(),
                &name,
                kind,
            ) {
                implementations
            } else {
                descendants
                    .into_iter()
                    .flat_map(|descendant| analyzer.get_direct_children(&descendant))
                    .filter(|child| implementation_member_matches(child, &name, kind))
                    .collect()
            }
        }
    };
    let locations = locations_for_units(analyzer, project, units.into_iter());
    if locations.is_empty() {
        return None;
    }
    Some(GotoDefinitionResponse::Array(locations))
}

fn rust_trait_member_implementations(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    target_units: &[CodeUnit],
    declaration: Option<&CodeUnit>,
    name: &str,
    kind: ImplementationMemberKind,
) -> Option<Vec<CodeUnit>> {
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
    if let Some(member) = declaration
        && let Some(implementations) = rust.rust_trait_member_implementations(member)
    {
        return Some(implementations);
    }

    target_units
        .iter()
        .filter(|unit| rust.is_rust_trait_declaration(unit))
        .find_map(|trait_unit| {
            analyzer
                .get_direct_children(trait_unit)
                .into_iter()
                .filter(|child| implementation_member_matches(child, name, kind))
                .find_map(|child| rust.rust_trait_member_implementations(&child))
        })
}

fn implementation_member_matches(
    child: &CodeUnit,
    name: &str,
    kind: ImplementationMemberKind,
) -> bool {
    child.identifier() == name
        && match kind {
            ImplementationMemberKind::Method => child.is_function(),
            ImplementationMemberKind::Field => false,
        }
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
