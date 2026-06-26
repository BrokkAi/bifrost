use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse, Location};
use std::sync::Arc;

use crate::analyzer::usages::get_type::{self, TypeLookupRequest};
use crate::analyzer::{CodeUnit, IAnalyzer, Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::hash::HashSet;
use crate::lsp::conversion::position_to_byte_offset;
use crate::lsp::handlers::hierarchy_support::cursor_byte_range;
use crate::lsp::handlers::util::{
    code_unit_location, identifier_selection_range, read_document_for_uri,
};

pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &GotoDefinitionParams,
) -> Option<GotoDefinitionResponse> {
    let analyzer = workspace.analyzer();
    let target = resolve_type_target(workspace, project, params)?;
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
    let target = resolve_type_target(workspace, project, params)?;

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

struct TypeTarget {
    units: Vec<CodeUnit>,
    implementation_kind: ImplementationTargetKind,
}

enum ImplementationTargetKind {
    Type,
    Method { name: String },
}

fn resolve_type_target(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &GotoDefinitionParams,
) -> Option<TypeTarget> {
    let uri = &params.text_document_position_params.text_document.uri;
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    let start_byte = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let cursor_range = cursor_byte_range(&content, start_byte);
    if let Some(type_unit) = selected_type_declaration(
        workspace.analyzer(),
        &file,
        &content,
        &line_starts,
        &cursor_range,
    ) {
        return Some(TypeTarget {
            units: vec![type_unit],
            implementation_kind: ImplementationTargetKind::Type,
        });
    }
    let outcomes = get_type::resolve_type_batch(
        workspace.analyzer(),
        vec![TypeLookupRequest {
            file,
            source: Some(Arc::new(content)),
            line: None,
            column: None,
            start_byte: Some(start_byte),
            end_byte: None,
        }],
    );
    let outcome = outcomes.into_iter().next()?;
    let implementation_kind = if outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "go_interface_method_owner")
    {
        let name = outcome
            .reference
            .as_ref()
            .map(|reference| reference.text.rsplit('.').next().unwrap_or(&reference.text))
            .filter(|name| !name.is_empty())?
            .to_string();
        ImplementationTargetKind::Method { name }
    } else {
        ImplementationTargetKind::Type
    };
    let mut units = Vec::new();
    let mut seen = HashSet::default();
    for item in outcome.types {
        for definition in item.definitions {
            if seen.insert(definition.clone()) {
                units.push(definition);
            }
        }
    }
    if units.is_empty() {
        None
    } else {
        Some(TypeTarget {
            units,
            implementation_kind,
        })
    }
}

fn selected_type_declaration(
    analyzer: &dyn IAnalyzer,
    file: &crate::analyzer::ProjectFile,
    content: &str,
    line_starts: &[usize],
    cursor_range: &ByteRange,
) -> Option<CodeUnit> {
    let code_unit = analyzer.enclosing_code_unit(file, cursor_range)?;
    if !code_unit.is_class() {
        return None;
    }
    let range = analyzer.ranges(&code_unit).iter().min().copied()?;
    let selection = identifier_selection_range(&code_unit, content, line_starts, &range)?;
    let cursor =
        crate::lsp::conversion::byte_range_to_lsp_range(content, line_starts, cursor_range);
    (cursor.start >= selection.start && cursor.start <= selection.end).then_some(code_unit)
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
