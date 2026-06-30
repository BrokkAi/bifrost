use lsp_types::{Position, Uri};
use std::sync::Arc;

use crate::analyzer::usages::get_type::{self, TypeLookupRequest};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{CodeUnit, IAnalyzer, Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::hash::HashSet;
use crate::lsp::conversion::position_to_byte_offset;
use crate::lsp::handlers::broad_symbol::selected_code_unit_declaration_at_cursor;
use crate::lsp::handlers::hierarchy_support::cursor_byte_range;
use crate::lsp::handlers::util::read_document_for_uri;

pub(crate) struct TypeTarget {
    pub(crate) units: Vec<CodeUnit>,
    pub(crate) implementation_kind: ImplementationTargetKind,
}

pub(crate) enum ImplementationTargetKind {
    Type,
    Method { name: String },
}

#[derive(Clone, Copy)]
pub(crate) enum TypeTargetEligibility {
    TypeDefinition,
    TypeHierarchy,
    Implementation,
}

pub(crate) fn resolve_type_target(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    uri: &Uri,
    position: &Position,
    eligibility: TypeTargetEligibility,
) -> Option<TypeTarget> {
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    let start_byte = position_to_byte_offset(&content, &line_starts, position);
    let cursor_range = cursor_byte_range(&content, start_byte);
    if let Some(type_unit) =
        selected_type_declaration(workspace.analyzer(), &file, &content, &cursor_range)
    {
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
    if !eligibility.accepts(&outcome.target_kind) {
        return None;
    }
    let implementation_kind = match &outcome.target_kind {
        TypeLookupTargetKind::MemberOwner { member_name } => ImplementationTargetKind::Method {
            name: member_name.clone(),
        },
        _ => ImplementationTargetKind::Type,
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

impl TypeTargetEligibility {
    fn accepts(self, target_kind: &TypeLookupTargetKind) -> bool {
        match self {
            Self::TypeDefinition => true,
            Self::TypeHierarchy => *target_kind == TypeLookupTargetKind::TypeReference,
            Self::Implementation => matches!(
                target_kind,
                TypeLookupTargetKind::TypeReference | TypeLookupTargetKind::MemberOwner { .. }
            ),
        }
    }
}

fn selected_type_declaration(
    analyzer: &dyn IAnalyzer,
    file: &crate::analyzer::ProjectFile,
    content: &str,
    cursor_range: &ByteRange,
) -> Option<CodeUnit> {
    selected_code_unit_declaration_at_cursor(analyzer, file, content, cursor_range, |code_unit| {
        code_unit.is_class()
    })
}
