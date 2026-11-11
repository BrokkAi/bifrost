//! Query-time proof of C# member and indexer identity (#9402).
//!
//! C# lowering resolves a member's declaration only from the file it lowers.
//! A member declared in another file (`request.Query`, with `HttpRequest` in
//! `Http.cs`) gets a field location keyed by the member's *name* within the
//! procedure, and an `Unknown` `FieldMemory` identity gap. A read through a
//! non-array indexer gets an index location and an `IndexMemory` gap, because
//! a user `this[...]` accessor may run and nothing in the file says which.
//!
//! At query time the workspace resolver can answer both questions. This
//! module retires such a gap when the resolver proves that the location's
//! identity names exactly one declaration in this procedure:
//!
//! - A field location's gap is retired when every location that shares its
//!   member identity resolves to one field or property declaration, and no
//!   location with a different member identity resolves to that declaration.
//!   Every store and load of the member in the procedure then addresses one
//!   location, which is what the gap protected. A name that two declarations
//!   share in one procedure (two types that each declare `Name`, or a hiding
//!   `new` member) keeps every gap of that name.
//! - An index location's gap is retired when its subscript is one constant
//!   value, its indexer resolves to one declaration, and every indexer access
//!   in the procedure that resolves at all resolves to that same declaration.
//!   A constant subscript is canonicalized to one value by the lowering, so
//!   equal subscripts on one object name one element, as for an array.
//!
//! Like a property read, the indexer getter is treated as a read of the
//! element slot; the accessor code it may run stays a point-scoped `Calls`
//! gap with no value impact. The proof is per procedure: occurrences in other
//! procedures do not share these locations.

use std::collections::HashMap;
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::semantic::type_flow::prepared_syntax_for_procedure;
use brokk_bifrost_analysis::analyzer::semantic::{
    MemoryLocation, MemoryLocationId, MemoryLocationKind, ProcedureHandle, SemanticCapability,
    SemanticGapDischarge, SemanticGapId, SemanticGapKind, SemanticGapSubject, SourceMappingKind,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch_with_source,
};
use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile};
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use tree_sitter::Node;

use super::CSharpAnalyzer;

/// The gaps of `procedure` whose member or indexer identity the workspace
/// resolver proves. `source` is the exact source the procedure was lowered
/// from.
pub(crate) fn resolved_member_identity_gaps(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
    source: &Arc<str>,
) -> Vec<SemanticGapId> {
    let semantics = procedure.semantics();
    let candidates = semantics
        .gaps()
        .iter()
        .filter_map(|gap| {
            let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
                return None;
            };
            (matches!(
                gap.capability,
                SemanticCapability::FieldMemory | SemanticCapability::IndexMemory
            ) && gap.kind == SemanticGapKind::Unknown
                && gap.discharge == SemanticGapDischarge::None)
                .then_some((gap.id, location))
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Vec::new();
    }

    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(workspace.analyzer()) else {
        return Vec::new();
    };
    let scope = AnalyzerQueryScope::new(csharp);
    // The indexed tree must be the exact snapshot the procedure was lowered
    // from, or its byte offsets would address other syntax.
    let Ok(prepared) = prepared_syntax_for_procedure(
        workspace,
        procedure,
        file,
        csharp.prepared_syntax_for_path(scope.token(), file),
    ) else {
        return Vec::new();
    };
    let tree = prepared.tree();

    // One definition request per field or index location, all in one batch.
    let mut occurrences = Vec::new();
    for location in semantics.memory_locations() {
        let Some(focus) = location_focus(procedure, tree, location) else {
            continue;
        };
        occurrences.push((location, focus));
    }
    let requests = occurrences
        .iter()
        .map(|(_, focus)| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(focus.start_byte()),
            end_byte: Some(focus.end_byte()),
        })
        .collect::<Vec<_>>();
    let outcomes = resolve_definition_batch_with_source(
        workspace.analyzer(),
        requests,
        file.clone(),
        Arc::clone(source),
    );
    assert_eq!(
        outcomes.len(),
        occurrences.len(),
        "a definition batch answers every request"
    );
    let resolved = occurrences
        .iter()
        .zip(outcomes)
        .map(|((location, _), outcome)| {
            let declaration = (outcome.status == DefinitionLookupStatus::Resolved)
                .then(|| match outcome.definitions.as_slice() {
                    [only] => Some(only.clone()),
                    _ => None,
                })
                .flatten();
            (location.id, declaration)
        })
        .collect::<HashMap<MemoryLocationId, Option<CodeUnit>>>();

    candidates
        .into_iter()
        .filter(|(_, location)| {
            semantics
                .memory_location(*location)
                .is_some_and(|row| identity_is_proven(procedure, row, &resolved))
        })
        .map(|(gap, _)| gap)
        .collect()
}

/// The syntax node a definition request for `location` focuses: the member
/// name of a field access, or the opening bracket of an element access's
/// subscript. A location whose occurrence is not one of those shapes has no
/// focus.
fn location_focus<'tree>(
    procedure: &ProcedureHandle,
    tree: &'tree tree_sitter::Tree,
    location: &MemoryLocation,
) -> Option<Node<'tree>> {
    let mapping = procedure.semantics().source_mapping(location.source)?;
    if mapping.kind != SourceMappingKind::Exact {
        return None;
    }
    let span = mapping.locator.anchor().span();
    let mut node = tree
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)?;
    // A store's point is its assignment; the location is the assignment's
    // target.
    if node.kind() == "assignment_expression" {
        node = node.child_by_field_name("left")?;
    }
    match (&location.kind, node.kind()) {
        (MemoryLocationKind::Field { .. }, "member_access_expression") => {
            node.child_by_field_name("name")
        }
        (MemoryLocationKind::Index { .. }, "element_access_expression") => {
            // A definition request names one token. The subscript's opening
            // bracket is the token that names the indexer.
            node.child_by_field_name("subscript")?.child(0)
        }
        _ => None,
    }
}

fn identity_is_proven(
    procedure: &ProcedureHandle,
    location: &MemoryLocation,
    resolved: &HashMap<MemoryLocationId, Option<CodeUnit>>,
) -> bool {
    let semantics = procedure.semantics();
    let Some(Some(declaration)) = resolved.get(&location.id) else {
        return false;
    };
    match &location.kind {
        MemoryLocationKind::Field { member, .. } => {
            if declaration.is_function() || declaration.is_class() {
                return false;
            }
            semantics.memory_locations().iter().all(|other| {
                let MemoryLocationKind::Field {
                    member: other_member,
                    ..
                } = &other.kind
                else {
                    return true;
                };
                let other_declaration = resolved.get(&other.id).and_then(Option::as_ref);
                if other_member == member {
                    other_declaration == Some(declaration)
                } else {
                    other_declaration != Some(declaration)
                }
            })
        }
        MemoryLocationKind::Index { index, .. } => {
            let constant = index
                .and_then(|index| semantics.value(index))
                .is_some_and(|value| value.kind.is_constant());
            constant
                && semantics.memory_locations().iter().all(|other| {
                    !matches!(other.kind, MemoryLocationKind::Index { .. })
                        || resolved
                            .get(&other.id)
                            .and_then(Option::as_ref)
                            .is_none_or(|other| other == declaration)
                })
        }
        _ => false,
    }
}
