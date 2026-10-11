//! Structured facts for C# catch clauses.

use super::CSharpAnalyzer;
use super::external::{CSharpExternalDeclarations, CSharpExternalTypeLookup};
use crate::analyzer::structural::failure_handlers::{
    CSharpCatchBodyFacts, HandlerBodyShape, HandlerRethrowKind, csharp_catch_body_facts,
};
use crate::analyzer::{CodeUnit, CodeUnitIndex, IAnalyzer, ProjectFile, Range};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_csharp::graph::resolver::{reference_type_text, resolve_type_fq_name};
use brokk_bifrost_csharp::graph_support::CSharpSource;
use std::collections::HashSet;
use tree_sitter::Node;

const SYSTEM_EXCEPTION: &str = "System.Exception";

/// The relation of a caught type to `System.Exception`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpCatchTypeRelation {
    SystemException,
    NotSystemException,
    Unknown,
}

impl CSharpCatchTypeRelation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SystemException => "system_exception",
            Self::NotSystemException => "not_system_exception",
            Self::Unknown => "unknown",
        }
    }
}

/// All structured facts needed by catch-all policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSharpCatchFacts {
    pub body: HandlerBodyShape,
    pub caught_type: Option<String>,
    pub caught_type_relation: CSharpCatchTypeRelation,
    pub has_filter: bool,
    pub rethrow: HandlerRethrowKind,
    pub type_reason: Option<&'static str>,
}

/// Resolve the exact C# catch clause selected by a normalized structural fact.
///
/// Source declarations are walked through their structured base-type facts.
/// An external type is published by identity when the shared external surface
/// resolves it. A non-`System.Exception` external hierarchy is exact only when
/// that surface publishes a complete direct-base chain; otherwise it remains
/// unknown at the external metadata boundary tracked by #3663.
pub fn csharp_catch_facts(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    catch: Range,
) -> CSharpCatchFacts {
    let CSharpCatchBodyFacts { shape, rethrow } = csharp_catch_body_facts(syntax, catch);
    let Some(node) = exact_catch_node(syntax, catch) else {
        return CSharpCatchFacts {
            body: shape,
            caught_type: None,
            caught_type_relation: CSharpCatchTypeRelation::Unknown,
            has_filter: false,
            rethrow,
            type_reason: Some("syntax_recovery"),
        };
    };
    let has_filter = has_named_child_kind(node, "catch_filter_clause");
    let Some(declaration) = named_child_kind(node, "catch_declaration") else {
        // A bare C# catch is exactly `System.Exception` by language rule.
        return CSharpCatchFacts {
            body: shape,
            caught_type: Some(SYSTEM_EXCEPTION.to_owned()),
            caught_type_relation: CSharpCatchTypeRelation::SystemException,
            has_filter,
            rethrow,
            type_reason: None,
        };
    };
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return CSharpCatchFacts {
            body: shape,
            caught_type: None,
            caught_type_relation: CSharpCatchTypeRelation::Unknown,
            has_filter,
            rethrow,
            type_reason: Some("caught_type_unresolved"),
        };
    };
    let reference = reference_type_text(type_node, syntax.source());
    let packs = csharp.semantic_model_overlay();
    let external = csharp.external_declarations(packs);
    let (caught_type, caught_type_relation, type_reason) =
        resolve_caught_type(csharp, token, file, &reference, &external);
    CSharpCatchFacts {
        body: shape,
        caught_type,
        caught_type_relation,
        has_filter,
        rethrow,
        type_reason,
    }
}

fn resolve_caught_type(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
    external: &CSharpExternalDeclarations<'_>,
) -> (
    Option<String>,
    CSharpCatchTypeRelation,
    Option<&'static str>,
) {
    if let Some(fqn) = resolve_type_fq_name(csharp, token, file, reference) {
        let definitions = csharp
            .get_definitions(&fqn)
            .into_iter()
            .filter(|unit| unit.is_class())
            .collect::<Vec<_>>();
        if definitions.is_empty() {
            let relation = if fqn == SYSTEM_EXCEPTION {
                CSharpCatchTypeRelation::SystemException
            } else {
                CSharpCatchTypeRelation::NotSystemException
            };
            return (Some(fqn), relation, None);
        }
        let relation = source_type_relation(csharp, token, &definitions, external);
        let reason = (relation == CSharpCatchTypeRelation::Unknown)
            .then_some("caught_type_hierarchy_unknown");
        return (Some(fqn), relation, reason);
    }

    let lookup = external.resolve_type_in_file(
        reference,
        &csharp.namespace_of_file(file),
        &csharp.using_namespaces_of(token, file),
        &csharp.using_aliases_of(token, file),
    );
    match lookup {
        CSharpExternalTypeLookup::Unique(candidate) => {
            let fqn = candidate.fqn.clone();
            let mut visited = HashSet::new();
            let relation =
                external_type_relation(csharp, token, file, external, &candidate, &mut visited);
            let reason = (relation == CSharpCatchTypeRelation::Unknown)
                .then_some("caught_type_hierarchy_unknown");
            (Some(fqn), relation, reason)
        }
        CSharpExternalTypeLookup::Ambiguous => (
            None,
            CSharpCatchTypeRelation::Unknown,
            Some("caught_type_ambiguous"),
        ),
        CSharpExternalTypeLookup::Absent => {
            if system_exception_from_structured_reference(csharp, token, file, reference) {
                return (
                    Some(SYSTEM_EXCEPTION.to_owned()),
                    CSharpCatchTypeRelation::SystemException,
                    None,
                );
            }
            (
                None,
                CSharpCatchTypeRelation::Unknown,
                Some("caught_type_unresolved"),
            )
        }
    }
}

fn source_type_relation(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    definitions: &[CodeUnit],
    external: &CSharpExternalDeclarations<'_>,
) -> CSharpCatchTypeRelation {
    let mut visited = HashSet::new();
    definitions
        .iter()
        .map(|unit| source_type_relation_from_unit(csharp, token, unit, external, &mut visited))
        .fold(
            CSharpCatchTypeRelation::NotSystemException,
            combine_relation,
        )
}

fn source_type_relation_from_unit(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    external: &CSharpExternalDeclarations<'_>,
    visited: &mut HashSet<String>,
) -> CSharpCatchTypeRelation {
    let fqn = unit.fq_name().to_owned();
    if fqn == SYSTEM_EXCEPTION {
        return CSharpCatchTypeRelation::SystemException;
    }
    if !visited.insert(fqn) {
        return CSharpCatchTypeRelation::Unknown;
    }
    let raw_supertypes = csharp.raw_supertypes_of(unit);
    if raw_supertypes.is_empty() {
        return CSharpCatchTypeRelation::NotSystemException;
    }
    raw_supertypes
        .iter()
        .map(|reference| {
            resolve_supertype_relation(csharp, token, unit, reference, external, visited)
        })
        .fold(
            CSharpCatchTypeRelation::NotSystemException,
            combine_relation,
        )
}

fn resolve_supertype_relation(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    reference: &str,
    external: &CSharpExternalDeclarations<'_>,
    visited: &mut HashSet<String>,
) -> CSharpCatchTypeRelation {
    if let Some(fqn) = resolve_type_fq_name(csharp, token, unit.source(), reference) {
        if fqn == SYSTEM_EXCEPTION {
            return CSharpCatchTypeRelation::SystemException;
        }
        let definitions = csharp
            .get_definitions(&fqn)
            .into_iter()
            .filter(|candidate| candidate.is_class())
            .collect::<Vec<_>>();
        if !definitions.is_empty() {
            return definitions
                .iter()
                .map(|candidate| {
                    source_type_relation_from_unit(csharp, token, candidate, external, visited)
                })
                .fold(
                    CSharpCatchTypeRelation::NotSystemException,
                    combine_relation,
                );
        }
        return CSharpCatchTypeRelation::NotSystemException;
    }
    if system_exception_from_structured_reference(csharp, token, unit.source(), reference) {
        return CSharpCatchTypeRelation::SystemException;
    }
    resolve_external_reference_relation(csharp, token, unit.source(), reference, external, visited)
}

fn external_type_relation(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    external: &CSharpExternalDeclarations<'_>,
    candidate: &super::external::CSharpExternalTypeCandidate,
    visited: &mut HashSet<String>,
) -> CSharpCatchTypeRelation {
    if candidate.fqn == SYSTEM_EXCEPTION {
        return CSharpCatchTypeRelation::SystemException;
    }
    if !visited.insert(candidate.fqn.clone()) {
        return CSharpCatchTypeRelation::Unknown;
    }
    if !candidate.hierarchy_complete || candidate.base_types.is_empty() {
        return CSharpCatchTypeRelation::Unknown;
    }
    candidate
        .base_types
        .iter()
        .map(|reference| {
            resolve_external_reference_relation(csharp, token, file, reference, external, visited)
        })
        .fold(
            CSharpCatchTypeRelation::NotSystemException,
            combine_relation,
        )
}

fn resolve_external_reference_relation(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
    external: &CSharpExternalDeclarations<'_>,
    visited: &mut HashSet<String>,
) -> CSharpCatchTypeRelation {
    if let Some(fqn) = resolve_type_fq_name(csharp, token, file, reference) {
        if fqn == SYSTEM_EXCEPTION {
            return CSharpCatchTypeRelation::SystemException;
        }
        let definitions = csharp
            .get_definitions(&fqn)
            .into_iter()
            .filter(|candidate| candidate.is_class())
            .collect::<Vec<_>>();
        if !definitions.is_empty() {
            return source_type_relation(csharp, token, &definitions, external);
        }
        return CSharpCatchTypeRelation::NotSystemException;
    }
    if system_exception_from_structured_reference(csharp, token, file, reference) {
        return CSharpCatchTypeRelation::SystemException;
    }
    let lookup = external.resolve_type_in_file(
        reference,
        &csharp.namespace_of_file(file),
        &csharp.using_namespaces_of(token, file),
        &csharp.using_aliases_of(token, file),
    );
    match lookup {
        CSharpExternalTypeLookup::Unique(candidate) => {
            external_type_relation(csharp, token, file, external, &candidate, visited)
        }
        CSharpExternalTypeLookup::Absent | CSharpExternalTypeLookup::Ambiguous => {
            CSharpCatchTypeRelation::Unknown
        }
    }
}

fn combine_relation(
    left: CSharpCatchTypeRelation,
    right: CSharpCatchTypeRelation,
) -> CSharpCatchTypeRelation {
    match (left, right) {
        (CSharpCatchTypeRelation::SystemException, _)
        | (_, CSharpCatchTypeRelation::SystemException) => CSharpCatchTypeRelation::SystemException,
        (CSharpCatchTypeRelation::Unknown, _) | (_, CSharpCatchTypeRelation::Unknown) => {
            CSharpCatchTypeRelation::Unknown
        }
        _ => CSharpCatchTypeRelation::NotSystemException,
    }
}

/// Resolve the standard BCL identity from the selected type path and the
/// analyzer's structured import/alias facts when no external metadata is
/// available. This keeps the metadata-light `using System;` case decidable
/// without scanning source text or treating every `Exception` spelling as a
/// framework type.
fn system_exception_from_structured_reference(
    csharp: &CSharpAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    if matches!(reference, SYSTEM_EXCEPTION | "global::System.Exception") {
        return true;
    }
    if reference == "Exception"
        && csharp
            .using_namespaces_of(token, file)
            .iter()
            .any(|namespace| namespace == "System")
    {
        return true;
    }
    csharp
        .using_aliases_of(token, file)
        .get(reference)
        .is_some_and(|target| target == SYSTEM_EXCEPTION)
}

fn exact_catch_node<'tree>(syntax: &'tree PreparedSyntaxTree, catch: Range) -> Option<Node<'tree>> {
    syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(catch.start_byte, catch.end_byte)
        .filter(|node| {
            node.kind() == "catch_clause"
                && node.start_byte() == catch.start_byte
                && node.end_byte() == catch.end_byte
        })
}

fn named_child_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn has_named_child_kind(node: Node<'_>, kind: &str) -> bool {
    named_child_kind(node, kind).is_some()
}
