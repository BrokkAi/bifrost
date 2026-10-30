//! Prepared-syntax qualification for ordinary local assignments.

use crate::CancellationToken;
use crate::analyzer::common::{CandidateState, exact_span};
use crate::analyzer::read_ledger::reason as derivation_reason;
use crate::analyzer::semantic::statement_entries::ProcedureSyntax;
use crate::analyzer::semantic::{
    ProcedureHandle, ProcedureSemantics, ProgramPoint, ProgramPointId, SemanticEffect,
    SemanticValueKind, SourceMappingKind, ValueId,
};
use crate::analyzer::{Language, Range, WorkspaceAnalyzer};
use brokk_bifrost_core::analyzer::tree_walk::{
    find_node_or_ancestor, node_range, subtree_contains,
};
use brokk_bifrost_js_ts::syntax::ts_type_wrapper_operand;
use brokk_bifrost_rust::ownership::rust_dereference_operand;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlainAssignmentVerdict {
    Supported,
    Excluded,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PlainAssignmentCandidate {
    /// Every program point that writes this assignment's target. A producer
    /// can lower one source assignment more than once, for example a
    /// `finally` body copied onto each continuation; each copy is a separate
    /// evaluation of the same target and value. Empty when unjoined.
    pub points: Vec<ProgramPointId>,
    pub target: Option<ValueId>,
    pub rhs_value: Option<ValueId>,
    pub range: Range,
    pub rhs_range: Option<Range>,
    /// The identifier inside any transparent parenthesized RHS wrappers.
    pub rhs_identifier_range: Option<Range>,
    pub next_assignment_start: Option<usize>,
    /// The exact Java or C# declaration type spelling, when assigning between
    /// two locals with that same spelling needs no value conversion.
    pub swap_type: Option<Box<str>>,
    pub verdict: PlainAssignmentVerdict,
    pub storage_kind: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct PlainAssignmentCandidates {
    pub rows: Vec<PlainAssignmentCandidate>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

/// A Java local value establishment whose RHS has already been evaluated.
/// The source join is independent of whether that RHS is a bare identifier.
#[derive(Debug, Clone)]
pub struct OverwrittenLocalCandidate {
    /// Every lowered copy of this source assignment (including cleanup paths).
    pub points: Vec<ProgramPointId>,
    pub target: Option<ValueId>,
    pub rhs_value: Option<ValueId>,
    pub range: Range,
    pub source_kind: OverwrittenLocalSourceKind,
    pub verdict: PlainAssignmentVerdict,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwrittenLocalSourceKind {
    DeclarationInitializer,
    PlainAssignment,
}

#[derive(Debug, Clone)]
pub struct OverwrittenLocalCandidates {
    pub rows: Vec<OverwrittenLocalCandidate>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

pub fn plain_assignment_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> PlainAssignmentCandidates {
    let language = procedure.artifact().key().language().language();
    let classify: for<'tree> fn(Node<'tree>, &str) -> Option<PlainWrite<'tree>> = match language {
        Language::Java | Language::JavaScript | Language::TypeScript | Language::Python => {
            return pilot_plain_assignment_candidates(workspace, procedure, cancellation, language);
        }
        Language::CSharp => csharp_plain_write,
        Language::Kotlin => kotlin_plain_write,
        Language::Go => go_plain_write,
        Language::Scala => scala_plain_write,
        Language::Rust => rust_plain_write,
        Language::Php => php_plain_write,
        Language::Ruby => ruby_plain_write,
        _ => {
            return PlainAssignmentCandidates {
                rows: Vec::new(),
                complete: true,
                reason: None,
            };
        }
    };
    single_target_plain_assignment_candidates(workspace, procedure, cancellation, classify)
}

fn pilot_plain_assignment_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
    language: Language,
) -> PlainAssignmentCandidates {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return unavailable(derivation_reason::CANCELLED);
    }
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let semantics = procedure.semantics();
    let syntax = &prepared.syntax;
    let procedure_node = match exact_assignment_procedure_node(&prepared, procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    if matches!(language, Language::JavaScript | Language::TypeScript)
        && !is_js_function(procedure_node.kind())
    {
        return PlainAssignmentCandidates {
            rows: Vec::new(),
            complete: true,
            reason: None,
        };
    }

    let mut assignments = Vec::new();
    let mut python_directives = HashSet::new();
    if !for_each_procedure_node(
        procedure_node,
        cancellation,
        |node| is_nested_body(node, language),
        |node| {
            if is_assignment(node, language) {
                assignments.push(node);
            }
            if language == Language::Python
                && matches!(node.kind(), "global_statement" | "nonlocal_statement")
            {
                python_directives.extend(python_directive_identifiers(node, syntax.source()));
            }
        },
    ) {
        return unavailable(derivation_reason::CANCELLED);
    }
    assignments.sort_unstable_by_key(Node::start_byte);
    let points_by_span = exact_program_points_by_span(semantics);
    let rows = assignments
        .into_iter()
        .map(|node| {
            classify_assignment(
                semantics,
                &points_by_span,
                &python_directives,
                syntax.source(),
                syntax.tree().root_node(),
                procedure_node,
                node,
                language,
            )
        })
        .collect();
    PlainAssignmentCandidates {
        rows,
        complete: true,
        reason: None,
    }
}

fn unavailable(reason: &'static str) -> PlainAssignmentCandidates {
    let CandidateState {
        rows,
        complete,
        reason,
    } = CandidateState::unavailable(reason);
    PlainAssignmentCandidates {
        rows,
        complete,
        reason,
    }
}

fn exact_assignment_procedure_node<'syntax>(
    prepared: &'syntax ProcedureSyntax,
    procedure: &ProcedureHandle,
) -> Result<Node<'syntax>, &'static str> {
    let semantics = procedure.semantics();
    let mapping = semantics
        .source_mapping(semantics.source())
        .ok_or(derivation_reason::PROCEDURE_MAPPING_MISSING)?;
    if mapping.kind != SourceMappingKind::Exact {
        return Err(derivation_reason::PROCEDURE_MAPPING_INEXACT);
    }
    let span = mapping.locator.anchor().span();
    let node = prepared
        .syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
        .ok_or(derivation_reason::PROCEDURE_SYNTAX_MISSING)?;
    if !exact_span(span, node) || node.has_error() {
        return Err(derivation_reason::PROCEDURE_SYNTAX_INEXACT);
    }
    Ok(node)
}

fn for_each_procedure_node<'tree>(
    procedure_node: Node<'tree>,
    cancellation: Option<&CancellationToken>,
    mut is_nested_body: impl FnMut(Node<'tree>) -> bool,
    mut visit: impl FnMut(Node<'tree>),
) -> bool {
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return false;
        }
        if node.id() != procedure_node.id() && is_nested_body(node) {
            continue;
        }
        visit(node);
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    true
}

fn exact_program_points_by_span(
    semantics: &ProcedureSemantics,
) -> HashMap<(usize, usize), Vec<&ProgramPoint>> {
    let mut points_by_span = HashMap::new();
    for point in semantics.points() {
        if let Some(mapping) = semantics
            .source_mapping(point.source)
            .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
        {
            let span = mapping.locator.anchor().span();
            points_by_span
                .entry((span.start_byte() as usize, span.end_byte() as usize))
                .or_insert_with(Vec::new)
                .push(point);
        }
    }
    points_by_span
}

/// Enumerate only Java source writes which could establish an ordinary local
/// value. In particular, a declaration initializer and a non-identifier RHS
/// are still candidates: the overwrite proof begins after their evaluation.
pub fn java_overwritten_local_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> OverwrittenLocalCandidates {
    let unavailable = |reason| OverwrittenLocalCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    };
    if procedure.artifact().key().language().language() != Language::Java {
        return unavailable(derivation_reason::UNSUPPORTED_LANGUAGE);
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return unavailable(derivation_reason::CANCELLED);
    }
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let semantics = procedure.semantics();
    let syntax = &prepared.syntax;
    let procedure_node = match exact_assignment_procedure_node(&prepared, procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };

    let mut nodes = Vec::new();
    if !for_each_procedure_node(
        procedure_node,
        cancellation,
        |node| is_nested_body(node, Language::Java),
        |node| {
            if node.kind() == "assignment_expression"
                || (node.kind() == "variable_declarator"
                    && node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "local_variable_declaration")
                    && node.child_by_field_name("value").is_some())
            {
                nodes.push(node);
            }
        },
    ) {
        return unavailable(derivation_reason::CANCELLED);
    }
    nodes.sort_unstable_by_key(Node::start_byte);
    let points_by_span = exact_program_points_by_span(semantics);
    let mut rows = Vec::with_capacity(nodes.len());
    for node in nodes {
        let mut row = OverwrittenLocalCandidate {
            points: Vec::new(),
            target: None,
            rhs_value: None,
            range: node_range(node),
            source_kind: if node.kind() == "variable_declarator" {
                OverwrittenLocalSourceKind::DeclarationInitializer
            } else {
                OverwrittenLocalSourceKind::PlainAssignment
            },
            verdict: PlainAssignmentVerdict::Unknown,
            reason: "syntax_unresolved",
        };
        if node.has_error() {
            rows.push(row);
            continue;
        }
        let name = if node.kind() == "variable_declarator" {
            node.child_by_field_name("name")
        } else if assignment_has_plain_operator(node) {
            node.child_by_field_name("left")
        } else {
            row.verdict = PlainAssignmentVerdict::Excluded;
            row.reason = "compound_assignment";
            rows.push(row);
            continue;
        };
        let Some(name) = name.filter(|name| name.kind() == "identifier" && !name.has_error())
        else {
            row.verdict = PlainAssignmentVerdict::Excluded;
            row.reason = "nonlocal_target";
            rows.push(row);
            continue;
        };
        let Some(points) = points_by_span.get(&(node.start_byte(), node.end_byte())) else {
            row.reason = "assignment_point_unmapped";
            rows.push(row);
            continue;
        };
        let mut locals = Vec::new();
        let mut member_store = false;
        let mut parameter_assignment = false;
        for point in points {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Assignment { target, value }
                        if semantics
                            .value(target)
                            .is_some_and(|value| value.kind == SemanticValueKind::Local) =>
                    {
                        locals.push((point.id, target, value));
                    }
                    SemanticEffect::Assignment { target, .. }
                        if semantics.value(target).is_some_and(|value| {
                            matches!(value.kind, SemanticValueKind::Parameter { .. })
                        }) =>
                    {
                        parameter_assignment = true;
                    }
                    SemanticEffect::MemoryStore { .. } => member_store = true,
                    _ => {}
                }
            }
        }
        let Some((_, target, rhs_value)) = locals.first() else {
            if locals.is_empty() && member_store {
                row.verdict = PlainAssignmentVerdict::Excluded;
                row.reason = "resolved_field_target";
            } else if locals.is_empty() && parameter_assignment {
                row.verdict = PlainAssignmentVerdict::Excluded;
                row.reason = "parameter_target";
            } else {
                row.reason = "local_assignment_join_ambiguous";
            }
            rows.push(row);
            continue;
        };
        let mut points = locals
            .iter()
            .map(|(point, _, _)| *point)
            .collect::<Vec<_>>();
        points.sort_unstable();
        points.dedup();
        if points.len() != locals.len() || locals.iter().any(|(_, other, _)| other != target) {
            row.reason = "local_assignment_join_ambiguous";
            rows.push(row);
            continue;
        }
        let target_row = semantics
            .value(*target)
            .expect("semantic assignment target exists");
        let Some(target_mapping) = semantics.source_mapping(target_row.source) else {
            row.reason = "target_mapping_missing";
            rows.push(row);
            continue;
        };
        if target_mapping.kind != SourceMappingKind::Exact {
            row.reason = "target_mapping_inexact";
            rows.push(row);
            continue;
        }
        let target_span = target_mapping.locator.anchor().span();
        let Some(declaration) = syntax.tree().root_node().named_descendant_for_byte_range(
            target_span.start_byte() as usize,
            target_span.end_byte() as usize,
        ) else {
            row.reason = "declaration_name_missing";
            rows.push(row);
            continue;
        };
        if !exact_span(target_span, declaration)
            || declaration.has_error()
            || declaration.kind() != "identifier"
        {
            row.reason = "declaration_name_inexact";
            rows.push(row);
            continue;
        }
        if declaration.start_byte() < procedure_node.start_byte()
            || declaration.end_byte() > procedure_node.end_byte()
        {
            row.verdict = PlainAssignmentVerdict::Excluded;
            row.reason = "declaration_outside_procedure";
            rows.push(row);
            continue;
        }
        if declaration
            .parent()
            .and_then(|node| node.parent())
            .is_some_and(java_declaration_is_final)
        {
            row.verdict = PlainAssignmentVerdict::Excluded;
            row.reason = "final_local";
            rows.push(row);
            continue;
        }
        if ordinary_local_declaration(
            declaration,
            syntax.source(),
            Language::Java,
            false,
            &HashSet::new(),
        )
        .is_none()
        {
            row.reason = "ordinary_local_unproved";
            rows.push(row);
            continue;
        }
        if node.kind() == "variable_declarator" && name.id() != declaration.id() {
            row.reason = "declarator_binding_mismatch";
            rows.push(row);
            continue;
        }
        row.points = points;
        row.target = Some(*target);
        row.rhs_value = Some(*rhs_value);
        row.verdict = PlainAssignmentVerdict::Supported;
        row.reason = "qualified";
        rows.push(row);
    }
    OverwrittenLocalCandidates {
        rows,
        complete: true,
        reason: None,
    }
}

/// Source-backed JavaScript/TypeScript local writes. The result retains
/// declaration versus assignment provenance because lexical assignments need
/// a separate TDZ proof before their semantic establishment can be trusted.
pub fn js_ts_overwritten_local_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> OverwrittenLocalCandidates {
    let unavailable = |reason| OverwrittenLocalCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    };
    let language = procedure.artifact().key().language().language();
    if !matches!(language, Language::JavaScript | Language::TypeScript) {
        return unavailable(derivation_reason::UNSUPPORTED_LANGUAGE);
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return unavailable(derivation_reason::CANCELLED);
    }
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let semantics = procedure.semantics();
    let syntax = &prepared.syntax;
    let procedure_node = match exact_assignment_procedure_node(&prepared, procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    if !is_js_function(procedure_node.kind()) {
        return if procedure_node.kind() == "program" {
            OverwrittenLocalCandidates {
                rows: Vec::new(),
                complete: true,
                reason: None,
            }
        } else {
            unavailable(derivation_reason::UNSUPPORTED_CALLABLE_KIND)
        };
    }

    let mut nodes = Vec::new();
    if !for_each_procedure_node(
        procedure_node,
        cancellation,
        |node| is_nested_body(node, language),
        |node| {
            if matches!(node.kind(), "for_in_statement" | "using_declaration")
                || node.kind() == "assignment_expression"
                || (node.kind() == "variable_declarator"
                    && (node.child_by_field_name("value").is_some()
                        || node.parent().is_some_and(|parent| {
                            matches!(parent.kind(), "for_in_statement" | "for_of_statement")
                        })))
            {
                nodes.push(node);
            }
        },
    ) {
        return unavailable(derivation_reason::CANCELLED);
    }
    nodes.sort_unstable_by_key(Node::start_byte);
    let points_by_span = exact_program_points_by_span(semantics);

    let mut rows = Vec::with_capacity(nodes.len());
    for node in nodes {
        let source_kind = if node.kind() == "variable_declarator" {
            OverwrittenLocalSourceKind::DeclarationInitializer
        } else {
            OverwrittenLocalSourceKind::PlainAssignment
        };
        let mut row = OverwrittenLocalCandidate {
            points: Vec::new(),
            target: None,
            rhs_value: None,
            range: node_range(node),
            source_kind,
            verdict: PlainAssignmentVerdict::Unknown,
            reason: "syntax_unresolved",
        };
        if matches!(node.kind(), "for_in_statement" | "using_declaration") {
            row.reason = "loop_or_resource_binding_unmodeled";
            rows.push(row);
            continue;
        }
        if node.has_error() {
            rows.push(row);
            continue;
        }
        let name = if source_kind == OverwrittenLocalSourceKind::DeclarationInitializer {
            if node.child_by_field_name("value").is_none() {
                row.reason = "loop_binding_unmodeled";
                rows.push(row);
                continue;
            }
            let Some(parent) = node.parent() else {
                rows.push(row);
                continue;
            };
            if !matches!(
                parent.kind(),
                "variable_declaration" | "lexical_declaration"
            ) {
                row.reason = "resource_or_loop_binding_unmodeled";
                rows.push(row);
                continue;
            }
            node.child_by_field_name("name")
        } else if assignment_has_plain_operator(node) {
            node.child_by_field_name("left")
        } else {
            row.verdict = PlainAssignmentVerdict::Excluded;
            row.reason = "compound_assignment";
            rows.push(row);
            continue;
        };
        let Some(name) = name else {
            rows.push(row);
            continue;
        };
        if name.kind() != "identifier" || name.has_error() {
            if matches!(name.kind(), "member_expression" | "subscript_expression") {
                row.verdict = PlainAssignmentVerdict::Excluded;
                row.reason = "nonlocal_target";
            } else {
                row.reason = "destructuring_target_unmodeled";
            }
            rows.push(row);
            continue;
        }
        let Some(points) = points_by_span.get(&(node.start_byte(), node.end_byte())) else {
            row.reason = "assignment_point_unmapped";
            rows.push(row);
            continue;
        };
        let mut locals = Vec::new();
        let mut parameter_assignment = false;
        for point in points {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Assignment { target, value }
                        if semantics
                            .value(target)
                            .is_some_and(|value| value.kind == SemanticValueKind::Local) =>
                    {
                        locals.push((point.id, target, value));
                    }
                    SemanticEffect::Assignment { target, .. }
                        if semantics.value(target).is_some_and(|value| {
                            matches!(value.kind, SemanticValueKind::Parameter { .. })
                        }) =>
                    {
                        parameter_assignment = true;
                    }
                    _ => {}
                }
            }
        }
        let [(point, target, rhs_value)] = locals.as_slice() else {
            if locals.is_empty() && parameter_assignment {
                row.verdict = PlainAssignmentVerdict::Excluded;
                row.reason = "parameter_target";
            } else {
                row.reason = "local_assignment_join_ambiguous";
            }
            rows.push(row);
            continue;
        };
        let target_row = semantics.value(*target).expect("assignment target exists");
        let Some(target_mapping) = semantics.source_mapping(target_row.source) else {
            row.reason = "target_mapping_missing";
            rows.push(row);
            continue;
        };
        if target_mapping.kind != SourceMappingKind::Exact {
            row.reason = "target_mapping_inexact";
            rows.push(row);
            continue;
        }
        let target_span = target_mapping.locator.anchor().span();
        let Some(declaration) = syntax.tree().root_node().named_descendant_for_byte_range(
            target_span.start_byte() as usize,
            target_span.end_byte() as usize,
        ) else {
            row.reason = "declaration_name_missing";
            rows.push(row);
            continue;
        };
        if !exact_span(target_span, declaration)
            || declaration.has_error()
            || declaration.kind() != "identifier"
        {
            row.reason = "declaration_name_inexact";
            rows.push(row);
            continue;
        }
        if declaration.start_byte() < procedure_node.start_byte()
            || declaration.end_byte() > procedure_node.end_byte()
        {
            row.verdict = PlainAssignmentVerdict::Excluded;
            row.reason = "declaration_outside_procedure";
            rows.push(row);
            continue;
        }
        let Some(declarator) = declaration.parent() else {
            rows.push(row);
            continue;
        };
        let Some(binding_declaration) = declarator.parent() else {
            rows.push(row);
            continue;
        };
        if declarator.kind() != "variable_declarator"
            || declarator
                .child_by_field_name("name")
                .is_none_or(|binder| binder.id() != declaration.id())
            || !matches!(
                binding_declaration.kind(),
                "variable_declaration" | "lexical_declaration"
            )
        {
            row.reason = "ordinary_local_unproved";
            rows.push(row);
            continue;
        }
        let mut cursor = binding_declaration.walk();
        if binding_declaration
            .children(&mut cursor)
            .any(|child| child.kind() == "const")
        {
            row.verdict = PlainAssignmentVerdict::Excluded;
            row.reason = "const_local";
            rows.push(row);
            continue;
        }
        if source_kind == OverwrittenLocalSourceKind::DeclarationInitializer
            && name.id() != declaration.id()
        {
            row.reason = "declarator_binding_mismatch";
            rows.push(row);
            continue;
        }
        row.points = vec![*point];
        row.target = Some(*target);
        row.rhs_value = Some(*rhs_value);
        row.verdict = PlainAssignmentVerdict::Supported;
        row.reason = "qualified";
        rows.push(row);
    }
    OverwrittenLocalCandidates {
        rows,
        complete: true,
        reason: None,
    }
}

/// Python local establishments by plain `=` assignment, in this procedure's
/// own body. Augmented assignment, attribute and item targets are excluded;
/// unpacking and annotation-only targets stay open or excluded explicitly.
/// Loop, `with`, `except` and walrus bindings are not candidates.
pub fn python_overwritten_local_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> OverwrittenLocalCandidates {
    let unavailable = |reason| OverwrittenLocalCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    };
    if procedure.artifact().key().language().language() != Language::Python {
        return unavailable(derivation_reason::UNSUPPORTED_LANGUAGE);
    }
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let procedure_node = match prepared.procedure_node(procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    let source = prepared.syntax.source();
    let semantics = procedure.semantics();

    let mut nodes = Vec::new();
    let mut python_directives = HashSet::new();
    if !for_each_procedure_node(
        procedure_node,
        cancellation,
        |node| is_nested_body(node, Language::Python),
        |node| match node.kind() {
            "assignment" | "augmented_assignment" => nodes.push(node),
            "global_statement" | "nonlocal_statement" => {
                python_directives.extend(python_directive_identifiers(node, source));
            }
            _ => {}
        },
    ) {
        return unavailable(derivation_reason::CANCELLED);
    }
    nodes.sort_unstable_by_key(Node::start_byte);
    let points_by_span = exact_program_points_by_span(semantics);

    let rows = nodes
        .into_iter()
        .map(|node| {
            let mut row = OverwrittenLocalCandidate {
                points: Vec::new(),
                target: None,
                rhs_value: None,
                range: node_range(node),
                source_kind: OverwrittenLocalSourceKind::PlainAssignment,
                verdict: PlainAssignmentVerdict::Unknown,
                reason: "syntax_unresolved",
            };
            let excluded = |mut row: OverwrittenLocalCandidate, reason| {
                row.verdict = PlainAssignmentVerdict::Excluded;
                row.reason = reason;
                row
            };
            if node.has_error() {
                return row;
            }
            if node.kind() == "augmented_assignment" {
                return excluded(row, "compound_assignment");
            }
            let Some(left) = node.child_by_field_name("left") else {
                return row;
            };
            // `x: int` declares an annotation and binds nothing.
            if node.child_by_field_name("right").is_none() {
                return excluded(row, "annotation_only");
            }
            match left.kind() {
                "identifier" => {}
                "attribute" | "subscript" => return excluded(row, "nonlocal_target"),
                _ => {
                    row.reason = "destructuring_target_unmodeled";
                    return row;
                }
            }
            if source
                .get(left.byte_range())
                .is_some_and(|name| python_directives.contains(name))
            {
                return excluded(row, "python_scope_directive");
            }
            match qualify_local_write(
                semantics,
                &points_by_span,
                &python_directives,
                source,
                prepared.syntax.tree().root_node(),
                procedure_node,
                left,
                left,
                Language::Python,
            ) {
                Ok(write)
                    if semantics
                        .value(write.target)
                        .is_some_and(|value| value.kind == SemanticValueKind::Local) =>
                {
                    row.points = write.points;
                    row.target = Some(write.target);
                    row.rhs_value = Some(write.rhs_value);
                    row.verdict = PlainAssignmentVerdict::Supported;
                    row.reason = "qualified";
                    row
                }
                Ok(_) => excluded(row, "parameter_target"),
                Err(rejection) => {
                    row.verdict = rejection.verdict;
                    row.reason = rejection.reason;
                    row
                }
            }
        })
        .collect();
    OverwrittenLocalCandidates {
        rows,
        complete: true,
        reason: None,
    }
}

#[track_caller]
fn python_directive_identifiers<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Vec<&'source str> {
    debug_assert!(matches!(
        node.kind(),
        "global_statement" | "nonlocal_statement"
    ));
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier")
        .filter_map(|name| source.get(name.byte_range()))
        .collect()
}

/// Go local establishments by `=`, `:=` and `var name = value`. A tuple
/// statement establishes several targets at one lowered point; each target
/// identifier is paired with the effect whose binding it names in that one
/// statement, and a missing or duplicate pairing stays open. The blank
/// identifier binds nothing. Compound assignment, field and index targets,
/// parameters and package-level variables are excluded; `range` bindings are
/// not candidates.
pub fn go_overwritten_local_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> OverwrittenLocalCandidates {
    let unavailable = |reason| OverwrittenLocalCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    };
    if procedure.artifact().key().language().language() != Language::Go {
        return unavailable(derivation_reason::UNSUPPORTED_LANGUAGE);
    }
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let procedure_node = match prepared.procedure_node(procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    let source = prepared.syntax.source();
    let semantics = procedure.semantics();

    let mut statements = Vec::new();
    if !for_each_procedure_node(
        procedure_node,
        cancellation,
        |node| is_nested_body(node, Language::Go),
        |node| match node.kind() {
            "assignment_statement" | "short_var_declaration" => statements.push(node),
            "var_spec" if node.child_by_field_name("value").is_some() => statements.push(node),
            _ => {}
        },
    ) {
        return unavailable(derivation_reason::CANCELLED);
    }
    statements.sort_unstable_by_key(Node::start_byte);
    let points_by_span = exact_program_points_by_span(semantics);

    let mut rows = Vec::new();
    for statement in statements {
        let source_kind = if statement.kind() == "assignment_statement" {
            OverwrittenLocalSourceKind::PlainAssignment
        } else {
            OverwrittenLocalSourceKind::DeclarationInitializer
        };
        let row = |node: Node<'_>, verdict, reason| OverwrittenLocalCandidate {
            points: Vec::new(),
            target: None,
            rhs_value: None,
            range: node_range(node),
            source_kind,
            verdict,
            reason,
        };
        if statement.has_error() {
            rows.push(row(
                statement,
                PlainAssignmentVerdict::Unknown,
                "syntax_unresolved",
            ));
            continue;
        }
        if statement.kind() == "assignment_statement"
            && statement
                .child_by_field_name("operator")
                .is_none_or(|operator| operator.kind() != "=")
        {
            rows.push(row(
                statement,
                PlainAssignmentVerdict::Excluded,
                "compound_assignment",
            ));
            continue;
        }
        let targets = if statement.kind() == "var_spec" {
            let mut cursor = statement.walk();
            statement
                .children_by_field_name("name", &mut cursor)
                .collect::<Vec<_>>()
        } else {
            let Some(left) = statement.child_by_field_name("left") else {
                rows.push(row(
                    statement,
                    PlainAssignmentVerdict::Unknown,
                    "syntax_unresolved",
                ));
                continue;
            };
            let mut cursor = left.walk();
            left.named_children(&mut cursor).collect::<Vec<_>>()
        };
        let writes = points_by_span
            .get(&(statement.start_byte(), statement.end_byte()))
            .map(|points| {
                points
                    .iter()
                    .flat_map(|point| {
                        point
                            .events
                            .iter()
                            .filter_map(move |event| match event.effect {
                                SemanticEffect::Assignment { target, value } => {
                                    Some((point.id, target, value))
                                }
                                _ => None,
                            })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let stores_memory = points_by_span
            .get(&(statement.start_byte(), statement.end_byte()))
            .is_some_and(|points| {
                points.iter().any(|point| {
                    point
                        .events
                        .iter()
                        .any(|event| matches!(event.effect, SemanticEffect::MemoryStore { .. }))
                })
            });
        let declared_name = |target: ValueId| {
            let value = semantics.value(target)?;
            let mapping = semantics
                .source_mapping(value.source)
                .filter(|mapping| mapping.kind == SourceMappingKind::Exact)?;
            let span = mapping.locator.anchor().span();
            let declaration = prepared
                .syntax
                .tree()
                .root_node()
                .named_descendant_for_byte_range(
                    span.start_byte() as usize,
                    span.end_byte() as usize,
                )?;
            (exact_span(span, declaration) && declaration.kind() == "identifier")
                .then_some(declaration)
        };
        for target in targets {
            if target.kind() != "identifier" {
                rows.push(row(
                    target,
                    PlainAssignmentVerdict::Excluded,
                    "nonlocal_target",
                ));
                continue;
            }
            let name = source.get(target.byte_range());
            if name == Some("_") {
                continue;
            }
            let matched = writes
                .iter()
                .filter(|(_, value, _)| {
                    declared_name(*value)
                        .is_some_and(|declaration| source.get(declaration.byte_range()) == name)
                })
                .collect::<Vec<_>>();
            let [(point, value, rhs)] = matched.as_slice() else {
                // A package-level variable is stored to memory rather than
                // established as a procedure binding.
                if matched.is_empty() && stores_memory {
                    rows.push(row(
                        target,
                        PlainAssignmentVerdict::Excluded,
                        "nonlocal_target",
                    ));
                } else {
                    rows.push(row(
                        target,
                        PlainAssignmentVerdict::Unknown,
                        "local_assignment_join_ambiguous",
                    ));
                }
                continue;
            };
            let kind = semantics.value(*value).map(|value| &value.kind);
            let declaration = declared_name(*value).expect("matched target has a declaration");
            if matches!(kind, Some(SemanticValueKind::Parameter { .. })) {
                rows.push(row(
                    target,
                    PlainAssignmentVerdict::Excluded,
                    "parameter_target",
                ));
            } else if !matches!(kind, Some(SemanticValueKind::Local)) {
                rows.push(row(
                    target,
                    PlainAssignmentVerdict::Unknown,
                    "ordinary_local_unproved",
                ));
            } else if declaration.start_byte() < procedure_node.start_byte()
                || declaration.end_byte() > procedure_node.end_byte()
            {
                rows.push(row(
                    target,
                    PlainAssignmentVerdict::Excluded,
                    "declaration_outside_procedure",
                ));
            } else {
                rows.push(OverwrittenLocalCandidate {
                    points: vec![*point],
                    target: Some(*value),
                    rhs_value: Some(*rhs),
                    range: node_range(target),
                    source_kind,
                    verdict: PlainAssignmentVerdict::Supported,
                    reason: "qualified",
                });
            }
        }
    }
    OverwrittenLocalCandidates {
        rows,
        complete: true,
        reason: None,
    }
}

/// One source write a language's syntax proposes for the single-target B1
/// join, or the reason it is not a candidate.
enum SingleTargetWrite<'tree> {
    /// `point_node` is the node the lowering maps the write to; `target` is
    /// the written simple name.
    Candidate {
        point_node: Node<'tree>,
        target: Node<'tree>,
        source_kind: OverwrittenLocalSourceKind,
    },
    Excluded(Node<'tree>, &'static str),
    Open(Node<'tree>, &'static str),
}

/// C#, Kotlin, Rust, Scala, PHP, and Ruby local establishments. Each lowered write point holds
/// exactly one binding (Local or Parameter) assignment; a C# point also
/// assigns the expression's own Temporary, which is not a binding. The
/// language supplies candidates from syntax; the join, the parameter
/// exclusion and the in-procedure declaration check are shared.
pub fn single_target_overwritten_local_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> OverwrittenLocalCandidates {
    let unavailable = |reason| OverwrittenLocalCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    };
    let language = procedure.artifact().key().language().language();
    let classify: for<'tree> fn(Node<'tree>, &str) -> Option<SingleTargetWrite<'tree>> =
        match language {
            Language::CSharp => csharp_single_target_write,
            Language::Kotlin => kotlin_single_target_write,
            Language::Rust => rust_single_target_write,
            Language::Scala => scala_single_target_write,
            Language::Php => php_single_target_write,
            Language::Ruby => ruby_single_target_write,
            _ => return unavailable(derivation_reason::UNSUPPORTED_LANGUAGE),
        };
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let procedure_node = match prepared.procedure_node(procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    let source = prepared.syntax.source();
    let semantics = procedure.semantics();
    let roles = prepared.roles;

    let mut writes = Vec::new();
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable(derivation_reason::CANCELLED);
        }
        if node.id() != procedure_node.id() && (roles.nested_procedure)(node) {
            continue;
        }
        if let Some(write) = classify(node, source) {
            writes.push(write);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    let points_by_span = exact_program_points_by_span(semantics);

    let mut rows = writes
        .into_iter()
        .map(|write| {
            let row = |node: Node<'_>, source_kind, verdict, reason| OverwrittenLocalCandidate {
                points: Vec::new(),
                target: None,
                rhs_value: None,
                range: node_range(node),
                source_kind,
                verdict,
                reason,
            };
            let (point_node, target, source_kind) = match write {
                SingleTargetWrite::Candidate {
                    point_node,
                    target,
                    source_kind,
                } => (point_node, target, source_kind),
                SingleTargetWrite::Excluded(node, reason) => {
                    return row(
                        node,
                        OverwrittenLocalSourceKind::PlainAssignment,
                        PlainAssignmentVerdict::Excluded,
                        reason,
                    );
                }
                SingleTargetWrite::Open(node, reason) => {
                    return row(
                        node,
                        OverwrittenLocalSourceKind::PlainAssignment,
                        PlainAssignmentVerdict::Unknown,
                        reason,
                    );
                }
            };
            let write = match join_binding_write(
                semantics,
                &points_by_span,
                source,
                procedure_node,
                point_node,
                target,
            ) {
                Ok(write) => write,
                Err((verdict, reason)) => {
                    if language == Language::Scala
                        && verdict == PlainAssignmentVerdict::Excluded
                        && reason == "nonlocal_target"
                    {
                        return row(target, source_kind, PlainAssignmentVerdict::Unknown, reason);
                    }
                    return row(target, source_kind, verdict, reason);
                }
            };
            if language == Language::Scala
                && !scala_var_declaration(write.declaration, procedure_node)
            {
                return row(
                    target,
                    source_kind,
                    PlainAssignmentVerdict::Unknown,
                    "immutable_or_nonlocal_target",
                );
            }
            if write.parameter {
                return row(
                    target,
                    source_kind,
                    PlainAssignmentVerdict::Excluded,
                    "parameter_target",
                );
            }
            OverwrittenLocalCandidate {
                points: vec![write.point],
                target: Some(write.binding),
                rhs_value: Some(write.value),
                range: node_range(target),
                source_kind,
                verdict: PlainAssignmentVerdict::Supported,
                reason: "qualified",
            }
        })
        .collect::<Vec<_>>();
    rows.sort_unstable_by_key(|row| row.range.start_byte);
    OverwrittenLocalCandidates {
        rows,
        complete: true,
        reason: None,
    }
}

/// A simple-name write joined to the one binding the lowering assigns at the
/// write's point.
#[doc(hidden)]
pub struct BindingWrite<'tree> {
    #[doc(hidden)]
    pub point: ProgramPointId,
    #[doc(hidden)]
    pub binding: ValueId,
    #[doc(hidden)]
    pub value: ValueId,
    #[doc(hidden)]
    pub parameter: bool,
    /// The binding's declared name.
    #[doc(hidden)]
    pub declaration: Node<'tree>,
}

/// Join the simple name `target` to the one binding (Local or Parameter)
/// that the lowering assigns at `point_node`, declared inside this procedure
/// and spelled like `target`. C#, Kotlin, Go, Rust, Scala, PHP, and Ruby lower a
/// simple-name write to exactly one binding assignment; a C# point also
/// assigns the expression's own Temporary, which is not a binding.
#[doc(hidden)]
pub fn join_binding_write<'tree>(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    points_by_span: &HashMap<(usize, usize), Vec<&crate::analyzer::semantic::ProgramPoint>>,
    source: &str,
    procedure_node: Node<'tree>,
    point_node: Node<'_>,
    target: Node<'_>,
) -> Result<BindingWrite<'tree>, (PlainAssignmentVerdict, &'static str)> {
    let open = |reason| Err((PlainAssignmentVerdict::Unknown, reason));
    let points = points_by_span
        .get(&(point_node.start_byte(), point_node.end_byte()))
        .map(Vec::as_slice)
        .unwrap_or_default();
    let bindings = points
        .iter()
        .flat_map(|point| {
            point
                .events
                .iter()
                .filter_map(move |event| match event.effect {
                    SemanticEffect::Assignment { target, value }
                        if semantics.value(target).is_some_and(|row| {
                            matches!(
                                row.kind,
                                SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
                            )
                        }) =>
                    {
                        Some((point.id, target, value))
                    }
                    _ => None,
                })
        })
        .collect::<Vec<_>>();
    let [(point, binding, value)] = bindings.as_slice() else {
        // A simple name the lowering resolved to a field or global is not
        // established as a binding: the point stores to memory, or (C#
        // implicit `this` fields) assigns only the expression's own
        // non-binding value.
        let lowered_without_binding = points.iter().any(|point| {
            point.events.iter().any(|event| match event.effect {
                SemanticEffect::MemoryStore { .. } => true,
                SemanticEffect::Assignment { target, .. } => semantics
                    .value(target)
                    .is_some_and(|row| row.kind == SemanticValueKind::Temporary),
                _ => false,
            })
        });
        return if bindings.is_empty() && lowered_without_binding {
            Err((PlainAssignmentVerdict::Excluded, "nonlocal_target"))
        } else if bindings.is_empty() {
            open("assignment_point_unmapped")
        } else {
            open("local_assignment_join_ambiguous")
        };
    };
    let row = semantics.value(*binding).expect("assignment target exists");
    let Some(mapping) = semantics
        .source_mapping(row.source)
        .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
    else {
        return open("target_mapping_inexact");
    };
    let span = mapping.locator.anchor().span();
    if (span.start_byte() as usize) < procedure_node.start_byte()
        || (span.end_byte() as usize) > procedure_node.end_byte()
    {
        return Err((
            PlainAssignmentVerdict::Excluded,
            "declaration_outside_procedure",
        ));
    }
    // The lowering joined this write to one binding; its declaration must be
    // spelled like the written name. A parameter can map to its whole
    // declaration, which names the binding in its `name` field, or (Rust) in
    // its `pattern` field, possibly as `mut name`.
    let Some(declaration) = procedure_node
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
        .filter(|node| exact_span(span, *node))
    else {
        return open("declaration_name_missing");
    };
    let mut name = declaration
        .child_by_field_name("name")
        .or_else(|| declaration.child_by_field_name("pattern"))
        .unwrap_or(declaration);
    if name.kind() == "mut_pattern"
        && let Some(inner) = name.named_child(0)
    {
        name = inner;
    }
    if source.get(name.byte_range()) != source.get(target.byte_range()) {
        return open("declaration_name_mismatch");
    }
    Ok(BindingWrite {
        point: *point,
        binding: *binding,
        value: *value,
        parameter: matches!(row.kind, SemanticValueKind::Parameter { .. }),
        declaration: name,
    })
}

/// One simple-name assignment that a language's syntax proposes for the
/// self-assignment and failed-swap relations, or the reason it is not one.
enum PlainWrite<'tree> {
    /// `assignment` is the node the lowering maps the write to. `next` is the
    /// start of the assignment in the next statement of the same block.
    Candidate {
        assignment: Node<'tree>,
        left: Node<'tree>,
        right: Node<'tree>,
        next: Option<usize>,
    },
    Excluded(Node<'tree>, &'static str, &'static str),
    Open(Node<'tree>, &'static str),
    OpenWithNext(Node<'tree>, &'static str, Option<usize>),
}

/// C#, Kotlin, Go, Rust, Scala, PHP, and Ruby assignments to a simple name. Each
/// lowering maps the write to the assignment node and assigns exactly one
/// binding there, so the B1 binding join also serves these relations.
fn single_target_plain_assignment_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
    classify: for<'tree> fn(Node<'tree>, &str) -> Option<PlainWrite<'tree>>,
) -> PlainAssignmentCandidates {
    let language = procedure.artifact().key().language().language();
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let procedure_node = match prepared.procedure_node(procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    let source = prepared.syntax.source();
    let semantics = procedure.semantics();

    let mut writes = Vec::new();
    if !for_each_procedure_node(
        procedure_node,
        cancellation,
        |node| (prepared.roles.nested_procedure)(node),
        |node| {
            if let Some(write) = classify(node, source) {
                writes.push(write);
            }
        },
    ) {
        return unavailable(derivation_reason::CANCELLED);
    }
    let points_by_span = exact_program_points_by_span(semantics);

    let mut rows = writes
        .into_iter()
        .map(|write| {
            let row =
                |node: Node<'_>, next, verdict, storage_kind, reason| PlainAssignmentCandidate {
                    points: Vec::new(),
                    target: None,
                    rhs_value: None,
                    range: node_range(node),
                    rhs_range: None,
                    rhs_identifier_range: None,
                    next_assignment_start: next,
                    swap_type: None,
                    verdict,
                    storage_kind,
                    reason,
                };
            let (assignment, left, right, next) = match write {
                PlainWrite::Candidate {
                    assignment,
                    left,
                    right,
                    next,
                } => (assignment, left, right, next),
                PlainWrite::Excluded(node, storage_kind, reason) => {
                    return row(
                        node,
                        None,
                        PlainAssignmentVerdict::Excluded,
                        storage_kind,
                        reason,
                    );
                }
                PlainWrite::Open(node, reason) => {
                    return row(
                        node,
                        None,
                        PlainAssignmentVerdict::Unknown,
                        "unknown",
                        reason,
                    );
                }
                PlainWrite::OpenWithNext(node, reason, next) => {
                    return row(
                        node,
                        next,
                        PlainAssignmentVerdict::Unknown,
                        "unknown",
                        reason,
                    );
                }
            };
            let mut row = row(
                assignment,
                next,
                PlainAssignmentVerdict::Unknown,
                "unknown",
                "syntax_unresolved",
            );
            row.rhs_range = Some(node_range(right));
            let Some(rhs_identifier) = parenthesized_name(right, left.kind()) else {
                row.verdict = PlainAssignmentVerdict::Excluded;
                row.storage_kind = "ordinary_local";
                row.reason = "rhs_not_bare_identifier";
                return row;
            };
            row.rhs_identifier_range = Some(node_range(rhs_identifier));
            match join_binding_write(
                semantics,
                &points_by_span,
                source,
                procedure_node,
                assignment,
                left,
            ) {
                Ok(write) => {
                    if language == Language::Scala
                        && !scala_var_declaration(write.declaration, procedure_node)
                    {
                        row.verdict = PlainAssignmentVerdict::Unknown;
                        row.storage_kind = "unknown";
                        row.reason = if write.parameter {
                            "parameter_target"
                        } else {
                            "immutable_target"
                        };
                        return row;
                    }
                    // C# conversions between distinct types can run
                    // user-defined code, so a swap needs equal declared types.
                    // Kotlin and Go assignments never convert a value.
                    if language == Language::CSharp {
                        row.swap_type = csharp_swap_type(write.declaration, source);
                    }
                    row.points = vec![write.point];
                    row.target = Some(write.binding);
                    row.rhs_value = Some(write.value);
                    row.verdict = PlainAssignmentVerdict::Supported;
                    row.storage_kind = "ordinary_local";
                    row.reason = "qualified";
                }
                Err((verdict, reason)) => {
                    // Scala's simple-name field and captured-local assignments
                    // can reach this join without a local binding. Their
                    // setter/capture behavior is effectful or deferred, so
                    // preserve an open row instead of certifying an absence.
                    if language == Language::Scala
                        && verdict == PlainAssignmentVerdict::Excluded
                        && reason == "nonlocal_target"
                    {
                        row.verdict = PlainAssignmentVerdict::Unknown;
                        row.storage_kind = "unknown";
                        row.reason = reason;
                        return row;
                    }
                    // A Ruby block may write a captured binding declared by
                    // its enclosing method. The exact binding join can see
                    // that target but correctly places its declaration
                    // outside the block procedure; preserve that as an open
                    // Ruby closure boundary instead of a clean exclusion.
                    if language == Language::Ruby
                        && verdict == PlainAssignmentVerdict::Excluded
                        && reason == "declaration_outside_procedure"
                    {
                        row.verdict = PlainAssignmentVerdict::Unknown;
                        row.storage_kind = "unknown";
                        row.reason = reason;
                        return row;
                    }
                    if verdict == PlainAssignmentVerdict::Excluded {
                        row.storage_kind = "nonlocal";
                    }
                    row.verdict = verdict;
                    row.reason = reason;
                }
            }
            row
        })
        .collect::<Vec<_>>();
    rows.sort_unstable_by_key(|row| row.range.start_byte);
    PlainAssignmentCandidates {
        rows,
        complete: true,
        reason: None,
    }
}

/// A Scala assignment is a local candidate only when its exact binding was
/// declared by a local `var`. `val`, `lazy val`, parameters, and `var`
/// members in a template body are effectful or immutable from this relation's
/// point of view; retaining those rows as unknown keeps them from becoming a
/// clean assignment proof.
fn scala_var_declaration(declaration: Node<'_>, procedure_node: Node<'_>) -> bool {
    let Some(var_definition) = declaration
        .parent()
        .filter(|parent| parent.kind() == "var_definition")
    else {
        return false;
    };
    let Some(container) = var_definition.parent() else {
        return false;
    };
    let is_template_member = matches!(container.kind(), "template_body" | "with_template_body")
        || matches!(container.kind(), "block" | "indented_block")
            && container.parent().is_some_and(|parent| {
                matches!(parent.kind(), "template_body" | "with_template_body")
            });
    if is_template_member {
        return false;
    }
    let mut current = Some(var_definition);
    while let Some(node) = current {
        if node.id() == procedure_node.id() {
            return true;
        }
        current = node.parent();
    }
    false
}

/// The name `node` spells inside transparent parentheses, when it is a
/// simple name of `name_kind`. Ruby represents these parentheses as a
/// `parenthesized_statements` node rather than the `parenthesized_expression`
/// kind used by several other grammars; one named child is still a
/// transparent expression for this join.
fn parenthesized_name<'tree>(mut node: Node<'tree>, name_kind: &str) -> Option<Node<'tree>> {
    loop {
        if node.has_error() {
            return None;
        }
        if node.kind() == name_kind {
            return Some(node);
        }
        if !matches!(
            node.kind(),
            "parenthesized_expression" | "parenthesized_statements"
        ) || node.named_child_count() != 1
        {
            return None;
        }
        node = node.named_child(0)?;
    }
}

/// A tuple assignment `a, b = c, d`. Distinct names in one statement denote
/// distinct bindings, so when no position assigns a name to the same
/// spelling, no element writes a binding to itself. Otherwise the element
/// self-assignment is not modeled and stays open.
fn tuple_plain_write<'tree>(
    assignment: Node<'tree>,
    lefts: &[Node<'_>],
    rights: &[Node<'_>],
    name_kind: &str,
    source: &str,
) -> PlainWrite<'tree> {
    let same_name = lefts.len() == rights.len()
        && lefts.iter().zip(rights).any(|(left, right)| {
            left.kind() == name_kind
                && parenthesized_name(*right, name_kind).is_some_and(|right| {
                    source.get(right.byte_range()) == source.get(left.byte_range())
                })
        });
    if same_name {
        PlainWrite::Open(assignment, "tuple_self_assignment_unmodeled")
    } else {
        PlainWrite::Excluded(assignment, "indirect", "no_element_self_assignment")
    }
}

/// The next statement after `statement` in the same statement list, skipping
/// comments.
fn next_statement(statement: Node<'_>) -> Option<Node<'_>> {
    let mut next = statement.next_named_sibling()?;
    while next.is_extra() {
        next = next.next_named_sibling()?;
    }
    Some(next)
}

fn next_block_assignment_expression(assignment: Node<'_>) -> Option<usize> {
    assignment
        .parent()
        .filter(|statement| {
            statement.kind() == "expression_statement"
                && statement
                    .parent()
                    .is_some_and(|block| block.kind() == "block")
        })
        .and_then(next_statement)
        .filter(|next| next.kind() == "expression_statement" && next.named_child_count() == 1)
        .and_then(|next| next.named_child(0))
        .filter(|next| next.kind() == "assignment_expression")
        .map(|next| next.start_byte())
}

/// The declared type spelling of a C# local or parameter named `name`, when
/// it is spelled rather than inferred with `var`.
fn csharp_swap_type(name: Node<'_>, source: &str) -> Option<Box<str>> {
    let parent = name.parent()?;
    let declaration = match parent.kind() {
        "variable_declarator" => parent.parent()?,
        "parameter" => parent,
        _ => return None,
    };
    let type_node = declaration.child_by_field_name("type")?;
    if type_node.kind() == "implicit_type" {
        return None;
    }
    source.get(type_node.byte_range()).map(Into::into)
}

/// C#: an `=` assignment expression statement. Its target is a simple name,
/// a member or element (excluded), or a tuple or declaration (open).
fn csharp_plain_write<'tree>(node: Node<'tree>, source: &str) -> Option<PlainWrite<'tree>> {
    if node.kind() != "assignment_expression" {
        return None;
    }
    if node.has_error() {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    }
    if node
        .child_by_field_name("operator")
        .is_none_or(|operator| operator.kind() != "=")
    {
        return Some(PlainWrite::Excluded(
            node,
            "compound",
            "compound_assignment",
        ));
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    };
    match left.kind() {
        "identifier" => {}
        "member_access_expression" | "element_access_expression" => {
            return Some(PlainWrite::Excluded(node, "indirect", "nonlocal_target"));
        }
        "tuple_expression" if right.kind() == "tuple_expression" => {
            let elements = |tuple: Node<'tree>| {
                let mut cursor = tuple.walk();
                tuple
                    .named_children(&mut cursor)
                    .map(|argument| {
                        (argument.kind() == "argument" && argument.named_child_count() == 1)
                            .then(|| argument.named_child(0))
                            .flatten()
                            .unwrap_or(argument)
                    })
                    .collect::<Vec<_>>()
            };
            return Some(tuple_plain_write(
                node,
                &elements(left),
                &elements(right),
                "identifier",
                source,
            ));
        }
        _ => return Some(PlainWrite::Open(node, "destructuring_target_unmodeled")),
    }
    let next = next_block_assignment_expression(node);
    Some(PlainWrite::Candidate {
        assignment: node,
        left,
        right,
        next,
    })
}

/// Kotlin: an `=` assignment statement to a simple name. A compound
/// operator is an anonymous `+=`-style token.
fn kotlin_plain_write<'tree>(node: Node<'tree>, _source: &str) -> Option<PlainWrite<'tree>> {
    if node.kind() != "assignment" {
        return None;
    }
    if node.has_error() {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    }
    let mut cursor = node.walk();
    if node
        .children(&mut cursor)
        .any(|child| !child.is_named() && matches!(child.kind(), "+=" | "-=" | "*=" | "/=" | "%="))
    {
        return Some(PlainWrite::Excluded(
            node,
            "compound",
            "compound_assignment",
        ));
    }
    let count = node.named_child_count();
    let (Some(target), Some(right)) = (node.named_child(0), node.named_child(count.max(1) - 1))
    else {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    };
    let left =
        if target.kind() == "directly_assignable_expression" && target.named_child_count() == 1 {
            target.named_child(0)?
        } else {
            target
        };
    if count != 2 || left.kind() != "simple_identifier" {
        return Some(PlainWrite::Excluded(node, "indirect", "nonlocal_target"));
    }
    let next = node
        .parent()
        .filter(|block| block.kind() == "statements")
        .and_then(|_| next_statement(node))
        .filter(|next| next.kind() == "assignment")
        .map(|next| next.start_byte());
    Some(PlainWrite::Candidate {
        assignment: node,
        left,
        right,
        next,
    })
}

/// Rust: an `=` assignment to a simple name. A compound assignment is its
/// own node kind, and a tuple target (`(a, b) = (b, a)`) pairs by position.
/// Rust assignment never converts a value between types.
fn rust_plain_write<'tree>(node: Node<'tree>, source: &str) -> Option<PlainWrite<'tree>> {
    match node.kind() {
        "compound_assignment_expr" => {
            return Some(PlainWrite::Excluded(
                node,
                "compound",
                "compound_assignment",
            ));
        }
        "assignment_expression" => {}
        _ => return None,
    }
    if node.has_error() {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    };
    match left.kind() {
        "identifier" => {}
        "field_expression" | "index_expression" => {
            return Some(PlainWrite::Excluded(node, "indirect", "nonlocal_target"));
        }
        "unary_expression" if rust_dereference_operand(left).is_some() => {
            return Some(PlainWrite::Excluded(node, "indirect", "nonlocal_target"));
        }
        "tuple_expression" if right.kind() == "tuple_expression" => {
            let elements = |tuple: Node<'tree>| {
                let mut cursor = tuple.walk();
                tuple.named_children(&mut cursor).collect::<Vec<_>>()
            };
            return Some(tuple_plain_write(
                node,
                &elements(left),
                &elements(right),
                "identifier",
                source,
            ));
        }
        _ => return Some(PlainWrite::Open(node, "destructuring_target_unmodeled")),
    }
    let next = next_block_assignment_expression(node);
    Some(PlainWrite::Candidate {
        assignment: node,
        left,
        right,
        next,
    })
}

/// Go: an `=` assignment statement with one target. A tuple assignment can
/// write a name to itself only where some right operand is a bare name; it
/// stays open then, and is excluded otherwise.
fn go_plain_write<'tree>(node: Node<'tree>, source: &str) -> Option<PlainWrite<'tree>> {
    if node.kind() != "assignment_statement" {
        return None;
    }
    if node.has_error() {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    }
    if node
        .child_by_field_name("operator")
        .is_none_or(|operator| operator.kind() != "=")
    {
        return Some(PlainWrite::Excluded(
            node,
            "compound",
            "compound_assignment",
        ));
    }
    let (Some(lefts), Some(rights)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    };
    let mut cursor = lefts.walk();
    let lefts = lefts.named_children(&mut cursor).collect::<Vec<_>>();
    let mut cursor = rights.walk();
    let rights = rights.named_children(&mut cursor).collect::<Vec<_>>();
    let ([left], [right]) = (lefts.as_slice(), rights.as_slice()) else {
        return Some(tuple_plain_write(
            node,
            &lefts,
            &rights,
            "identifier",
            source,
        ));
    };
    if left.kind() != "identifier" {
        return Some(PlainWrite::Excluded(node, "indirect", "nonlocal_target"));
    }
    if source.get(left.byte_range()) == Some("_") {
        return Some(PlainWrite::Excluded(node, "nonlocal", "blank_target"));
    }
    let next = node
        .parent()
        .filter(|block| block.kind() == "statement_list")
        .and_then(|_| next_statement(node))
        .filter(|next| next.kind() == "assignment_statement")
        .map(|next| next.start_byte());
    Some(PlainWrite::Candidate {
        assignment: node,
        left: *left,
        right: *right,
        next,
    })
}

/// Scala: a direct `=` assignment whose target is a plain identifier. Scala
/// compound updates are `infix_expression` nodes and named call arguments
/// also use `assignment_expression`; neither is a local write candidate.
/// Non-identifier targets stay open because they can dispatch through a
/// setter, field, update method, or another effectful assignment protocol.
fn scala_plain_write<'tree>(node: Node<'tree>, _source: &str) -> Option<PlainWrite<'tree>> {
    if node.kind() != "assignment_expression" || is_named_argument_assignment(node) {
        return None;
    }
    if node.has_error() {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return Some(PlainWrite::Open(node, "syntax_unresolved"));
    };
    let next = node
        .parent()
        .filter(|parent| {
            matches!(
                parent.kind(),
                "block" | "indented_block" | "case_clause" | "template_body"
            )
        })
        .and_then(|_| next_statement(node))
        .filter(|next| {
            next.kind() == "assignment_expression" && !is_named_argument_assignment(*next)
        })
        .map(|next| next.start_byte());
    if left.kind() != "identifier" {
        return Some(PlainWrite::OpenWithNext(node, "nonlocal_target", next));
    }
    Some(PlainWrite::Candidate {
        assignment: node,
        left,
        right,
        next,
    })
}

/// Scala: an initialized local `var` or a direct `=` assignment to a simple
/// name. `val` declarations do not establish a mutable value for B1. Member,
/// setter, tuple and other non-simple targets stay open because assignment
/// syntax can execute user code or establish more than one binding.
fn scala_single_target_write<'tree>(
    node: Node<'tree>,
    _source: &str,
) -> Option<SingleTargetWrite<'tree>> {
    match node.kind() {
        "var_definition" => {
            if node.has_error() {
                return Some(SingleTargetWrite::Open(node, "syntax_unresolved"));
            }
            let pattern = node.child_by_field_name("pattern")?;
            node.child_by_field_name("value")?;
            Some(if pattern.kind() == "identifier" {
                SingleTargetWrite::Candidate {
                    point_node: node,
                    target: pattern,
                    source_kind: OverwrittenLocalSourceKind::DeclarationInitializer,
                }
            } else {
                SingleTargetWrite::Open(node, "destructuring_target_unmodeled")
            })
        }
        "assignment_expression" => {
            if is_named_argument_assignment(node) {
                return None;
            }
            if node.has_error() {
                return Some(SingleTargetWrite::Open(node, "syntax_unresolved"));
            }
            if !assignment_has_plain_operator(node) {
                return Some(SingleTargetWrite::Excluded(node, "compound_assignment"));
            }
            let left = node.child_by_field_name("left")?;
            Some(if left.kind() == "identifier" {
                SingleTargetWrite::Candidate {
                    point_node: node,
                    target: left,
                    source_kind: OverwrittenLocalSourceKind::PlainAssignment,
                }
            } else {
                SingleTargetWrite::Open(node, "nonlocal_target")
            })
        }
        _ => None,
    }
}

/// PHP's direct local assignment shape. PHP variables are bindings only for a
/// plain `variable_name` target; properties, elements, references,
/// destructuring and variable variables can invoke runtime protocols or alias
/// storage, so they remain open for review. The enclosing procedure is also
/// checked for PHP's dynamic local-scope constructs because the lowering does
/// not bind those constructs to the ordinary local value it creates for a
/// same-spelled assignment.
fn php_plain_write<'tree>(node: Node<'tree>, source: &str) -> Option<PlainWrite<'tree>> {
    if node.kind() == "reference_assignment_expression" {
        return Some(PlainWrite::OpenWithNext(
            node,
            "reference_assignment",
            php_next_assignment_start(node),
        ));
    }
    if node.kind() == "augmented_assignment_expression" {
        return Some(PlainWrite::Excluded(
            node,
            "compound",
            "compound_assignment",
        ));
    }
    if node.kind() != "assignment_expression" {
        return None;
    }
    let next = php_next_assignment_start(node);
    if node.has_error() {
        return Some(PlainWrite::OpenWithNext(node, "syntax_unresolved", next));
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return Some(PlainWrite::OpenWithNext(node, "syntax_unresolved", next));
    };
    match left.kind() {
        "variable_name" => {
            if let Some(reason) = php_dynamic_scope_reason(node, source) {
                return Some(PlainWrite::OpenWithNext(node, reason, next));
            }
            Some(PlainWrite::Candidate {
                assignment: node,
                left,
                right,
                next,
            })
        }
        "member_access_expression"
        | "nullsafe_member_access_expression"
        | "scoped_property_access_expression"
        | "subscript_expression" => Some(PlainWrite::OpenWithNext(node, "effectful_target", next)),
        "dynamic_variable_name" => Some(PlainWrite::OpenWithNext(node, "variable_variable", next)),
        "list_literal" => Some(PlainWrite::OpenWithNext(node, "destructuring_target", next)),
        _ => Some(PlainWrite::OpenWithNext(
            node,
            "assignment_target_unresolved",
            next,
        )),
    }
}

/// PHP's single-target B1 shape. A plain variable assignment can be joined to
/// one local binding; every other write that reads, aliases, dispatches, or
/// spreads storage remains open until a more precise lowering exists.
fn php_single_target_write<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<SingleTargetWrite<'tree>> {
    if matches!(
        node.kind(),
        "reference_assignment_expression" | "augmented_assignment_expression" | "update_expression"
    ) {
        return Some(SingleTargetWrite::Open(node, "effectful_or_reading_write"));
    }
    if node.kind() != "assignment_expression" {
        return None;
    }
    if node.has_error() {
        return Some(SingleTargetWrite::Open(node, "syntax_unresolved"));
    }
    let (Some(left), Some(_right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return Some(SingleTargetWrite::Open(node, "syntax_unresolved"));
    };
    if left.kind() != "variable_name" {
        return Some(SingleTargetWrite::Open(
            node,
            "nonlocal_or_destructuring_target",
        ));
    }
    if let Some(reason) = php_dynamic_scope_reason(node, source) {
        return Some(SingleTargetWrite::Open(node, reason));
    }
    Some(SingleTargetWrite::Candidate {
        point_node: node,
        target: left,
        source_kind: OverwrittenLocalSourceKind::PlainAssignment,
    })
}

fn php_next_assignment_start(node: Node<'_>) -> Option<usize> {
    let statement = node
        .parent()
        .filter(|parent| parent.kind() == "expression_statement")?;
    let next = next_statement(statement)?;
    if next.kind() != "expression_statement" || next.named_child_count() != 1 {
        return None;
    }
    let expression = next.named_child(0)?;
    matches!(
        expression.kind(),
        "assignment_expression" | "reference_assignment_expression"
    )
    .then_some(expression.start_byte())
}

fn php_dynamic_scope_reason(node: Node<'_>, source: &str) -> Option<&'static str> {
    let procedure = nearest_php_procedure(node)?;
    if php_procedure_has_reference_parameter(procedure) {
        return Some("reference_parameter");
    }
    let body = procedure.child_by_field_name("body")?;
    let mut stack = vec![body];
    while let Some(current) = stack.pop() {
        if current.id() != body.id() && is_php_assignment_procedure(current) {
            if php_closure_captures_by_reference(current) {
                return Some("closure_reference_capture");
            }
            continue;
        }
        match current.kind() {
            "global_declaration"
            | "static_variable_declaration"
            | "function_static_declaration" => {
                return Some("dynamic_local_scope");
            }
            "dynamic_variable_name" => return Some("variable_variable"),
            "reference_modifier" => return Some("reference_alias"),
            "variable_name"
                if source
                    .get(current.byte_range())
                    .is_some_and(|text| text.trim_start_matches('$') == "GLOBALS") =>
            {
                return Some("dynamic_local_scope");
            }
            "function_call_expression"
                if php_dynamic_function_call(current, source, "extract")
                    || php_dynamic_function_call(current, source, "compact")
                    || php_dynamic_function_call(current, source, "get_defined_vars") =>
            {
                return Some("dynamic_local_scope");
            }
            _ => {}
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    None
}

fn php_procedure_has_reference_parameter(procedure: Node<'_>) -> bool {
    let Some(parameters) = procedure.child_by_field_name("parameters") else {
        return false;
    };
    let mut stack = vec![parameters];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "reference_modifier" | "by_ref") {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn nearest_php_procedure(node: Node<'_>) -> Option<Node<'_>> {
    find_node_or_ancestor(node, is_php_assignment_procedure)
}

fn is_php_assignment_procedure(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition"
            | "method_declaration"
            | "anonymous_function"
            | "arrow_function"
            | "property_hook"
    )
}

fn php_closure_captures_by_reference(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).any(|child| {
        child.kind() == "anonymous_function_use_clause" && {
            let mut cursor = child.walk();
            child
                .named_children(&mut cursor)
                .any(|capture| capture.kind() == "by_ref")
        }
    })
}

fn php_dynamic_function_call(node: Node<'_>, source: &str, expected: &str) -> bool {
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    if !matches!(
        function.kind(),
        "name" | "qualified_name" | "fully_qualified_name" | "relative_name"
    ) {
        return false;
    }
    let terminal = if function.kind() == "name" {
        Some(function)
    } else {
        brokk_bifrost_core::analyzer::tree_walk::single_named_child_matching(function, |child| {
            child.kind() == "name"
        })
    };
    terminal
        .and_then(|name| source.get(name.byte_range()))
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

/// Ruby's direct local assignment shape. Ruby's parser distinguishes a plain
/// local `assignment` from an `operator_assignment`; only the former can be
/// joined to one lexical binding. Parallel assignment is an intentional
/// corrected form when every position crosses distinct names, while a
/// same-name position remains open because the lowering does not expose one
/// scalar write for that element.
fn ruby_plain_write<'tree>(node: Node<'tree>, source: &str) -> Option<PlainWrite<'tree>> {
    let next = ruby_next_assignment_start(node);
    match node.kind() {
        "operator_assignment" => {
            return Some(PlainWrite::OpenWithNext(node, "compound_assignment", next));
        }
        "assignment" => {}
        _ => return None,
    }
    if node.has_error() {
        return Some(PlainWrite::OpenWithNext(node, "syntax_unresolved", next));
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return Some(PlainWrite::OpenWithNext(node, "syntax_unresolved", next));
    };
    if let Some(reason) = ruby_dynamic_scope_reason(node, source) {
        return Some(PlainWrite::OpenWithNext(node, reason, next));
    }
    match left.kind() {
        "identifier" => Some(PlainWrite::Candidate {
            assignment: node,
            left,
            right,
            next,
        }),
        "left_assignment_list" => Some(ruby_parallel_plain_write(node, left, right, source, next)),
        "instance_variable" | "class_variable" | "global_variable" => {
            Some(PlainWrite::OpenWithNext(node, "nonlocal_target", next))
        }
        "call" => Some(PlainWrite::OpenWithNext(node, "writer_target", next)),
        "element_reference" => Some(PlainWrite::OpenWithNext(node, "element_target", next)),
        "destructured_left_assignment" | "rest_assignment" => {
            Some(PlainWrite::OpenWithNext(node, "destructuring_target", next))
        }
        _ => Some(PlainWrite::OpenWithNext(
            node,
            "assignment_target_unresolved",
            next,
        )),
    }
}

fn ruby_parallel_plain_write<'tree>(
    assignment: Node<'tree>,
    left: Node<'tree>,
    right: Node<'tree>,
    source: &str,
    next: Option<usize>,
) -> PlainWrite<'tree> {
    if !matches!(right.kind(), "right_assignment_list" | "array") {
        return PlainWrite::OpenWithNext(assignment, "parallel_assignment_unmodeled", next);
    }
    let mut left_cursor = left.walk();
    let lefts = left.named_children(&mut left_cursor).collect::<Vec<_>>();
    let mut right_cursor = right.walk();
    let rights = right.named_children(&mut right_cursor).collect::<Vec<_>>();
    if lefts.is_empty()
        || lefts.len() != rights.len()
        || lefts.iter().any(|node| node.kind() != "identifier")
        || rights
            .iter()
            .any(|node| node.kind() == "splat_argument" || node.has_error())
    {
        return PlainWrite::OpenWithNext(assignment, "parallel_assignment_unmodeled", next);
    }
    let same_name = lefts.iter().zip(&rights).any(|(left, right)| {
        parenthesized_name(*right, "identifier")
            .is_some_and(|right| source.get(left.byte_range()) == source.get(right.byte_range()))
    });
    if same_name {
        PlainWrite::OpenWithNext(assignment, "parallel_self_assignment_unmodeled", next)
    } else {
        PlainWrite::Excluded(assignment, "indirect", "parallel_assignment")
    }
}

fn ruby_next_assignment_start(node: Node<'_>) -> Option<usize> {
    let parent = node.parent()?;
    let (statement, list) = if is_ruby_statement_modifier(parent.kind()) {
        (parent, parent.parent()?)
    } else if is_ruby_statement_list(parent.kind()) {
        (node, parent)
    } else {
        return None;
    };
    debug_assert_eq!(
        statement.parent().map(|parent| parent.id()),
        Some(list.id())
    );
    let next = next_statement(statement)?;
    ruby_statement_assignment(next).map(|assignment| assignment.start_byte())
}

fn ruby_statement_assignment(node: Node<'_>) -> Option<Node<'_>> {
    if matches!(node.kind(), "assignment" | "operator_assignment") {
        return Some(node);
    }
    if is_ruby_statement_modifier(node.kind()) {
        return node
            .child_by_field_name("body")
            .filter(|child| matches!(child.kind(), "assignment" | "operator_assignment"));
    }
    None
}

fn is_ruby_statement_modifier(kind: &str) -> bool {
    matches!(
        kind,
        "if_modifier" | "unless_modifier" | "while_modifier" | "until_modifier"
    )
}

fn is_ruby_statement_list(kind: &str) -> bool {
    matches!(
        kind,
        "program"
            | "body_statement"
            | "block_body"
            | "then"
            | "else"
            | "do"
            | "begin"
            | "ensure"
            | "parenthesized_statements"
    )
}

fn ruby_dynamic_scope_reason(node: Node<'_>, source: &str) -> Option<&'static str> {
    let procedure = nearest_ruby_assignment_procedure(node)?;
    if matches!(procedure.kind(), "block" | "do_block") {
        return Some("block_local_or_captured_write");
    }
    let mut stack = vec![procedure];
    while let Some(current) = stack.pop() {
        if current.id() != procedure.id() && ruby_assignment_nested_procedure(current) {
            if matches!(current.kind(), "block" | "do_block") && ruby_block_writes_local(current) {
                return Some("block_local_or_captured_write");
            }
            continue;
        }
        if current.kind() == "call"
            && current
                .child_by_field_name("method")
                .and_then(|method| source.get(method.byte_range()))
                .is_some_and(|name| {
                    matches!(
                        name,
                        "binding" | "eval" | "local_variable_get" | "local_variable_set"
                    )
                })
        {
            return Some("dynamic_local_scope");
        }
        if current.kind() == "identifier"
            && ruby_identifier_value_position(current)
            && source.get(current.byte_range()).is_some_and(|name| {
                matches!(
                    name,
                    "binding" | "eval" | "local_variable_get" | "local_variable_set"
                )
            })
            && !ruby_procedure_declares_name(procedure, source, current)
        {
            return Some("dynamic_local_scope");
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    None
}

fn nearest_ruby_assignment_procedure(node: Node<'_>) -> Option<Node<'_>> {
    find_node_or_ancestor(node, ruby_assignment_procedure)
}

fn ruby_assignment_procedure(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "program"
            | "method"
            | "singleton_method"
            | "lambda"
            | "block"
            | "do_block"
            | "class"
            | "module"
            | "singleton_class"
    )
}

fn ruby_assignment_nested_procedure(node: Node<'_>) -> bool {
    ruby_assignment_procedure(node) && node.kind() != "program"
}

fn ruby_block_writes_local(block: Node<'_>) -> bool {
    let mut stack = vec![block];
    while let Some(current) = stack.pop() {
        if current.id() != block.id() && ruby_assignment_nested_procedure(current) {
            continue;
        }
        if matches!(current.kind(), "assignment" | "operator_assignment")
            && current
                .child_by_field_name("left")
                .is_some_and(ruby_target_contains_identifier)
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn ruby_target_contains_identifier(node: Node<'_>) -> bool {
    subtree_contains(node, |current| current.kind() == "identifier")
}

fn ruby_procedure_declares_name(procedure: Node<'_>, source: &str, name: Node<'_>) -> bool {
    let Some(name) = source.get(name.byte_range()) else {
        return false;
    };
    let mut stack = vec![procedure];
    while let Some(current) = stack.pop() {
        if current.id() != procedure.id() && ruby_assignment_nested_procedure(current) {
            continue;
        }
        let declaration = match current.kind() {
            "assignment" | "operator_assignment" => current.child_by_field_name("left"),
            "for" | "rescue" | "match_pattern" | "test_pattern" | "in_clause" => current
                .child_by_field_name("pattern")
                .or_else(|| current.child_by_field_name("variable")),
            "method_parameters" | "lambda_parameters" | "block_parameters" => Some(current),
            _ => None,
        };
        if declaration
            .is_some_and(|declaration| ruby_target_contains_name(declaration, source, name))
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn ruby_target_contains_name(node: Node<'_>, source: &str, name: &str) -> bool {
    subtree_contains(node, |current| {
        current.kind() == "identifier" && source.get(current.byte_range()) == Some(name)
    })
}

fn ruby_identifier_value_position(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let field_is = |field: &str| {
        parent
            .child_by_field_name(field)
            .is_some_and(|child| child.id() == node.id())
    };
    match parent.kind() {
        "program"
        | "body_statement"
        | "then"
        | "else"
        | "do"
        | "block_body"
        | "begin"
        | "interpolation"
        | "argument_list"
        | "splat_argument"
        | "hash_splat_argument"
        | "block_argument"
        | "binary"
        | "range"
        | "array"
        | "element_reference"
        | "if"
        | "unless"
        | "elsif"
        | "while"
        | "until"
        | "conditional"
        | "case"
        | "case_match"
        | "when"
        | "rescue_modifier" => true,
        "parenthesized_statements" => true,
        "assignment" | "operator_assignment" => field_is("right"),
        "call" => field_is("receiver"),
        "pair" => field_is("key") || field_is("value"),
        "unary" => field_is("operand"),
        _ => false,
    }
}

/// Ruby's exact B1 write shape. A plain identifier assignment is the only
/// scalar write that can be joined to one lexical binding. Ruby's dynamic
/// scope, closure, method-call ambiguity, and re-execution constructs keep the
/// corresponding procedure open until the lowering models those boundaries.
fn ruby_single_target_write<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<SingleTargetWrite<'tree>> {
    match node.kind() {
        "operator_assignment" => {
            return Some(SingleTargetWrite::Open(node, "compound_assignment"));
        }
        "assignment" => {}
        _ => return None,
    }
    if node.has_error() {
        return Some(SingleTargetWrite::Open(node, "syntax_unresolved"));
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return Some(SingleTargetWrite::Open(node, "syntax_unresolved"));
    };
    if let Some(reason) = ruby_dynamic_scope_reason(node, source) {
        return Some(SingleTargetWrite::Open(node, reason));
    }
    if ruby_procedure_reexecutes(node) {
        return Some(SingleTargetWrite::Open(node, "redo_or_retry"));
    }
    match left.kind() {
        "identifier" => {
            let Some(procedure) = nearest_ruby_assignment_procedure(node) else {
                return Some(SingleTargetWrite::Open(
                    node,
                    "assignment_procedure_unresolved",
                ));
            };
            if ruby_nested_callable_observes_name(procedure, left, source) {
                return Some(SingleTargetWrite::Open(node, "captured_local_observation"));
            }
            if ruby_rhs_has_method_or_unresolved_name(right, procedure, source) {
                return Some(SingleTargetWrite::Open(node, "method_local_ambiguity"));
            }
            Some(SingleTargetWrite::Candidate {
                point_node: node,
                target: left,
                source_kind: OverwrittenLocalSourceKind::PlainAssignment,
            })
        }
        "left_assignment_list" | "destructured_left_assignment" | "rest_assignment" => Some(
            SingleTargetWrite::Open(node, "parallel_or_destructuring_assignment"),
        ),
        "instance_variable" | "class_variable" | "global_variable" => {
            Some(SingleTargetWrite::Open(node, "nonlocal_target"))
        }
        "call" => Some(SingleTargetWrite::Open(node, "writer_target")),
        "element_reference" => Some(SingleTargetWrite::Open(node, "element_target")),
        _ => Some(SingleTargetWrite::Open(
            node,
            "assignment_target_unresolved",
        )),
    }
}

fn ruby_procedure_reexecutes(node: Node<'_>) -> bool {
    let Some(procedure) = nearest_ruby_assignment_procedure(node) else {
        return false;
    };
    let mut stack = vec![procedure];
    while let Some(current) = stack.pop() {
        if current.id() != procedure.id() && ruby_assignment_nested_procedure(current) {
            continue;
        }
        if matches!(current.kind(), "redo" | "retry") {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn ruby_nested_callable_observes_name(procedure: Node<'_>, target: Node<'_>, source: &str) -> bool {
    let Some(name) = source.get(target.byte_range()) else {
        return true;
    };
    let mut stack = vec![procedure];
    while let Some(current) = stack.pop() {
        if current.id() != procedure.id() && ruby_assignment_nested_procedure(current) {
            if ruby_closure_procedure(current) && ruby_callable_observes_name(current, name, source)
            {
                return true;
            }
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn ruby_closure_procedure(node: Node<'_>) -> bool {
    matches!(node.kind(), "lambda" | "block" | "do_block")
}

fn ruby_callable_observes_name(callable: Node<'_>, name: &str, source: &str) -> bool {
    let mut stack = vec![callable];
    while let Some(current) = stack.pop() {
        if current.id() != callable.id()
            && ruby_assignment_nested_procedure(current)
            && !ruby_closure_procedure(current)
        {
            continue;
        }
        let target_write = matches!(current.kind(), "assignment" | "operator_assignment")
            && current
                .child_by_field_name("left")
                .is_some_and(|left| ruby_target_contains_name(left, source, name));
        if target_write
            || (current.kind() == "identifier"
                && source.get(current.byte_range()) == Some(name)
                && ruby_identifier_value_position(current))
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn ruby_rhs_has_method_or_unresolved_name(
    rhs: Node<'_>,
    procedure: Node<'_>,
    source: &str,
) -> bool {
    let mut stack = vec![rhs];
    while let Some(current) = stack.pop() {
        if current.id() != rhs.id() && ruby_assignment_nested_procedure(current) {
            continue;
        }
        if current.kind() == "call" && current.child_by_field_name("receiver").is_none() {
            return true;
        }
        if current.kind() == "identifier"
            && ruby_identifier_value_position(current)
            && !ruby_procedure_declares_name(procedure, source, current)
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

/// C#: an initialized local declarator, an assignment, or an integral
/// update expression on a simple name. Field initializers belong to other
/// procedures. Update candidates join only when the lowering publishes the
/// exact binding write; a user-defined or non-integral update stays open.
fn csharp_single_target_write<'tree>(
    node: Node<'tree>,
    _source: &str,
) -> Option<SingleTargetWrite<'tree>> {
    match node.kind() {
        "variable_declarator" => {
            let declaration = node.parent()?;
            if declaration.kind() != "variable_declaration"
                || declaration
                    .parent()
                    .is_none_or(|parent| parent.kind() != "local_declaration_statement")
            {
                return None;
            }
            let name = node.child_by_field_name("name")?;
            let mut cursor = node.walk();
            let initialized = node
                .named_children(&mut cursor)
                .any(|child| child.id() != name.id() && child.kind() != "bracketed_argument_list");
            initialized.then_some(SingleTargetWrite::Candidate {
                point_node: node,
                target: name,
                source_kind: OverwrittenLocalSourceKind::DeclarationInitializer,
            })
        }
        "assignment_expression" => {
            let left = node.child_by_field_name("left")?;
            // Compound operators read the old target, but their computed
            // result is a new write. The exact binding-write join below admits
            // only assignments actually published by semantic lowering.
            Some(match left.kind() {
                "identifier" => SingleTargetWrite::Candidate {
                    point_node: node,
                    target: left,
                    source_kind: OverwrittenLocalSourceKind::PlainAssignment,
                },
                "member_access_expression" | "element_access_expression" => {
                    SingleTargetWrite::Excluded(node, "nonlocal_target")
                }
                _ => SingleTargetWrite::Open(node, "destructuring_target_unmodeled"),
            })
        }
        "prefix_unary_expression" | "postfix_unary_expression"
            if csharp_is_update_expression(node) =>
        {
            let target = node.named_child(0)?;
            Some(match target.kind() {
                "identifier" => SingleTargetWrite::Candidate {
                    point_node: node,
                    target,
                    source_kind: OverwrittenLocalSourceKind::PlainAssignment,
                },
                "member_access_expression" | "element_access_expression" => {
                    SingleTargetWrite::Excluded(node, "nonlocal_target")
                }
                _ => SingleTargetWrite::Open(node, "update_target_unmodeled"),
            })
        }
        _ => None,
    }
}

fn csharp_is_update_expression(node: Node<'_>) -> bool {
    if !matches!(
        node.kind(),
        "prefix_unary_expression" | "postfix_unary_expression"
    ) {
        return false;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| !child.is_named() && matches!(child.kind(), "++" | "--"))
}

/// Rust: an initialized `let` of one name (`let x` or `let mut x`) or an `=`
/// assignment to a simple name. A compound assignment is its own node kind.
fn rust_single_target_write<'tree>(
    node: Node<'tree>,
    _source: &str,
) -> Option<SingleTargetWrite<'tree>> {
    match node.kind() {
        "let_declaration" => {
            node.child_by_field_name("value")?;
            let mut pattern = node.child_by_field_name("pattern")?;
            if pattern.kind() == "mut_pattern" {
                pattern = pattern.named_child(0)?;
            }
            (pattern.kind() == "identifier").then_some(SingleTargetWrite::Candidate {
                point_node: node,
                target: pattern,
                source_kind: OverwrittenLocalSourceKind::DeclarationInitializer,
            })
        }
        "compound_assignment_expr" => {
            Some(SingleTargetWrite::Excluded(node, "compound_assignment"))
        }
        "assignment_expression" => {
            let left = node.child_by_field_name("left")?;
            Some(match left.kind() {
                "identifier" => SingleTargetWrite::Candidate {
                    point_node: node,
                    target: left,
                    source_kind: OverwrittenLocalSourceKind::PlainAssignment,
                },
                "field_expression" | "index_expression" => {
                    SingleTargetWrite::Excluded(node, "nonlocal_target")
                }
                "unary_expression" if rust_dereference_operand(left).is_some() => {
                    SingleTargetWrite::Excluded(node, "nonlocal_target")
                }
                _ => SingleTargetWrite::Open(node, "destructuring_target_unmodeled"),
            })
        }
        _ => None,
    }
}

/// Kotlin: an initialized local `var`/`val` or an `=` assignment to a simple
/// name. A compound operator is an anonymous `+=`-style token.
fn kotlin_single_target_write<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<SingleTargetWrite<'tree>> {
    match node.kind() {
        "property_declaration" => {
            if node
                .parent()
                .is_none_or(|parent| parent.kind() != "statements")
            {
                return None;
            }
            let mut cursor = node.walk();
            let children = node.named_children(&mut cursor).collect::<Vec<_>>();
            let variable = children
                .iter()
                .find(|child| child.kind() == "variable_declaration")?;
            let mut cursor = variable.walk();
            let name = variable
                .named_children(&mut cursor)
                .find(|child| child.kind() == "simple_identifier")?;
            if children
                .iter()
                .any(|child| child.kind() == "property_delegate")
            {
                return Some(SingleTargetWrite::Open(node, "delegated_local"));
            }
            let initialized = children.iter().any(|child| {
                !matches!(
                    child.kind(),
                    "variable_declaration"
                        | "binding_pattern_kind"
                        | "modifiers"
                        | "type_constraints"
                        | "type_parameters"
                        | "property_delegate"
                        | "getter"
                        | "setter"
                )
            });
            initialized.then_some(SingleTargetWrite::Candidate {
                point_node: node,
                target: name,
                source_kind: OverwrittenLocalSourceKind::DeclarationInitializer,
            })
        }
        "assignment" => {
            let mut cursor = node.walk();
            let compound = node.children(&mut cursor).any(|child| {
                !child.is_named() && matches!(child.kind(), "+=" | "-=" | "*=" | "/=" | "%=")
            });
            if compound {
                // A compound assignment reads the old value before it writes
                // the replacement. Its operator convention is deliberately
                // opaque to B1, even when the semantic lowering can model a
                // primitive offset for other policies.
                return Some(SingleTargetWrite::Open(node, "compound_assignment"));
            }
            let target = node.named_child(0)?;
            let name = if target.kind() == "directly_assignable_expression"
                && target.named_child_count() == 1
            {
                target.named_child(0)?
            } else {
                target
            };
            Some(if name.kind() != "simple_identifier" {
                SingleTargetWrite::Open(node, "nonlocal_target")
            } else if let Some(reason) = kotlin_unmodeled_target_reason(node, name, source) {
                SingleTargetWrite::Open(node, reason)
            } else {
                SingleTargetWrite::Candidate {
                    point_node: node,
                    target: name,
                    source_kind: OverwrittenLocalSourceKind::PlainAssignment,
                }
            })
        }
        _ => None,
    }
}

/// Return the Kotlin-specific reason a simple spelling is not a stable local
/// binding for B1. The assignment relation deliberately stays conservative at
/// this syntax boundary: delegated properties dispatch through `setValue`, and
/// a lambda or nested function can write an outer mutable binding through a
/// capture slot whose call-time value is not a plain local establishment.
fn kotlin_unmodeled_target_reason(
    assignment: Node<'_>,
    target: Node<'_>,
    source: &str,
) -> Option<&'static str> {
    let name = target.utf8_text(source.as_bytes()).ok()?;
    if kotlin_target_is_delegated(assignment, name, source) {
        return Some("delegated_local");
    }
    kotlin_target_is_captured(assignment, name, source).then_some("captured_local")
}

fn kotlin_target_is_delegated(assignment: Node<'_>, name: &str, source: &str) -> bool {
    let mut current = assignment.parent();
    while let Some(node) = current {
        if node.kind() == "statements"
            && let Some(property) = kotlin_visible_property(node, name, assignment, source)
        {
            return property;
        }
        current = node.parent();
    }
    false
}

/// Find the nearest declaration with `name` in an enclosing Kotlin statement
/// scope. `Some(true)` means that declaration is delegated and `Some(false)`
/// means it shadows any outer declaration for this assignment.
fn kotlin_visible_property(
    statements: Node<'_>,
    name: &str,
    assignment: Node<'_>,
    source: &str,
) -> Option<bool> {
    let mut cursor = statements.walk();
    statements
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "property_declaration")
        .filter(|child| child.start_byte() < assignment.start_byte())
        .filter_map(|property| {
            let mut property_cursor = property.walk();
            let variable = property
                .named_children(&mut property_cursor)
                .find(|child| child.kind() == "variable_declaration")?;
            let mut variable_cursor = variable.walk();
            let binding = variable
                .named_children(&mut variable_cursor)
                .find(|child| child.kind() == "simple_identifier")?;
            let mut property_cursor = property.walk();
            let delegated = property
                .named_children(&mut property_cursor)
                .any(|child| child.kind() == "property_delegate");
            (binding.utf8_text(source.as_bytes()).ok()? == name).then_some(delegated)
        })
        .next()
}

fn kotlin_target_is_captured(assignment: Node<'_>, name: &str, source: &str) -> bool {
    let mut current = assignment.parent();
    let mut boundary = None;
    while let Some(node) = current {
        if matches!(
            node.kind(),
            "lambda_literal" | "anonymous_function" | "function_declaration"
        ) {
            boundary = Some(node);
            break;
        }
        current = node.parent();
    }
    let Some(boundary) = boundary else {
        return false;
    };

    let mut scope = assignment.parent();
    while let Some(node) = scope {
        if node.kind() == "statements"
            && kotlin_visible_property(node, name, assignment, source).is_some()
        {
            return false;
        }
        if node.id() == boundary.id() {
            break;
        }
        scope = node.parent();
    }

    if boundary.kind() == "function_declaration" {
        let mut stack = vec![boundary];
        while let Some(node) = stack.pop() {
            if node.kind() == "function_value_parameters" {
                let mut cursor = node.walk();
                if node.named_children(&mut cursor).any(|parameter| {
                    let mut parameter_cursor = parameter.walk();
                    parameter
                        .named_children(&mut parameter_cursor)
                        .find(|child| child.kind() == "simple_identifier")
                        .and_then(|child| child.utf8_text(source.as_bytes()).ok())
                        == Some(name)
                }) {
                    return false;
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.id() != boundary.id()
                    && matches!(
                        child.kind(),
                        "lambda_literal" | "anonymous_function" | "function_declaration"
                    )
                {
                    continue;
                }
                stack.push(child);
            }
        }
    }
    true
}

fn is_nested_body(node: Node<'_>, language: Language) -> bool {
    match language {
        Language::Java => matches!(
            node.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "lambda_expression"
                | "class_declaration"
                | "anonymous_class_body"
        ),
        Language::JavaScript | Language::TypeScript => {
            is_js_function(node.kind()) || node.kind() == "class_declaration"
        }
        Language::Python => matches!(
            node.kind(),
            "function_definition" | "lambda" | "class_definition"
        ),
        Language::Go => node.kind() == "func_literal",
        _ => false,
    }
}

fn is_js_function(kind: &str) -> bool {
    kind == "function" || brokk_bifrost_js_ts::syntax::is_function_like(kind)
}

fn is_assignment(node: Node<'_>, language: Language) -> bool {
    if language == Language::Python {
        node.kind() == "assignment"
    } else {
        node.kind() == "assignment_expression"
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_assignment(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    points_by_span: &HashMap<(usize, usize), Vec<&crate::analyzer::semantic::ProgramPoint>>,
    python_directives: &HashSet<&str>,
    source: &str,
    root: Node<'_>,
    procedure_node: Node<'_>,
    assignment: Node<'_>,
    language: Language,
) -> PlainAssignmentCandidate {
    let range = node_range(assignment);
    let mut row = PlainAssignmentCandidate {
        points: Vec::new(),
        target: None,
        rhs_value: None,
        range,
        rhs_range: None,
        rhs_identifier_range: None,
        next_assignment_start: next_assignment_start(assignment, language),
        swap_type: None,
        verdict: PlainAssignmentVerdict::Unknown,
        storage_kind: "unknown",
        reason: "syntax_unresolved",
    };
    if assignment.has_error() {
        return row;
    }
    if matches!(language, Language::JavaScript | Language::TypeScript) {
        let mut ancestor = assignment.parent();
        while let Some(node) = ancestor {
            if node.id() == procedure_node.id() {
                break;
            }
            if node.kind() == "with_statement" {
                row.reason = "dynamic_with_scope";
                return row;
            }
            ancestor = node.parent();
        }
    }
    let Some(left) = assignment.child_by_field_name("left") else {
        return row;
    };
    let Some(right) = assignment.child_by_field_name("right") else {
        return row;
    };
    row.rhs_range = Some(node_range(right));
    if language != Language::Python && !assignment_has_plain_operator(assignment) {
        row.verdict = PlainAssignmentVerdict::Excluded;
        row.storage_kind = "compound";
        row.reason = "compound_assignment";
        return row;
    }
    if left.kind() != "identifier" {
        row.verdict = PlainAssignmentVerdict::Excluded;
        row.storage_kind = "indirect";
        row.reason = "nonlocal_target";
        return row;
    }
    if language == Language::Python
        && source
            .get(left.byte_range())
            .is_some_and(|name| python_directives.contains(name))
    {
        row.verdict = PlainAssignmentVerdict::Excluded;
        row.storage_kind = "nonlocal";
        row.reason = "python_scope_directive";
        return row;
    }
    let Some(rhs_identifier) = bare_identifier_rhs(right) else {
        row.verdict = PlainAssignmentVerdict::Excluded;
        row.storage_kind = "ordinary_local";
        row.reason = "rhs_not_bare_identifier";
        return row;
    };
    row.rhs_identifier_range = Some(node_range(rhs_identifier));
    // Python's boundary point maps to the whole assignment, while its actual
    // local write is emitted at a second point mapped to the target identifier.
    let write_node = if language == Language::Python {
        left
    } else {
        assignment
    };
    match qualify_local_write(
        semantics,
        points_by_span,
        python_directives,
        source,
        root,
        procedure_node,
        left,
        write_node,
        language,
    ) {
        Ok(write) => {
            row.points = write.points;
            row.target = Some(write.target);
            row.rhs_value = Some(write.rhs_value);
            row.swap_type = write.swap_type;
            row.verdict = PlainAssignmentVerdict::Supported;
            row.storage_kind = "ordinary_local";
            row.reason = "qualified";
        }
        Err(rejection) => {
            row.verdict = rejection.verdict;
            if let Some(storage_kind) = rejection.storage_kind {
                row.storage_kind = storage_kind;
            }
            row.reason = rejection.reason;
        }
    }
    row
}

/// One source write proved to establish an ordinary local of this procedure.
struct QualifiedLocalWrite {
    points: Vec<ProgramPointId>,
    target: ValueId,
    rhs_value: ValueId,
    swap_type: Option<Box<str>>,
}

struct LocalWriteRejection {
    verdict: PlainAssignmentVerdict,
    storage_kind: Option<&'static str>,
    reason: &'static str,
}

/// Join a simple-name assignment target to the lowering's local write and
/// prove that the written binding is an ordinary local (or parameter) of this
/// procedure. `write_node` is the source node the lowering maps the write to.
#[allow(clippy::too_many_arguments)]
fn qualify_local_write(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    points_by_span: &HashMap<(usize, usize), Vec<&crate::analyzer::semantic::ProgramPoint>>,
    python_directives: &HashSet<&str>,
    source: &str,
    root: Node<'_>,
    procedure_node: Node<'_>,
    left: Node<'_>,
    write_node: Node<'_>,
    language: Language,
) -> Result<QualifiedLocalWrite, LocalWriteRejection> {
    let open = |reason| LocalWriteRejection {
        verdict: PlainAssignmentVerdict::Unknown,
        storage_kind: None,
        reason,
    };
    let excluded = |storage_kind, reason| LocalWriteRejection {
        verdict: PlainAssignmentVerdict::Excluded,
        storage_kind: Some(storage_kind),
        reason,
    };
    // Pattern variables are not in the Java lowering's lexical environment,
    // so it can bind a same-named target to a field or leave it unbound.
    if language == Language::Java && java_pattern_variable_named(source, procedure_node, left) {
        return Err(open("pattern_variable_unresolved"));
    }
    let Some(points) = points_by_span.get(&(write_node.start_byte(), write_node.end_byte())) else {
        return Err(open("assignment_point_unmapped"));
    };
    let mut locals = Vec::new();
    let mut member_store = false;
    for point in points {
        for event in point.events.iter() {
            match event.effect {
                SemanticEffect::Assignment { target, value }
                    if semantics.value(target).is_some_and(|row| {
                        matches!(
                            row.kind,
                            SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
                        )
                    }) =>
                {
                    locals.push((point, target, value))
                }
                SemanticEffect::MemoryStore { .. } => member_store = true,
                _ => {}
            }
        }
    }
    // Copies of one lowered assignment write the same target from distinct
    // points. Two writes at one point, or writes of different targets, are
    // not one source assignment.
    let Some(&(_, target, rhs_value)) = locals.first() else {
        if language == Language::Java
            && (member_store || java_names_enclosing_field(source, procedure_node, left))
        {
            return Err(excluded("member", "resolved_field_target"));
        }
        return Err(open("local_assignment_join_ambiguous"));
    };
    let mut points = locals
        .iter()
        .map(|(point, _, _)| point.id)
        .collect::<Vec<_>>();
    points.sort_unstable();
    points.dedup();
    if points.len() != locals.len()
        || locals
            .iter()
            .any(|(_, other_target, _)| *other_target != target)
    {
        return Err(open("local_assignment_join_ambiguous"));
    }
    let Some(target_row) = semantics.value(target) else {
        return Err(open("target_value_missing"));
    };
    let is_parameter = matches!(target_row.kind, SemanticValueKind::Parameter { .. });
    let Some(target_mapping) = semantics.source_mapping(target_row.source) else {
        return Err(open("target_mapping_missing"));
    };
    if target_mapping.kind != SourceMappingKind::Exact {
        return Err(open("target_mapping_inexact"));
    }
    let target_span = target_mapping.locator.anchor().span();
    let Some(declaration) = root.named_descendant_for_byte_range(
        target_span.start_byte() as usize,
        target_span.end_byte() as usize,
    ) else {
        return Err(open("declaration_name_missing"));
    };
    if !exact_span(target_span, declaration) || declaration.has_error() {
        return Err(open("declaration_name_inexact"));
    }
    let name = if is_parameter && declaration.kind() != "identifier" {
        let Some(name) = declaration.child_by_field_name("name") else {
            return Err(open("parameter_name_missing"));
        };
        name
    } else {
        declaration
    };
    if name.kind() != "identifier" || name.has_error() {
        return Err(open("declaration_name_inexact"));
    }
    if name.start_byte() < procedure_node.start_byte()
        || name.end_byte() > procedure_node.end_byte()
    {
        return Err(excluded("nonlocal", "declaration_outside_procedure"));
    }
    if language == Language::Python
        && source
            .get(name.byte_range())
            .is_some_and(|name| python_directives.contains(name))
    {
        return Err(excluded("nonlocal", "python_scope_directive"));
    }
    let Some(swap_type) =
        ordinary_local_declaration(name, source, language, is_parameter, python_directives)
    else {
        return Err(open("ordinary_local_unproved"));
    };
    Ok(QualifiedLocalWrite {
        points,
        target,
        rhs_value,
        swap_type,
    })
}

fn ordinary_local_declaration(
    name: Node<'_>,
    source: &str,
    language: Language,
    is_parameter: bool,
    python_directives: &HashSet<&str>,
) -> Option<Option<Box<str>>> {
    match language {
        Language::Java => {
            let declaration = name.parent()?;
            if is_parameter {
                if !matches!(declaration.kind(), "formal_parameter" | "spread_parameter")
                    || declaration
                        .child_by_field_name("name")
                        .is_none_or(|node| node.id() != name.id())
                {
                    return None;
                }
                return Some(java_swap_type(declaration, declaration, source));
            }
            match declaration.kind() {
                "variable_declarator" => {
                    if declaration
                        .child_by_field_name("name")
                        .is_none_or(|node| node.id() != name.id())
                    {
                        return None;
                    }
                    let statement = declaration.parent()?;
                    if statement.kind() != "local_variable_declaration"
                        || java_declaration_is_final(statement)
                    {
                        return None;
                    }
                    Some(java_swap_type(statement, declaration, source))
                }
                // A single-type catch parameter is an ordinary local unless
                // declared final. A multi-catch parameter is implicitly final.
                "catch_formal_parameter" => {
                    if declaration
                        .child_by_field_name("name")
                        .is_none_or(|node| node.id() != name.id())
                        || java_declaration_is_final(declaration)
                    {
                        return None;
                    }
                    let mut cursor = declaration.walk();
                    let catch_type = declaration
                        .named_children(&mut cursor)
                        .find(|child| child.kind() == "catch_type")?;
                    let mut cursor = catch_type.walk();
                    let mut types = catch_type.named_children(&mut cursor);
                    let single = types.next()?;
                    if types.next().is_some() {
                        return None;
                    }
                    Some(java_swap_type_node(single, declaration, source))
                }
                // An enhanced-for variable is an ordinary local that each
                // iteration establishes, unless declared final.
                "enhanced_for_statement" => {
                    if declaration
                        .child_by_field_name("name")
                        .is_none_or(|node| node.id() != name.id())
                        || java_declaration_is_final(declaration)
                    {
                        return None;
                    }
                    Some(java_swap_type(declaration, declaration, source))
                }
                _ => None,
            }
        }
        Language::JavaScript | Language::TypeScript => {
            if is_parameter {
                return Some(None);
            }
            let declarator = name.parent()?;
            if declarator.kind() != "variable_declarator"
                || declarator
                    .child_by_field_name("name")
                    .is_none_or(|node| node.id() != name.id())
            {
                return None;
            }
            let declaration = declarator.parent()?;
            if !matches!(
                declaration.kind(),
                "variable_declaration" | "lexical_declaration"
            ) {
                return None;
            }
            let mut cursor = declaration.walk();
            if declaration
                .children(&mut cursor)
                .any(|child| child.kind() == "const")
            {
                return None;
            }
            Some(None)
        }
        Language::Python => {
            if is_parameter {
                return Some(None);
            }
            let name_text = source.get(name.byte_range())?;
            debug_assert!(!python_directives.contains(name_text));
            Some(None)
        }
        Language::Ruby => Some(None),
        _ => None,
    }
}

/// The declared type spelling of a Java local or parameter, when an
/// assignment between two bindings with this same spelling needs no value
/// conversion. Primitive and reference types qualify. `var` does not, because
/// its spelling hides the inferred type (one `var` can be `int` and another
/// `Integer`, which converts by boxing). A binding with declarator dimensions
/// has a different type from its spelled type.
fn java_swap_type(typed: Node<'_>, declarator: Node<'_>, source: &str) -> Option<Box<str>> {
    java_swap_type_node(typed.child_by_field_name("type")?, declarator, source)
}

fn java_swap_type_node(
    type_node: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<Box<str>> {
    if declarator.child_by_field_name("dimensions").is_some() {
        return None;
    }
    let text = source.get(type_node.byte_range())?;
    match type_node.kind() {
        "integral_type"
        | "floating_point_type"
        | "boolean_type"
        | "scoped_type_identifier"
        | "generic_type"
        | "array_type" => Some(text.into()),
        "type_identifier" if text != "var" => Some(text.into()),
        _ => None,
    }
}

/// Whether a pattern variable in `procedure`, outside nested lambdas and
/// classes, has the name of `name`. Recovered syntax counts as a match.
fn java_pattern_variable_named(source: &str, procedure: Node<'_>, name: Node<'_>) -> bool {
    let Some(body) = procedure.child_by_field_name("body") else {
        return true;
    };
    crate::analyzer::structural::branch_relations::java_pattern_binders([body], source)
        .map_or(true, |binders| {
            binders.contains(&source.get(name.byte_range()).unwrap_or_default())
        })
}

/// Whether a Java simple name that the lowering bound to no local or
/// parameter names a field of an enclosing type. The lowering publishes no
/// store for a bare `static` field, and Java has no other assignable simple
/// name once pattern variables are ruled out.
fn java_names_enclosing_field(source: &str, procedure: Node<'_>, name: Node<'_>) -> bool {
    let Some(text) = source.get(name.byte_range()) else {
        return false;
    };
    let mut ancestor = procedure.parent();
    while let Some(node) = ancestor {
        if matches!(node.kind(), "class_body" | "enum_body_declarations") {
            let mut members = node.walk();
            let declares = node
                .named_children(&mut members)
                .filter(|member| member.kind() == "field_declaration")
                .any(|field| {
                    let mut declarators = field.walk();
                    field
                        .children_by_field_name("declarator", &mut declarators)
                        .filter_map(|declarator| declarator.child_by_field_name("name"))
                        .any(|field_name| source.get(field_name.byte_range()) == Some(text))
                });
            if declares {
                return true;
            }
        }
        ancestor = node.parent();
    }
    false
}

fn java_declaration_is_final(declaration: Node<'_>) -> bool {
    let mut cursor = declaration.walk();
    declaration.children(&mut cursor).any(|child| {
        child.kind() == "final"
            || (child.kind() == "modifiers"
                && (0..child.child_count())
                    .filter_map(|index| child.child(index))
                    .any(|modifier| modifier.kind() == "final"))
    })
}

fn next_assignment_start(assignment: Node<'_>, language: Language) -> Option<usize> {
    let parent = assignment.parent()?;
    let statement = if parent.kind() == "expression_statement" {
        parent
    } else if language == Language::Python {
        assignment
    } else {
        return None;
    };
    let parent = statement.parent()?;
    if !matches!(parent.kind(), "block" | "statement_block" | "program") {
        return None;
    }
    let mut next = statement.next_named_sibling()?;
    while next.kind() == "comment" {
        next = next.next_named_sibling()?;
    }
    let next_assignment = if language == Language::Python && next.kind() == "assignment" {
        next
    } else {
        if next.kind() != "expression_statement" {
            return None;
        }
        let mut cursor = next.walk();
        let mut children = next.named_children(&mut cursor);
        let child = children.next()?;
        if children.next().is_some() {
            return None;
        }
        child
    };
    is_assignment(next_assignment, language).then_some(next_assignment.start_byte())
}

#[doc(hidden)]
pub fn is_plain_assignment_operator_kind(kind: &str) -> bool {
    kind == "="
}

fn assignment_has_plain_operator(node: Node<'_>) -> bool {
    (0..node.child_count())
        .filter_map(|index| node.child(index))
        .any(|child| is_plain_assignment_operator_kind(child.kind()))
}

fn is_named_argument_assignment(node: Node<'_>) -> bool {
    node.kind() == "assignment_expression"
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "arguments")
        && node
            .parent()
            .and_then(|arguments| arguments.parent())
            .is_some_and(|invocation| {
                matches!(invocation.kind(), "call_expression" | "instance_expression")
            })
}

/// The identifier inside wrappers that have no run-time effect: parentheses
/// and the TypeScript type-only forms `x as T`, `x satisfies T`, `x!` and
/// `<T>x`, which compile to `x` itself.
fn bare_identifier_rhs(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.has_error() {
            return None;
        }
        node = match node.kind() {
            "identifier" => return Some(node),
            "parenthesized_expression" | "parenthesized_list_splat" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor);
                let child = children.next()?;
                if children.next().is_some() {
                    return None;
                }
                child
            }
            "as_expression" | "satisfies_expression" | "non_null_expression" | "type_assertion" => {
                ts_type_wrapper_operand(node)?
            }
            _ => return None,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[track_caller]
    fn parse(source: &str, language: tree_sitter::Language) -> tree_sitter::Tree {
        crate::test_support::parse_valid_fixture_tree(source, language, "")
    }

    fn nodes<'tree>(tree: &'tree tree_sitter::Tree, kind: &str) -> Vec<Node<'tree>> {
        use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
        let mut found = Vec::new();
        walk_named_tree_preorder(tree.root_node(), true, |node| {
            if node.kind() == kind {
                found.push(node);
            }
            WalkControl::Continue
        });
        found
    }

    #[test]
    fn procedure_walk_discards_a_cancelled_prefix() {
        let tree = parse(
            "def f(a); a = a; a = 2; end",
            tree_sitter_ruby::LANGUAGE.into(),
        );
        let procedure = nodes(&tree, "method")[0];
        let cancellation = CancellationToken::default();
        let mut all = Vec::new();
        assert!(for_each_procedure_node(
            procedure,
            None,
            |_| false,
            |n| all.push(n.id())
        ));
        assert!(all.len() > 1);
        let mut prefix = Vec::new();
        assert!(!for_each_procedure_node(
            procedure,
            Some(&cancellation),
            |_| false,
            |n| {
                prefix.push(n.id());
                cancellation.cancel();
            }
        ));
        assert_eq!(prefix, all[..1]);
    }

    #[test]
    fn ruby_assignment_grammar_preserves_modifiers_comments_and_scopes() {
        for modifier in ["if", "unless", "while", "until"] {
            let source = format!("def f(a,b,flag); a=b; # inert\n b=a {modifier} flag; end");
            let tree = parse(&source, tree_sitter_ruby::LANGUAGE.into());
            let writes = nodes(&tree, "assignment");
            let wrapper = writes[1].parent().unwrap();
            assert_eq!(wrapper.child_by_field_name("body"), Some(writes[1]));
            assert_eq!(ruby_statement_assignment(wrapper), Some(writes[1]));
            assert_eq!(
                ruby_next_assignment_start(writes[0]),
                Some(writes[1].start_byte())
            );
        }
        for source in ["def f; each { x=x }; end", "def f; each do x=x end; end"] {
            let tree = parse(source, tree_sitter_ruby::LANGUAGE.into());
            let write = nodes(&tree, "assignment")[0];
            let procedure = nearest_ruby_assignment_procedure(write).unwrap();
            assert!(ruby_closure_procedure(procedure), "{}", procedure.kind());
            assert_eq!(
                ruby_dynamic_scope_reason(write, source),
                Some("block_local_or_captured_write")
            );
        }
    }

    #[test]
    fn ruby_rescue_and_receiver_fields_preserve_binding_roles() {
        for source in [
            "def f; begin; fail; rescue => eval; eval; end; end",
            "def f; for eval in values; eval; end; end",
            "def f(eval); eval; end",
        ] {
            let tree = parse(source, tree_sitter_ruby::LANGUAGE.into());
            let procedure = nodes(&tree, "method")[0];
            let uses = nodes(&tree, "identifier")
                .into_iter()
                .filter(|n| &source[n.byte_range()] == "eval")
                .collect::<Vec<_>>();
            assert!(uses.len() >= 2);
            assert!(
                ruby_procedure_declares_name(procedure, source, *uses.last().unwrap()),
                "{source}"
            );
        }
        let source = "def f; x=1; binding.to_s; x=x; end";
        let tree = parse(source, tree_sitter_ruby::LANGUAGE.into());
        let call = nodes(&tree, "call")[0];
        let receiver = call.child_by_field_name("receiver").unwrap();
        assert_eq!(&source[receiver.byte_range()], "binding");
        assert!(ruby_identifier_value_position(receiver));
        assert_eq!(
            ruby_dynamic_scope_reason(nodes(&tree, "assignment")[0], source),
            Some("dynamic_local_scope")
        );
        let source = "def f; x=1; eval('x = 2'); x=x; end";
        let tree = parse(source, tree_sitter_ruby::LANGUAGE.into());
        let method = nodes(&tree, "call")[0]
            .child_by_field_name("method")
            .unwrap();
        assert_eq!(&source[method.byte_range()], "eval");
        assert_eq!(
            ruby_dynamic_scope_reason(nodes(&tree, "assignment")[0], source),
            Some("dynamic_local_scope")
        );
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: evaluated hash keys lost capture reads"
    )]
    fn ruby_closure_observations_include_evaluated_hash_keys() {
        for expression in ["{x => 0}", "{0 => x}", "x.to_s"] {
            let source = format!("def f; x=1; reader=-> {{ {expression} }}; x=2; reader.call; end");
            let tree = parse(&source, tree_sitter_ruby::LANGUAGE.into());
            let procedure = nodes(&tree, "method")[0];
            let target = nodes(&tree, "assignment")[0]
                .child_by_field_name("left")
                .unwrap();
            assert!(
                ruby_nested_callable_observes_name(procedure, target, &source),
                "{source}"
            );
        }
        for expression in [
            "def other; x; end",
            "class Other; x; end",
            "reader=-> { 0 }",
        ] {
            let source = format!("def f; x=1; {expression}; x=2; end");
            let tree = parse(&source, tree_sitter_ruby::LANGUAGE.into());
            let procedure = nodes(&tree, "method")[0];
            let target = nodes(&tree, "assignment")[0]
                .child_by_field_name("left")
                .unwrap();
            assert!(
                !ruby_nested_callable_observes_name(procedure, target, &source),
                "{source}"
            );
        }
    }

    #[test]
    fn declaration_grammar_distinguishes_const_and_annotated_final_locals() {
        for (source, accepted) in [
            ("let a=1;", true),
            ("var a=1;", true),
            ("const a=1;", false),
        ] {
            let tree = parse(source, tree_sitter_javascript::LANGUAGE.into());
            let name = nodes(&tree, "variable_declarator")[0]
                .child_by_field_name("name")
                .unwrap();
            assert_eq!(
                ordinary_local_declaration(
                    name,
                    source,
                    Language::JavaScript,
                    false,
                    &HashSet::new()
                )
                .is_some(),
                accepted,
                "{source}"
            );
        }
        for (modifier, is_final) in [
            ("@Deprecated final", true),
            ("@Deprecated", false),
            ("final", true),
            ("", false),
        ] {
            let source = format!("class C {{ void f() {{ {modifier} int a=1; }} }}");
            let tree = parse(&source, tree_sitter_java::LANGUAGE.into());
            let declaration = nodes(&tree, "local_variable_declaration")[0];
            assert_eq!(java_declaration_is_final(declaration), is_final, "{source}");
        }
        let tree = parse(
            "class C { void f() { class Local { int a=1; } } }",
            tree_sitter_java::LANGUAGE.into(),
        );
        let class = nodes(&tree, "class_declaration")[1];
        assert!(is_nested_body(class, Language::Java));
        let mut visited = Vec::new();
        assert!(for_each_procedure_node(
            nodes(&tree, "method_declaration")[0],
            None,
            |n| is_nested_body(n, Language::Java),
            |n| visited.push(n.kind())
        ));
        assert!(!visited.contains(&"variable_declarator"));
    }

    #[test]
    fn assignment_adjacency_skips_only_inert_comment_nodes() {
        let source = "def f(a,b); a=b; # inert\n b=a; c=0; a=b; end";
        let tree = parse(source, tree_sitter_ruby::LANGUAGE.into());
        let writes = nodes(&tree, "assignment");
        assert_eq!(next_statement(writes[0]), Some(writes[1]));
        assert_eq!(next_statement(writes[1]), Some(writes[2]));
        let source = "function f(a,b) { a=b; /* inert */ b=a; ping(); a=b; }";
        let tree = parse(source, tree_sitter_javascript::LANGUAGE.into());
        let writes = nodes(&tree, "assignment_expression");
        assert_eq!(
            next_assignment_start(writes[0], Language::JavaScript),
            Some(writes[1].start_byte())
        );
        assert_eq!(next_assignment_start(writes[1], Language::JavaScript), None);
    }

    #[test]
    fn php_dynamic_call_names_are_terminal_grammar_children() {
        for spelling in [
            "extract",
            "\\extract",
            "Tools\\extract",
            "namespace\\extract",
            "Tools\\ExTrAcT",
        ] {
            let source = format!("<?php function f() {{ {spelling}([]); }}");
            let tree = parse(
                &source,
                crate::analyzer::parser_language_for(Language::Php).unwrap(),
            );
            let call = nodes(&tree, "function_call_expression")[0];
            let function = call.child_by_field_name("function").unwrap();
            if function.kind() != "name" {
                let terminal =
                    brokk_bifrost_core::analyzer::tree_walk::single_named_child_matching(
                        function,
                        |n| n.kind() == "name",
                    )
                    .unwrap();
                assert!(source[terminal.byte_range()].eq_ignore_ascii_case("extract"));
            }
            assert!(
                php_dynamic_function_call(call, &source, "extract"),
                "{source}"
            );
            assert!(!php_dynamic_function_call(call, &source, "compact"));
        }
        let source = "<?php function f($extract) { $extract([]); }";
        let tree = parse(
            source,
            crate::analyzer::parser_language_for(Language::Php).unwrap(),
        );
        assert!(!php_dynamic_function_call(
            nodes(&tree, "function_call_expression")[0],
            source,
            "extract"
        ));
    }
    #[test]
    fn ruby_reexecution_belongs_to_its_lexical_procedure() {
        for source in [
            "def f; x=1; begin; x=2; rescue; retry; end; end",
            "def f(flag); x=1; while flag; x=2; redo; end; end",
        ] {
            let tree = parse(source, tree_sitter_ruby::LANGUAGE.into());
            assert!(
                ruby_procedure_reexecutes(nodes(&tree, "assignment")[0]),
                "{source}"
            );
        }
        let source = "def f; x=1; def g; begin; fail; rescue; retry; end; end; x=2; end";
        let tree = parse(source, tree_sitter_ruby::LANGUAGE.into());
        assert!(!ruby_procedure_reexecutes(nodes(&tree, "assignment")[0]));
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: nested closures lost transitive capture reads"
    )]
    fn ruby_closure_observations_include_transitive_captures() {
        let source = "def f; x=1; reader=-> { -> { x } }; x=2; reader.call.call; end";
        let tree = parse(source, tree_sitter_ruby::LANGUAGE.into());
        let procedure = nodes(&tree, "method")[0];
        let target = nodes(&tree, "assignment")[0]
            .child_by_field_name("left")
            .unwrap();
        assert!(ruby_nested_callable_observes_name(
            procedure, target, source
        ));
    }
}
