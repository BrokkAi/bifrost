//! Prepared-syntax qualification for ordinary local assignments in the first
//! Java, JavaScript, TypeScript, and Python lint pilots.

use crate::CancellationToken;
use crate::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;
use crate::analyzer::semantic::{
    ProcedureHandle, ProgramPointId, SemanticEffect, SemanticValueKind, SourceMappingKind, ValueId,
};
use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::{Language, ProjectFile, Range, WorkspaceAnalyzer};
use brokk_bifrost_js_ts::syntax::ts_type_wrapper_operand;
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
    /// The exact Java declaration type spelling, when assigning between two
    /// locals with that same spelling needs no value conversion.
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

const MAX_SOURCE_BYTES: usize = 1_048_576;

pub fn plain_assignment_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> PlainAssignmentCandidates {
    let language = procedure.artifact().key().language().language();
    if !matches!(
        language,
        Language::Java | Language::JavaScript | Language::TypeScript | Language::Python
    ) {
        return PlainAssignmentCandidates {
            rows: Vec::new(),
            complete: true,
            reason: None,
        };
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return unavailable("cancelled");
    }
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        procedure.artifact().key().path().as_path(),
    );
    let syntax = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .map(|provider| provider.structural_syntax_limited(&file, MAX_SOURCE_BYTES, cancellation));
    let syntax = match syntax {
        Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax,
        Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
            return unavailable("source_budget_exhausted");
        }
        Some(StructuralSyntaxLimitedOutcome::Cancelled) => return unavailable("cancelled"),
        Some(StructuralSyntaxLimitedOutcome::Unavailable) | None => {
            return unavailable("prepared_syntax_unavailable");
        }
    };
    let Ok(syntax) = validate_prepared_syntax_source_for_procedure(
        workspace,
        procedure,
        &file,
        syntax.into_inner(),
    ) else {
        return unavailable("source_identity_mismatch");
    };
    let semantics = procedure.semantics();
    let Some(mapping) = semantics.source_mapping(semantics.source()) else {
        return unavailable("procedure_mapping_missing");
    };
    if mapping.kind != SourceMappingKind::Exact {
        return unavailable("procedure_mapping_inexact");
    }
    let span = mapping.locator.anchor().span();
    let Some(procedure_node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
    else {
        return unavailable("procedure_syntax_missing");
    };
    if !exact_span(span, procedure_node) || procedure_node.has_error() {
        return unavailable("procedure_syntax_inexact");
    }
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
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id() && is_nested_body(node, language) {
            continue;
        }
        if is_assignment(node, language) {
            assignments.push(node);
        }
        if language == Language::Python
            && matches!(node.kind(), "global_statement" | "nonlocal_statement")
        {
            let mut cursor = node.walk();
            for name in node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "identifier")
            {
                if let Some(text) = syntax.source().get(name.byte_range()) {
                    python_directives.insert(text);
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    assignments.sort_unstable_by_key(Node::start_byte);
    let mut points_by_span: HashMap<(usize, usize), Vec<&crate::analyzer::semantic::ProgramPoint>> =
        HashMap::new();
    for point in semantics.points() {
        if let Some(mapping) = semantics
            .source_mapping(point.source)
            .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
        {
            let span = mapping.locator.anchor().span();
            points_by_span
                .entry((span.start_byte() as usize, span.end_byte() as usize))
                .or_default()
                .push(point);
        }
    }
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
    PlainAssignmentCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    }
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
        return unavailable("unsupported_language");
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return unavailable("cancelled");
    }
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        procedure.artifact().key().path().as_path(),
    );
    let syntax = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Java)
        .map(|provider| provider.structural_syntax_limited(&file, MAX_SOURCE_BYTES, cancellation));
    let syntax = match syntax {
        Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax,
        Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
            return unavailable("source_budget_exhausted");
        }
        Some(StructuralSyntaxLimitedOutcome::Cancelled) => return unavailable("cancelled"),
        Some(StructuralSyntaxLimitedOutcome::Unavailable) | None => {
            return unavailable("prepared_syntax_unavailable");
        }
    };
    let Ok(syntax) = validate_prepared_syntax_source_for_procedure(
        workspace,
        procedure,
        &file,
        syntax.into_inner(),
    ) else {
        return unavailable("source_identity_mismatch");
    };
    let semantics = procedure.semantics();
    let Some(mapping) = semantics.source_mapping(semantics.source()) else {
        return unavailable("procedure_mapping_missing");
    };
    if mapping.kind != SourceMappingKind::Exact {
        return unavailable("procedure_mapping_inexact");
    }
    let span = mapping.locator.anchor().span();
    let Some(procedure_node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
    else {
        return unavailable("procedure_syntax_missing");
    };
    if !exact_span(span, procedure_node) || procedure_node.has_error() {
        return unavailable("procedure_syntax_inexact");
    }

    let mut nodes = Vec::new();
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id() && is_nested_body(node, Language::Java) {
            continue;
        }
        if node.kind() == "assignment_expression"
            || (node.kind() == "variable_declarator"
                && node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "local_variable_declaration")
                && node.child_by_field_name("value").is_some())
        {
            nodes.push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    nodes.sort_unstable_by_key(Node::start_byte);
    let mut points_by_span: HashMap<(usize, usize), Vec<&crate::analyzer::semantic::ProgramPoint>> =
        HashMap::new();
    for point in semantics.points() {
        if let Some(mapping) = semantics
            .source_mapping(point.source)
            .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
        {
            let span = mapping.locator.anchor().span();
            points_by_span
                .entry((span.start_byte() as usize, span.end_byte() as usize))
                .or_default()
                .push(point);
        }
    }
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
        return unavailable("unsupported_language");
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return unavailable("cancelled");
    }
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        procedure.artifact().key().path().as_path(),
    );
    let syntax = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .map(|provider| provider.structural_syntax_limited(&file, MAX_SOURCE_BYTES, cancellation));
    let syntax = match syntax {
        Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax,
        Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
            return unavailable("source_budget_exhausted");
        }
        Some(StructuralSyntaxLimitedOutcome::Cancelled) => return unavailable("cancelled"),
        Some(StructuralSyntaxLimitedOutcome::Unavailable) | None => {
            return unavailable("prepared_syntax_unavailable");
        }
    };
    let Ok(syntax) = validate_prepared_syntax_source_for_procedure(
        workspace,
        procedure,
        &file,
        syntax.into_inner(),
    ) else {
        return unavailable("source_identity_mismatch");
    };
    let semantics = procedure.semantics();
    let Some(mapping) = semantics.source_mapping(semantics.source()) else {
        return unavailable("procedure_mapping_missing");
    };
    if mapping.kind != SourceMappingKind::Exact {
        return unavailable("procedure_mapping_inexact");
    }
    let span = mapping.locator.anchor().span();
    let Some(procedure_node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
    else {
        return unavailable("procedure_syntax_missing");
    };
    if !exact_span(span, procedure_node) || procedure_node.has_error() {
        return unavailable("procedure_syntax_inexact");
    }
    if !is_js_function(procedure_node.kind()) {
        return if procedure_node.kind() == "program" {
            OverwrittenLocalCandidates {
                rows: Vec::new(),
                complete: true,
                reason: None,
            }
        } else {
            unavailable("unsupported_callable_kind")
        };
    }

    let mut nodes = Vec::new();
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id() && is_nested_body(node, language) {
            continue;
        }
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
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    nodes.sort_unstable_by_key(Node::start_byte);
    let mut points_by_span: HashMap<(usize, usize), Vec<&crate::analyzer::semantic::ProgramPoint>> =
        HashMap::new();
    for point in semantics.points() {
        if let Some(mapping) = semantics
            .source_mapping(point.source)
            .filter(|mapping| mapping.kind == SourceMappingKind::Exact)
        {
            let span = mapping.locator.anchor().span();
            points_by_span
                .entry((span.start_byte() as usize, span.end_byte() as usize))
                .or_default()
                .push(point);
        }
    }

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
        _ => false,
    }
}

fn is_js_function(kind: &str) -> bool {
    matches!(
        kind,
        "function"
            | "function_declaration"
            | "function_expression"
            | "generator_function"
            | "generator_function_declaration"
            | "arrow_function"
            | "method_definition"
    )
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
    // Pattern variables are not in the Java lowering's lexical environment,
    // so it can bind a same-named target to a field or leave it unbound.
    if language == Language::Java && java_pattern_variable_named(source, procedure_node, left) {
        row.reason = "pattern_variable_unresolved";
        return row;
    }
    // Python's boundary point maps to the whole assignment, while its actual
    // local write is emitted at a second point mapped to the target identifier.
    let write_node = if language == Language::Python {
        left
    } else {
        assignment
    };
    let Some(points) = points_by_span.get(&(write_node.start_byte(), write_node.end_byte())) else {
        row.reason = "assignment_point_unmapped";
        return row;
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
            row.verdict = PlainAssignmentVerdict::Excluded;
            row.storage_kind = "member";
            row.reason = "resolved_field_target";
            return row;
        }
        row.reason = "local_assignment_join_ambiguous";
        return row;
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
        row.reason = "local_assignment_join_ambiguous";
        return row;
    }
    let Some(target_row) = semantics.value(target) else {
        row.reason = "target_value_missing";
        return row;
    };
    let is_parameter = matches!(target_row.kind, SemanticValueKind::Parameter { .. });
    let Some(target_mapping) = semantics.source_mapping(target_row.source) else {
        row.reason = "target_mapping_missing";
        return row;
    };
    if target_mapping.kind != SourceMappingKind::Exact {
        row.reason = "target_mapping_inexact";
        return row;
    }
    let target_span = target_mapping.locator.anchor().span();
    let Some(declaration) = root.named_descendant_for_byte_range(
        target_span.start_byte() as usize,
        target_span.end_byte() as usize,
    ) else {
        row.reason = "declaration_name_missing";
        return row;
    };
    if !exact_span(target_span, declaration) || declaration.has_error() {
        row.reason = "declaration_name_inexact";
        return row;
    }
    let name = if is_parameter && declaration.kind() != "identifier" {
        let Some(name) = declaration.child_by_field_name("name") else {
            row.reason = "parameter_name_missing";
            return row;
        };
        name
    } else {
        declaration
    };
    if name.kind() != "identifier" || name.has_error() {
        row.reason = "declaration_name_inexact";
        return row;
    }
    if name.start_byte() < procedure_node.start_byte()
        || name.end_byte() > procedure_node.end_byte()
    {
        row.verdict = PlainAssignmentVerdict::Excluded;
        row.storage_kind = "nonlocal";
        row.reason = "declaration_outside_procedure";
        return row;
    }
    if language == Language::Python
        && source
            .get(name.byte_range())
            .is_some_and(|name| python_directives.contains(name))
    {
        row.verdict = PlainAssignmentVerdict::Excluded;
        row.storage_kind = "nonlocal";
        row.reason = "python_scope_directive";
        return row;
    }
    let Some(swap_type) =
        ordinary_local_declaration(name, source, language, is_parameter, python_directives)
    else {
        row.reason = "ordinary_local_unproved";
        return row;
    };
    row.points = points;
    row.target = Some(target);
    row.rhs_value = Some(rhs_value);
    row.swap_type = swap_type;
    row.verdict = PlainAssignmentVerdict::Supported;
    row.storage_kind = "ordinary_local";
    row.reason = "qualified";
    row
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

fn assignment_has_plain_operator(node: Node<'_>) -> bool {
    (0..node.child_count())
        .filter_map(|index| node.child(index))
        .any(|child| child.kind() == "=")
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

fn exact_span(span: crate::analyzer::semantic::SourceSpan, node: Node<'_>) -> bool {
    node.start_byte() == span.start_byte() as usize && node.end_byte() == span.end_byte() as usize
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}
