//! Prepared-syntax qualification for ordinary local assignments.

use crate::CancellationToken;
use crate::analyzer::semantic::statement_entries::ProcedureSyntax;
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

const MAX_SOURCE_BYTES: usize = 1_048_576;

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
        Language::Rust => rust_plain_write,
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
        return unavailable("unsupported_language");
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
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id() && is_nested_body(node, Language::Python) {
            continue;
        }
        match node.kind() {
            "assignment" | "augmented_assignment" => nodes.push(node),
            "global_statement" | "nonlocal_statement" => {
                let mut cursor = node.walk();
                for name in node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "identifier")
                {
                    if let Some(text) = source.get(name.byte_range()) {
                        python_directives.insert(text);
                    }
                }
            }
            _ => {}
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
        return unavailable("unsupported_language");
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
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id() && is_nested_body(node, Language::Go) {
            continue;
        }
        match node.kind() {
            "assignment_statement" | "short_var_declaration" => statements.push(node),
            "var_spec" if node.child_by_field_name("value").is_some() => statements.push(node),
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    statements.sort_unstable_by_key(Node::start_byte);
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

/// C# and Kotlin local establishments. Each lowered write point holds
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
            _ => return unavailable("unsupported_language"),
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
            return unavailable("cancelled");
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
                Err((verdict, reason)) => return row(target, source_kind, verdict, reason),
            };
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
struct BindingWrite<'tree> {
    point: ProgramPointId,
    binding: ValueId,
    value: ValueId,
    parameter: bool,
    /// The binding's declared name.
    declaration: Node<'tree>,
}

/// Join the simple name `target` to the one binding (Local or Parameter)
/// that the lowering assigns at `point_node`, declared inside this procedure
/// and spelled like `target`. C#, Kotlin and Go lower a simple-name write to
/// exactly one binding assignment; a C# point also assigns the expression's
/// own Temporary, which is not a binding.
fn join_binding_write<'tree>(
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
}

/// C#, Kotlin and Go assignments to a simple name. Each lowering maps the
/// write to the assignment node and assigns exactly one binding there, so
/// the B1 binding join also serves these relations.
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
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id() && (prepared.roles.nested_procedure)(node) {
            continue;
        }
        if let Some(write) = classify(node, source) {
            writes.push(write);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
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

/// The name `node` spells inside transparent parentheses, when it is a
/// simple name of `name_kind`.
fn parenthesized_name<'tree>(mut node: Node<'tree>, name_kind: &str) -> Option<Node<'tree>> {
    loop {
        if node.has_error() {
            return None;
        }
        if node.kind() == name_kind {
            return Some(node);
        }
        if node.kind() != "parenthesized_expression" || node.named_child_count() != 1 {
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
    let next = node
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
        .map(|next| next.start_byte());
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
    let next = node
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
        .map(|next| next.start_byte());
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

/// C#: an initialized local declarator or an `=` assignment to a simple
/// name. Field initializers belong to other procedures.
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
            if node
                .child_by_field_name("operator")
                .is_none_or(|operator| operator.kind() != "=")
            {
                return Some(SingleTargetWrite::Excluded(node, "compound_assignment"));
            }
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
        _ => None,
    }
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
    _source: &str,
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
                return Some(SingleTargetWrite::Excluded(node, "compound_assignment"));
            }
            let target = node.named_child(0)?;
            let name = if target.kind() == "directly_assignable_expression"
                && target.named_child_count() == 1
            {
                target.named_child(0)?
            } else {
                target
            };
            Some(if name.kind() == "simple_identifier" {
                SingleTargetWrite::Candidate {
                    point_node: node,
                    target: name,
                    source_kind: OverwrittenLocalSourceKind::PlainAssignment,
                }
            } else {
                SingleTargetWrite::Excluded(node, "nonlocal_target")
            })
        }
        _ => None,
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
        Language::Go => node.kind() == "func_literal",
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
