//! Bounded C syntax qualification for expression and branch policy facts.
//!
//! This module deliberately does not parse source text. It joins the C/C++
//! lowerer's exact semantic source mappings back to the analyzer-generation
//! prepared tree, then publishes only the syntax/storage classification that
//! language-neutral flow analysis cannot recover from the IR.

use crate::CancellationToken;
use crate::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;
use crate::analyzer::semantic::{
    ProcedureHandle, ProgramPointId, SemanticEffect, SemanticValueKind, SourceMappingKind, ValueId,
};
use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::{Language, LanguageDialect, ProjectFile, Range, WorkspaceAnalyzer};
use tree_sitter::Node;

use super::node_text;
use super::semantic::{
    cpp_declarator_contains_kind, cpp_local_declarators, cpp_type_is_fundamental,
    declarator_name_node,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CAssignmentSyntaxVerdict {
    Supported,
    Excluded,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CAssignmentCandidate {
    pub point: Option<ProgramPointId>,
    pub target: Option<ValueId>,
    pub rhs_value: Option<ValueId>,
    pub range: Range,
    pub rhs_range: Option<Range>,
    pub next_assignment_start: Option<usize>,
    pub verdict: CAssignmentSyntaxVerdict,
    pub storage_kind: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct CAssignmentCandidates {
    pub rows: Vec<CAssignmentCandidate>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

const DEFAULT_MAX_SOURCE_BYTES: usize = 1_048_576;

pub fn c_assignment_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> CAssignmentCandidates {
    if procedure.artifact().key().language() != LanguageDialect::CppC {
        return CAssignmentCandidates {
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
        .find(|provider| provider.structural_language() == Language::Cpp)
        .map(|provider| {
            provider.structural_syntax_limited(&file, DEFAULT_MAX_SOURCE_BYTES, cancellation)
        });
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
    let Some(procedure_mapping) = semantics.source_mapping(semantics.source()) else {
        return unavailable("procedure_mapping_missing");
    };
    let procedure_span = procedure_mapping.locator.anchor().span();
    let Some(procedure_node) = syntax.tree().root_node().named_descendant_for_byte_range(
        procedure_span.start_byte() as usize,
        procedure_span.end_byte() as usize,
    ) else {
        return unavailable("procedure_syntax_missing");
    };
    if procedure_node.start_byte() != procedure_span.start_byte() as usize
        || procedure_node.end_byte() != procedure_span.end_byte() as usize
        || procedure_node.has_error()
    {
        return unavailable("procedure_syntax_inexact");
    }

    let mut assignments = Vec::new();
    let mut has_preprocessing = false;
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        if node.id() != procedure_node.id()
            && matches!(node.kind(), "function_definition" | "lambda_expression")
        {
            continue;
        }
        if node.kind() == "assignment_expression" {
            assignments.push(node);
        }
        has_preprocessing |= node.kind().starts_with("preproc_");
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    assignments.sort_unstable_by_key(Node::start_byte);

    let mut rows = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
        rows.push(classify_assignment(
            semantics,
            syntax.source(),
            syntax.tree().root_node(),
            assignment,
        ));
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return unavailable("cancelled");
        }
    }
    CAssignmentCandidates {
        rows,
        complete: !has_preprocessing,
        reason: has_preprocessing.then_some("preprocessing_present"),
    }
}

fn unavailable(reason: &'static str) -> CAssignmentCandidates {
    CAssignmentCandidates {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    }
}

fn classify_assignment(
    semantics: &crate::analyzer::semantic::ProcedureSemantics,
    source: &str,
    root: Node<'_>,
    assignment: Node<'_>,
) -> CAssignmentCandidate {
    let range = node_range(assignment);
    let next_assignment_start = next_assignment_start(assignment);
    if assignment.has_error() || has_preprocessing_ancestor(assignment) {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "preprocessing_or_recovery",
        );
    }
    let Some(operator) = assignment.child_by_field_name("operator") else {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "operator_missing",
        );
    };
    if node_text(operator, source) != "=" {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Excluded,
            "compound",
            "compound_assignment",
        );
    }
    let Some(left) = assignment.child_by_field_name("left") else {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "left_operand_missing",
        );
    };
    let Some(right) = assignment.child_by_field_name("right") else {
        return candidate(
            range,
            None,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "right_operand_missing",
        );
    };
    if left.kind() != "identifier" {
        let storage = match left.kind() {
            "field_expression" => "member",
            "subscript_expression" => "element",
            "pointer_expression" => "indirect",
            _ => "indirect",
        };
        return candidate(
            range,
            Some(node_range(right)),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Excluded,
            storage,
            "nonlocal_target",
        );
    }
    match bare_identifier_rhs(right) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return candidate(
                range,
                Some(node_range(right)),
                next_assignment_start,
                CAssignmentSyntaxVerdict::Excluded,
                "ordinary_local",
                "rhs_not_bare_identifier",
            );
        }
        Err(()) => {
            return candidate(
                range,
                Some(node_range(right)),
                next_assignment_start,
                CAssignmentSyntaxVerdict::Unknown,
                "unknown",
                "rhs_syntax_unresolved",
            );
        }
    }
    let rhs_range = node_range(right);

    let point = semantics.points().iter().find(|point| {
        semantics
            .source_mapping(point.source)
            .is_some_and(|mapping| {
                mapping.kind == SourceMappingKind::Exact
                    && exact_span(mapping.locator.anchor().span(), assignment)
            })
    });
    let Some(point) = point else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "assignment_point_unmapped",
        );
    };
    let local_assignments = point
        .events
        .iter()
        .filter_map(|event| match event.effect {
            SemanticEffect::Assignment { target, value }
                if semantics
                    .value(target)
                    .is_some_and(|row| matches!(&row.kind, SemanticValueKind::Local)) =>
            {
                Some((target, value))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [(target, rhs_value)] = local_assignments.as_slice() else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "local_assignment_join_ambiguous",
        );
    };
    let Some(target_row) = semantics.value(*target) else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "target_value_missing",
        );
    };
    let Some(target_mapping) = semantics.source_mapping(target_row.source) else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "target_mapping_missing",
        );
    };
    if target_mapping.kind != SourceMappingKind::Exact {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "target_mapping_inexact",
        );
    }
    let target_span = target_mapping.locator.anchor().span();
    let Some(name) = root.named_descendant_for_byte_range(
        target_span.start_byte() as usize,
        target_span.end_byte() as usize,
    ) else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declaration_name_missing",
        );
    };
    if !exact_span(target_span, name) || name.kind() != "identifier" || name.has_error() {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declaration_name_inexact",
        );
    }
    let Some((declaration, declarator)) = containing_local_declarator(name) else {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declarator_identity_unproved",
        );
    };
    if declarator_name_node(declarator).is_none_or(|actual| actual.id() != name.id()) {
        return candidate(
            range,
            Some(rhs_range),
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declarator_identity_mismatch",
        );
    }
    if declaration.has_error() || declarator.has_error() {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declaration_syntax_unresolved",
        );
    }
    if has_qualifier(source, declaration, declarator, "volatile") {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Excluded,
            "volatile",
            "volatile_local",
        );
    }
    if has_atomic_qualifier(source, declaration, declarator) {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Excluded,
            "atomic",
            "atomic_local",
        );
    }
    if has_unsupported_storage_class(source, declaration) {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "unsupported_storage_class",
        );
    }
    if [
        "pointer_declarator",
        "array_declarator",
        "function_declarator",
        "reference_declarator",
    ]
    .into_iter()
    .any(|kind| cpp_declarator_contains_kind(declarator, kind))
    {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "unsupported_declarator",
        );
    }
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "declared_type_missing",
        );
    };
    if !cpp_type_is_fundamental(type_node) {
        return completed_candidate(
            point.id,
            *target,
            *rhs_value,
            range,
            rhs_range,
            next_assignment_start,
            CAssignmentSyntaxVerdict::Unknown,
            "unknown",
            "unsupported_declared_type",
        );
    }
    completed_candidate(
        point.id,
        *target,
        *rhs_value,
        range,
        rhs_range,
        next_assignment_start,
        CAssignmentSyntaxVerdict::Supported,
        "ordinary_local",
        "qualified",
    )
}

fn candidate(
    range: Range,
    rhs_range: Option<Range>,
    next_assignment_start: Option<usize>,
    verdict: CAssignmentSyntaxVerdict,
    storage_kind: &'static str,
    reason: &'static str,
) -> CAssignmentCandidate {
    CAssignmentCandidate {
        point: None,
        target: None,
        rhs_value: None,
        range,
        rhs_range,
        next_assignment_start,
        verdict,
        storage_kind,
        reason,
    }
}

#[allow(clippy::too_many_arguments)]
fn completed_candidate(
    point: ProgramPointId,
    target: ValueId,
    rhs_value: ValueId,
    range: Range,
    rhs_range: Range,
    next_assignment_start: Option<usize>,
    verdict: CAssignmentSyntaxVerdict,
    storage_kind: &'static str,
    reason: &'static str,
) -> CAssignmentCandidate {
    CAssignmentCandidate {
        point: Some(point),
        target: Some(target),
        rhs_value: Some(rhs_value),
        range,
        rhs_range: Some(rhs_range),
        next_assignment_start,
        verdict,
        storage_kind,
        reason,
    }
}

fn next_assignment_start(assignment: Node<'_>) -> Option<usize> {
    let statement = assignment.parent()?;
    if statement.kind() != "expression_statement" || statement.has_error() {
        return None;
    }
    let mut cursor = statement.walk();
    let mut expressions = statement.named_children(&mut cursor);
    if expressions.next()?.id() != assignment.id() || expressions.next().is_some() {
        return None;
    }

    let block = statement.parent()?;
    if block.kind() != "compound_statement" || block.has_error() {
        return None;
    }
    let mut next = statement.next_named_sibling()?;
    while next.kind() == "comment" {
        next = next.next_named_sibling()?;
    }
    if next.kind() != "expression_statement" || next.has_error() {
        return None;
    }
    let mut cursor = next.walk();
    let mut expressions = next.named_children(&mut cursor);
    let expression = expressions.next()?;
    if expressions.next().is_some()
        || expression.kind() != "assignment_expression"
        || expression.has_error()
    {
        return None;
    }
    Some(expression.start_byte())
}

fn containing_local_declarator(name: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut current = name;
    while let Some(parent) = current.parent() {
        if parent.kind() == "declaration" {
            let declarator = cpp_local_declarators(parent)
                .into_iter()
                .find(|candidate| {
                    candidate.start_byte() <= name.start_byte()
                        && candidate.end_byte() >= name.end_byte()
                })?;
            return Some((parent, declarator));
        }
        if matches!(
            parent.kind(),
            "function_definition" | "parameter_declaration"
        ) {
            return None;
        }
        current = parent;
    }
    None
}

fn bare_identifier_rhs(mut node: Node<'_>) -> Result<Option<Node<'_>>, ()> {
    loop {
        if node.has_error() {
            return Err(());
        }
        match node.kind() {
            "identifier" => return Ok(Some(node)),
            "parenthesized_expression" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor);
                let Some(child) = children.next() else {
                    return Err(());
                };
                if children.next().is_some() {
                    return Err(());
                }
                node = child;
            }
            _ => return Ok(None),
        }
    }
}

fn has_qualifier(
    source: &str,
    declaration: Node<'_>,
    declarator: Node<'_>,
    expected: &str,
) -> bool {
    declaration_direct_qualifier(source, declaration, expected)
        || declaration
            .child_by_field_name("type")
            .is_some_and(|node| subtree_has_qualifier(source, node, expected))
        || subtree_has_qualifier(source, declarator, expected)
}

fn has_atomic_qualifier(source: &str, declaration: Node<'_>, declarator: Node<'_>) -> bool {
    declaration_direct_atomic(source, declaration)
        || declaration
            .child_by_field_name("type")
            .is_some_and(|node| subtree_has_atomic(source, node))
        || subtree_has_atomic(source, declarator)
}

fn declaration_direct_qualifier(source: &str, declaration: Node<'_>, expected: &str) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .any(|node| node.kind() == "type_qualifier" && node_text(node, source) == expected)
}

fn declaration_direct_atomic(source: &str, declaration: Node<'_>) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .any(|node| node_is_atomic(source, node))
}

fn subtree_has_qualifier(source: &str, root: Node<'_>, expected: &str) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_qualifier" && node_text(node, source) == expected {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn subtree_has_atomic(source: &str, root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node_is_atomic(source, node) {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn node_is_atomic(source: &str, node: Node<'_>) -> bool {
    matches!(node.kind(), "atomic_type_specifier" | "_Atomic")
        || (node.kind() == "type_qualifier" && node_text(node, source) == "_Atomic")
}

fn has_unsupported_storage_class(source: &str, declaration: Node<'_>) -> bool {
    let mut cursor = declaration.walk();
    declaration.named_children(&mut cursor).any(|child| {
        child.kind() == "storage_class_specifier"
            && !matches!(node_text(child, source), "auto" | "register")
    })
}

fn has_preprocessing_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind().starts_with("preproc_") {
            return true;
        }
        node = parent;
    }
    false
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{
        DeclarationSegment, SemanticBudget, SemanticOutcome, SemanticRequest,
    };
    use crate::test_support::AnalyzerFixture;

    #[test]
    fn c_assignment_candidates_reports_source_budget_exhaustion() {
        let source = format!(
            "void oversized(void) {{ int first = 1; int second = 2; first = second; second = first; }}\n/*{}*/\n",
            "x".repeat(DEFAULT_MAX_SOURCE_BYTES)
        );
        assert!(source.len() > DEFAULT_MAX_SOURCE_BYTES);
        let fixture =
            AnalyzerFixture::new_for_language(Language::Cpp, &[("main.c", source.as_str())]);
        let file = ProjectFile::new(fixture.project_root(), "main.c");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("oversized C semantic materialization");
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = outcome
        else {
            panic!("oversized C semantic materialization must be complete: {outcome:#?}");
        };
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("oversized")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("oversized C procedure");

        let candidates = c_assignment_candidates(&fixture.analyzer, &procedure, None);

        assert!(candidates.rows.is_empty(), "{candidates:#?}");
        assert!(!candidates.complete, "{candidates:#?}");
        assert_eq!(
            candidates.reason,
            Some("source_budget_exhausted"),
            "{candidates:#?}"
        );
    }
}
