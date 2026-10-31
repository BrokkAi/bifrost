//! Exact prepared-source loop sites for procedure-local control proofs.

use crate::CancellationToken;
use crate::analyzer::read_ledger::reason as derivation_reason;
use crate::analyzer::semantic::statement_entries::ProcedureSyntax;
use crate::analyzer::semantic::type_flow::source_span_for_node;
use crate::analyzer::semantic::{ProcedureHandle, SourceSpan};
use crate::analyzer::structural::lexical_environment::{
    BindingOfOutcome, EnvironmentFileResult, binding_of, environment_for_file,
};
use crate::analyzer::structural::occurrences::Namespace;
use crate::analyzer::structural::resolution::EnvironmentAxis;
use crate::analyzer::{
    Language, Range, WorkspaceAnalyzer,
    common::{CandidateState, language_for_file},
};
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use brokk_bifrost_core::analyzer::structural::conditional_regions::ConditionalRegions;
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use std::mem::size_of;
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    While,
    Until,
    For,
    Do,
}

/// One conditional loop's syntax as its language classifies it. A missing
/// field is recovery, reported by the enumerator; a `for` may have no
/// condition. `Until` records a condition whose false arm enters the body.
#[derive(Debug, Clone, Copy)]
pub struct LoopSyntax<'tree> {
    pub kind: LoopKind,
    pub body: Option<Node<'tree>>,
    pub condition: Option<Node<'tree>>,
}

#[derive(Debug, Clone, Copy)]
pub struct LoopSite {
    pub kind: LoopKind,
    pub loop_span: SourceSpan,
    pub body_span: SourceSpan,
    pub condition_span: Option<SourceSpan>,
}

#[derive(Debug, Clone)]
pub struct LoopCandidate {
    pub range: Range,
    pub coordinates: LoopCoordinates,
    pub body_coordinates: Option<LoopCoordinates>,
    pub kind: LoopKind,
    pub site: Option<LoopSite>,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct LoopCoordinates {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone)]
pub struct LoopCandidates {
    pub rows: Vec<LoopCandidate>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

/// The inner `for` loops whose update writes any lexical counter selected by
/// an enclosing `for` header. All declarations at the selected header stage
/// participate, independently of their order. Syntax and lexical rows stay
/// query-local to the procedure that produced these ranges.
#[derive(Debug, Clone)]
pub struct NestedLoopFacts {
    pub rows: Vec<Range>,
    /// Inner sites whose pair evidence has unproven conditional activation.
    pub undecided: Vec<Range>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

fn unavailable(reason: &'static str) -> LoopCandidates {
    let CandidateState {
        rows,
        complete,
        reason,
    } = CandidateState::unavailable(reason);
    LoopCandidates {
        rows,
        complete,
        reason,
    }
}

/// Collect only loops owned by this exact semantic procedure. Nested callable
/// bodies have separate semantic owners and are never attributed to the outer
/// procedure. The prepared tree is validated against the artifact snapshot.
pub fn loop_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> Result<LoopCandidates, crate::analyzer::QueryReadIncomplete> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Ok(build_loop_candidates(workspace, procedure, cancellation));
    }
    workspace
        .analyzer()
        .loop_candidates_for(workspace, procedure, cancellation)
        .map(|candidates| (*candidates).clone())
}

pub(crate) fn weight_loop_candidates(
    _key: &(
        crate::analyzer::semantic::SemanticArtifactMaterializationId,
        crate::analyzer::semantic::ProcedureId,
    ),
    value: &Arc<LoopCandidates>,
) -> u32 {
    let size = size_of::<LoopCandidates>().saturating_add(
        value
            .rows
            .capacity()
            .saturating_mul(size_of::<LoopCandidate>()),
    );
    size.clamp(1, u32::MAX as usize) as u32
}

pub(crate) fn build_loop_candidates(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> LoopCandidates {
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return unavailable(reason),
    };
    let procedure_node = match prepared.procedure_node(procedure) {
        Ok(node) => node,
        Err(reason) => return unavailable(reason),
    };
    let source = prepared.syntax.source();
    let roles = prepared.roles;
    let line_starts = compute_line_starts(source);
    let observations = match collect_loop_observations(procedure_node, roles, source, cancellation)
    {
        Ok(observations) => observations,
        Err(reason) => return unavailable(reason),
    };
    candidates_from_observations(observations, source, &line_starts)
}

fn candidates_from_observations(
    observations: Vec<LoopObservation<'_>>,
    source: &str,
    line_starts: &[usize],
) -> LoopCandidates {
    let mut rows = observations
        .into_iter()
        .map(|observation| {
            let LoopObservation {
                node,
                syntax:
                    LoopSyntax {
                        kind,
                        body,
                        condition,
                    },
                reason,
            } = observation;
            LoopCandidate {
                range: node_range(node),
                coordinates: node_coordinates(node, source, line_starts),
                body_coordinates: body.map(|body| node_coordinates(body, source, line_starts)),
                kind,
                site: if reason.is_none() {
                    Some(LoopSite {
                        kind,
                        loop_span: source_span_for_node(node),
                        body_span: source_span_for_node(body.expect("checked body field")),
                        condition_span: condition.map(source_span_for_node),
                    })
                } else {
                    None
                },
                reason,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_unstable_by_key(|row| row.range.start_byte);
    LoopCandidates {
        rows,
        complete: true,
        reason: None,
    }
}

/// Derive the nested-loop relation shared by languages whose `for` grammar
/// supplies initializer, condition, and update fields. The C++ and C# roles
/// select their grammar-specific loop nodes; this function owns containment,
/// binding identity, update-target selection, and the C# CodeQL safety rule.
pub fn nested_loop_facts(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    cancellation: Option<&CancellationToken>,
) -> NestedLoopFacts {
    let prepared = match ProcedureSyntax::prepare(workspace, procedure, cancellation) {
        Ok(prepared) => prepared,
        Err(reason) => return NestedLoopFacts::unavailable(reason),
    };
    let procedure_node = match prepared.procedure_node(procedure) {
        Ok(node) => node,
        Err(reason) => return NestedLoopFacts::unavailable(reason),
    };
    let source = prepared.syntax.source();
    let observations =
        match collect_loop_observations(procedure_node, prepared.roles, source, cancellation) {
            Ok(observations) => observations,
            Err(reason) => return NestedLoopFacts::unavailable(reason),
        };
    let environment = environment_for_file(workspace.analyzer(), &prepared.file);
    if !environment.completeness.covers(EnvironmentAxis::Scopes)
        || !environment
            .completeness
            .covers(EnvironmentAxis::BindingIntervals)
    {
        return NestedLoopFacts::unavailable(derivation_reason::LEXICAL_ENVIRONMENT_INCOMPLETE);
    }

    let language = language_for_file(&prepared.file);
    let regions = prepared.syntax.conditional_regions();
    nested_facts_from_observations(&observations, &environment, source, language, &regions)
}

fn nested_facts_from_observations(
    observations: &[LoopObservation<'_>],
    environment: &EnvironmentFileResult,
    source: &str,
    language: Language,
    regions: &ConditionalRegions,
) -> NestedLoopFacts {
    let mut rows = Vec::new();
    let mut undecided = Vec::new();
    for outer in observations.iter().filter(|observation| {
        observation.reason.is_none() && observation.syntax.kind == LoopKind::For
    }) {
        let outer_variables = loop_header_bindings(outer.node, environment, source, language);
        let Some(body) = outer.syntax.body else {
            continue;
        };
        for inner in observations.iter().filter(|observation| {
            observation.reason.is_none()
                && observation.syntax.kind == LoopKind::For
                && observation.node.id() != outer.node.id()
                && body.start_byte() <= observation.node.start_byte()
                && observation.node.end_byte() <= body.end_byte()
        }) {
            // A relation depends on this pair, not on unrelated text elsewhere
            // in the outer body. Report uncertainty at the inner result site.
            if regions.has_uncertain_text(outer.node.start_byte()..body.start_byte())
                || regions.has_uncertain_text(inner.node.byte_range())
            {
                undecided.push(node_range(inner.node));
                continue;
            }
            let inner_updates = update_bindings(inner.node, environment, source);
            if outer_variables.iter().copied().any(|outer_variable| {
                inner_updates.contains(&outer_variable)
                    && !(language == Language::CSharp
                        && csharp_nested_loop_is_safe(
                            outer,
                            inner,
                            outer_variable,
                            environment,
                            source,
                        ))
            }) {
                rows.push(node_range(inner.node));
            }
        }
    }
    rows.sort_unstable_by_key(|range| range.start_byte);
    rows.dedup_by(|left, right| {
        left.start_byte == right.start_byte && left.end_byte == right.end_byte
    });
    undecided.sort_unstable();
    undecided.dedup();
    NestedLoopFacts {
        rows,
        undecided,
        complete: true,
        reason: None,
    }
}

impl NestedLoopFacts {
    fn unavailable(reason: &'static str) -> Self {
        Self {
            rows: Vec::new(),
            undecided: Vec::new(),
            complete: false,
            reason: Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LoopObservation<'tree> {
    node: Node<'tree>,
    syntax: LoopSyntax<'tree>,
    reason: Option<&'static str>,
}

fn collect_loop_observations<'tree>(
    procedure_node: Node<'tree>,
    roles: crate::analyzer::languages::ProcedureSyntaxRoles,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<LoopObservation<'tree>>, &'static str> {
    let mut observations = Vec::new();
    let mut stack = vec![procedure_node];
    while let Some(node) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(derivation_reason::CANCELLED);
        }
        if node.id() != procedure_node.id() && (roles.nested_procedure)(node) {
            continue;
        }
        let loop_syntax = roles
            .loop_site_with_source
            .map(|classify| classify(node, source))
            .unwrap_or_else(|| (roles.loop_site)(node));
        if let Some(
            syntax @ LoopSyntax {
                kind,
                body,
                condition,
            },
        ) = loop_syntax
        {
            let reason = if node.has_error() {
                Some(derivation_reason::SYNTAX_RECOVERY)
            } else if body.is_none() {
                Some(derivation_reason::BODY_FIELD_MISSING)
            } else if kind != LoopKind::For && condition.is_none() {
                Some(derivation_reason::CONDITION_FIELD_MISSING)
            } else {
                None
            };
            observations.push(LoopObservation {
                node,
                syntax,
                reason,
            });
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    Ok(observations)
}

fn field_nodes<'tree>(node: Node<'tree>, field: &str) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor)
        .filter(Node::is_named)
        .collect()
}

fn identifier_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "identifier") && !is_member_name(node)
}

fn is_member_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let is_named_field = ["name", "field"].into_iter().any(|field| {
        parent
            .child_by_field_name(field)
            .is_some_and(|child| child.id() == node.id())
    });
    is_named_field
        && matches!(
            parent.kind(),
            "member_access_expression"
                | "member_binding_expression"
                | "field_expression"
                | "qualified_identifier"
                | "scoped_identifier"
        )
}

fn binder_identity_for_node(node: Node<'_>, environment: &EnvironmentFileResult) -> Option<usize> {
    environment.bindings.iter().position(|binding| {
        binding.range.start_byte == node.start_byte()
            && binding.range.end_byte == node.end_byte()
            && binding.occupies(Namespace::Value)
    })
}

fn binding_identity(
    node: Node<'_>,
    environment: &EnvironmentFileResult,
    source: &str,
) -> Option<usize> {
    if !identifier_node(node) {
        return None;
    }
    if let Some(binding) = binder_identity_for_node(node, environment) {
        return Some(binding);
    }
    let name = node.utf8_text(source.as_bytes()).ok()?;
    match binding_of(environment, name, node.start_byte(), Some(Namespace::Value)) {
        BindingOfOutcome::Reached(binding)
        | BindingOfOutcome::Shadowed {
            winner: binding, ..
        } => Some(binding),
        BindingOfOutcome::NoBinding | BindingOfOutcome::Incomplete(_) => None,
    }
}

fn binders_in(node: Node<'_>, environment: &EnvironmentFileResult) -> Vec<usize> {
    let mut bindings = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if let Some(binding) = binder_identity_for_node(current, environment) {
            bindings.push(binding);
            continue;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    bindings
}

fn named_children<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

/// Select the left-hand side of an assignment or the operand of an update.
/// The fallback cases cover comma/expression-list wrappers without parsing
/// source delimiters.
fn target_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut targets = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if identifier_node(current) {
            targets.push(current);
            continue;
        }
        match current.kind() {
            "assignment_expression" | "assignment" => {
                if let Some(left) = current.child_by_field_name("left") {
                    stack.push(left);
                }
            }
            "update_expression"
            | "prefix_unary_expression"
            | "postfix_unary_expression"
            | "parenthesized_expression" => {
                let child = current
                    .child_by_field_name("operand")
                    .or_else(|| current.child_by_field_name("argument"));
                if let Some(child) = child {
                    stack.push(child);
                } else if let Some(child) = named_children(current).into_iter().next() {
                    stack.push(child);
                }
            }
            "comma_expression" | "expression_list" | "initializer_list" => {
                stack.extend(named_children(current).into_iter().rev());
            }
            _ => {}
        }
    }
    targets
}

fn update_bindings(
    loop_node: Node<'_>,
    environment: &EnvironmentFileResult,
    source: &str,
) -> Vec<usize> {
    field_nodes(loop_node, "update")
        .into_iter()
        .flat_map(target_nodes)
        .filter_map(|node| binding_identity(node, environment, source))
        .collect()
}

fn loop_header_bindings(
    loop_node: Node<'_>,
    environment: &EnvironmentFileResult,
    source: &str,
    language: Language,
) -> Vec<usize> {
    let initializers = crate::analyzer::structural_spec_for(language)
        .and_then(|spec| spec.statement_fact_syntax())
        .map(|syntax| syntax.loop_initializers(loop_node))
        .unwrap_or_else(|| field_nodes(loop_node, "initializer"));
    let declarations = initializers
        .iter()
        .flat_map(|initializer| binders_in(*initializer, environment))
        .collect::<Vec<_>>();
    if !declarations.is_empty() {
        return declarations;
    }
    let assignments = initializers
        .into_iter()
        .flat_map(target_nodes)
        .filter_map(|node| binding_identity(node, environment, source))
        .collect::<Vec<_>>();
    if !assignments.is_empty() {
        return assignments;
    }
    let updates = update_bindings(loop_node, environment, source);
    if !updates.is_empty() {
        return updates;
    }
    let condition_bindings = field_nodes(loop_node, "condition")
        .into_iter()
        .flat_map(|condition| {
            let mut stack = vec![condition];
            let mut bindings = Vec::new();
            while let Some(current) = stack.pop() {
                if let Some(binding) = binding_identity(current, environment, source) {
                    bindings.push(binding);
                }
                let mut cursor = current.walk();
                stack.extend(current.named_children(&mut cursor));
            }
            bindings
        })
        .collect::<Vec<_>>();
    condition_bindings.into_iter().take(1).collect()
}

fn syntax_equivalent(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    let mut pending = vec![(left, right)];
    while let Some((left, right)) = pending.pop() {
        if left.kind() != right.kind() || left.is_named() != right.is_named() {
            return false;
        }
        let mut left_cursor = left.walk();
        let left_children = left.children(&mut left_cursor).collect::<Vec<_>>();
        let mut right_cursor = right.walk();
        let right_children = right.children(&mut right_cursor).collect::<Vec<_>>();
        if left_children.len() != right_children.len() {
            return false;
        }
        if left_children.is_empty()
            && source.as_bytes().get(left.start_byte()..left.end_byte())
                != source.as_bytes().get(right.start_byte()..right.end_byte())
        {
            return false;
        }
        pending.extend(left_children.into_iter().zip(right_children).rev());
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateDirection {
    Increment,
    Decrement,
}

fn update_direction(node: Node<'_>) -> Option<UpdateDirection> {
    if matches!(node.kind(), "++") {
        return Some(UpdateDirection::Increment);
    }
    if matches!(node.kind(), "--") {
        return Some(UpdateDirection::Decrement);
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find_map(|child| match child.kind() {
            "++" => Some(UpdateDirection::Increment),
            "--" => Some(UpdateDirection::Decrement),
            _ => None,
        })
}

fn csharp_nested_loop_is_safe(
    outer: &LoopObservation<'_>,
    inner: &LoopObservation<'_>,
    outer_variable: usize,
    environment: &EnvironmentFileResult,
    source: &str,
) -> bool {
    let outer_updates = field_nodes(outer.node, "update");
    let inner_updates = field_nodes(inner.node, "update");
    outer_updates.len() == inner_updates.len()
        && outer_updates.len() == 1
        && update_direction(outer_updates[0])
            .zip(update_direction(inner_updates[0]))
            .is_some_and(|(outer_direction, inner_direction)| outer_direction == inner_direction)
        && outer
            .syntax
            .condition
            .zip(inner.syntax.condition)
            .is_some_and(|(outer_condition, inner_condition)| {
                syntax_equivalent(outer_condition, inner_condition, source)
            })
        && outer.syntax.body.is_some_and(|body| {
            !has_post_inner_binding_access(body, inner.node, outer_variable, environment, source)
        })
}

/// A same-condition loop is safe only when no later access can observe the
/// value after the inner loop. Guarded accesses need control-flow facts that
/// this relation does not currently materialize, so they remain findings.
fn has_post_inner_binding_access(
    body: Node<'_>,
    inner: Node<'_>,
    binding: usize,
    environment: &EnvironmentFileResult,
    source: &str,
) -> bool {
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.id() == inner.id() {
            continue;
        }
        if node.start_byte() >= inner.end_byte()
            && binding_identity(node, environment, source) == Some(binding)
        {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn node_coordinates(node: Node<'_>, source: &str, line_starts: &[usize]) -> LoopCoordinates {
    let (start_line, start_column) = line_column_for_offset(source, line_starts, node.start_byte());
    let (end_line, end_column) = line_column_for_offset(source, line_starts, node.end_byte());
    LoopCoordinates {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::ProjectFile;
    use crate::analyzer::semantic::ContentIdentity;
    use crate::analyzer::structural::lexical_environment::{
        BindingRow, EnvironmentCompleteness, PackageClauseRow, ScopeAnchor, ScopeRow,
    };
    use crate::analyzer::structural::resolution::{BindingKind, DeclaredVisibility, HoistingClass};
    use brokk_bifrost_test_macros::hardwon;

    // Hand-written lexical rows isolate the grammar/lexical consumer from
    // analyzer hosts, which this crate's library-test registry does not link.
    // The fixtures only need source-ordered local binders in one active scope.
    fn syntax_fixture(
        language: Language,
        source: &str,
    ) -> (tree_sitter::Tree, EnvironmentFileResult) {
        let grammar: tree_sitter::Language = match language {
            Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
            Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
            _ => unreachable!(),
        };
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&grammar).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path().to_path_buf(), "subject");
        let content_identity = ContentIdentity::hash_bytes(source.as_bytes());
        let range = node_range(root);
        let mut bindings = Vec::new();
        for node in nodes(root) {
            let binder = match node.kind() {
                "init_declarator" | "parameter_declaration" => {
                    node.child_by_field_name("declarator")
                }
                "variable_declarator" | "parameter" => node.child_by_field_name("name"),
                _ => None,
            };
            if let Some(binder) = binder {
                assert_eq!(binder.kind(), "identifier");
                bindings.push(BindingRow {
                    file: file.clone(),
                    content_identity,
                    node: None,
                    range: node_range(binder),
                    name: binder.utf8_text(source.as_bytes()).unwrap().to_owned(),
                    kind: BindingKind::Local,
                    hoisting: HoistingClass::SourceOrder,
                    declaring_scope: 0,
                    activation: Range {
                        start_byte: binder.start_byte(),
                        ..range
                    },
                    source_order: 0,
                    visibility: DeclaredVisibility::Unknown,
                    import: None,
                });
            }
        }
        let environment = EnvironmentFileResult::new(
            vec![ScopeRow {
                file: file.clone(),
                content_identity,
                index: 0,
                anchor: ScopeAnchor::File,
                range,
                parent_scope: None,
            }],
            bindings,
            PackageClauseRow {
                file,
                package_fq: None,
                syntactic: false,
            },
            EnvironmentCompleteness::Complete,
        );
        (tree, environment)
    }

    fn nodes(root: Node<'_>) -> Vec<Node<'_>> {
        let mut pending = vec![root];
        let mut nodes = Vec::new();
        while let Some(node) = pending.pop() {
            nodes.push(node);
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        nodes
    }

    fn facts(language: Language, source: &str) -> (LoopCandidates, NestedLoopFacts) {
        let (tree, environment) = syntax_fixture(language, source);
        let observations = nodes(tree.root_node())
            .into_iter()
            .filter(|node| node.kind() == "for_statement")
            .map(|node| LoopObservation {
                node,
                syntax: LoopSyntax {
                    kind: LoopKind::For,
                    body: node.child_by_field_name("body"),
                    condition: node.child_by_field_name("condition"),
                },
                reason: None,
            })
            .collect::<Vec<_>>();
        let regions = crate::analyzer::structural_spec_for(language)
            .map(|spec| {
                spec.preprocess(source)
                    .map(|p| p.conditional_regions(source))
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let nested =
            nested_facts_from_observations(&observations, &environment, source, language, &regions);
        let candidates =
            candidates_from_observations(observations, source, &compute_line_starts(source));
        (candidates, nested)
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: sibling inner loops were omitted"
    )]
    fn every_reused_counter_sibling_is_reported() {
        let (_, nested) = facts(
            Language::Cpp,
            "void f() {\n for (int i=0; i<10; ++i) {\n  for (; i<5; ++i) {}\n  for (; i<7; ++i) {}\n }\n}",
        );
        assert_eq!(
            nested.rows.iter().map(|r| r.start_line).collect::<Vec<_>>(),
            [3, 4]
        );
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: header counter order discarded reused bindings"
    )]
    fn header_counter_set_is_order_independent() {
        for header in [
            "int i=0, j=0; i<10 && j<10; ++i, ++j",
            "int j=0, i=0; i<10 && j<10; ++j, ++i",
            "; i<10 && j<10; ++i, ++j",
            "; i<10 && j<10; ++j, ++i",
        ] {
            for counter in ["i", "j"] {
                let source = format!(
                    "void f() {{ int i=0, j=0;\n for ({header}) {{\n  for (; {counter}<5; ++{counter}) {{}}\n }}\n}}"
                );
                let (_, nested) = facts(Language::Cpp, &source);
                assert_eq!(
                    nested.rows.iter().map(|r| r.start_line).collect::<Vec<_>>(),
                    [3],
                    "{source}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: anonymous condition operators compared equal"
    )]
    fn different_condition_operators_are_not_safe() {
        for (outer, inner, expected) in [("<", ">", 1), ("==", "!=", 1), ("<", "<", 0)] {
            let source = format!(
                "class C {{ void F() {{ for (int i=0; i {outer} 10; i++) {{ for (; i {inner} 10; i++) {{}} }} }} }}"
            );
            let (_, nested) = facts(Language::CSharp, &source);
            assert_eq!(nested.rows.len(), expected, "{source}");
        }
    }

    #[test]
    #[hardwon(
        "97a35feae74c: quicksilver round 12 on brokk-bifrost-analysis: unknown update directions were considered equal"
    )]
    fn unknown_update_directions_do_not_prove_safety() {
        let (_, nested) = facts(
            Language::CSharp,
            "class C { void F() { for (int i=0; i<10; i+=1) { for (; i<10; i-=1) {} } } }",
        );
        assert_eq!(nested.rows.len(), 1);
    }

    // Pin the consumer/grammar boundary directly: binder token ranges join
    // Value rows; assignment fields and receiver/member fields have distinct
    // roles. No downstream relation answer serves as the grammar oracle.
    #[test]
    fn lexical_loop_header_and_access_grammar() {
        for (language, source) in [
            (
                Language::Cpp,
                "void f(int i) { int j=0; for (int i=0; i<10; ++i) { for (; j<5; i=j) {} } }",
            ),
            (
                Language::CSharp,
                "class C { void F(C obj) { int j=0; for (int i=0; i<10; i++) { for (; j<5; i=j) {} obj.i.ToString(); i.ToString(); } } }",
            ),
        ] {
            let (tree, env) = syntax_fixture(language, source);
            assert!(env.bindings.len() >= 3);
            for (index, row) in env.bindings.iter().enumerate() {
                let binder = tree
                    .root_node()
                    .named_descendant_for_byte_range(row.range.start_byte, row.range.end_byte)
                    .unwrap();
                assert_eq!(binder.kind(), "identifier");
                assert_eq!(binder_identity_for_node(binder, &env), Some(index));
            }
            let mut assignments = 0;
            let mut members = 0;
            let mut shadowed = 0;
            for node in nodes(tree.root_node()) {
                if node.kind() == "assignment_expression" {
                    let left = node.child_by_field_name("left").unwrap();
                    let right = node.child_by_field_name("right").unwrap();
                    assert_eq!((left.kind(), right.kind()), ("identifier", "identifier"));
                    assert_eq!(target_nodes(node), [left]);
                    assert_ne!(
                        binding_identity(left, &env, source),
                        binding_identity(right, &env, source)
                    );
                    assignments += 1;
                }
                if node.kind() == "member_access_expression" {
                    let name = node.child_by_field_name("name").unwrap();
                    assert_eq!(name.kind(), "identifier");
                    assert!(is_member_name(name));
                    let receiver = node.child_by_field_name("expression").unwrap();
                    if receiver.kind() == "identifier" {
                        assert!(!is_member_name(receiver));
                        assert!(binding_identity(receiver, &env, source).is_some());
                    }
                    members += 1;
                }
                if node.kind() == "identifier"
                    && node.utf8_text(source.as_bytes()).unwrap() == "i"
                    && let BindingOfOutcome::Shadowed { winner, .. } =
                        binding_of(&env, "i", node.start_byte(), Some(Namespace::Value))
                {
                    assert_eq!(binding_identity(node, &env, source), Some(winner));
                    shadowed += 1;
                }
            }
            assert_eq!(assignments, 1);
            if language == Language::Cpp {
                assert!(shadowed > 0);
            } else {
                assert_eq!(members, 3);
            }
        }
    }

    #[test]
    fn loop_ranges_follow_source_order_and_unicode_coordinates() {
        let source = "// lambda: \u{03bb}\nvoid f() {\n for (int i=0; i<10; ++i) {\n  for (; i<5; ++i) {}\n }\n}";
        let (candidates, _) = facts(Language::Cpp, source);
        let ranges = candidates
            .rows
            .iter()
            .map(|row| {
                let c = row.coordinates;
                let b = row.body_coordinates.unwrap();
                (
                    (c.start_line, c.start_column, c.end_line, c.end_column),
                    (b.start_line, b.start_column, b.end_line, b.end_column),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ranges,
            [
                ((3, 2, 5, 3), (3, 27, 5, 3)),
                ((4, 3, 4, 22), (4, 20, 4, 22))
            ]
        );
    }
}
