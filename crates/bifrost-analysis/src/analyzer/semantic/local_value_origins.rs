//! Bounded exact local-copy origins over the production procedure CFG.
//!
//! Only the qualified Java adapter participates. Its callable, allocation and
//! invocation results have non-copy value kinds or AST shapes and never enter
//! the allowed set. Parentheses and conditional arms are followed through
//! exact Local edges, so a supported wrapper cannot hide an unsupported child.
//! Heap carriers must have a local-variable declaration mapping, excluding
//! Java's implicit-field carriers even when their uses look like identifiers.

use std::collections::{HashMap, HashSet};

use crate::CancellationToken;
use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::{Language, LanguageDialect, ProjectFile, WorkspaceAnalyzer};

use super::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, GenKillFacts, forward_reachability,
    reaching_definitions,
};
use super::type_flow::validate_prepared_syntax_source_for_procedure;
use super::{
    CallSiteId, EvidenceCompleteness, ProcedureHandle, ProgramPointId, ProofStatus, SemanticEffect,
    SemanticGapImpact, SemanticGapSubject, SemanticValueKind, SourceMappingKind, ValueFlowKind,
    ValueId,
};

#[derive(Clone, Copy, Debug)]
pub struct LocalConstantOriginLimits {
    pub max_depth: usize,
    pub max_work: usize,
    pub max_roots: usize,
    pub max_source_bytes: usize,
}

impl Default for LocalConstantOriginLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_work: 4096,
            max_roots: 16,
            max_source_bytes: 1_048_576,
        }
    }
}

/// No partial roots escape this boundary. All failures preserve the caller's
/// whole-store join, while budget exhaustion remains separately observable.
#[derive(Debug)]
pub struct LocalConstantOrigins {
    pub roots: Option<Vec<ValueId>>,
    pub work: usize,
    pub source_bytes: usize,
    pub budget_exhausted: bool,
    pub cancelled: bool,
}

#[derive(Clone, Copy)]
struct Definition {
    target: ValueId,
    source: Option<ValueId>,
    point: ProgramPointId,
    event: usize,
}

/// The point is observed before its Invoke event. Source mappings qualify
/// copy syntax; the CFG and exact ValueIds decide which definitions reach.
pub fn derive_local_constant_origins(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    value: ValueId,
    call: CallSiteId,
    limits: LocalConstantOriginLimits,
    cancellation: &CancellationToken,
) -> LocalConstantOrigins {
    let mut result = LocalConstantOrigins {
        roots: None,
        work: 0,
        source_bytes: 0,
        budget_exhausted: false,
        cancelled: cancellation.is_cancelled(),
    };
    if result.cancelled {
        return result;
    }
    let mut charge = |amount: usize| {
        if amount > limits.max_work.saturating_sub(result.work) {
            result.budget_exhausted = true;
            false
        } else {
            result.work += amount;
            result.cancelled = cancellation.is_cancelled();
            !result.cancelled
        }
    };
    // Java's local declaration and copy shapes are qualified here. Other
    // adapters retain their existing conservative key join.
    if procedure.artifact().key().language() != LanguageDialect::Standard(Language::Java) {
        return result;
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
        .map(|provider| {
            provider.structural_syntax_limited(&file, limits.max_source_bytes, Some(cancellation))
        });
    let syntax = match syntax {
        Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax,
        Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
            result.budget_exhausted = true;
            return result;
        }
        Some(StructuralSyntaxLimitedOutcome::Cancelled) => {
            result.cancelled = true;
            return result;
        }
        _ => return result,
    };
    let Ok(syntax) = validate_prepared_syntax_source_for_procedure(
        workspace,
        procedure,
        &file,
        syntax.into_inner(),
    ) else {
        return result;
    };
    result.source_bytes = syntax.source().len();
    let semantics = procedure.semantics();
    let point = semantics
        .call_site(call)
        .expect("validated store call")
        .point;
    let exact_node = |source| {
        let mapping = semantics.source_mapping(source)?;
        if mapping.kind != SourceMappingKind::Exact {
            return None;
        }
        let span = mapping.locator.anchor().span();
        let node = syntax.tree().root_node().named_descendant_for_byte_range(
            span.start_byte() as usize,
            span.end_byte() as usize,
        )?;
        (node.start_byte() == span.start_byte() as usize
            && node.end_byte() == span.end_byte() as usize
            && !node.has_error())
        .then_some(node)
    };
    let evidence_ok = |id| {
        semantics.evidence_row(id).is_some_and(|e| {
            e.proof == ProofStatus::Proven && e.completeness == EvidenceCompleteness::Complete
        })
    };
    let plain_assignment = |node: tree_sitter::Node<'_>| {
        node.kind() != "assignment_expression"
            || node
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "=")
    };
    if !charge(
        semantics
            .points()
            .len()
            .saturating_add(semantics.values().len()),
    ) {
        return result;
    }
    let mut allowed = HashSet::new();
    let mut constants = HashSet::new();
    for row in semantics.values() {
        if !evidence_ok(row.evidence) {
            continue;
        }
        let Some(node) = exact_node(row.source) else {
            continue;
        };
        let valid = match row.kind {
            SemanticValueKind::Constant => {
                if node.kind() == "string_literal" {
                    constants.insert(row.id);
                    true
                } else {
                    false
                }
            }
            SemanticValueKind::Local => {
                node.kind() == "identifier"
                    && node.parent().is_some_and(|parent| {
                        parent.kind() == "variable_declarator"
                            && parent.parent().is_some_and(|declaration| {
                                declaration.kind() == "local_variable_declaration"
                            })
                    })
            }
            SemanticValueKind::Temporary => {
                matches!(
                    node.kind(),
                    "identifier" | "parenthesized_expression" | "ternary_expression"
                ) || (node.kind() == "assignment_expression" && plain_assignment(node))
            }
            _ => false,
        };
        if valid {
            allowed.insert(row.id);
        }
    }
    let mut definitions = Vec::new();
    let mut by_target = HashMap::<ValueId, Vec<usize>>::new();
    let mut by_point = vec![Vec::new(); semantics.points().len()];
    // Undefined entry facts are essential: one initialized branch cannot
    // certify a variable whose other branch reaches the call uninitialized.
    for row in semantics.values() {
        let index = definitions.len();
        definitions.push(Definition {
            target: row.id,
            source: None,
            point: semantics.entry_point(),
            event: 0,
        });
        by_target.entry(row.id).or_default().push(index);
        by_point[semantics.entry_point().index()].push(index);
    }
    for p in semantics.points() {
        if !evidence_ok(p.evidence) {
            return result;
        }
        for (index, event) in p.events.iter().enumerate() {
            if !charge(1) {
                return result;
            }
            let pair = match event.effect {
                SemanticEffect::Assignment { target, value } => Some((target, Some(value))),
                SemanticEffect::ValueFlow {
                    target,
                    source,
                    kind: ValueFlowKind::Local,
                } => {
                    // The second row repeats the assignment's dependence. It
                    // must not become a second, independently exact producer.
                    if index > 0
                        && matches!(p.events[index-1].effect, SemanticEffect::Assignment { target: t, value: v } if t == target && v == source)
                    {
                        continue;
                    }
                    Some((target, Some(source)))
                }
                SemanticEffect::ValueFlow { target, .. } => Some((target, None)),
                SemanticEffect::MemoryLoad { result, .. } => Some((result, None)),
                SemanticEffect::Gap { gap } => {
                    let gap = semantics.gap(gap).expect("validated gap");
                    if gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                        || matches!(
                            gap.subject,
                            SemanticGapSubject::Procedure | SemanticGapSubject::Point
                        )
                    {
                        return result;
                    }
                    if let SemanticGapSubject::Value(value) = gap.subject {
                        allowed.remove(&value);
                    }
                    None
                }
                _ => None,
            };
            if let Some((target, mut source)) = pair {
                if !evidence_ok(event.evidence)
                    || !exact_node(event.source).is_some_and(plain_assignment)
                    || (matches!(event.effect, SemanticEffect::Assignment { .. })
                        && p.assignment_has_transfer_marker(index))
                {
                    source = None;
                }
                let id = definitions.len();
                definitions.push(Definition {
                    target,
                    source,
                    point: p.id,
                    event: index,
                });
                by_target.entry(target).or_default().push(id);
                by_point[p.id.index()].push(id);
            }
        }
    }
    // A bounded dense product also bounds the gen/kill and reaching bitsets.
    if !charge(
        semantics
            .points()
            .len()
            .saturating_mul(definitions.len().div_ceil(64)),
    ) {
        return result;
    }
    let mut facts = GenKillFacts::new(semantics.points().len(), definitions.len());
    for (point_index, ids) in by_point.iter().enumerate() {
        let mut last = HashMap::new();
        for id in ids {
            last.insert(definitions[*id].target, *id);
        }
        for (target, id) in last {
            for killed in &by_target[&target] {
                if !charge(1) {
                    return result;
                }
                facts.record_killed(point_index, *killed);
            }
            facts.record_generated(point_index, id);
        }
    }
    for edge in semantics.control_edges() {
        if !charge(1) || !evidence_ok(edge.evidence) {
            return result;
        }
    }
    let remaining = limits.max_work.saturating_sub(result.work) / 2;
    let mut budget = CfgAlgorithmBudget::uniform(remaining);
    let mut request = CfgAlgorithmRequest::new(&mut budget, cancellation);
    let reachable = forward_reachability(semantics, semantics.entry_point(), &mut request);
    let reaching = reaching_definitions(semantics, semantics.entry_point(), &facts, &mut request);
    let work = budget.used();
    result.work += work.node_visits.saturating_add(work.edge_visits);
    let (reachable, reaching) = match (reachable, reaching) {
        (Ok(reachable), Ok(reaching)) => (reachable, reaching),
        (left, right) => {
            for failure in [left.err(), right.err()].into_iter().flatten() {
                match failure {
                    CfgAlgorithmError::Cancelled { .. } => result.cancelled = true,
                    CfgAlgorithmError::ExceededBudget(_) => result.budget_exhausted = true,
                    CfgAlgorithmError::InvalidNode(node) => {
                        panic!("validated procedure CFG contains invalid node {node:?}")
                    }
                }
            }
            return result;
        }
    };
    if !reachable.contains(semantics, point) {
        return result;
    }
    let query_point = semantics.point(point).expect("validated query point");
    let Some(event_limit) = query_point.events.iter().position(
        |event| matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == call),
    ) else {
        return result;
    };
    #[derive(Clone, Copy, Hash, PartialEq, Eq)]
    struct State {
        value: ValueId,
        point: ProgramPointId,
        event: usize,
    }
    enum Visit {
        Enter(State, usize),
        Leave(State),
    }
    let mut stack = vec![Visit::Enter(
        State {
            value,
            point,
            event: event_limit,
        },
        0,
    )];
    let mut active = HashSet::new();
    let mut complete = HashSet::new();
    let mut roots = HashMap::new();
    while let Some(visit) = stack.pop() {
        if cancellation.is_cancelled() {
            result.cancelled = true;
            return result;
        }
        if result.work >= limits.max_work {
            result.budget_exhausted = true;
            return result;
        }
        result.work += 1;
        let (state, depth) = match visit {
            Visit::Leave(state) => {
                active.remove(&state);
                complete.insert(state);
                continue;
            }
            Visit::Enter(state, depth) => (state, depth),
        };
        if depth > limits.max_depth {
            result.budget_exhausted = true;
            return result;
        }
        if !allowed.contains(&state.value) {
            return result;
        }
        if constants.contains(&state.value) {
            let row = semantics.value(state.value).expect("validated constant");
            let node = exact_node(row.source).expect("qualified constant source");
            let token = &syntax.source()[node.byte_range()];
            roots.entry(token).or_insert(state.value);
            if roots.len() > limits.max_roots {
                result.budget_exhausted = true;
                return result;
            }
            continue;
        }
        if complete.contains(&state) {
            continue;
        }
        if !active.insert(state) {
            return result;
        }
        stack.push(Visit::Leave(state));
        let search_work = by_point[state.point.index()]
            .len()
            .saturating_add(by_target.get(&state.value).map_or(0, Vec::len));
        if search_work > limits.max_work.saturating_sub(result.work) {
            result.budget_exhausted = true;
            return result;
        }
        result.work += search_work;
        let local = by_point[state.point.index()]
            .iter()
            .rev()
            .find(|id| {
                let d = definitions[**id];
                d.target == state.value
                    && d.event < state.event
                    && d.point != semantics.entry_point()
            })
            .copied();
        let candidates: Vec<_> = if let Some(id) = local {
            vec![id]
        } else {
            by_target
                .get(&state.value)
                .into_iter()
                .flatten()
                .copied()
                .filter(|id| reaching.reaches_in(state.point.index(), *id))
                .collect()
        };
        if candidates.is_empty() {
            return result;
        }
        for id in candidates {
            let d = definitions[id];
            let Some(source) = d.source else {
                return result;
            };
            stack.push(Visit::Enter(
                State {
                    value: source,
                    point: d.point,
                    event: d.event,
                },
                depth + 1,
            ));
        }
    }
    if !roots.is_empty() {
        let mut roots: Vec<_> = roots.into_values().collect();
        roots.sort_unstable();
        result.roots = Some(roots);
    }
    result
}
