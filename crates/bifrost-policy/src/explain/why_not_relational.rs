//! `why-not` for a relational assertion policy: decide, per authored row
//! binding, whether one explicit candidate's row is a member of that binding's
//! relation.
//!
//! # What this adapter answers, and what it does not
//!
//! A relational plan is a set of named row relations, joined and grouped, with
//! assertions over the aggregates. A candidate can fail to produce a finding at
//! three different levels:
//!
//! 1. its row is not in some binding's relation at all;
//! 2. its row is in every binding but the join or the group key does not put it
//!    in a violated group;
//! 3. the aggregate over its group satisfies the authored cardinality.
//!
//! This slice answers level 1 exactly, by re-executing each binding's query the
//! way the relational driver executes it and reusing the milestone-5 prefix
//! walk to name the *stage inside that binding* that dropped the candidate.
//! Levels 2 and 3 need a join-level replay, which this slice does not attempt;
//! when every binding retains the candidate the root outcome is `unknown` and
//! carries an explicit `join_replay_unavailable` node, never a `satisfied` that
//! would overclaim.
//!
//! # Failed versus unknown
//!
//! Exactly the milestone-5 rule, applied per binding: a binding is `failed`
//! only when its query completed and declared itself exhaustive and the
//! candidate was still not there. A non-exhaustive query, an unexecutable
//! prefix, or a row expansion this adapter does not replay is `unknown`.
//!
//! # Bounds
//!
//! Every binding's prefix walk draws on one shared execution budget
//! (`ExplanationLimits::max_prefix_executions`), and the walk stops at the
//! first binding that does not retain the candidate. What the budget cut is
//! reported through the root's `children_truncated` pair.

use crate::budget::PolicyBudget;
use crate::definition::{
    PolicyAnalysisType, RelationalAssertionPlan, RowBinding, RowBindingSource,
    relational_binding_selector_path,
};
use crate::evaluator::PolicyEvaluationContext;
use crate::finding::{PolicyIncompleteReason, PolicySourceLocation};
use crate::resolved::LoadedPolicy;

use super::model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNodeKind,
    ExplanationOutcome, ExplanationQuestion, ExplanationSubject, PolicyExplanation, RawNode,
    build_explanation,
};
use super::why_not::{ExplanationCandidate, PrefixExecution, StageWalk, run_prefixes, stage_node};

/// Explain why one explicit candidate is not reported by a relational
/// assertion policy.
///
/// The tree is rooted at the candidate and carries one `relation_binding` node
/// per authored binding, in plan order, each holding that binding's own
/// selector stages as children. The walk stops at the first binding that does
/// not retain the candidate.
///
/// # Errors
///
/// - [`ExplainError::RelationalPlanUnavailable`] when the assertion policy has
///   no row plan (the capture-oriented assertion families are a later slice).
/// - [`ExplainError::BindingSelectorUnavailable`] when the plan names a query
///   binding whose resolved selector the loaded policy does not carry.
/// - [`ExplainError::BudgetExhausted`] when `limits` allow no prefix execution
///   or cannot hold a root node.
pub(super) fn explain_relational_candidate(
    policy: &LoadedPolicy,
    plan: &RelationalAssertionPlan,
    context: &PolicyEvaluationContext<'_>,
    candidate: &ExplanationCandidate,
    budget: &PolicyBudget,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    if limits.max_prefix_executions() == 0 {
        return Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::PrefixExecutions,
        });
    }
    let walk = walk_bindings(policy, plan, context, candidate, budget, limits)?;
    let root = candidate_root(candidate, plan, walk);
    build_explanation(
        ExplanationQuestion::WhyNot,
        policy.definition().metadata.id.clone(),
        policy.semantic_hash(),
        PolicyAnalysisType::Assertion,
        ExplanationSubject::Candidate {
            path: candidate.path().as_str().to_string(),
            byte_start: candidate.byte_start(),
            byte_end: candidate.byte_end(),
        },
        root,
        limits,
    )
}

/// What one binding concluded about the candidate.
#[derive(Debug)]
struct BindingOutcome {
    name: String,
    outcome: ExplanationOutcome,
    actual: String,
    reasons: Vec<PolicyIncompleteReason>,
    /// The executed prefix walk, absent for a binding this adapter does not
    /// replay.
    walk: Option<StageWalk>,
}

/// Every binding that was decided, plus what the shared execution budget cut.
#[derive(Debug)]
struct BindingWalk {
    bindings: Vec<BindingOutcome>,
    /// Bindings the plan declares that were never reached.
    omitted_bindings: u64,
}

impl BindingWalk {
    fn decided(&self) -> Option<&BindingOutcome> {
        self.bindings
            .iter()
            .find(|binding| binding.outcome != ExplanationOutcome::Satisfied)
    }
    const fn truncated(&self) -> bool {
        self.omitted_bindings > 0
    }
}

fn walk_bindings(
    policy: &LoadedPolicy,
    plan: &RelationalAssertionPlan,
    context: &PolicyEvaluationContext<'_>,
    candidate: &ExplanationCandidate,
    budget: &PolicyBudget,
    limits: &ExplanationLimits,
) -> Result<BindingWalk, ExplainError> {
    let mut remaining = limits.max_prefix_executions();
    let mut bindings = Vec::with_capacity(plan.bindings.len());
    let mut index = 0;
    while index < plan.bindings.len() {
        let binding = &plan.bindings[index];
        if remaining == 0 {
            break;
        }
        let outcome = match &binding.source {
            RowBindingSource::Query(_) => {
                let query = binding_query(policy, binding)?;
                let walk = run_prefixes(
                    query,
                    context,
                    candidate,
                    budget,
                    remaining,
                    PrefixExecution::PreferWorkspace,
                    // The relational driver bounds every binding query by the
                    // pipeline row budget, not by the finding budget.
                    budget.query_limits().max_pipeline_rows,
                );
                remaining = remaining.saturating_sub(walk.executed());
                query_binding_outcome(binding, walk)
            }
            RowBindingSource::Expansion { from, step } => BindingOutcome {
                name: binding.name.as_str().to_string(),
                outcome: ExplanationOutcome::Unknown,
                actual: format!(
                    "the row expansion `{}` of binding `{from}` is not replayed by this adapter",
                    step.label()
                ),
                reasons: vec![PolicyIncompleteReason::CapabilityIncomplete],
                walk: None,
            },
        };
        let decided = outcome.outcome != ExplanationOutcome::Satisfied;
        bindings.push(outcome);
        index += 1;
        if decided {
            break;
        }
    }
    let omitted_bindings =
        u64::try_from(plan.bindings.len().saturating_sub(index)).unwrap_or(u64::MAX);
    Ok(BindingWalk {
        bindings,
        omitted_bindings,
    })
}

/// The resolved query one authored query binding executes.
fn binding_query<'a>(
    policy: &'a LoadedPolicy,
    binding: &RowBinding,
) -> Result<&'a brokk_bifrost_rql::structural::CodeQuery, ExplainError> {
    let path = relational_binding_selector_path(&binding.name);
    policy
        .resolved_selectors()
        .iter()
        .find(|selector| selector.path.as_str() == path)
        .map(|selector| &selector.query)
        .ok_or_else(|| ExplainError::BindingSelectorUnavailable {
            binding: binding.name.as_str().to_string(),
        })
}

fn query_binding_outcome(binding: &RowBinding, walk: StageWalk) -> BindingOutcome {
    let name = binding.name.as_str().to_string();
    let decided = walk.decided();
    let (outcome, actual, reasons) = match decided {
        Some(stage) => (
            stage.outcome(),
            match stage.outcome() {
                ExplanationOutcome::Failed => format!(
                    "the candidate's row is not in binding `{name}`: stage {} dropped it",
                    stage.label()
                ),
                _ => format!(
                    "binding `{name}` could not decide the candidate at stage {}",
                    stage.label()
                ),
            },
            Vec::new(),
        ),
        None if walk.prefixes_truncated() => (
            ExplanationOutcome::Unknown,
            format!(
                "the prefix-execution budget stopped binding `{name}` before its query was exhausted"
            ),
            vec![PolicyIncompleteReason::ReportRetentionBudget],
        ),
        None => (
            ExplanationOutcome::Satisfied,
            format!("binding `{name}` contains a row covering the candidate"),
            Vec::new(),
        ),
    };
    BindingOutcome {
        name,
        outcome,
        actual,
        reasons,
        walk: Some(walk),
    }
}

fn candidate_root(
    candidate: &ExplanationCandidate,
    plan: &RelationalAssertionPlan,
    walk: BindingWalk,
) -> RawNode {
    let decided = walk.decided();
    let all_retained = decided.is_none() && !walk.truncated();
    let root_outcome = match decided {
        Some(binding) => binding.outcome,
        // Membership in every binding is not a finding: the join, the group key
        // and the aggregate still stand between the row and a violation, and
        // this slice replays none of them.
        None => ExplanationOutcome::Unknown,
    };
    let actual = match decided {
        Some(binding) => match binding.outcome {
            ExplanationOutcome::Failed => format!(
                "the candidate's row is absent from row binding `{}`",
                binding.name
            ),
            _ => format!(
                "row binding `{}` could not decide the candidate",
                binding.name
            ),
        },
        None if walk.truncated() => String::from(
            "the prefix-execution limit stopped the walk before every row binding was tested",
        ),
        None => String::from(
            "every row binding contains a row covering the candidate; whether those rows join \
             into a violated group is not replayed by this slice",
        ),
    };

    let mut root = RawNode::new(
        ExplanationNodeKind::FindingProjection,
        root_outcome,
        "relational_candidate",
    )
    .with_expected(format!(
        "the candidate's row is a member of each of the plan's {} row binding(s)",
        plan.bindings.len()
    ))
    .with_actual(actual)
    .with_location(Some(PolicySourceLocation::artifact(
        candidate.path().clone(),
    )))
    .with_source_truncation(walk.truncated(), walk.omitted_bindings);

    for binding in walk.bindings {
        root.push_child(binding_node(binding, candidate));
    }
    if all_retained {
        root.push_child(
            RawNode::new(
                ExplanationNodeKind::CoverageObligation,
                ExplanationOutcome::Unknown,
                "join_replay_unavailable",
            )
            .with_expected("the plan's joins, group keys and aggregates are replayed")
            .with_actual(
                "this adapter decides row-binding membership only, so it cannot state whether \
                 the candidate's row reaches a violated group",
            )
            .with_reasons(vec![PolicyIncompleteReason::CapabilityIncomplete]),
        );
    }
    root
}

fn binding_node(binding: BindingOutcome, candidate: &ExplanationCandidate) -> RawNode {
    let mut node = RawNode::new(
        ExplanationNodeKind::RelationBinding,
        binding.outcome,
        binding.name,
    )
    .with_expected("the binding's relation contains a row covering the candidate")
    .with_actual(binding.actual)
    .with_location(Some(PolicySourceLocation::artifact(
        candidate.path().clone(),
    )))
    .with_reasons(binding.reasons);
    if let Some(walk) = binding.walk {
        let prefixes_truncated = walk.prefixes_truncated();
        let omitted_prefixes = walk.omitted_prefixes();
        for stage in walk.into_stages() {
            node.push_child(stage_node(stage, candidate));
        }
        node = node.with_source_truncation(prefixes_truncated, omitted_prefixes);
    }
    node
}
