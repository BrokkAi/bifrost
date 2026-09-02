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
//! 1. its row is not in some binding's relation at all, either because the
//!    binding's query never returned it or because a `filter` the plan attaches
//!    directly to that binding removed it;
//! 2. its row is in every binding but the join or the group key does not put it
//!    in a violated group;
//! 3. the aggregate over its group satisfies the authored cardinality.
//!
//! This adapter answers level 1 exactly. It re-executes each binding's query
//! the way the relational driver executes it, reusing the milestone-5 prefix
//! walk to name the *stage inside that binding* that dropped the candidate,
//! and then replays every `filter` record whose input chain reaches that
//! binding without crossing a join or a group, against the rows the binding's
//! query actually returned for the candidate. Levels 2 and 3 need a join-level
//! replay, which this adapter does not attempt; when every binding retains the
//! candidate the root outcome is `unknown` and carries an explicit
//! `join_replay_unavailable` node, never a `satisfied` that would overclaim.
//!
//! # Failed versus unknown
//!
//! Exactly the milestone-5 rule, applied per binding: a binding is `failed`
//! only when its query completed and declared itself exhaustive, every
//! relevant later prefix was exhaustive, and the candidate was still not there.
//! A non-exhaustive prefix, a prefix omitted by the execution budget, or a row
//! expansion this adapter does not replay is `unknown`.
//!
//! A filter replay obeys the same rule for the same reason. A located row that
//! fails a predicate is definitely removed, but a non-exhaustive query may have
//! left out another row covering the candidate that would have passed, so a
//! filter drop is `failed` only over an exhaustive, untruncated row set and is
//! `unknown` otherwise. A predicate that cannot be read against a row is
//! `unknown` with `capability_incomplete`, never a panic.
//!
//! # Bounds
//!
//! Every binding's prefix walk and every filter relation it replays draw on one
//! shared execution budget (`ExplanationLimits::max_prefix_executions`), one
//! unit each, and the walk stops at the first binding that does not retain the
//! candidate. What the budget cut is reported through the root's
//! `children_truncated` pair.

use brokk_bifrost_rql::structural::CodeQueryResultValue;

use crate::budget::PolicyBudget;
use crate::definition::{
    PolicyAnalysisType, RelationalAssertionPlan, RowBinding, RowBindingName, RowBindingSource,
    relational_binding_selector_path,
};
use crate::evaluator::PolicyEvaluationContext;
use crate::finding::{PolicyIncompleteReason, PolicySourceLocation};
use crate::relational::{
    IrColumn, IrPredicate, IrRelationOp, RelationalAssertionEvaluationError, RelationalPlanIr,
    ReplayRow, RowScalar, lower_relational_assertion_plan,
};
use crate::resolved::LoadedPolicy;

use super::model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNodeKind,
    ExplanationOutcome, ExplanationQuestion, ExplanationSubject, PolicyExplanation, RawNode,
    build_explanation,
};
use super::why_not::{
    ExplanationCandidate, LocatedRows, PrefixExecution, StageWalk, run_prefixes, stage_node,
};

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
    // Every loaded policy was lowered and validated by the source decoder, so a
    // plan that reaches an explanation lowers again.
    let ir = lower_relational_assertion_plan(plan)
        .expect("a loaded relational assertion plan lowers to its IR");
    let lineages = binding_lineages(&ir);
    let walk = walk_bindings(
        policy, plan, &ir, &lineages, context, candidate, budget, limits,
    )?;
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
    /// One entry per located row a replayed filter removed, present only when
    /// every located row was removed.
    dropped: Vec<DroppedRow>,
    /// Filter relations the shared execution budget did not reach.
    omitted_filters: u64,
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

#[allow(clippy::too_many_arguments)]
fn walk_bindings(
    policy: &LoadedPolicy,
    plan: &RelationalAssertionPlan,
    ir: &RelationalPlanIr,
    lineages: &[Option<BindingLineage>],
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
                let verdict = if walk.decided().is_none() && !walk.prefixes_truncated() {
                    replay_filters(ir, lineages, &binding.name, walk.located(), &mut remaining)
                } else {
                    FilterVerdict::Retained
                };
                query_binding_outcome(binding, walk, verdict)
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
                dropped: Vec::new(),
                omitted_filters: 0,
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
        .and_then(|selector| selector.as_query().map(|(_, query)| query))
        .ok_or_else(|| ExplainError::BindingSelectorUnavailable {
            binding: binding.name.as_str().to_string(),
        })
}

/// One relation that derives from exactly one row binding without a join or a
/// group in between, and the row field each of its columns reads.
///
/// A `filter` over such a relation tests that binding's own rows, so it can be
/// replayed against one located row. A projection between the two republishes
/// the columns under its own name, which is why the row field each column
/// reads is carried beside the column.
#[derive(Debug, Clone)]
struct BindingLineage {
    binding: RowBindingName,
    columns: Vec<(IrColumn, String)>,
}

impl BindingLineage {
    fn field_of(&self, column: &IrColumn) -> &str {
        self.columns
            .iter()
            .find(|(candidate, _)| candidate == column)
            .map(|(_, field)| field.as_str())
            .expect("a lowered projection source is a column of its input")
    }
}

/// The lineage of every relation of the plan, indexed by relation id.
///
/// Relations are ordered so that an operator's inputs have smaller ids than the
/// operator, so one forward pass decides every relation. A join or a group
/// ends a lineage: past either, a row is no longer one binding's row.
fn binding_lineages(plan: &RelationalPlanIr) -> Vec<Option<BindingLineage>> {
    let mut lineages: Vec<Option<BindingLineage>> = Vec::with_capacity(plan.relations.len());
    for relation in &plan.relations {
        let lineage = match &relation.op {
            IrRelationOp::Source { binding, .. } | IrRelationOp::Expand { binding, .. } => {
                Some(BindingLineage {
                    binding: binding.clone(),
                    columns: relation
                        .schema
                        .fields()
                        .iter()
                        .map(|field| (field.column.clone(), field.column.name.clone()))
                        .collect(),
                })
            }
            // A filter republishes its input's schema unchanged.
            IrRelationOp::Filter { input, .. } => lineages[input.index()].clone(),
            IrRelationOp::Project { input, columns } => {
                lineages[input.index()]
                    .as_ref()
                    .map(|input| BindingLineage {
                        binding: input.binding.clone(),
                        columns: columns
                            .iter()
                            .map(|projection| {
                                (
                                    projection.output.clone(),
                                    input.field_of(&projection.source).to_string(),
                                )
                            })
                            .collect(),
                    })
            }
            IrRelationOp::Join { .. } | IrRelationOp::Group { .. } => None,
        };
        lineages.push(lineage);
    }
    lineages
}

/// One located row a replayed filter removed.
#[derive(Debug)]
struct DroppedRow {
    predicate: String,
    column: IrColumn,
    value: Option<RowScalar>,
}

/// What replaying one binding's directly attached filters concluded.
#[derive(Debug)]
enum FilterVerdict {
    /// No filter is established to have removed the candidate from the
    /// binding. Either a located row survived every replayed filter, or the
    /// stage walk retained the candidate through a provenance path whose own
    /// rows do not cover it and there was nothing to replay. The second case
    /// keeps the pre-replay answer rather than claiming a drop it cannot show.
    Retained,
    /// Every located row was removed, each by the first filter predicate it
    /// failed.
    Dropped(Vec<DroppedRow>),
    /// The shared execution budget stopped the replay with filters left.
    Truncated(u64),
    /// A predicate could not be read against a located row.
    Unreadable(RelationalAssertionEvaluationError),
}

/// Replay every `filter` the plan attaches directly to `binding` against the
/// rows its query returned for the candidate.
///
/// Filters run in relation-id order, which is authored derivation order, and a
/// row leaves the replay at the first filter that removes it. Each filter
/// relation costs one unit of the shared execution budget, whatever the number
/// of rows it tests, because the unit measures the plan work replayed and not
/// the rows the candidate happens to occupy.
fn replay_filters(
    plan: &RelationalPlanIr,
    lineages: &[Option<BindingLineage>],
    binding: &RowBindingName,
    located: &LocatedRows,
    remaining: &mut usize,
) -> FilterVerdict {
    let filters = plan
        .relations
        .iter()
        .filter_map(|relation| {
            let IrRelationOp::Filter { predicates, .. } = &relation.op else {
                return None;
            };
            let lineage = lineages[relation.id.index()].as_ref()?;
            (lineage.binding == *binding).then_some((lineage, predicates.as_slice()))
        })
        .collect::<Vec<_>>();

    let mut surviving = located
        .rows()
        .iter()
        .collect::<Vec<&CodeQueryResultValue>>();
    let mut dropped = Vec::new();
    for (index, (lineage, predicates)) in filters.iter().enumerate() {
        if *remaining == 0 {
            return FilterVerdict::Truncated(
                u64::try_from(filters.len().saturating_sub(index)).unwrap_or(u64::MAX),
            );
        }
        *remaining -= 1;
        let mut kept = Vec::with_capacity(surviving.len());
        for row in surviving {
            match drop_reason(lineage, predicates, row) {
                Ok(Some(reason)) => dropped.push(reason),
                Ok(None) => kept.push(row),
                Err(error) => return FilterVerdict::Unreadable(error),
            }
        }
        surviving = kept;
        if surviving.is_empty() {
            break;
        }
    }
    if surviving.is_empty() && !dropped.is_empty() {
        FilterVerdict::Dropped(dropped)
    } else {
        FilterVerdict::Retained
    }
}

/// The first predicate of one filter that `row` fails, with the value the row
/// carried for the column that predicate tests.
fn drop_reason(
    lineage: &BindingLineage,
    predicates: &[IrPredicate],
    row: &CodeQueryResultValue,
) -> Result<Option<DroppedRow>, RelationalAssertionEvaluationError> {
    let replay = ReplayRow::new(&lineage.columns, row.row())?;
    let Some(predicate) = replay.first_failed_predicate(predicates)? else {
        return Ok(None);
    };
    Ok(Some(DroppedRow {
        predicate: predicate.to_string(),
        column: predicate.column().clone(),
        value: replay.value(predicate.column())?,
    }))
}

fn query_binding_outcome(
    binding: &RowBinding,
    walk: StageWalk,
    verdict: FilterVerdict,
) -> BindingOutcome {
    let name = binding.name.as_str().to_string();
    let decided = walk.decided();
    let exhaustive = walk.located().exhaustive();
    let mut dropped = Vec::new();
    let mut omitted_filters = 0;
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
        None => match verdict {
            FilterVerdict::Retained => (
                ExplanationOutcome::Satisfied,
                format!("binding `{name}` contains a row covering the candidate"),
                Vec::new(),
            ),
            FilterVerdict::Dropped(rows) => {
                let predicate = rows[0].predicate.clone();
                dropped = rows;
                if exhaustive {
                    (
                        ExplanationOutcome::Failed,
                        format!(
                            "the candidate's row is not in binding `{name}`: filter {predicate} \
                             removed it"
                        ),
                        Vec::new(),
                    )
                } else {
                    (
                        ExplanationOutcome::Unknown,
                        format!(
                            "filter {predicate} removed every row binding `{name}` returned for \
                             the candidate, but that query was not exhaustive"
                        ),
                        walk.located().reasons().to_vec(),
                    )
                }
            }
            FilterVerdict::Truncated(omitted) => {
                omitted_filters = omitted;
                (
                    ExplanationOutcome::Unknown,
                    format!(
                        "the prefix-execution budget stopped binding `{name}` before its filters \
                         were replayed"
                    ),
                    vec![PolicyIncompleteReason::ReportRetentionBudget],
                )
            }
            FilterVerdict::Unreadable(error) => (
                ExplanationOutcome::Unknown,
                format!("a filter over binding `{name}` could not be replayed: {error}"),
                vec![PolicyIncompleteReason::CapabilityIncomplete],
            ),
        },
    };
    BindingOutcome {
        name,
        outcome,
        actual,
        reasons,
        walk: Some(walk),
        dropped,
        omitted_filters,
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
    let outcome = binding.outcome;
    let reasons = binding.reasons;
    let mut node = RawNode::new(ExplanationNodeKind::RelationBinding, outcome, binding.name)
        .with_expected("the binding's relation contains a row covering the candidate")
        .with_actual(binding.actual)
        .with_location(Some(PolicySourceLocation::artifact(
            candidate.path().clone(),
        )))
        .with_reasons(reasons.clone());
    if let Some(walk) = binding.walk {
        let prefixes_truncated = walk.prefixes_truncated();
        let omitted_prefixes = walk.omitted_prefixes();
        for stage in walk.into_stages() {
            node.push_child(stage_node(stage, candidate));
        }
        node = node.with_source_truncation(prefixes_truncated, omitted_prefixes);
    }
    for dropped in binding.dropped {
        node.push_child(
            RawNode::new(ExplanationNodeKind::FilterPredicate, outcome, "filter")
                .with_expected(dropped.predicate)
                .with_actual(format!(
                    "`{}` is {}",
                    dropped.column,
                    dropped
                        .value
                        .map_or_else(|| String::from("absent"), |value| value.to_string())
                ))
                .with_location(Some(PolicySourceLocation::artifact(
                    candidate.path().clone(),
                )))
                .with_reasons(reasons.clone()),
        );
    }
    node.with_source_truncation(binding.omitted_filters > 0, binding.omitted_filters)
}
