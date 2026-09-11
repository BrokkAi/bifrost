//! Replay the candidate's initial binding, then its joins and group keys.
//!
//! Only the initial binding must cover the candidate's source position. Right
//! bindings are addressed by typed join keys; a row at a different position is
//! a valid witness. Query coverage and row-engine bounds remain proof
//! obligations, including when an anti join retained an unwitnessed row.

use crate::budget::PolicyBudget;
use crate::definition::{
    PolicyAnalysisType, RelationalAssertionPlan, RowBinding, relational_binding_selector_path,
};
use crate::evaluator::PolicyEvaluationContext;
use crate::finding::{PolicyIncompleteReason, PolicySourceLocation};
use crate::relational::{
    RelationCoverage, RelationalAssertionEvaluationError, ReplayConstraints, ReplayInput,
    RowScalar, lower_relational_assertion_plan, replay_candidate_ir,
};
use crate::resolved::LoadedPolicy;
use brokk_bifrost_rql::structural::search::{
    UnitRowItem, execute_code_query_detailed_eager_index,
    execute_code_query_detailed_eager_index_workspace,
};
use brokk_bifrost_rql::structural::{CodeQuery, CodeQueryResultDetail};
use brokk_bifrost_rql::{
    QueryRowLiteral, QueryRowPredicate, QueryRowPredicateOp, QueryRowPredicateOperand, QueryStep,
};

use super::model::{
    ExplainError, ExplanationBudgetLimit, ExplanationLimits, ExplanationNodeKind,
    ExplanationOutcome, ExplanationQuestion, ExplanationSubject, PolicyExplanation, RawNode,
    build_explanation,
};
use super::why_not::{ExplanationCandidate, PrefixExecution, run_prefixes, stage_node};

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
    let binding = plan
        .bindings
        .first()
        .expect("validated row plan has an initial binding");
    let mut walk = run_prefixes(
        binding_query(policy, binding)?,
        context,
        candidate,
        budget,
        limits.max_prefix_executions(),
        PrefixExecution::PreferWorkspace,
        budget.query_limits().max_pipeline_rows,
    );
    let remaining_prefixes = limits
        .max_prefix_executions()
        .saturating_sub(walk.executed());
    let decided = walk.decided();
    let binding_outcome = decided.map_or_else(
        || {
            if walk.prefixes_truncated() {
                ExplanationOutcome::Unknown
            } else {
                ExplanationOutcome::Satisfied
            }
        },
        |stage| stage.outcome(),
    );
    let binding_actual = decided.map_or_else(
        || format!("binding `{}` retains the candidate", binding.name),
        |stage| {
            format!(
                "binding `{}`: stage {} {}",
                binding.name,
                stage.label(),
                if stage.outcome() == ExplanationOutcome::Failed {
                    "dropped it"
                } else {
                    "could not decide the candidate"
                }
            )
        },
    );
    let mut root = RawNode::new(
        ExplanationNodeKind::FindingProjection,
        binding_outcome,
        "relational_candidate",
    )
    .with_expected("the candidate reaches a group with a violated assertion")
    .with_actual(if binding_outcome == ExplanationOutcome::Failed {
        format!(
            "the candidate's row is absent from row binding `{}`",
            binding.name
        )
    } else {
        binding_actual.clone()
    })
    .with_location(Some(PolicySourceLocation::artifact(
        candidate.path().clone(),
    )))
    .with_source_truncation(walk.prefixes_truncated(), walk.omitted_prefixes());
    let binding_reasons = decided.map_or_else(Vec::new, |stage| stage.reasons().to_vec());
    let seed = ReplayInput {
        rows: std::mem::take(&mut walk.terminal_rows),
        coverage: walk.terminal_coverage.clone(),
    };
    let candidate_rows = std::mem::take(&mut walk.candidate_rows);
    let mut binding_node = RawNode::new(
        ExplanationNodeKind::RelationBinding,
        binding_outcome,
        binding.name.as_str(),
    )
    .with_actual(binding_actual)
    .with_reasons(binding_reasons);
    for stage in walk.into_stages() {
        binding_node.push_child(stage_node(stage, candidate));
    }
    root.push_child(binding_node);

    if binding_outcome == ExplanationOutcome::Satisfied {
        let ir = lower_relational_assertion_plan(plan).map_err(|error| {
            ExplainError::PolicyUnavailable {
                message: error.to_string(),
            }
        })?;
        let mut remaining = limits.max_relation_executions().min(remaining_prefixes);
        let mut omitted_queries = 0u64;
        let mut load = |name: &crate::definition::RowBindingName,
                        constraints: &ReplayConstraints| {
            if remaining == 0 {
                omitted_queries = omitted_queries.saturating_add(1);
                return Ok(ReplayInput {
                    rows: Vec::new(),
                    coverage: RelationCoverage::incomplete(vec![
                        PolicyIncompleteReason::ReportRetentionBudget,
                    ]),
                });
            }
            remaining -= 1;
            let binding = plan
                .bindings
                .iter()
                .find(|binding| binding.name == *name)
                .expect("IR source has an authored binding");
            let mut query = binding_query(policy, binding)
                .map_err(|error| RelationalAssertionEvaluationError::InvalidPlan {
                    message: error.to_string(),
                })?
                .clone();
            let predicates = constraints
                .iter()
                .map(|(column, value)| key_predicate(&column.name, value))
                .collect::<Vec<_>>();
            if !predicates.is_empty() {
                if let Some(QueryStep::Filter(existing)) = query.plan.steps.last_mut() {
                    existing.extend(predicates);
                } else {
                    query.plan.steps.push(QueryStep::Filter(predicates));
                }
            }
            query.result_detail = CodeQueryResultDetail::Full;
            query.limit = budget.query_limits().max_pipeline_rows;
            let detailed = if let Some(workspace) = context.workspace {
                execute_code_query_detailed_eager_index_workspace(
                    workspace,
                    &query,
                    budget.query_limits(),
                    context.cancellation,
                )
            } else {
                execute_code_query_detailed_eager_index(
                    context.analyzer,
                    &query,
                    budget.query_limits(),
                    context.cancellation,
                )
            };
            let rows = detailed
                .result
                .results
                .iter()
                .map(UnitRowItem::project)
                .collect::<Vec<_>>();
            let coverage = RelationCoverage::from_query(
                &rows,
                &detailed.result.completion(),
                detailed.result.truncated,
            );
            Ok(ReplayInput { rows, coverage })
        };
        let replay =
            replay_candidate_ir(&ir, seed, &candidate_rows, &mut load, context.cancellation);
        match replay {
            Ok(replay) => {
                root.outcome = replay.outcome;
                root.actual = Some(match replay.outcome {
                    ExplanationOutcome::Satisfied => "the candidate reaches a witnessed violated group",
                    ExplanationOutcome::Failed => "a join removes the candidate or its group satisfies the assertion",
                    ExplanationOutcome::Unknown => "coverage or a replay limit prevents deciding the candidate's violated group",
                }.to_string());
                for observation in replay.observations {
                    let reasons = observation.reasons;
                    let mut node = RawNode::new(
                        ExplanationNodeKind::SelectorStage,
                        observation.outcome,
                        observation.label,
                    )
                    .with_actual(observation.actual)
                    .with_reasons(reasons.clone());
                    if let Some(representative) = observation.representative {
                        node.push_child(
                            RawNode::new(
                                ExplanationNodeKind::SourceFact,
                                ExplanationOutcome::Satisfied,
                                "representative",
                            )
                            .with_actual(representative),
                        );
                    }
                    if !reasons.is_empty() {
                        node.push_child(
                            RawNode::new(
                                ExplanationNodeKind::CoverageObligation,
                                ExplanationOutcome::Unknown,
                                "relation_coverage",
                            )
                            .with_expected("exhaustive coverage for the requested key")
                            .with_reasons(reasons),
                        );
                    }
                    root.push_child(node);
                }
            }
            Err(RelationalAssertionEvaluationError::Cancelled) => {
                root = RawNode::new(
                    ExplanationNodeKind::FindingProjection,
                    ExplanationOutcome::Unknown,
                    "relational_candidate",
                )
                .with_actual("candidate replay was cancelled")
                .with_reasons(vec![PolicyIncompleteReason::Cancelled]);
            }
            Err(error) => {
                return Err(ExplainError::PolicyUnavailable {
                    message: error.to_string(),
                });
            }
        }
        if omitted_queries > 0 {
            root.children_truncated = true;
            root.omitted_children_lower_bound = omitted_queries;
            root.actual
                .as_mut()
                .expect("root has a conclusion")
                .push_str(
                    "; the prefix-execution limit or relation-execution limit omitted key queries",
                );
        }
    }
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

fn binding_query<'a>(
    policy: &'a LoadedPolicy,
    binding: &RowBinding,
) -> Result<&'a CodeQuery, ExplainError> {
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

fn key_predicate(field: &str, value: &Option<RowScalar>) -> QueryRowPredicate {
    let Some(value) = value else {
        return QueryRowPredicate {
            field: field.to_string(),
            op: QueryRowPredicateOp::IsNull,
            operand: QueryRowPredicateOperand::None,
        };
    };
    let literal = match value {
        RowScalar::StableId(value)
        | RowScalar::String(value)
        | RowScalar::DeclarationIdentity(value) => QueryRowLiteral::String(value.clone()),
        RowScalar::ConstrainedEnum(value) => QueryRowLiteral::ConstrainedEnum(value.clone()),
        RowScalar::Integer(value) => QueryRowLiteral::Integer(*value),
        RowScalar::Boolean(value) => QueryRowLiteral::Boolean(*value),
    };
    QueryRowPredicate {
        field: field.to_string(),
        op: QueryRowPredicateOp::Eq,
        operand: QueryRowPredicateOperand::Literal(literal),
    }
}
