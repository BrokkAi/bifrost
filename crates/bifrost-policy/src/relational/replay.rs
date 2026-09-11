//! Candidate and group-key replay over the ordinary row evaluator.
//!
//! Source callbacks execute bounded queries with typed equality constraints.
//! A join requests only keys carried by its left input. Group replay starts
//! again with all peers of the candidate's key, rather than counting just the
//! candidate. No replay state is used by normal policy evaluation.

use super::*;
use crate::explain::ExplanationOutcome;

pub(crate) type ReplayConstraints = Vec<(IrColumn, Option<RowScalar>)>;

#[derive(Debug)]
pub(crate) struct ReplayInput {
    pub rows: Vec<UnitRowItem>,
    pub coverage: RelationCoverage,
}

#[derive(Debug)]
pub(crate) struct ReplayObservation {
    pub label: String,
    pub outcome: ExplanationOutcome,
    pub actual: String,
    pub reasons: Vec<PolicyIncompleteReason>,
    pub representative: Option<String>,
}

#[derive(Debug)]
pub(crate) struct CandidateReplay {
    pub outcome: ExplanationOutcome,
    pub observations: Vec<ReplayObservation>,
}

/// Replay a lowered left-deep plan. The source row indexes are the candidate's
/// structured lineage in the first binding, not indexes into other bindings.
pub(crate) fn replay_candidate_ir(
    plan: &RelationalPlanIr,
    seed: ReplayInput,
    candidate_rows: &[usize],
    load: &mut impl FnMut(&RowBindingName, &ReplayConstraints) -> EvalResult<ReplayInput>,
    cancellation: Option<&CancellationToken>,
) -> EvalResult<CandidateReplay> {
    // This boundary accepts the lowered source/join/group form, including the
    // IR-only left join. Fail at construction if a caller bypasses lowering.
    let mut chain = IrRelationId(0);
    for relation in &plan.relations {
        match &relation.op {
            IrRelationOp::Source { .. } => {}
            IrRelationOp::Join { left, right, .. } => {
                assert_eq!(*left, chain, "candidate replay requires a left-deep plan");
                assert!(matches!(
                    plan.relations[right.index()].op,
                    IrRelationOp::Source { .. }
                ));
                chain = relation.id;
            }
            IrRelationOp::Group { input, .. } => assert_eq!(*input, chain),
            IrRelationOp::Project { .. } | IrRelationOp::Filter { .. } => {
                return Err(RelationalAssertionEvaluationError::InvalidPlan {
                    message: "candidate replay requires query-local projections and filters in source bindings".to_string(),
                });
            }
        }
    }
    let mut state = EvalState {
        limits: plan.limits,
        comparisons: 0,
        limit_exceeded: false,
        work: RelationalEvaluationWork::default(),
        cancellation,
    };
    state.check_cancelled()?;
    let mut observations = Vec::new();
    let first = &plan.relations[0];
    let mut source = materialize(plan, first.id, &seed, &mut state)?;
    source.tuples.retain(|tuple| {
        tuple
            .contributors
            .iter()
            .flatten()
            .any(|row| candidate_rows.contains(&row.row))
    });
    // This relation enumerates known candidate lineages. Its coverage still
    // records missing/unknown seed rows; presence never upgrades absence.
    let candidate = replay_chain(plan, source, load, &mut state, &mut observations)?;
    if candidate.tuples.is_empty() {
        let outcome = if candidate.coverage.is_exhaustive() {
            ExplanationOutcome::Failed
        } else {
            ExplanationOutcome::Unknown
        };
        if observations.is_empty() {
            observations.push(ReplayObservation {
                label: "candidate_rows".to_string(),
                outcome,
                actual: "no materialized row establishes the candidate's referenced fields"
                    .to_string(),
                reasons: candidate.coverage.incomplete_reasons(),
                representative: None,
            });
        }
        return Ok(CandidateReplay {
            outcome,
            observations,
        });
    }

    let mut verdicts = Vec::new();
    for relation in &plan.relations {
        let IrRelationOp::Group { by, aggregates, .. } = &relation.op else {
            continue;
        };
        let key_indices = by
            .iter()
            .map(|column| {
                candidate
                    .index_of(column)
                    .expect("validated group key is materialized")
            })
            .collect::<Vec<_>>();
        let mut keys = candidate
            .tuples
            .iter()
            .map(|tuple| {
                key_indices
                    .iter()
                    .map(|index| tuple.values[*index].clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        keys.sort();
        keys.dedup();
        for key in keys {
            state.check_cancelled()?;
            let candidate_witnessed = candidate.tuples.iter().any(|tuple| {
                tuple.witness_sound
                    && key_indices
                        .iter()
                        .zip(&key)
                        .all(|(index, value)| tuple.values[*index] == *value)
            });
            // Only constraints on the initial source can be pushed before a
            // left/anti join without changing its absence semantics. Remaining
            // columns are checked on joined tuples before folding the group.
            let constraints = by
                .iter()
                .cloned()
                .zip(key.iter().cloned())
                .filter(|(column, _)| first.schema.field(column).is_some())
                .collect();
            let IrRelationOp::Source { binding, .. } = &first.op else {
                unreachable!("a lowered row plan starts with its source")
            };
            let peers = load(binding, &constraints)?;
            let peers = materialize(plan, first.id, &peers, &mut state)?;
            let mut peers = replay_chain(plan, peers, load, &mut state, &mut Vec::new())?;
            peers.tuples.retain(|tuple| {
                key_indices
                    .iter()
                    .zip(&key)
                    .all(|(index, value)| tuple.values[*index] == *value)
            });
            let grouped = evaluate_group(
                &peers,
                by,
                aggregates,
                &binding_declaration_order(plan),
                &mut state,
            )?;
            for assertion in plan
                .assertions
                .iter()
                .filter(|assertion| assertion.relation == relation.id)
            {
                let value_index = grouped
                    .index_of(&assertion.column)
                    .expect("validated aggregate");
                let tuple = grouped.tuples.first();
                let actual = tuple.and_then(|tuple| tuple.values[value_index].as_ref());
                let mut reasons = grouped.coverage.incomplete_reasons();
                reasons.extend(grouped.witness_reasons.iter().copied());
                if !candidate_witnessed {
                    reasons.extend(candidate.witness_reasons.iter().copied());
                    reasons.extend(candidate.coverage.incomplete_reasons());
                }
                let outcome = if let Some(RowScalar::Integer(value)) = actual {
                    let bounded = u32::try_from(*value).unwrap_or(u32::MAX);
                    let passes = assertion.cardinality.satisfied_by(bounded);
                    if !candidate_witnessed
                        || verdict_obligation(
                            assertion,
                            aggregates,
                            tuple.expect("aggregate has a tuple").witness_sound,
                            grouped.coverage.is_exhaustive(),
                            bounded,
                        )
                        .is_some()
                    {
                        ExplanationOutcome::Unknown
                    } else if passes {
                        ExplanationOutcome::Failed
                    } else {
                        ExplanationOutcome::Satisfied
                    }
                } else if grouped.coverage.is_exhaustive() {
                    // Empty keyed inputs do not manufacture a zero-count group.
                    ExplanationOutcome::Failed
                } else {
                    ExplanationOutcome::Unknown
                };
                reasons.sort();
                reasons.dedup();
                verdicts.push(outcome);
                observations.push(ReplayObservation {
                    label: format!("group:{}:{}", relation.name, assertion.aggregate),
                    outcome,
                    actual: format!("assertion {}; group key {key:?}; aggregate {actual:?}; cardinality {:?}; outcome describes whether a violation is established", assertion.id, assertion.cardinality),
                    reasons,
                    representative: tuple.filter(|tuple| tuple.witness_sound).map(|tuple| format!("{:?} = {:?}", grouped.layout, tuple.values)),
                });
            }
        }
    }
    state.check_cancelled()?;
    let outcome = if verdicts.contains(&ExplanationOutcome::Satisfied) {
        ExplanationOutcome::Satisfied
    } else if verdicts.is_empty() || verdicts.contains(&ExplanationOutcome::Unknown) {
        ExplanationOutcome::Unknown
    } else {
        ExplanationOutcome::Failed
    };
    Ok(CandidateReplay {
        outcome,
        observations,
    })
}

fn materialize(
    plan: &RelationalPlanIr,
    id: IrRelationId,
    input: &ReplayInput,
    state: &mut EvalState<'_>,
) -> EvalResult<EvalRelation> {
    let IrRelationOp::Source { binding, .. } = &plan.relations[id.index()].op else {
        unreachable!("lowered join operands are binding sources")
    };
    let input = RelationalInput {
        binding,
        rows: &input.rows,
        coverage: input.coverage.clone(),
    };
    load_rows(
        plan,
        id,
        binding,
        state.limits.max_source_rows,
        RelationCoverage::Exhaustive,
        Vec::new(),
        UnknownInputEvidence::default(),
        &HashMap::from([(binding.as_str(), &input)]),
        &referenced_columns(plan),
        state,
    )
}

fn replay_chain(
    plan: &RelationalPlanIr,
    mut left: EvalRelation,
    load: &mut impl FnMut(&RowBindingName, &ReplayConstraints) -> EvalResult<ReplayInput>,
    state: &mut EvalState<'_>,
    observations: &mut Vec<ReplayObservation>,
) -> EvalResult<EvalRelation> {
    for relation in &plan.relations {
        let IrRelationOp::Join {
            right, kind, on, ..
        } = &relation.op
        else {
            continue;
        };
        let IrRelationOp::Source { binding, .. } = &plan.relations[right.index()].op else {
            unreachable!("lowered joins have source right operands")
        };
        if left.tuples.is_empty() {
            let empty = ReplayInput {
                rows: Vec::new(),
                coverage: RelationCoverage::Exhaustive,
            };
            let right_relation = materialize(plan, *right, &empty, state)?;
            left = evaluate_join(&left, &right_relation, *kind, on, state)?;
            continue;
        }
        let mut buckets: Vec<(ReplayConstraints, Vec<EvalTuple>)> = Vec::new();
        let mut indexes = HashMap::new();
        for tuple in &left.tuples {
            state.check_cancelled()?;
            let constraints: ReplayConstraints = on
                .iter()
                .map(|key| {
                    (
                        key.right.clone(),
                        tuple.values[left.index_of(&key.left).expect("validated join key")].clone(),
                    )
                })
                .collect();
            let next = buckets.len();
            let index = *indexes.entry(constraints.clone()).or_insert(next);
            if index == next {
                buckets.push((constraints, Vec::new()));
            }
            buckets[index].1.push(tuple.clone());
        }
        let mut combined: Option<EvalRelation> = None;
        for (constraints, tuples) in buckets {
            state.check_cancelled()?;
            let input = if state.comparisons >= state.limits.max_join_comparisons {
                state.limit_exceeded = true;
                ReplayInput {
                    rows: Vec::new(),
                    coverage: RelationCoverage::row_budget(),
                }
            } else {
                load(binding, &constraints)?
            };
            let right_relation = materialize(plan, *right, &input, state)?;
            let scoped_left = EvalRelation {
                layout: left.layout.clone(),
                tuples,
                coverage: left.coverage.clone(),
                witness_reasons: left.witness_reasons.clone(),
                unknown_inputs: left.unknown_inputs.clone(),
            };
            let mut joined = evaluate_join(&scoped_left, &right_relation, *kind, on, state)?;
            let matching = right_relation.tuples.iter().find(|tuple| {
                constraints.iter().all(|(column, value)| {
                    tuple.values[right_relation.index_of(column).expect("validated key")] == *value
                })
            });
            let outcome = if matching.is_some_and(|tuple| tuple.witness_sound) {
                ExplanationOutcome::Satisfied
            } else if right_relation.coverage.is_exhaustive() && !state.limit_exceeded {
                ExplanationOutcome::Failed
            } else {
                ExplanationOutcome::Unknown
            };
            let mut reasons = right_relation.coverage.incomplete_reasons();
            reasons.extend(right_relation.witness_reasons.iter().copied());
            if state.limit_exceeded {
                reasons.push(PolicyIncompleteReason::PipelineRowBudget);
            }
            reasons.sort();
            reasons.dedup();
            observations.push(ReplayObservation {
                label: format!("{}_join", kind.label()),
                outcome,
                actual: format!(
                    "{}: key {constraints:?}; matching row {}; candidate output {}",
                    relation.name,
                    if matching.is_some() {
                        "exists"
                    } else {
                        "absent"
                    },
                    if joined.tuples.is_empty() {
                        "removed"
                    } else {
                        "retained"
                    }
                ),
                reasons,
                representative: matching
                    .map(|tuple| format!("{:?} = {:?}", right_relation.layout, tuple.values)),
            });
            // An anti join that removed a witnessed candidate by a known
            // match is decisive even when other right rows remain unknown.
            // Conversely an empty inner/semi join needs right coverage.
            if joined.tuples.is_empty()
                && *kind == IrJoinKind::Anti
                && matching.is_some_and(|tuple| tuple.witness_sound)
            {
                joined.coverage = scoped_left.coverage.clone();
            }
            if let Some(combined) = &mut combined {
                combined.coverage = combined.coverage.clone().meet(joined.coverage);
                combined.witness_reasons.extend(joined.witness_reasons);
                combined.unknown_inputs.extend(&joined.unknown_inputs);
                let remaining = state
                    .limits
                    .max_joined_rows
                    .saturating_sub(combined.tuples.len());
                if joined.tuples.len() > remaining {
                    combined.coverage = state.truncate(combined.coverage.clone());
                }
                combined
                    .tuples
                    .extend(joined.tuples.into_iter().take(remaining));
            } else {
                combined = Some(joined);
            }
        }
        left = combined.expect("nonempty left input has at least one key bucket");
    }
    Ok(left)
}
