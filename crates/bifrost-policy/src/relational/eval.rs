//! Bounded evaluation of a validated relational plan.
//!
//! All mutable evaluation state lives here: the materialized relations, the
//! shared comparison budget, and the obligations an assertion could not
//! discharge. Every operator is bounded, every bound that trips is recorded as
//! coverage rather than being silently absorbed, and the output order is one
//! sort over group keys rather than any map's iteration order.
//!
//! The verdict rules are the point of the module. A relational assertion is not
//! simply "did the number match": whether a verdict may be published depends on
//! what the rows prove.
//!
//! | verdict                            | claim    | publishable when                    |
//! |------------------------------------|----------|-------------------------------------|
//! | `at-most`/`exactly` exceeded        | presence | contributing rows are witness-sound |
//! | `at-least`/`exactly` under bound    | absence  | rows witness-sound and coverage exhaustive |
//! | clean `at-most`/`exactly`           | absence  | rows witness-sound and coverage exhaustive |
//! | clean `at-least`                    | presence | contributing rows are witness-sound |
//!
//! A verdict that cannot be published is not silently dropped: it becomes an
//! unmet obligation carrying the typed reasons that blocked it.

use std::collections::{BTreeSet, HashMap, HashSet};

use brokk_bifrost_rql::structural::CodeQueryRowRef;
use brokk_bifrost_rql::structural::search::UnitRowItem;

use crate::definition::{
    AssertCardinality, PolicyAssertId, RowBindingName, RowGroupName, RowLiteral,
};
use crate::finding::PolicyIncompleteReason;

use super::coverage::{
    MAX_RETAINED_RELATIONAL_OBLIGATIONS, RelationCoverage, RelationalInput, RelationalObligation,
    RelationalObligationKind,
};
use super::ir::{
    IrAggregate, IrAggregateOp, IrColumn, IrCompareOp, IrJoinKind, IrOperand, IrOrderedSequence,
    IrPredicate, IrRelationId, IrRelationOp, RelationalPlanIr, RowScalar,
};

/// One row of one binding that contributed to a violated group, addressed by
/// its index into that binding's executed row set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationalViolationRow {
    pub binding: RowBindingName,
    pub row: usize,
}

/// The number of contributing tuples a violation retains for diagnostics. The
/// aggregate value already states the complete count; representatives exist so
/// a finding can point at exact source ranges, not to enumerate the group.
pub const MAX_VIOLATION_REPRESENTATIVE_TUPLES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationalAssertionViolation {
    pub assertion: PolicyAssertId,
    pub group: RowGroupName,
    pub key: Vec<Option<RowScalar>>,
    pub actual: u64,
    /// Bounded contributing tuples of the violated group. Each tuple lists its
    /// rows in binding declaration order.
    pub representatives: Vec<Vec<RelationalViolationRow>>,
}

/// What one relational plan concluded.
///
/// `violations` holds only verdicts the rows prove; anything the coverage rules
/// blocked is in `unmet_obligations` instead, so a caller can never mistake a
/// suppressed verdict for a clean one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationalAssertionEvaluation {
    pub violations: Vec<RelationalAssertionViolation>,
    /// Verdicts the plan could not publish, in deterministic order.
    pub unmet_obligations: Vec<RelationalObligation>,
    pub obligations_truncated: bool,
    pub omitted_obligations_lower_bound: u64,
    /// Whether every bound relation was exhaustively covered and no plan bound
    /// tripped. A false value never invalidates a published violation; it makes
    /// the run non-reliable.
    pub exhaustive: bool,
    pub limit_exceeded: bool,
    /// Row-engine work beyond the CodeQuery scans that produced the inputs.
    pub work: RelationalEvaluationWork,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelationalEvaluationWork {
    pub input_rows: u64,
    pub materialized_rows: u64,
    pub join_key_probes: u64,
    pub produced_groups: u64,
    pub assertion_checks: u64,
}

/// The provenance selected by one endpoint row-selector plan.
///
/// `upstream_rows` names every row supplied by the output relation's producer
/// before authored derivations ran. `selected_rows` names the rows that remain
/// after those derivations. The distinction is semantic: an incomplete
/// terminal call-binding row may be filtered out, but it still prevents the
/// endpoint from treating the empty selected set as a clean negative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationalRowSelection {
    pub upstream_rows: Vec<RelationalViolationRow>,
    pub selected_rows: Vec<RelationalViolationRow>,
    pub upstream_coverage: RelationCoverage,
    pub selected_coverage: RelationCoverage,
    pub limit_exceeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationalAssertionEvaluationError {
    MissingInput {
        binding: String,
    },
    UnsupportedExpansion {
        binding: String,
    },
    DisconnectedJoin {
        binding: String,
    },
    MissingTupleBinding {
        binding: String,
    },
    MissingAggregate {
        group: String,
        aggregate: String,
    },
    RowField {
        binding: String,
        field: String,
    },
    /// The plan could not be lowered or did not validate. A decoded policy is
    /// validated at load, so this is an internal invariant failure.
    InvalidPlan {
        message: String,
    },
}

impl std::fmt::Display for RelationalAssertionEvaluationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingInput { binding } => {
                write!(formatter, "no executed rows for binding `{binding}`")
            }
            Self::UnsupportedExpansion { binding } => {
                write!(formatter, "binding `{binding}` cannot seed a row plan")
            }
            Self::DisconnectedJoin { binding } => {
                write!(formatter, "join reads unjoined binding `{binding}`")
            }
            Self::MissingTupleBinding { binding } => {
                write!(formatter, "row tuple does not bind `{binding}`")
            }
            Self::MissingAggregate { group, aggregate } => {
                write!(formatter, "group `{group}` computed no `{aggregate}`")
            }
            Self::RowField { binding, field } => {
                write!(formatter, "binding `{binding}` has no field `{field}`")
            }
            Self::InvalidPlan { message } => {
                write!(formatter, "invalid relational plan: {message}")
            }
        }
    }
}

impl std::error::Error for RelationalAssertionEvaluationError {}

type EvalResult<T> = Result<T, RelationalAssertionEvaluationError>;

/// One derived tuple.
#[derive(Debug, Clone)]
struct EvalTuple {
    /// Values positioned by the owning relation's layout.
    values: Vec<Option<RowScalar>>,
    /// The source rows behind this tuple. A base or joined tuple carries one
    /// entry; a grouped tuple carries its bounded representative tuples.
    contributors: Vec<Vec<RelationalViolationRow>>,
    /// Whether this tuple's presence is established. See `coverage`.
    witness_sound: bool,
}

/// One materialized relation.
#[derive(Debug)]
struct EvalRelation {
    /// The columns actually materialized, in value order. Columns no operator
    /// reads are not materialized at all, which keeps a wide row domain from
    /// costing anything a plan does not use.
    layout: Vec<IrColumn>,
    tuples: Vec<EvalTuple>,
    coverage: RelationCoverage,
    /// Why rows of this relation may not be witness-sound. Empty when every row
    /// is established.
    witness_reasons: Vec<PolicyIncompleteReason>,
}

impl EvalRelation {
    fn index_of(&self, column: &IrColumn) -> Option<usize> {
        self.layout.iter().position(|candidate| candidate == column)
    }
}

fn provenance_rows(relation: &EvalRelation) -> EvalResult<Vec<RelationalViolationRow>> {
    let mut rows = Vec::with_capacity(relation.tuples.len());
    for tuple in &relation.tuples {
        let [contributors] = tuple.contributors.as_slice() else {
            return Err(RelationalAssertionEvaluationError::InvalidPlan {
                message: "row selector output contains grouped representatives".to_owned(),
            });
        };
        let [row] = contributors.as_slice() else {
            return Err(RelationalAssertionEvaluationError::InvalidPlan {
                message: "row selector output depends on more than one source row".to_owned(),
            });
        };
        rows.push(row.clone());
    }
    Ok(rows)
}

fn provenance_rows_for_binding(
    relation: &EvalRelation,
    binding: &RowBindingName,
) -> EvalResult<Vec<RelationalViolationRow>> {
    let mut rows = Vec::with_capacity(relation.tuples.len());
    for tuple in &relation.tuples {
        let [contributors] = tuple.contributors.as_slice() else {
            return Err(RelationalAssertionEvaluationError::InvalidPlan {
                message: "row selector output contains grouped representatives".to_owned(),
            });
        };
        let mut matching = contributors.iter().filter(|row| row.binding == *binding);
        let Some(row) = matching.next() else {
            return Err(RelationalAssertionEvaluationError::InvalidPlan {
                message: format!(
                    "row selector output has no contributor for `{}`",
                    binding.as_str()
                ),
            });
        };
        if matching.next().is_some() {
            return Err(RelationalAssertionEvaluationError::InvalidPlan {
                message: format!(
                    "row selector output has ambiguous contributors for `{}`",
                    binding.as_str()
                ),
            });
        }
        if !rows.contains(row) {
            rows.push(row.clone());
        }
    }
    Ok(rows)
}

/// Evaluate the upstream and filtered output of a validated row selector.
pub fn evaluate_row_selector_ir(
    plan: &RelationalPlanIr,
    relation: IrRelationId,
    upstream: IrRelationId,
    upstream_binding: &RowBindingName,
    inputs: &[RelationalInput<'_>],
) -> EvalResult<RelationalRowSelection> {
    let inputs_by_binding = inputs
        .iter()
        .map(|input| (input.binding.as_str(), input))
        .collect::<HashMap<_, _>>();
    let referenced = referenced_columns(plan);
    let needed = needed_relations_for_targets(plan, [relation, upstream]);
    let binding_order = binding_declaration_order(plan);
    let mut state = EvalState {
        limits: plan.limits,
        comparisons: 0,
        limit_exceeded: false,
        work: RelationalEvaluationWork::default(),
    };
    let mut relations: Vec<Option<EvalRelation>> = Vec::with_capacity(plan.relations.len());
    for relation in &plan.relations {
        if !needed.contains(&relation.id) {
            relations.push(None);
            continue;
        }
        let evaluated = evaluate_relation(
            plan,
            relation.id,
            &relations,
            &inputs_by_binding,
            &referenced,
            &binding_order,
            &mut state,
        )?;
        state.work.materialized_rows = state
            .work
            .materialized_rows
            .saturating_add(u64::try_from(evaluated.tuples.len()).unwrap_or(u64::MAX));
        relations.push(Some(evaluated));
    }
    let get = |id: IrRelationId| {
        relations
            .get(id.index())
            .and_then(Option::as_ref)
            .ok_or_else(|| RelationalAssertionEvaluationError::InvalidPlan {
                message: format!("row selector relation {} was not evaluated", id.index()),
            })
    };
    let upstream_relation = get(upstream)?;
    let selected_relation = get(relation)?;
    Ok(RelationalRowSelection {
        upstream_rows: provenance_rows(upstream_relation)?,
        selected_rows: provenance_rows_for_binding(selected_relation, upstream_binding)?,
        upstream_coverage: upstream_relation.coverage.clone(),
        selected_coverage: selected_relation.coverage.clone(),
        limit_exceeded: state.limit_exceeded,
    })
}

/// Evaluate a validated plan over already executed row sets.
pub fn evaluate_plan_ir(
    plan: &RelationalPlanIr,
    inputs: &[RelationalInput<'_>],
) -> EvalResult<RelationalAssertionEvaluation> {
    let inputs_by_binding = inputs
        .iter()
        .map(|input| (input.binding.as_str(), input))
        .collect::<HashMap<_, _>>();
    let referenced = referenced_columns(plan);
    let needed = needed_relations(plan);
    let binding_order = binding_declaration_order(plan);

    let mut state = EvalState {
        limits: plan.limits,
        comparisons: 0,
        limit_exceeded: false,
        work: RelationalEvaluationWork::default(),
    };
    let mut relations: Vec<Option<EvalRelation>> = Vec::with_capacity(plan.relations.len());
    for relation in &plan.relations {
        if !needed.contains(&relation.id) {
            relations.push(None);
            continue;
        }
        let evaluated = evaluate_relation(
            plan,
            relation.id,
            &relations,
            &inputs_by_binding,
            &referenced,
            &binding_order,
            &mut state,
        )?;
        state.work.materialized_rows = state
            .work
            .materialized_rows
            .saturating_add(u64::try_from(evaluated.tuples.len()).unwrap_or(u64::MAX));
        relations.push(Some(evaluated));
    }

    let mut violations = Vec::new();
    let mut obligations = Obligations::default();
    for assertion in &plan.assertions {
        let Some(Some(relation)) = relations.get(assertion.relation.index()) else {
            return Err(RelationalAssertionEvaluationError::MissingAggregate {
                group: assertion.group.as_str().to_string(),
                aggregate: assertion.aggregate.as_str().to_string(),
            });
        };
        let IrRelationOp::Group { by, .. } = &plan
            .relation(assertion.relation)
            .expect("a validated assertion reads a relation of its own plan")
            .op
        else {
            return Err(RelationalAssertionEvaluationError::MissingAggregate {
                group: assertion.group.as_str().to_string(),
                aggregate: assertion.aggregate.as_str().to_string(),
            });
        };
        let key_width = by.len();
        let Some(value_index) = relation.index_of(&assertion.column) else {
            return Err(RelationalAssertionEvaluationError::MissingAggregate {
                group: assertion.group.as_str().to_string(),
                aggregate: assertion.aggregate.as_str().to_string(),
            });
        };

        if relation.tuples.is_empty() && !relation.coverage.is_exhaustive() {
            // No group was observed at all, so the assertion's clean verdict is
            // a claim about rows nobody read.
            obligations.push(RelationalObligation::new(
                assertion.id.clone(),
                RelationalObligationKind::AbsenceRequiresExhaustiveCoverage,
                assertion.group.clone(),
                Vec::new(),
                relation.coverage.incomplete_reasons(),
            ));
        }

        for tuple in &relation.tuples {
            state.work.assertion_checks = state.work.assertion_checks.saturating_add(1);
            let key = tuple.values[..key_width].to_vec();
            let Some(RowScalar::Integer(actual)) = tuple.values.get(value_index).cloned().flatten()
            else {
                return Err(RelationalAssertionEvaluationError::MissingAggregate {
                    group: assertion.group.as_str().to_string(),
                    aggregate: assertion.aggregate.as_str().to_string(),
                });
            };
            let bounded = u32::try_from(actual).unwrap_or(u32::MAX);
            let satisfied = assertion.cardinality.satisfied_by(bounded);
            let witnessed = tuple.witness_sound;
            let exhaustive = relation.coverage.is_exhaustive();

            if !witnessed {
                // Neither verdict is publishable: the rows behind the number
                // are not established.
                obligations.push(RelationalObligation::new(
                    assertion.id.clone(),
                    RelationalObligationKind::VerdictRequiresWitnessedRows,
                    assertion.group.clone(),
                    key,
                    relation.witness_reasons.clone(),
                ));
                continue;
            }
            if satisfied {
                if states_upper_bound(assertion.cardinality) && !exhaustive {
                    obligations.push(RelationalObligation::new(
                        assertion.id.clone(),
                        RelationalObligationKind::AbsenceRequiresExhaustiveCoverage,
                        assertion.group.clone(),
                        key,
                        relation.coverage.incomplete_reasons(),
                    ));
                }
                continue;
            }
            let positive = exceeds_upper_bound(assertion.cardinality, bounded);
            if !positive && !exhaustive {
                // Fewer rows than required is a claim that no further row
                // exists, which a partial relation cannot support.
                obligations.push(RelationalObligation::new(
                    assertion.id.clone(),
                    RelationalObligationKind::AbsenceRequiresExhaustiveCoverage,
                    assertion.group.clone(),
                    key,
                    relation.coverage.incomplete_reasons(),
                ));
                continue;
            }
            violations.push(RelationalAssertionViolation {
                assertion: assertion.id.clone(),
                group: assertion.group.clone(),
                key,
                actual,
                representatives: tuple.contributors.clone(),
            });
        }
    }

    let exhaustive =
        inputs.iter().all(|input| input.coverage.is_exhaustive()) && !state.limit_exceeded;
    Ok(RelationalAssertionEvaluation {
        violations,
        unmet_obligations: obligations.retained,
        obligations_truncated: obligations.truncated,
        omitted_obligations_lower_bound: obligations.omitted,
        exhaustive,
        limit_exceeded: state.limit_exceeded,
        work: state.work,
    })
}

/// Whether the cardinality states an upper bound, which is the property that
/// makes a clean verdict a claim about rows that were never seen.
const fn states_upper_bound(cardinality: AssertCardinality) -> bool {
    matches!(
        cardinality,
        AssertCardinality::AtMost(_) | AssertCardinality::Exactly(_)
    )
}

/// Whether an unsatisfied cardinality was unsatisfied by having too many rows,
/// which is positive evidence rather than an absence claim.
const fn exceeds_upper_bound(cardinality: AssertCardinality, actual: u32) -> bool {
    match cardinality {
        AssertCardinality::AtMost(bound) | AssertCardinality::Exactly(bound) => actual > bound,
        AssertCardinality::AtLeast(_) => false,
    }
}

#[derive(Debug, Default)]
struct Obligations {
    retained: Vec<RelationalObligation>,
    truncated: bool,
    omitted: u64,
}

impl Obligations {
    fn push(&mut self, obligation: RelationalObligation) {
        if self.retained.len() == MAX_RETAINED_RELATIONAL_OBLIGATIONS {
            self.truncated = true;
            self.omitted = self.omitted.saturating_add(1);
            return;
        }
        self.retained.push(obligation);
    }
}

struct EvalState {
    limits: super::ir::IrLimits,
    comparisons: usize,
    limit_exceeded: bool,
    work: RelationalEvaluationWork,
}

impl EvalState {
    /// Record that a bound truncated a relation, and degrade its coverage.
    fn truncate(&mut self, coverage: RelationCoverage) -> RelationCoverage {
        self.limit_exceeded = true;
        coverage.meet(RelationCoverage::row_budget())
    }
}

/// Every column any operator or assertion reads.
///
/// A projection's source column is included as well as its output, because the
/// output cannot be produced without it.
fn referenced_columns(plan: &RelationalPlanIr) -> BTreeSet<IrColumn> {
    let mut columns = BTreeSet::new();
    let predicate_columns = |columns: &mut BTreeSet<IrColumn>, predicates: &[IrPredicate]| {
        for predicate in predicates {
            match predicate {
                IrPredicate::Compare { left, right, .. } => {
                    columns.insert(left.clone());
                    if let IrOperand::Column(right) = right {
                        columns.insert(right.clone());
                    }
                }
                IrPredicate::IsNull { column, .. } | IrPredicate::InSet { column, .. } => {
                    columns.insert(column.clone());
                }
            }
        }
    };
    for relation in &plan.relations {
        match &relation.op {
            IrRelationOp::Source { .. } | IrRelationOp::Expand { .. } => {}
            IrRelationOp::Project { columns: list, .. } => {
                for projection in list {
                    columns.insert(projection.source.clone());
                    columns.insert(projection.output.clone());
                }
            }
            IrRelationOp::Filter { predicates, .. } => {
                predicate_columns(&mut columns, predicates);
            }
            IrRelationOp::Join { on, .. } => {
                for key in on {
                    columns.insert(key.left.clone());
                    columns.insert(key.right.clone());
                }
            }
            IrRelationOp::Group { by, aggregates, .. } => {
                columns.extend(by.iter().cloned());
                for aggregate in aggregates {
                    columns.insert(aggregate.output.clone());
                    if let Some(value) = &aggregate.value {
                        columns.insert(value.clone());
                    }
                    if let Some(sequences) = &aggregate.sequences {
                        for sequence in [&sequences.left, &sequences.right] {
                            columns.insert(sequence.position.clone());
                            columns.insert(sequence.value.clone());
                        }
                    }
                    predicate_columns(&mut columns, &aggregate.predicates);
                }
            }
        }
    }
    for assertion in &plan.assertions {
        columns.insert(assertion.column.clone());
    }
    columns
}

/// The relations worth materializing.
///
/// A source relation nothing reads costs no work and can trip no bound, so it
/// is not evaluated: binding a row set the plan never uses must not make the
/// run unreliable on its own.
fn needed_relations(plan: &RelationalPlanIr) -> HashSet<IrRelationId> {
    let mut needed = plan
        .relations
        .iter()
        .filter(|relation| {
            !matches!(
                relation.op,
                IrRelationOp::Source { .. } | IrRelationOp::Expand { .. }
            )
        })
        .map(|relation| relation.id)
        .collect::<HashSet<_>>();
    for relation in plan.relations.iter().rev() {
        if !needed.contains(&relation.id) {
            continue;
        }
        needed.extend(relation.op.inputs());
    }
    needed
}

fn needed_relations_for_targets(
    plan: &RelationalPlanIr,
    targets: impl IntoIterator<Item = IrRelationId>,
) -> HashSet<IrRelationId> {
    let mut needed = targets.into_iter().collect::<HashSet<_>>();
    for relation in plan.relations.iter().rev() {
        if needed.contains(&relation.id) {
            needed.extend(relation.op.inputs());
        }
    }
    needed
}

/// The order bindings were declared in, which is the order a violation lists
/// its contributing rows in.
fn binding_declaration_order(plan: &RelationalPlanIr) -> HashMap<String, usize> {
    let mut order = HashMap::new();
    for relation in &plan.relations {
        if let IrRelationOp::Source { binding, .. } | IrRelationOp::Expand { binding, .. } =
            &relation.op
        {
            let next = order.len();
            order.entry(binding.as_str().to_string()).or_insert(next);
        }
    }
    order
}

#[allow(clippy::too_many_arguments)]
fn evaluate_relation(
    plan: &RelationalPlanIr,
    id: IrRelationId,
    evaluated: &[Option<EvalRelation>],
    inputs: &HashMap<&str, &RelationalInput<'_>>,
    referenced: &BTreeSet<IrColumn>,
    binding_order: &HashMap<String, usize>,
    state: &mut EvalState,
) -> EvalResult<EvalRelation> {
    let relation = plan
        .relation(id)
        .expect("relations are evaluated by their own id");
    let input_relation = |input: IrRelationId| -> EvalResult<&EvalRelation> {
        evaluated
            .get(input.index())
            .and_then(Option::as_ref)
            .ok_or_else(|| RelationalAssertionEvaluationError::DisconnectedJoin {
                binding: plan
                    .relation(input)
                    .map(|relation| relation.name.clone())
                    .unwrap_or_default(),
            })
    };

    match &relation.op {
        IrRelationOp::Source { binding, .. } => load_rows(
            plan,
            id,
            binding,
            state.limits.max_source_rows,
            RelationCoverage::Exhaustive,
            Vec::new(),
            inputs,
            referenced,
            state,
        ),
        IrRelationOp::Expand { input, binding, .. } => {
            let source = input_relation(*input)?;
            let coverage = source.coverage.clone();
            let witness_reasons = source.witness_reasons.clone();
            load_rows(
                plan,
                id,
                binding,
                state.limits.max_expanded_rows,
                coverage,
                witness_reasons,
                inputs,
                referenced,
                state,
            )
        }
        IrRelationOp::Project { input, columns } => {
            let source = input_relation(*input)?;
            let layout = columns
                .iter()
                .filter(|projection| referenced.contains(&projection.output))
                .map(|projection| projection.output.clone())
                .collect::<Vec<_>>();
            let sources = columns
                .iter()
                .filter(|projection| referenced.contains(&projection.output))
                .map(|projection| {
                    source.index_of(&projection.source).ok_or_else(|| {
                        RelationalAssertionEvaluationError::MissingTupleBinding {
                            binding: projection.source.qualifier.clone(),
                        }
                    })
                })
                .collect::<EvalResult<Vec<_>>>()?;
            let tuples = source
                .tuples
                .iter()
                .map(|tuple| EvalTuple {
                    values: sources
                        .iter()
                        .map(|index| tuple.values[*index].clone())
                        .collect(),
                    contributors: tuple.contributors.clone(),
                    witness_sound: tuple.witness_sound,
                })
                .collect();
            Ok(EvalRelation {
                layout,
                tuples,
                coverage: source.coverage.clone(),
                witness_reasons: source.witness_reasons.clone(),
            })
        }
        IrRelationOp::Filter { input, predicates } => {
            let source = input_relation(*input)?;
            let mut tuples = Vec::new();
            for tuple in &source.tuples {
                if predicates_match(source, tuple, predicates)? {
                    tuples.push(tuple.clone());
                }
            }
            Ok(EvalRelation {
                layout: source.layout.clone(),
                tuples,
                coverage: source.coverage.clone(),
                witness_reasons: source.witness_reasons.clone(),
            })
        }
        IrRelationOp::Join {
            left,
            right,
            kind,
            on,
        } => evaluate_join(
            input_relation(*left)?,
            input_relation(*right)?,
            *kind,
            on,
            state,
        ),
        IrRelationOp::Group {
            input,
            by,
            aggregates,
        } => evaluate_group(
            input_relation(*input)?,
            by,
            aggregates,
            binding_order,
            state,
        ),
    }
}

/// Materialize one binding's executed rows, bounded by the operator's limit.
#[allow(clippy::too_many_arguments)]
fn load_rows(
    plan: &RelationalPlanIr,
    id: IrRelationId,
    binding: &RowBindingName,
    max_rows: usize,
    inherited: RelationCoverage,
    witness_reasons: Vec<PolicyIncompleteReason>,
    inputs: &HashMap<&str, &RelationalInput<'_>>,
    referenced: &BTreeSet<IrColumn>,
    state: &mut EvalState,
) -> EvalResult<EvalRelation> {
    let Some(input) = inputs.get(binding.as_str()) else {
        return Err(RelationalAssertionEvaluationError::MissingInput {
            binding: binding.as_str().to_string(),
        });
    };
    let schema = &plan
        .relation(id)
        .expect("relations are evaluated by their own id")
        .schema;
    let layout = schema
        .fields()
        .iter()
        .map(|field| field.column.clone())
        .filter(|column| referenced.contains(column))
        .collect::<Vec<_>>();

    let mut coverage = inherited.meet(input.coverage.clone());
    let count = input.rows.len().min(max_rows);
    state.work.input_rows = state
        .work
        .input_rows
        .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
    if count < input.rows.len() {
        coverage = state.truncate(coverage);
    }
    let mut tuples = Vec::with_capacity(count);
    for (row, item) in input.rows[..count].iter().enumerate() {
        let mut values = Vec::with_capacity(layout.len());
        for column in &layout {
            values.push(row_field(item, binding, &column.name)?);
        }
        tuples.push(EvalTuple {
            values,
            contributors: vec![vec![RelationalViolationRow {
                binding: binding.clone(),
                row,
            }]],
            witness_sound: true,
        });
    }
    Ok(EvalRelation {
        layout,
        tuples,
        coverage,
        witness_reasons,
    })
}

fn evaluate_join(
    left: &EvalRelation,
    right: &EvalRelation,
    kind: IrJoinKind,
    on: &[super::ir::IrEquiKey],
    state: &mut EvalState,
) -> EvalResult<EvalRelation> {
    let keys = on
        .iter()
        .map(|key| {
            let left_index = left.index_of(&key.left).ok_or_else(|| {
                RelationalAssertionEvaluationError::MissingTupleBinding {
                    binding: key.left.qualifier.clone(),
                }
            })?;
            let right_index = right.index_of(&key.right).ok_or_else(|| {
                RelationalAssertionEvaluationError::MissingTupleBinding {
                    binding: key.right.qualifier.clone(),
                }
            })?;
            Ok((left_index, right_index))
        })
        .collect::<EvalResult<Vec<_>>>()?;

    // An anti join publishes rows because nothing matched them. That is only a
    // fact about the world when the right relation held every row that exists.
    let right_is_exhaustive = right.coverage.is_exhaustive();
    let mut witness_reasons = left.witness_reasons.clone();
    if kind == IrJoinKind::Anti && !right_is_exhaustive {
        witness_reasons.extend(right.coverage.incomplete_reasons());
    } else {
        witness_reasons.extend(right.witness_reasons.iter().copied());
    }
    witness_reasons.sort();
    witness_reasons.dedup();

    let mut coverage = match kind {
        IrJoinKind::Inner | IrJoinKind::Semi => left.coverage.clone().meet(right.coverage.clone()),
        // Missing right rows cannot remove an anti-join row that exists; they
        // can only add one, which the witness rule handles.
        IrJoinKind::Anti => left.coverage.clone(),
    };

    // Equality keys are typed values, so a composite key can be indexed
    // directly. Buckets append right tuples in relation order; the map itself
    // is never iterated, which keeps output order independent of hash seeding.
    let mut right_index: HashMap<Vec<Option<RowScalar>>, Vec<&EvalTuple>> = HashMap::new();
    for right_tuple in &right.tuples {
        let key = keys
            .iter()
            .map(|(_, right_index)| right_tuple.values[*right_index].clone())
            .collect();
        right_index.entry(key).or_default().push(right_tuple);
    }

    let mut joined = Vec::new();
    'left: for tuple in &left.tuples {
        // This is a plan-wide one-unit-per-left-key-probe budget. The lookup
        // replaces the old per-pair comparison loop, while output remains
        // independently bounded by max_joined_rows below.
        state.comparisons = state.comparisons.saturating_add(1);
        state.work.join_key_probes = state.work.join_key_probes.saturating_add(1);
        if state.comparisons > state.limits.max_join_comparisons {
            coverage = state.truncate(coverage);
            break;
        }

        let key = keys
            .iter()
            .map(|(left_index, _)| tuple.values[*left_index].clone())
            .collect::<Vec<_>>();
        let matches = right_index.get(&key);
        let matched = matches.is_some();
        if let Some(matches) = matches
            && kind == IrJoinKind::Inner
        {
            for right_tuple in matches {
                if joined.len() == state.limits.max_joined_rows {
                    coverage = state.truncate(coverage);
                    break 'left;
                }
                let mut values = tuple.values.clone();
                values.extend(right_tuple.values.iter().cloned());
                let mut rows = tuple.contributors.first().cloned().unwrap_or_default();
                rows.extend(
                    right_tuple
                        .contributors
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                );
                joined.push(EvalTuple {
                    values,
                    contributors: vec![rows],
                    witness_sound: tuple.witness_sound && right_tuple.witness_sound,
                });
            }
        }
        let retain = match kind {
            IrJoinKind::Inner => false,
            IrJoinKind::Semi => matched,
            IrJoinKind::Anti => !matched,
        };
        if retain {
            if joined.len() == state.limits.max_joined_rows {
                coverage = state.truncate(coverage);
                break;
            }
            joined.push(EvalTuple {
                values: tuple.values.clone(),
                contributors: tuple.contributors.clone(),
                witness_sound: tuple.witness_sound
                    && (kind != IrJoinKind::Anti || right_is_exhaustive),
            });
        }
    }

    let layout = match kind {
        IrJoinKind::Inner => {
            let mut layout = left.layout.clone();
            layout.extend(right.layout.iter().cloned());
            layout
        }
        IrJoinKind::Semi | IrJoinKind::Anti => left.layout.clone(),
    };
    Ok(EvalRelation {
        layout,
        tuples: joined,
        coverage,
        witness_reasons,
    })
}

fn evaluate_group(
    input: &EvalRelation,
    by: &[IrColumn],
    aggregates: &[IrAggregate],
    binding_order: &HashMap<String, usize>,
    state: &mut EvalState,
) -> EvalResult<EvalRelation> {
    let key_indices = by
        .iter()
        .map(|column| {
            input.index_of(column).ok_or_else(|| {
                RelationalAssertionEvaluationError::MissingTupleBinding {
                    binding: column.qualifier.clone(),
                }
            })
        })
        .collect::<EvalResult<Vec<_>>>()?;

    let mut coverage = input.coverage.clone();
    let mut witness_reasons = input.witness_reasons.clone();
    let mut grouped: HashMap<Vec<Option<RowScalar>>, GroupRows<'_>> = HashMap::new();
    let mut any_group_truncated = false;
    for tuple in &input.tuples {
        let key = key_indices
            .iter()
            .map(|index| tuple.values[*index].clone())
            .collect::<Vec<_>>();
        if !grouped.contains_key(&key) && grouped.len() == state.limits.max_groups {
            // A group that never existed cannot degrade "only itself": the
            // group relation as a whole is now a subset.
            coverage = state.truncate(coverage);
            continue;
        }
        let rows = grouped.entry(key).or_default();
        if rows.tuples.len() == state.limits.max_values_per_group {
            // Only this group loses its witness; every other group is intact.
            state.limit_exceeded = true;
            rows.truncated = true;
            any_group_truncated = true;
            continue;
        }
        rows.tuples.push(tuple);
    }
    if any_group_truncated {
        witness_reasons.push(PolicyIncompleteReason::PipelineRowBudget);
        witness_reasons.sort();
        witness_reasons.dedup();
    }

    let mut layout = by.to_vec();
    layout.extend(aggregates.iter().map(|aggregate| aggregate.output.clone()));

    state.work.produced_groups = state
        .work
        .produced_groups
        .saturating_add(u64::try_from(grouped.len()).unwrap_or(u64::MAX));
    let mut tuples = Vec::with_capacity(grouped.len());
    for (key, rows) in grouped {
        let mut values = key;
        for aggregate in aggregates {
            values.push(Some(RowScalar::Integer(fold(
                input,
                &rows.tuples,
                aggregate,
            )?)));
        }
        let witness_sound = !rows.truncated && rows.tuples.iter().all(|tuple| tuple.witness_sound);
        let contributors = rows
            .tuples
            .iter()
            .flat_map(|tuple| tuple.contributors.iter())
            .take(MAX_VIOLATION_REPRESENTATIVE_TUPLES)
            .map(|contributor| {
                let mut rows = contributor.clone();
                rows.sort_by_key(|row| {
                    binding_order
                        .get(row.binding.as_str())
                        .copied()
                        .unwrap_or(usize::MAX)
                });
                rows
            })
            .collect::<Vec<_>>();
        tuples.push(EvalTuple {
            values,
            contributors,
            witness_sound,
        });
    }
    // One sort over group keys is the plan's only ordering decision: hash order
    // never reaches a finding.
    tuples.sort_by(|left, right| left.values.cmp(&right.values));

    Ok(EvalRelation {
        layout,
        tuples,
        coverage,
        witness_reasons,
    })
}

#[derive(Debug, Default)]
struct GroupRows<'a> {
    tuples: Vec<&'a EvalTuple>,
    truncated: bool,
}

/// Fold one group's rows into the integer an assertion compares.
fn fold(
    relation: &EvalRelation,
    tuples: &[&EvalTuple],
    aggregate: &IrAggregate,
) -> EvalResult<u64> {
    let mut matching = Vec::with_capacity(tuples.len());
    for tuple in tuples {
        if predicates_match(relation, tuple, &aggregate.predicates)? {
            matching.push(*tuple);
        }
    }
    let value_index = aggregate
        .value
        .as_ref()
        .map(|column| {
            relation.index_of(column).ok_or_else(|| {
                RelationalAssertionEvaluationError::MissingTupleBinding {
                    binding: column.qualifier.clone(),
                }
            })
        })
        .transpose()?;
    let values = || {
        value_index.into_iter().flat_map(|index| {
            matching
                .iter()
                .map(move |tuple| tuple.values[index].clone())
        })
    };
    Ok(match aggregate.op {
        IrAggregateOp::Count => matching.len() as u64,
        IrAggregateOp::CountDistinct => values().flatten().collect::<HashSet<_>>().len() as u64,
        IrAggregateOp::Min => integers(values()).min().unwrap_or(0),
        IrAggregateOp::Max => integers(values()).max().unwrap_or(0),
        // An absent value is not `true`, so `any` ignores it and `all` fails on
        // it. An empty group is vacuously `all`.
        IrAggregateOp::Any => {
            u64::from(values().any(|value| value == Some(RowScalar::Boolean(true))))
        }
        IrAggregateOp::All => {
            u64::from(values().all(|value| value == Some(RowScalar::Boolean(true))))
        }
        IrAggregateOp::OrderedEqual => {
            let sequences = aggregate
                .sequences
                .as_ref()
                .expect("a validated ordered fold declares both sequences");
            let left = ordered_sequence(relation, &matching, &sequences.left)?;
            let right = ordered_sequence(relation, &matching, &sequences.right)?;
            u64::from(left.is_some() && left == right)
        }
    })
}

fn integers(values: impl Iterator<Item = Option<RowScalar>>) -> impl Iterator<Item = u64> {
    values.filter_map(|value| match value {
        Some(RowScalar::Integer(value)) => Some(value),
        _ => None,
    })
}

/// One recovered sequence: each stated position with the value read there,
/// ascending by position.
type OrderedSequence = Vec<(u64, Option<RowScalar>)>;

/// Recover one ordered sequence from a group's contributing tuples.
///
/// A joined tuple set has no inherent order, so the sequence comes from the
/// position each row states about itself. Two rows that state the same
/// position must therefore agree on the value; if they do not, the sequence is
/// not defined and the answer is `None`, which the caller reads as "parity is
/// not proven" rather than as "the lists differ in a specific way". A row whose
/// position is absent is undecidable for the same reason.
fn ordered_sequence(
    relation: &EvalRelation,
    tuples: &[&EvalTuple],
    sequence: &IrOrderedSequence,
) -> EvalResult<Option<OrderedSequence>> {
    let position_index = relation.index_of(&sequence.position).ok_or_else(|| {
        RelationalAssertionEvaluationError::MissingTupleBinding {
            binding: sequence.position.qualifier.clone(),
        }
    })?;
    let value_index = relation.index_of(&sequence.value).ok_or_else(|| {
        RelationalAssertionEvaluationError::MissingTupleBinding {
            binding: sequence.value.qualifier.clone(),
        }
    })?;
    let mut positions: HashMap<u64, Option<RowScalar>> = HashMap::new();
    for tuple in tuples {
        let Some(RowScalar::Integer(position)) = tuple.values[position_index].clone() else {
            return Ok(None);
        };
        let value = tuple.values[value_index].clone();
        match positions.entry(position) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                if entry.get() != &value {
                    return Ok(None);
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(value);
            }
        }
    }
    let mut ordered = positions.into_iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(position, _)| *position);
    Ok(Some(ordered))
}

/// Evaluate a conjunction of row tests.
///
/// Every comparison against an absent value is false, including `ne`: a policy
/// that means "absent" writes `is-null`, so an unread field never satisfies a
/// test written about read ones.
fn predicates_match(
    relation: &EvalRelation,
    tuple: &EvalTuple,
    predicates: &[IrPredicate],
) -> EvalResult<bool> {
    for predicate in predicates {
        let holds = match predicate {
            IrPredicate::Compare { left, op, right } => {
                let left = read(relation, tuple, left)?;
                match right {
                    IrOperand::Literal(literal) => left
                        .as_ref()
                        .is_some_and(|left| compare_literal(left, *op, literal)),
                    IrOperand::Column(column) => {
                        let right = read(relation, tuple, column)?;
                        match (left, right) {
                            (Some(left), Some(right)) => compare_scalars(&left, *op, &right),
                            _ => false,
                        }
                    }
                }
            }
            IrPredicate::IsNull { column, negated } => {
                read(relation, tuple, column)?.is_none() != *negated
            }
            IrPredicate::InSet { column, values } => {
                let actual = read(relation, tuple, column)?;
                actual.is_some_and(|actual| {
                    values
                        .iter()
                        .any(|literal| scalar_matches_literal(&actual, literal))
                })
            }
        };
        if !holds {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One located CodeQuery row, materialized under the column names one
/// relation's predicates address it by.
///
/// The `why-not` explainer replays a single located row through the filters a
/// plan attaches directly to a row binding. Deciding a predicate is the
/// evaluator's semantics -- two-valued null handling, ordered comparison only
/// over integers, literal matching by scalar type -- so the explainer builds
/// this and asks, instead of re-deriving what a comparison means.
pub(crate) struct ReplayRow {
    relation: EvalRelation,
    tuple: EvalTuple,
}

impl ReplayRow {
    /// Read one CodeQuery row under `columns`, each pair naming a column of the
    /// replayed relation and the row field that column reads. A projection
    /// between the binding and the filter is what makes the two names differ.
    pub(crate) fn new(
        columns: &[(IrColumn, String)],
        row: CodeQueryRowRef<'_>,
    ) -> EvalResult<Self> {
        let mut values = Vec::with_capacity(columns.len());
        for (column, field) in columns {
            let value =
                row.field(field)
                    .map_err(|_| RelationalAssertionEvaluationError::RowField {
                        binding: column.qualifier.clone(),
                        field: field.clone(),
                    })?;
            values.push(value.map(RowScalar::from));
        }
        Ok(Self {
            relation: EvalRelation {
                layout: columns.iter().map(|(column, _)| column.clone()).collect(),
                tuples: Vec::new(),
                coverage: RelationCoverage::Exhaustive,
                witness_reasons: Vec::new(),
            },
            tuple: EvalTuple {
                values,
                contributors: Vec::new(),
                witness_sound: true,
            },
        })
    }

    /// This row's value for one column of the replayed relation.
    pub(crate) fn value(&self, column: &IrColumn) -> EvalResult<Option<RowScalar>> {
        read(&self.relation, &self.tuple, column)
    }

    /// The first test of `predicates` this row does not satisfy, if any.
    pub(crate) fn first_failed_predicate<'a>(
        &self,
        predicates: &'a [IrPredicate],
    ) -> EvalResult<Option<&'a IrPredicate>> {
        for predicate in predicates {
            if !predicates_match(&self.relation, &self.tuple, std::slice::from_ref(predicate))? {
                return Ok(Some(predicate));
            }
        }
        Ok(None)
    }
}

fn read(
    relation: &EvalRelation,
    tuple: &EvalTuple,
    column: &IrColumn,
) -> EvalResult<Option<RowScalar>> {
    let index = relation.index_of(column).ok_or_else(|| {
        RelationalAssertionEvaluationError::MissingTupleBinding {
            binding: column.qualifier.clone(),
        }
    })?;
    Ok(tuple.values[index].clone())
}

fn compare_literal(actual: &RowScalar, op: IrCompareOp, expected: &RowLiteral) -> bool {
    match op {
        IrCompareOp::Eq => scalar_matches_literal(actual, expected),
        IrCompareOp::Ne => !scalar_matches_literal(actual, expected),
        IrCompareOp::Lt | IrCompareOp::Le | IrCompareOp::Gt | IrCompareOp::Ge => {
            match (actual, expected) {
                (RowScalar::Integer(actual), RowLiteral::Integer(expected)) => {
                    ordered(*actual, op, *expected)
                }
                _ => false,
            }
        }
    }
}

fn compare_scalars(left: &RowScalar, op: IrCompareOp, right: &RowScalar) -> bool {
    match op {
        IrCompareOp::Eq => left == right,
        IrCompareOp::Ne => left != right,
        IrCompareOp::Lt | IrCompareOp::Le | IrCompareOp::Gt | IrCompareOp::Ge => {
            match (left, right) {
                (RowScalar::Integer(left), RowScalar::Integer(right)) => ordered(*left, op, *right),
                _ => false,
            }
        }
    }
}

const fn ordered(left: u64, op: IrCompareOp, right: u64) -> bool {
    match op {
        IrCompareOp::Lt => left < right,
        IrCompareOp::Le => left <= right,
        IrCompareOp::Gt => left > right,
        IrCompareOp::Ge => left >= right,
        IrCompareOp::Eq => left == right,
        IrCompareOp::Ne => left != right,
    }
}

fn scalar_matches_literal(actual: &RowScalar, expected: &RowLiteral) -> bool {
    match (actual, expected) {
        (RowScalar::StableId(actual), RowLiteral::String(expected))
        | (RowScalar::String(actual), RowLiteral::String(expected))
        | (RowScalar::DeclarationIdentity(actual), RowLiteral::String(expected))
        | (RowScalar::ConstrainedEnum(actual), RowLiteral::ConstrainedEnum(expected)) => {
            actual == expected
        }
        (RowScalar::Integer(actual), RowLiteral::Integer(expected)) => actual == expected,
        (RowScalar::Boolean(actual), RowLiteral::Boolean(expected)) => actual == expected,
        _ => false,
    }
}

fn row_field(
    row: &UnitRowItem,
    binding: &RowBindingName,
    field: &str,
) -> EvalResult<Option<RowScalar>> {
    row.field(field)
        .map(|value| value.map(RowScalar::from))
        .map_err(|_| RelationalAssertionEvaluationError::RowField {
            binding: binding.as_str().to_string(),
            field: field.to_string(),
        })
}
