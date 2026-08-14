//! Typed validation and bounded execution primitives for relational assertion
//! plans. Policy source decoding builds the authoring model in `definition`;
//! this module resolves its row domains against the analyzer-owned registry.

use std::collections::{HashMap, HashSet};
use std::fmt;

use brokk_bifrost_analysis::analyzer::structural::search::{
    CodeQueryResultItem, DetailedCodeQueryDomain,
};
use brokk_bifrost_analysis::analyzer::structural::{
    CodeQueryResultValue, CodeQueryRowScalarRef, CodeQueryRowScalarType,
};

use crate::definition::{
    PolicyAssertId, PolicySelector, RelationalAssertionPlan, RowAggregateName, RowAggregateOp,
    RowBindingName, RowBindingSource, RowFieldRef, RowGroupName, RowLiteral, RowPredicate,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RowScalar {
    StableId(String),
    String(String),
    Integer(u64),
    Boolean(bool),
    ConstrainedEnum(String),
    DeclarationIdentity(String),
}

impl From<CodeQueryRowScalarRef<'_>> for RowScalar {
    fn from(value: CodeQueryRowScalarRef<'_>) -> Self {
        match value {
            CodeQueryRowScalarRef::StableId(value) => Self::StableId(value.to_string()),
            CodeQueryRowScalarRef::String(value) => Self::String(value.to_string()),
            CodeQueryRowScalarRef::Integer(value) => Self::Integer(value),
            CodeQueryRowScalarRef::Boolean(value) => Self::Boolean(value),
            CodeQueryRowScalarRef::ConstrainedEnum(value) => {
                Self::ConstrainedEnum(value.to_string())
            }
            CodeQueryRowScalarRef::DeclarationIdentity(value) => {
                Self::DeclarationIdentity(value.to_string())
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RelationalInput<'a> {
    pub binding: &'a RowBindingName,
    pub rows: &'a [CodeQueryResultItem],
    pub exhaustive: bool,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationalAssertionEvaluation {
    pub violations: Vec<RelationalAssertionViolation>,
    pub exhaustive: bool,
    pub limit_exceeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationalAssertionEvaluationError {
    MissingInput { binding: String },
    UnsupportedExpansion { binding: String },
    DisconnectedJoin { binding: String },
    MissingTupleBinding { binding: String },
    MissingAggregate { group: String, aggregate: String },
    RowField { binding: String, field: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationalAssertionPlanError {
    DuplicateBinding {
        name: String,
    },
    ForwardBinding {
        binding: String,
        referenced: String,
    },
    DuplicateGroup {
        name: String,
    },
    DuplicateAggregate {
        group: String,
        name: String,
    },
    DuplicateAssertion {
        id: String,
    },
    UnknownBinding {
        name: String,
    },
    UnknownGroup {
        name: String,
    },
    UnknownAggregate {
        group: String,
        name: String,
    },
    UnknownField {
        binding: String,
        field: String,
    },
    JoinTypeMismatch {
        left: String,
        left_type: CodeQueryRowScalarType,
        right: String,
        right_type: CodeQueryRowScalarType,
    },
    EmptyJoin {
        left: String,
        right: String,
    },
    EmptyGroupKey {
        group: String,
    },
    AggregateValueRequired {
        group: String,
        aggregate: String,
    },
    AggregateValueForbidden {
        group: String,
        aggregate: String,
    },
    InvalidMinType {
        group: String,
        aggregate: String,
        actual: CodeQueryRowScalarType,
    },
    OrderedSequencesRequired {
        group: String,
        aggregate: String,
    },
    OrderedSequencesForbidden {
        group: String,
        aggregate: String,
    },
    InvalidOrderedPositionType {
        group: String,
        aggregate: String,
        field: String,
        actual: CodeQueryRowScalarType,
    },
    OrderedValueTypeMismatch {
        group: String,
        aggregate: String,
        left_type: CodeQueryRowScalarType,
        right_type: CodeQueryRowScalarType,
    },
    PredicateTypeMismatch {
        field: String,
        actual: CodeQueryRowScalarType,
        literal: &'static str,
    },
    DeferredSelectorDomain {
        binding: String,
    },
    ExpansionDomainUnavailable {
        binding: String,
        step: &'static str,
    },
    InvalidQuery {
        binding: String,
        message: String,
    },
    ZeroLimit {
        name: &'static str,
    },
}

impl fmt::Display for RelationalAssertionPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateBinding { name } => write!(formatter, "duplicate binding `{name}`"),
            Self::ForwardBinding {
                binding,
                referenced,
            } => write!(
                formatter,
                "binding `{binding}` references `{referenced}` before it is declared"
            ),
            Self::DuplicateGroup { name } => write!(formatter, "duplicate group `{name}`"),
            Self::DuplicateAggregate { group, name } => {
                write!(formatter, "duplicate aggregate `{group}.{name}`")
            }
            Self::DuplicateAssertion { id } => write!(formatter, "duplicate assertion `{id}`"),
            Self::UnknownBinding { name } => write!(formatter, "unknown binding `{name}`"),
            Self::UnknownGroup { name } => write!(formatter, "unknown group `{name}`"),
            Self::UnknownAggregate { group, name } => {
                write!(formatter, "unknown aggregate `{group}.{name}`")
            }
            Self::UnknownField { binding, field } => {
                write!(formatter, "unknown field `{binding}.{field}`")
            }
            Self::JoinTypeMismatch {
                left,
                left_type,
                right,
                right_type,
            } => write!(
                formatter,
                "join fields `{left}` ({left_type:?}) and `{right}` ({right_type:?}) have incompatible types"
            ),
            Self::EmptyJoin { left, right } => {
                write!(
                    formatter,
                    "join `{left}` to `{right}` has no equality fields"
                )
            }
            Self::EmptyGroupKey { group } => {
                write!(formatter, "group `{group}` has no grouping fields")
            }
            Self::AggregateValueRequired { group, aggregate } => write!(
                formatter,
                "aggregate `{group}.{aggregate}` requires a value field"
            ),
            Self::AggregateValueForbidden { group, aggregate } => write!(
                formatter,
                "aggregate `{group}.{aggregate}` must not declare a value field"
            ),
            Self::InvalidMinType {
                group,
                aggregate,
                actual,
            } => write!(
                formatter,
                "aggregate `{group}.{aggregate}` requires an integer value, found {actual:?}"
            ),
            Self::OrderedSequencesRequired { group, aggregate } => write!(
                formatter,
                "aggregate `{group}.{aggregate}` requires both :left and :right ordered sequences"
            ),
            Self::OrderedSequencesForbidden { group, aggregate } => write!(
                formatter,
                "aggregate `{group}.{aggregate}` must not declare :left or :right ordered sequences"
            ),
            Self::InvalidOrderedPositionType {
                group,
                aggregate,
                field,
                actual,
            } => write!(
                formatter,
                "aggregate `{group}.{aggregate}` position field `{field}` must be an integer, found {actual:?}"
            ),
            Self::OrderedValueTypeMismatch {
                group,
                aggregate,
                left_type,
                right_type,
            } => write!(
                formatter,
                "aggregate `{group}.{aggregate}` compares a {left_type:?} value with a {right_type:?} value"
            ),
            Self::PredicateTypeMismatch {
                field,
                actual,
                literal,
            } => write!(
                formatter,
                "predicate field `{field}` ({actual:?}) cannot be compared with a {literal} literal"
            ),
            Self::DeferredSelectorDomain { binding } => write!(
                formatter,
                "binding `{binding}` uses an RQL file whose row domain is not resolved yet"
            ),
            Self::ExpansionDomainUnavailable { binding, step } => write!(
                formatter,
                "binding `{binding}` uses row expansion `{step}`, whose result domain is not registered yet"
            ),
            Self::InvalidQuery { binding, message } => {
                write!(
                    formatter,
                    "binding `{binding}` has an invalid query: {message}"
                )
            }
            Self::ZeroLimit { name } => {
                write!(formatter, "assertion limit `{name}` must be positive")
            }
        }
    }
}

impl std::error::Error for RelationalAssertionPlanError {}

/// Validate names, dependency order, row fields, scalar types and aggregate
/// shapes before any workspace query executes.
pub fn validate_relational_assertion_plan(
    plan: &RelationalAssertionPlan,
) -> Result<(), RelationalAssertionPlanError> {
    validate_limits(plan)?;

    let mut domains: HashMap<&RowBindingName, DetailedCodeQueryDomain> = HashMap::new();
    for binding in &plan.bindings {
        if domains.contains_key(&binding.name) {
            return Err(RelationalAssertionPlanError::DuplicateBinding {
                name: binding.name.as_str().to_string(),
            });
        }
        let domain = match &binding.source {
            RowBindingSource::Query(PolicySelector::Inline { query, .. }) => query
                .validate_steps()
                .map(DetailedCodeQueryDomain::from_query_value_kind)
                .map_err(|error| RelationalAssertionPlanError::InvalidQuery {
                    binding: binding.name.as_str().to_string(),
                    message: error.to_string(),
                })?,
            RowBindingSource::Query(PolicySelector::File { .. }) => {
                return Err(RelationalAssertionPlanError::DeferredSelectorDomain {
                    binding: binding.name.as_str().to_string(),
                });
            }
            RowBindingSource::Expansion { from, step } => {
                let Some(source_domain) = domains.get(from).copied() else {
                    return Err(RelationalAssertionPlanError::ForwardBinding {
                        binding: binding.name.as_str().to_string(),
                        referenced: from.as_str().to_string(),
                    });
                };
                match (source_domain, step) {
                    (
                        DetailedCodeQueryDomain::StructuralMatch
                        | DetailedCodeQueryDomain::ReferenceSite
                        | DetailedCodeQueryDomain::CallSite
                        | DetailedCodeQueryDomain::ExpressionSite
                        | DetailedCodeQueryDomain::Occurrence
                        | DetailedCodeQueryDomain::ReceiverAnalysis,
                        crate::definition::RowExpansionStep::ReceiverOutcome,
                    ) => DetailedCodeQueryDomain::ReceiverOutcome,
                    (
                        DetailedCodeQueryDomain::StructuralMatch
                        | DetailedCodeQueryDomain::ReferenceSite
                        | DetailedCodeQueryDomain::CallSite
                        | DetailedCodeQueryDomain::ExpressionSite
                        | DetailedCodeQueryDomain::Occurrence
                        | DetailedCodeQueryDomain::ReceiverAnalysis,
                        crate::definition::RowExpansionStep::ReceiverEvidence,
                    ) => DetailedCodeQueryDomain::ReceiverEvidence,
                    (
                        DetailedCodeQueryDomain::Occurrence,
                        crate::definition::RowExpansionStep::MemberSelection,
                    ) => DetailedCodeQueryDomain::MemberSelection,
                    (
                        DetailedCodeQueryDomain::Occurrence,
                        crate::definition::RowExpansionStep::CandidateHierarchy,
                    ) => DetailedCodeQueryDomain::CandidateHop,
                    (
                        DetailedCodeQueryDomain::Occurrence
                        | DetailedCodeQueryDomain::CallSite
                        | DetailedCodeQueryDomain::ReferenceSite
                        | DetailedCodeQueryDomain::StructuralMatch,
                        crate::definition::RowExpansionStep::DispatchOutcome,
                    ) => DetailedCodeQueryDomain::DispatchOutcome,
                    (
                        DetailedCodeQueryDomain::Occurrence
                        | DetailedCodeQueryDomain::CallSite
                        | DetailedCodeQueryDomain::ReferenceSite
                        | DetailedCodeQueryDomain::StructuralMatch,
                        crate::definition::RowExpansionStep::DispatchTargets,
                    ) => DetailedCodeQueryDomain::DispatchTarget,
                    (
                        DetailedCodeQueryDomain::Declaration,
                        crate::definition::RowExpansionStep::MemberFamily,
                    ) => DetailedCodeQueryDomain::MemberFamily,
                    (
                        DetailedCodeQueryDomain::Declaration,
                        crate::definition::RowExpansionStep::FamilyEdges,
                    ) => DetailedCodeQueryDomain::MemberFamilyEdge,
                    _ => {
                        return Err(RelationalAssertionPlanError::ExpansionDomainUnavailable {
                            binding: binding.name.as_str().to_string(),
                            step: step.label(),
                        });
                    }
                }
            }
        };
        domains.insert(&binding.name, domain);
    }

    for join in &plan.joins {
        let left_domain = binding_domain(&domains, &join.left)?;
        let right_domain = binding_domain(&domains, &join.right)?;
        if join.on.is_empty() {
            return Err(RelationalAssertionPlanError::EmptyJoin {
                left: join.left.as_str().to_string(),
                right: join.right.as_str().to_string(),
            });
        }
        for condition in &join.on {
            let left_type = field_type(left_domain, &join.left, &condition.left_field)?;
            let right_type = field_type(right_domain, &join.right, &condition.right_field)?;
            if left_type != right_type {
                return Err(RelationalAssertionPlanError::JoinTypeMismatch {
                    left: format!("{}.{}", join.left, condition.left_field),
                    left_type,
                    right: format!("{}.{}", join.right, condition.right_field),
                    right_type,
                });
            }
        }
    }

    let mut groups = HashMap::new();
    for group in &plan.groups {
        if groups.contains_key(&group.name) {
            return Err(RelationalAssertionPlanError::DuplicateGroup {
                name: group.name.as_str().to_string(),
            });
        }
        if group.by.is_empty() {
            return Err(RelationalAssertionPlanError::EmptyGroupKey {
                group: group.name.as_str().to_string(),
            });
        }
        for field in &group.by {
            validate_field_ref(&domains, field)?;
        }
        let mut aggregates = HashSet::new();
        for aggregate in &group.aggregates {
            if !aggregates.insert(&aggregate.name) {
                return Err(RelationalAssertionPlanError::DuplicateAggregate {
                    group: group.name.as_str().to_string(),
                    name: aggregate.name.as_str().to_string(),
                });
            }
            let value_type = aggregate
                .value
                .as_ref()
                .map(|field| validate_field_ref(&domains, field))
                .transpose()?;
            match (aggregate.op, value_type) {
                (RowAggregateOp::Count | RowAggregateOp::OrderedEqual, None) => {}
                (RowAggregateOp::Count | RowAggregateOp::OrderedEqual, Some(_)) => {
                    return Err(RelationalAssertionPlanError::AggregateValueForbidden {
                        group: group.name.as_str().to_string(),
                        aggregate: aggregate.name.as_str().to_string(),
                    });
                }
                (RowAggregateOp::Min | RowAggregateOp::CountDistinct, None) => {
                    return Err(RelationalAssertionPlanError::AggregateValueRequired {
                        group: group.name.as_str().to_string(),
                        aggregate: aggregate.name.as_str().to_string(),
                    });
                }
                (RowAggregateOp::Min, Some(CodeQueryRowScalarType::Integer))
                | (RowAggregateOp::CountDistinct, Some(_)) => {}
                (RowAggregateOp::Min, Some(actual)) => {
                    return Err(RelationalAssertionPlanError::InvalidMinType {
                        group: group.name.as_str().to_string(),
                        aggregate: aggregate.name.as_str().to_string(),
                        actual,
                    });
                }
            }
            validate_ordered_sequences(&domains, group, aggregate)?;
            for predicate in &aggregate.predicate {
                let actual = validate_field_ref(&domains, &predicate.field)?;
                if !literal_matches_type(&predicate.value, actual) {
                    return Err(RelationalAssertionPlanError::PredicateTypeMismatch {
                        field: format!("{}.{}", predicate.field.binding, predicate.field.field),
                        actual,
                        literal: row_literal_kind(&predicate.value),
                    });
                }
            }
        }
        groups.insert(&group.name, aggregates);
    }

    let mut assertion_ids = HashSet::new();
    for assertion in &plan.assertions {
        if !assertion_ids.insert(&assertion.id) {
            return Err(RelationalAssertionPlanError::DuplicateAssertion {
                id: assertion.id.as_str().to_string(),
            });
        }
        let Some(aggregates) = groups.get(&assertion.group) else {
            return Err(RelationalAssertionPlanError::UnknownGroup {
                name: assertion.group.as_str().to_string(),
            });
        };
        if !aggregates.contains(&assertion.aggregate) {
            return Err(RelationalAssertionPlanError::UnknownAggregate {
                group: assertion.group.as_str().to_string(),
                name: assertion.aggregate.as_str().to_string(),
            });
        }
    }

    Ok(())
}

/// An ordered comparison is only defined when both sides state an integer
/// position and the two value columns hold the same scalar type. Anything else
/// is rejected before a workspace query runs, because a comparison across
/// scalar types would silently be false at every position rather than being an
/// authoring mistake.
fn validate_ordered_sequences(
    domains: &HashMap<&RowBindingName, DetailedCodeQueryDomain>,
    group: &crate::definition::RowGroup,
    aggregate: &crate::definition::RowAggregate,
) -> Result<(), RelationalAssertionPlanError> {
    let names = || {
        (
            group.name.as_str().to_string(),
            aggregate.name.as_str().to_string(),
        )
    };
    let sequences = match (aggregate.op, aggregate.sequences.as_ref()) {
        (RowAggregateOp::OrderedEqual, Some(sequences)) => sequences,
        (RowAggregateOp::OrderedEqual, None) => {
            let (group, aggregate) = names();
            return Err(RelationalAssertionPlanError::OrderedSequencesRequired {
                group,
                aggregate,
            });
        }
        (_, None) => return Ok(()),
        (_, Some(_)) => {
            let (group, aggregate) = names();
            return Err(RelationalAssertionPlanError::OrderedSequencesForbidden {
                group,
                aggregate,
            });
        }
    };
    for sequence in [&sequences.left, &sequences.right] {
        let position = validate_field_ref(domains, &sequence.position)?;
        if position != CodeQueryRowScalarType::Integer {
            let (group, aggregate) = names();
            return Err(RelationalAssertionPlanError::InvalidOrderedPositionType {
                group,
                aggregate,
                field: format!("{}.{}", sequence.position.binding, sequence.position.field),
                actual: position,
            });
        }
    }
    let left_type = validate_field_ref(domains, &sequences.left.value)?;
    let right_type = validate_field_ref(domains, &sequences.right.value)?;
    if left_type != right_type {
        let (group, aggregate) = names();
        return Err(RelationalAssertionPlanError::OrderedValueTypeMismatch {
            group,
            aggregate,
            left_type,
            right_type,
        });
    }
    Ok(())
}

fn literal_matches_type(
    literal: &crate::definition::RowLiteral,
    scalar_type: CodeQueryRowScalarType,
) -> bool {
    use crate::definition::RowLiteral;
    matches!(
        (literal, scalar_type),
        (RowLiteral::Integer(_), CodeQueryRowScalarType::Integer)
            | (RowLiteral::Boolean(_), CodeQueryRowScalarType::Boolean)
            | (
                RowLiteral::ConstrainedEnum(_),
                CodeQueryRowScalarType::ConstrainedEnum
            )
            | (
                RowLiteral::String(_),
                CodeQueryRowScalarType::String
                    | CodeQueryRowScalarType::StableId
                    | CodeQueryRowScalarType::DeclarationIdentity
            )
    )
}

fn row_literal_kind(literal: &crate::definition::RowLiteral) -> &'static str {
    use crate::definition::RowLiteral;
    match literal {
        RowLiteral::String(_) => "string",
        RowLiteral::Integer(_) => "integer",
        RowLiteral::Boolean(_) => "boolean",
        RowLiteral::ConstrainedEnum(_) => "constrained-enum",
    }
}

fn validate_limits(plan: &RelationalAssertionPlan) -> Result<(), RelationalAssertionPlanError> {
    for (name, value) in [
        ("max_source_rows", plan.limits.max_source_rows),
        ("max_expanded_rows", plan.limits.max_expanded_rows),
        ("max_join_comparisons", plan.limits.max_join_comparisons),
        ("max_joined_rows", plan.limits.max_joined_rows),
        ("max_groups", plan.limits.max_groups),
        ("max_values_per_group", plan.limits.max_values_per_group),
    ] {
        if value == 0 {
            return Err(RelationalAssertionPlanError::ZeroLimit { name });
        }
    }
    Ok(())
}

fn binding_domain(
    domains: &HashMap<&RowBindingName, DetailedCodeQueryDomain>,
    binding: &RowBindingName,
) -> Result<DetailedCodeQueryDomain, RelationalAssertionPlanError> {
    domains
        .get(binding)
        .copied()
        .ok_or_else(|| RelationalAssertionPlanError::UnknownBinding {
            name: binding.as_str().to_string(),
        })
}

fn validate_field_ref(
    domains: &HashMap<&RowBindingName, DetailedCodeQueryDomain>,
    field: &RowFieldRef,
) -> Result<CodeQueryRowScalarType, RelationalAssertionPlanError> {
    let domain = binding_domain(domains, &field.binding)?;
    field_type(domain, &field.binding, &field.field)
}

fn field_type(
    domain: DetailedCodeQueryDomain,
    binding: &RowBindingName,
    field: &str,
) -> Result<CodeQueryRowScalarType, RelationalAssertionPlanError> {
    domain
        .row_fields()
        .iter()
        .find(|candidate| candidate.name == field)
        .map(|candidate| candidate.scalar_type)
        .ok_or_else(|| RelationalAssertionPlanError::UnknownField {
            binding: binding.as_str().to_string(),
            field: field.to_string(),
        })
}

type JoinedTuple<'a> = HashMap<&'a RowBindingName, (usize, &'a CodeQueryResultValue)>;
type GroupAggregateValues<'a> =
    HashMap<(&'a RowGroupName, Vec<Option<RowScalar>>), HashMap<&'a RowAggregateName, u64>>;
type GroupRepresentatives<'a> =
    HashMap<(&'a RowGroupName, Vec<Option<RowScalar>>), Vec<Vec<RelationalViolationRow>>>;

/// Evaluate a validated query-only relational plan over already executed
/// CodeQuery row sets. Typed expansions use the same engine once their row
/// domains land in later milestones.
pub fn evaluate_relational_assertion_rows(
    plan: &RelationalAssertionPlan,
    inputs: &[RelationalInput<'_>],
) -> Result<RelationalAssertionEvaluation, RelationalAssertionEvaluationError> {
    let input_by_name = inputs
        .iter()
        .map(|input| (input.binding, input))
        .collect::<HashMap<_, _>>();
    let mut exhaustive = inputs.iter().all(|input| input.exhaustive);
    let mut limit_exceeded = false;

    let first =
        plan.bindings
            .first()
            .ok_or_else(|| RelationalAssertionEvaluationError::MissingInput {
                binding: "<first>".to_string(),
            })?;
    if matches!(first.source, RowBindingSource::Expansion { .. }) {
        return Err(RelationalAssertionEvaluationError::UnsupportedExpansion {
            binding: first.name.as_str().to_string(),
        });
    }
    let first_input = input_by_name.get(&first.name).ok_or_else(|| {
        RelationalAssertionEvaluationError::MissingInput {
            binding: first.name.as_str().to_string(),
        }
    })?;
    let source_count = first_input.rows.len().min(plan.limits.max_source_rows);
    if source_count < first_input.rows.len() {
        exhaustive = false;
        limit_exceeded = true;
    }
    let mut tuples = first_input.rows[..source_count]
        .iter()
        .enumerate()
        .map(|(index, item)| HashMap::from([(&first.name, (index, &item.value))]))
        .collect::<Vec<_>>();
    let mut comparisons = 0usize;

    for join in &plan.joins {
        if !tuples.iter().all(|tuple| tuple.contains_key(&join.left)) {
            return Err(RelationalAssertionEvaluationError::DisconnectedJoin {
                binding: join.left.as_str().to_string(),
            });
        }
        let right = input_by_name.get(&join.right).ok_or_else(|| {
            RelationalAssertionEvaluationError::MissingInput {
                binding: join.right.as_str().to_string(),
            }
        })?;
        let right_count = right.rows.len().min(plan.limits.max_source_rows);
        if right_count < right.rows.len() {
            exhaustive = false;
            limit_exceeded = true;
        }
        let mut joined = Vec::new();
        'left: for tuple in &tuples {
            let (_, left_row) = tuple[&join.left];
            let mut matched = false;
            for (right_index, right_item) in right.rows[..right_count].iter().enumerate() {
                comparisons = comparisons.saturating_add(1);
                if comparisons > plan.limits.max_join_comparisons {
                    exhaustive = false;
                    limit_exceeded = true;
                    break 'left;
                }
                if join_conditions_match(left_row, &right_item.value, join)? {
                    matched = true;
                    if join.kind == crate::definition::RowJoinKind::Inner {
                        if joined.len() == plan.limits.max_joined_rows {
                            exhaustive = false;
                            limit_exceeded = true;
                            break 'left;
                        }
                        let mut next = tuple.clone();
                        next.insert(&join.right, (right_index, &right_item.value));
                        joined.push(next);
                    }
                }
            }
            if join.kind == crate::definition::RowJoinKind::Anti && !matched {
                if joined.len() == plan.limits.max_joined_rows {
                    exhaustive = false;
                    limit_exceeded = true;
                    break;
                }
                joined.push(tuple.clone());
            }
        }
        tuples = joined;
    }

    let mut aggregate_values: GroupAggregateValues<'_> = HashMap::new();
    let mut group_representatives: GroupRepresentatives<'_> = HashMap::new();
    for group in &plan.groups {
        let mut grouped: HashMap<Vec<Option<RowScalar>>, Vec<&JoinedTuple<'_>>> = HashMap::new();
        for tuple in &tuples {
            let key = group
                .by
                .iter()
                .map(|field| tuple_field(tuple, field))
                .collect::<Result<Vec<_>, _>>()?;
            if !grouped.contains_key(&key) && grouped.len() == plan.limits.max_groups {
                exhaustive = false;
                limit_exceeded = true;
                continue;
            }
            let values = grouped.entry(key).or_default();
            if values.len() == plan.limits.max_values_per_group {
                exhaustive = false;
                limit_exceeded = true;
                continue;
            }
            values.push(tuple);
        }
        for (key, rows) in grouped {
            let mut values = HashMap::new();
            for aggregate in &group.aggregates {
                let matching = rows
                    .iter()
                    .copied()
                    .map(|tuple| {
                        predicates_match(tuple, &aggregate.predicate)
                            .map(|matches| (tuple, matches))
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter_map(|(tuple, matches)| matches.then_some(tuple))
                    .collect::<Vec<_>>();
                let value = match aggregate.op {
                    RowAggregateOp::Count => matching.len() as u64,
                    RowAggregateOp::CountDistinct => {
                        let field = aggregate.value.as_ref().expect("validated aggregate value");
                        matching
                            .into_iter()
                            .filter_map(|tuple| tuple_field(tuple, field).transpose())
                            .collect::<Result<HashSet<_>, _>>()?
                            .len() as u64
                    }
                    RowAggregateOp::Min => {
                        let field = aggregate.value.as_ref().expect("validated aggregate value");
                        matching
                            .into_iter()
                            .filter_map(|tuple| match tuple_field(tuple, field) {
                                Ok(Some(RowScalar::Integer(value))) => Some(Ok(value)),
                                Ok(None) => None,
                                Ok(Some(_)) => unreachable!("validated min field type"),
                                Err(error) => Some(Err(error)),
                            })
                            .collect::<Result<Vec<_>, _>>()?
                            .into_iter()
                            .min()
                            .unwrap_or(0)
                    }
                    RowAggregateOp::OrderedEqual => {
                        let sequences = aggregate
                            .sequences
                            .as_ref()
                            .expect("validated ordered sequences");
                        let left = ordered_sequence(&matching, &sequences.left)?;
                        let right = ordered_sequence(&matching, &sequences.right)?;
                        u64::from(left.is_some() && left == right)
                    }
                };
                values.insert(&aggregate.name, value);
            }
            let representatives = rows
                .iter()
                .take(MAX_VIOLATION_REPRESENTATIVE_TUPLES)
                .map(|tuple| {
                    plan.bindings
                        .iter()
                        .filter_map(|binding| {
                            tuple
                                .get(&binding.name)
                                .map(|(index, _)| RelationalViolationRow {
                                    binding: binding.name.clone(),
                                    row: *index,
                                })
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            group_representatives.insert((&group.name, key.clone()), representatives);
            aggregate_values.insert((&group.name, key), values);
        }
    }

    // Deterministic finding order: one sort over every (group, key) pair,
    // not map order and not a per-assertion sort. Assertions over one group
    // read their contiguous slice of the same ordering.
    let mut sorted_group_keys: Vec<(&RowGroupName, Vec<Option<RowScalar>>)> = aggregate_values
        .keys()
        .map(|(group, key)| (*group, key.clone()))
        .collect();
    sorted_group_keys.sort();

    let mut violations = Vec::new();
    for assertion in &plan.assertions {
        let group_keys = sorted_group_keys
            .iter()
            .filter(|(group, _)| *group == &assertion.group)
            .map(|(_, key)| key.clone())
            .collect::<Vec<_>>();
        for key in group_keys {
            let values = &aggregate_values[&(&assertion.group, key.clone())];
            let actual = values.get(&assertion.aggregate).copied().ok_or_else(|| {
                RelationalAssertionEvaluationError::MissingAggregate {
                    group: assertion.group.as_str().to_string(),
                    aggregate: assertion.aggregate.as_str().to_string(),
                }
            })?;
            let bounded_actual = u32::try_from(actual).unwrap_or(u32::MAX);
            if !assertion.cardinality.satisfied_by(bounded_actual) {
                let representatives = group_representatives
                    .get(&(&assertion.group, key.clone()))
                    .cloned()
                    .unwrap_or_default();
                violations.push(RelationalAssertionViolation {
                    assertion: assertion.id.clone(),
                    group: assertion.group.clone(),
                    key,
                    actual,
                    representatives,
                });
            }
        }
    }
    Ok(RelationalAssertionEvaluation {
        violations,
        exhaustive,
        limit_exceeded,
    })
}

/// Recover one ordered sequence from a group's contributing tuples.
///
/// A joined tuple set has no inherent order, so the sequence comes from the
/// position each row states about itself. Two rows that state the same
/// position must therefore agree on the value; if they do not, the sequence is
/// not defined and the answer is `None`, which the caller reads as "parity is
/// not proven" rather than as "the lists differ in a specific way". A row whose
/// position is absent is undecidable for the same reason.
fn ordered_sequence(
    tuples: &[&JoinedTuple<'_>],
    sequence: &crate::definition::RowOrderedSequence,
) -> Result<Option<OrderedSequence>, RelationalAssertionEvaluationError> {
    let mut positions: HashMap<u64, Option<RowScalar>> = HashMap::new();
    for tuple in tuples {
        let Some(RowScalar::Integer(position)) = tuple_field(tuple, &sequence.position)? else {
            return Ok(None);
        };
        let value = tuple_field(tuple, &sequence.value)?;
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

/// One recovered sequence: each stated position with the value read there,
/// ascending by position.
type OrderedSequence = Vec<(u64, Option<RowScalar>)>;

fn join_conditions_match(
    left: &CodeQueryResultValue,
    right: &CodeQueryResultValue,
    join: &crate::definition::RowJoin,
) -> Result<bool, RelationalAssertionEvaluationError> {
    for condition in &join.on {
        let left_value = row_field(left, &join.left, &condition.left_field)?;
        let right_value = row_field(right, &join.right, &condition.right_field)?;
        if left_value != right_value {
            return Ok(false);
        }
    }
    Ok(true)
}

fn tuple_field(
    tuple: &JoinedTuple<'_>,
    field: &RowFieldRef,
) -> Result<Option<RowScalar>, RelationalAssertionEvaluationError> {
    let (_, row) = tuple.get(&field.binding).ok_or_else(|| {
        RelationalAssertionEvaluationError::MissingTupleBinding {
            binding: field.binding.as_str().to_string(),
        }
    })?;
    row_field(row, &field.binding, &field.field)
}

fn row_field(
    row: &CodeQueryResultValue,
    binding: &RowBindingName,
    field: &str,
) -> Result<Option<RowScalar>, RelationalAssertionEvaluationError> {
    row.row()
        .field(field)
        .map(|value| value.map(RowScalar::from))
        .map_err(|_| RelationalAssertionEvaluationError::RowField {
            binding: binding.as_str().to_string(),
            field: field.to_string(),
        })
}

fn predicates_match(
    tuple: &JoinedTuple<'_>,
    predicates: &[RowPredicate],
) -> Result<bool, RelationalAssertionEvaluationError> {
    for predicate in predicates {
        let actual = tuple_field(tuple, &predicate.field)?;
        if !actual.is_some_and(|actual| scalar_matches_literal(&actual, &predicate.value)) {
            return Ok(false);
        }
    }
    Ok(true)
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use brokk_bifrost_analysis::analyzer::structural::search::{
        CodeQueryOccurrence, CodeQueryOccurrenceTarget,
    };
    use brokk_bifrost_analysis::analyzer::structural::{CodeQuery, CodeQueryRange};
    use brokk_bifrost_analysis::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
    use serde_json::json;

    use super::*;
    use crate::definition::{
        AssertCardinality, PolicyAssertId, RelationalAssertionLimits, RowAggregate,
        RowAggregateName, RowAssertion, RowBinding, RowGroup, RowGroupName, RowJoin,
        RowJoinCondition, RowJoinKind,
    };

    fn name<T: FromStr>(value: &str) -> T
    where
        T::Err: fmt::Debug,
    {
        value.parse().expect("valid test identifier")
    }

    fn inline_selector(query: serde_json::Value) -> PolicySelector {
        PolicySelector::Inline {
            schema: SchemaVersionResolution {
                version: 8,
                origin: SchemaVersionOrigin::Explicit,
            },
            query: CodeQuery::from_json(&query).expect("valid inline query"),
        }
    }

    fn occurrence_selector() -> PolicySelector {
        inline_selector(json!({
            "schema_version": 1,
            "occurrences": { "role": "member_position" }
        }))
    }

    fn call_argument_selector() -> PolicySelector {
        inline_selector(json!({
            "schema_version": 1,
            "occurrences": { "role": "member_position" },
            "steps": [
                { "op": "call_shape" },
                { "op": "call_argument_groups" },
                { "op": "call_arguments" }
            ]
        }))
    }

    fn signature_parameter_selector() -> PolicySelector {
        inline_selector(json!({
            "schema_version": 1,
            "match": { "kind": "function" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "callable_signature" },
                { "op": "signature_parameters" }
            ]
        }))
    }

    fn unit_range() -> CodeQueryRange {
        CodeQueryRange {
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
        }
    }

    fn item(value: CodeQueryResultValue) -> CodeQueryResultItem {
        CodeQueryResultItem {
            value,
            provenance: Vec::new(),
            provenance_truncated: false,
        }
    }

    fn occurrence(id: &str, ast_id: &str) -> CodeQueryResultItem {
        item(CodeQueryResultValue::Occurrence {
            value: Box::new(CodeQueryOccurrence {
                id: id.to_string(),
                ast_id: ast_id.to_string(),
                path: "src/lib.rs".to_string(),
                language: "rust",
                class: "reference",
                role: "member_position",
                namespace: "value",
                range: unit_range(),
                start_byte: 0,
                end_byte: 1,
                enclosing_symbol: None,
                raw_spelling: "member".to_string(),
                decoded_spelling: None,
                target: CodeQueryOccurrenceTarget::None,
            }),
        })
    }

    fn valid_plan() -> RelationalAssertionPlan {
        let site: RowBindingName = name("site");
        let candidate: RowBindingName = name("candidate");
        let group: RowGroupName = name("by-site");
        let count: RowAggregateName = name("count");
        RelationalAssertionPlan {
            bindings: vec![
                RowBinding {
                    name: site.clone(),
                    source: RowBindingSource::Query(occurrence_selector()),
                },
                RowBinding {
                    name: candidate.clone(),
                    source: RowBindingSource::Query(occurrence_selector()),
                },
            ],
            joins: vec![RowJoin {
                left: site.clone(),
                right: candidate.clone(),
                kind: RowJoinKind::Inner,
                on: vec![RowJoinCondition {
                    left_field: "ast_id".to_string(),
                    right_field: "ast_id".to_string(),
                }],
            }],
            groups: vec![RowGroup {
                name: group.clone(),
                by: vec![RowFieldRef {
                    binding: site,
                    field: "ast_id".to_string(),
                }],
                aggregates: vec![RowAggregate {
                    name: count.clone(),
                    op: RowAggregateOp::Count,
                    value: None,
                    sequences: None,
                    predicate: Vec::new(),
                }],
            }],
            assertions: vec![RowAssertion {
                id: name::<PolicyAssertId>("one-candidate"),
                group,
                aggregate: count,
                cardinality: AssertCardinality::Exactly(1),
            }],
            limits: RelationalAssertionLimits::default(),
        }
    }

    #[test]
    fn validates_typed_occurrence_join_and_group_plan() {
        validate_relational_assertion_plan(&valid_plan()).expect("valid relational plan");
    }

    #[test]
    fn validates_occurrence_to_receiver_evidence_expansion() {
        let mut plan = valid_plan();
        let site = plan.bindings[0].name.clone();
        plan.bindings[1].source = RowBindingSource::Expansion {
            from: site,
            step: crate::definition::RowExpansionStep::ReceiverEvidence,
        };
        plan.joins[0].on[0].right_field = "site_ast_id".to_string();
        validate_relational_assertion_plan(&plan)
            .expect("member occurrences expand into receiver evidence rows");
    }

    #[test]
    fn rejects_unknown_row_field_before_execution() {
        let mut plan = valid_plan();
        plan.joins[0].on[0].right_field = "source_range".to_string();
        assert_eq!(
            validate_relational_assertion_plan(&plan),
            Err(RelationalAssertionPlanError::UnknownField {
                binding: "candidate".to_string(),
                field: "source_range".to_string(),
            })
        );
    }

    #[test]
    fn rejects_join_fields_with_different_scalar_types() {
        let mut plan = valid_plan();
        plan.joins[0].on[0].right_field = "target_count".to_string();
        assert!(matches!(
            validate_relational_assertion_plan(&plan),
            Err(RelationalAssertionPlanError::JoinTypeMismatch { .. })
        ));
    }

    #[test]
    fn rejects_forward_expansion_binding() {
        let plan = RelationalAssertionPlan {
            bindings: vec![RowBinding {
                name: name("receiver"),
                source: RowBindingSource::Expansion {
                    from: name("site"),
                    step: crate::definition::RowExpansionStep::ReceiverEvidence,
                },
            }],
            joins: Vec::new(),
            groups: Vec::new(),
            assertions: Vec::new(),
            limits: RelationalAssertionLimits::default(),
        };
        assert_eq!(
            validate_relational_assertion_plan(&plan),
            Err(RelationalAssertionPlanError::ForwardBinding {
                binding: "receiver".to_string(),
                referenced: "site".to_string(),
            })
        );
    }

    #[test]
    fn rejects_min_over_non_integer_field() {
        let mut plan = valid_plan();
        plan.groups[0].aggregates[0].op = RowAggregateOp::Min;
        plan.groups[0].aggregates[0].value = Some(RowFieldRef {
            binding: name("candidate"),
            field: "role".to_string(),
        });
        assert_eq!(
            validate_relational_assertion_plan(&plan),
            Err(RelationalAssertionPlanError::InvalidMinType {
                group: "by-site".to_string(),
                aggregate: "count".to_string(),
                actual: CodeQueryRowScalarType::ConstrainedEnum,
            })
        );
    }

    #[test]
    fn evaluates_clean_finding_and_incomplete_relations() {
        let plan = valid_plan();
        let site_rows = vec![occurrence("site", "ast-1")];
        let one_candidate = vec![occurrence("candidate-1", "ast-1")];
        let two_candidates = vec![
            occurrence("candidate-1", "ast-1"),
            occurrence("candidate-2", "ast-1"),
        ];
        let site = &plan.bindings[0].name;
        let candidate = &plan.bindings[1].name;

        let clean = evaluate_relational_assertion_rows(
            &plan,
            &[
                RelationalInput {
                    binding: site,
                    rows: &site_rows,
                    exhaustive: true,
                },
                RelationalInput {
                    binding: candidate,
                    rows: &one_candidate,
                    exhaustive: true,
                },
            ],
        )
        .unwrap();
        assert!(clean.violations.is_empty());
        assert!(clean.exhaustive);

        let finding = evaluate_relational_assertion_rows(
            &plan,
            &[
                RelationalInput {
                    binding: site,
                    rows: &site_rows,
                    exhaustive: true,
                },
                RelationalInput {
                    binding: candidate,
                    rows: &two_candidates,
                    exhaustive: true,
                },
            ],
        )
        .unwrap();
        assert_eq!(finding.violations.len(), 1);
        assert_eq!(finding.violations[0].actual, 2);

        let incomplete = evaluate_relational_assertion_rows(
            &plan,
            &[
                RelationalInput {
                    binding: site,
                    rows: &site_rows,
                    exhaustive: true,
                },
                RelationalInput {
                    binding: candidate,
                    rows: &one_candidate,
                    exhaustive: false,
                },
            ],
        )
        .unwrap();
        assert!(incomplete.violations.is_empty());
        assert!(!incomplete.exhaustive);
    }

    fn call_argument(site: &str, index: usize, name: &str) -> CodeQueryResultItem {
        item(CodeQueryResultValue::CallArgument {
            value: Box::new(
                brokk_bifrost_analysis::analyzer::structural::search::CodeQueryCallShapeArgument {
                    id: format!("{site}-arg-{index}"),
                    group_id: format!("{site}-group"),
                    site_id: site.to_string(),
                    path: "app.py".to_string(),
                    range: unit_range(),
                    argument_index: index,
                    name: Some(name.to_string()),
                    spread: false,
                },
            ),
        })
    }

    fn signature_parameter(signature: &str, index: usize, label: &str) -> CodeQueryResultItem {
        item(CodeQueryResultValue::SignatureParameter {
            value: Box::new(
                brokk_bifrost_analysis::analyzer::structural::search::CodeQuerySignatureParameter {
                    id: format!("{signature}-param-{index}"),
                    signature_id: signature.to_string(),
                    path: "app.py".to_string(),
                    range: unit_range(),
                    parameter_index: index,
                    label: label.to_string(),
                    label_start_byte: 0,
                    label_end_byte: label.len(),
                    declared_type: None,
                    optional: Some(false),
                    repeated: Some(false),
                },
            ),
        })
    }

    /// An `ordered-equal` plan: every named argument of a call must sit at the
    /// position its parameter was declared at.
    ///
    /// The join is a correlation join -- one call site to one callable -- so
    /// every argument row meets every parameter row of that pair and the group
    /// therefore holds both sequences complete. That is what makes a length
    /// difference visible: a join on the compared value instead would retain
    /// only positions that already matched on both sides, and two projections
    /// of that kind are equal in length by construction.
    fn ordered_equal_plan() -> RelationalAssertionPlan {
        let arg: RowBindingName = name("arg");
        let param: RowBindingName = name("param");
        let group: RowGroupName = name("shape");
        let parity: RowAggregateName = name("parity");
        RelationalAssertionPlan {
            bindings: vec![
                RowBinding {
                    name: arg.clone(),
                    source: RowBindingSource::Query(call_argument_selector()),
                },
                RowBinding {
                    name: param.clone(),
                    source: RowBindingSource::Query(signature_parameter_selector()),
                },
            ],
            joins: vec![RowJoin {
                left: arg.clone(),
                right: param.clone(),
                kind: RowJoinKind::Inner,
                on: vec![RowJoinCondition {
                    left_field: "site_id".to_string(),
                    right_field: "signature_id".to_string(),
                }],
            }],
            groups: vec![RowGroup {
                name: group.clone(),
                by: vec![RowFieldRef {
                    binding: arg.clone(),
                    field: "site_id".to_string(),
                }],
                aggregates: vec![RowAggregate {
                    name: parity.clone(),
                    op: RowAggregateOp::OrderedEqual,
                    value: None,
                    sequences: Some(crate::definition::RowOrderedSequencePair {
                        left: crate::definition::RowOrderedSequence {
                            position: RowFieldRef {
                                binding: arg,
                                field: "argument_index".to_string(),
                            },
                            value: RowFieldRef {
                                binding: name("arg"),
                                field: "name".to_string(),
                            },
                        },
                        right: crate::definition::RowOrderedSequence {
                            position: RowFieldRef {
                                binding: param.clone(),
                                field: "parameter_index".to_string(),
                            },
                            value: RowFieldRef {
                                binding: param,
                                field: "label".to_string(),
                            },
                        },
                    }),
                    predicate: Vec::new(),
                }],
            }],
            assertions: vec![RowAssertion {
                id: name::<PolicyAssertId>("argument-order"),
                group,
                aggregate: parity,
                cardinality: AssertCardinality::Exactly(1),
            }],
            limits: RelationalAssertionLimits::default(),
        }
    }

    fn ordered_equal_parity(plan: &RelationalAssertionPlan, arguments: &[(usize, &str)]) -> u64 {
        let argument_rows = arguments
            .iter()
            .map(|(index, name)| call_argument("site", *index, name))
            .collect::<Vec<_>>();
        // The parameter rows are correlated to the call site by the key the
        // plan's join declares.
        let parameter_rows = vec![
            signature_parameter("site", 0, "name"),
            signature_parameter("site", 1, "greeting"),
        ];
        let outcome = evaluate_relational_assertion_rows(
            plan,
            &[
                RelationalInput {
                    binding: &plan.bindings[0].name,
                    rows: &argument_rows,
                    exhaustive: true,
                },
                RelationalInput {
                    binding: &plan.bindings[1].name,
                    rows: &parameter_rows,
                    exhaustive: true,
                },
            ],
        )
        .unwrap();
        // The assertion demands parity, so a violation carries the aggregate's
        // actual value and no violation means the aggregate was one.
        outcome
            .violations
            .first()
            .map(|violation| violation.actual)
            .unwrap_or(1)
    }

    /// The predicate exists because a set-equality check cannot tell these two
    /// calls apart: the same two names, written in two orders.
    #[test]
    fn ordered_equal_separates_list_order_from_list_membership() {
        let plan = ordered_equal_plan();
        validate_relational_assertion_plan(&plan).expect("valid ordered plan");
        assert_eq!(
            ordered_equal_parity(&plan, &[(0, "name"), (1, "greeting")]),
            1,
            "declaration order is parity"
        );
        assert_eq!(
            ordered_equal_parity(&plan, &[(0, "greeting"), (1, "name")]),
            0,
            "the same set in a different order is not parity"
        );
    }

    /// A shorter list is not parity either, which is the case a positional
    /// inner join alone silently accepts: the surplus position simply has no
    /// partner to disagree with.
    #[test]
    fn ordered_equal_rejects_a_prefix_of_the_declared_list() {
        let plan = ordered_equal_plan();
        assert_eq!(ordered_equal_parity(&plan, &[(0, "name")]), 0);
    }

    /// Two rows that claim one position and disagree leave the sequence
    /// undefined, and an undefined sequence is never reported as parity.
    #[test]
    fn ordered_equal_never_claims_parity_over_a_contradictory_position() {
        let plan = ordered_equal_plan();
        assert_eq!(
            ordered_equal_parity(&plan, &[(0, "name"), (0, "greeting")]),
            0
        );
    }

    #[test]
    fn an_ordered_aggregate_must_declare_both_sequences() {
        let mut plan = ordered_equal_plan();
        plan.groups[0].aggregates[0].sequences = None;
        assert_eq!(
            validate_relational_assertion_plan(&plan),
            Err(RelationalAssertionPlanError::OrderedSequencesRequired {
                group: "shape".to_string(),
                aggregate: "parity".to_string(),
            })
        );
    }

    #[test]
    fn a_folding_aggregate_must_not_declare_sequences() {
        let mut plan = ordered_equal_plan();
        plan.groups[0].aggregates[0].op = RowAggregateOp::Count;
        assert_eq!(
            validate_relational_assertion_plan(&plan),
            Err(RelationalAssertionPlanError::OrderedSequencesForbidden {
                group: "shape".to_string(),
                aggregate: "parity".to_string(),
            })
        );
    }

    #[test]
    fn source_and_join_limits_mark_truncation() {
        let mut plan = valid_plan();
        plan.limits.max_source_rows = 1;
        plan.limits.max_join_comparisons = 1;
        let site_rows = vec![occurrence("site-1", "ast-1"), occurrence("site-2", "ast-2")];
        let candidates = vec![
            occurrence("candidate-1", "ast-1"),
            occurrence("candidate-2", "ast-2"),
        ];
        let outcome = evaluate_relational_assertion_rows(
            &plan,
            &[
                RelationalInput {
                    binding: &plan.bindings[0].name,
                    rows: &site_rows,
                    exhaustive: true,
                },
                RelationalInput {
                    binding: &plan.bindings[1].name,
                    rows: &candidates,
                    exhaustive: true,
                },
            ],
        )
        .unwrap();
        assert!(outcome.limit_exceeded);
        assert!(!outcome.exhaustive);
    }
}
