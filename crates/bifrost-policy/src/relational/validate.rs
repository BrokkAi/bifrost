//! Typed validation of a lowered relational plan.
//!
//! Everything a policy claims about rows is checked here, before any workspace
//! query runs: that every column exists in the relation the operator reads,
//! that comparisons are defined over the scalar types they compare, that a null
//! test names a field the registry can actually leave absent, that folds get the
//! value column their arithmetic needs, and that the dependency graph is acyclic
//! and reachable.
//!
//! A rejected plan is an authoring error reported at load time. Nothing here is
//! a runtime condition.

use std::collections::HashSet;
use std::fmt;

use brokk_bifrost_rql::structural::CodeQueryRowScalarType;

use crate::definition::RowLiteral;

use super::ir::{
    IrAggregate, IrColumn, IrLimits, IrOperand, IrPredicate, IrRelation, IrRelationOp, IrSchema,
    MAX_IR_SET_MEMBERS, RelationalPlanIr,
};

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
    NestedRowSelector {
        binding: String,
    },
    InvalidRowSelectorOutput {
        detail: String,
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
    /// A fold other than `min` read a value column of the wrong scalar type.
    InvalidAggregateValueType {
        group: String,
        aggregate: String,
        aggregate_op: &'static str,
        expected: CodeQueryRowScalarType,
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
    /// Two compared columns hold different scalar types.
    ComparisonTypeMismatch {
        left: String,
        left_type: CodeQueryRowScalarType,
        right: String,
        right_type: CodeQueryRowScalarType,
    },
    /// An ordered comparison was written over a scalar type that has no order.
    UnorderedComparison {
        field: String,
        operator: &'static str,
        actual: CodeQueryRowScalarType,
    },
    /// A null test was written about a field the registry always populates.
    NullTestOnRequiredField {
        field: String,
    },
    /// A literal was compared against a `ConstrainedEnum` column whose value
    /// domain does not contain it. The comparison could never be true, so the
    /// whole plan would report a clean run forever (issue #2515).
    UnknownEnumLabel {
        field: String,
        label: String,
        legal: &'static [&'static str],
    },
    /// A membership test enumerated no literals, or more than the bound allows.
    InvalidSetMembership {
        field: String,
        count: usize,
        max: usize,
    },
    /// A projection published the same column name twice, which would make one
    /// of them unaddressable.
    DuplicateProjectionColumn {
        relation: String,
        column: String,
    },
    /// An operator was paired with an operand it does not take -- a null test
    /// with a value, or a membership test without a set. Only a hand-built
    /// authoring model can state this; the decoder cannot produce it.
    MalformedPredicate {
        field: String,
        operator: &'static str,
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
    /// A plan with no bindings has nothing to evaluate.
    EmptyPlan,
    /// An operator reads a binding whose rows never reach it.
    DisconnectedBinding {
        binding: String,
    },
    /// One binding was joined into the same row set twice, which would make its
    /// columns ambiguous.
    RepeatedJoinBinding {
        binding: String,
    },
    /// An operator reads a relation that is not defined before it. Only a
    /// hand-built IR can state this; lowering cannot produce it.
    RelationCycle {
        relation: String,
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
            Self::NestedRowSelector { binding } => write!(
                formatter,
                "binding `{binding}` cannot use a nested row selector as its query"
            ),
            Self::InvalidRowSelectorOutput { detail } => {
                write!(formatter, "invalid row-selector output: {detail}")
            }
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
            Self::InvalidAggregateValueType {
                group,
                aggregate,
                aggregate_op,
                expected,
                actual,
            } => write!(
                formatter,
                "aggregate `{group}.{aggregate}` (`{aggregate_op}`) requires a {expected:?} value, found {actual:?}"
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
            Self::ComparisonTypeMismatch {
                left,
                left_type,
                right,
                right_type,
            } => write!(
                formatter,
                "predicate compares `{left}` ({left_type:?}) with `{right}` ({right_type:?})"
            ),
            Self::UnorderedComparison {
                field,
                operator,
                actual,
            } => write!(
                formatter,
                "predicate operator `{operator}` is not defined over `{field}` ({actual:?})"
            ),
            Self::NullTestOnRequiredField { field } => write!(
                formatter,
                "field `{field}` is always present, so a null test over it is constant"
            ),
            Self::UnknownEnumLabel {
                field,
                label,
                legal,
            } => write!(
                formatter,
                "`{label}` is not a value of `{field}`; the accepted values are {}",
                legal.join(", ")
            ),
            Self::InvalidSetMembership { field, count, max } => write!(
                formatter,
                "membership test over `{field}` lists {count} literals, which is outside 1..={max}"
            ),
            Self::DuplicateProjectionColumn { relation, column } => write!(
                formatter,
                "projection `{relation}` publishes column `{column}` twice"
            ),
            Self::MalformedPredicate { field, operator } => write!(
                formatter,
                "predicate over `{field}` pairs operator `{operator}` with an operand it does not take"
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
            Self::EmptyPlan => write!(
                formatter,
                "a relational plan must bind at least one row set"
            ),
            Self::DisconnectedBinding { binding } => write!(
                formatter,
                "binding `{binding}` is never joined into the rows this plan reads"
            ),
            Self::RepeatedJoinBinding { binding } => {
                write!(formatter, "binding `{binding}` is joined in more than once")
            }
            Self::RelationCycle { relation } => write!(
                formatter,
                "relation `{relation}` reads a relation that is not defined before it"
            ),
        }
    }
}

impl std::error::Error for RelationalAssertionPlanError {}

/// Every operator bound must be positive: a zero bound admits no rows at all,
/// which would silently pass every absence assertion.
pub fn validate_limits(limits: &IrLimits) -> Result<(), RelationalAssertionPlanError> {
    for (name, value) in [
        ("max_source_rows", limits.max_source_rows),
        ("max_expanded_rows", limits.max_expanded_rows),
        ("max_join_comparisons", limits.max_join_comparisons),
        ("max_joined_rows", limits.max_joined_rows),
        ("max_groups", limits.max_groups),
        ("max_values_per_group", limits.max_values_per_group),
    ] {
        if value == 0 {
            return Err(RelationalAssertionPlanError::ZeroLimit { name });
        }
    }
    Ok(())
}

/// Validate a lowered plan against the row registry and the IR's typing rules.
pub fn validate_plan_ir(plan: &RelationalPlanIr) -> Result<(), RelationalAssertionPlanError> {
    validate_limits(&plan.limits)?;
    if plan.relations.is_empty() {
        return Err(RelationalAssertionPlanError::EmptyPlan);
    }

    for (index, relation) in plan.relations.iter().enumerate() {
        if relation.id.index() != index {
            return Err(RelationalAssertionPlanError::RelationCycle {
                relation: relation.name.clone(),
            });
        }
        // Inputs precede their reader, so the dependency graph is acyclic and
        // one forward pass evaluates it.
        for input in relation.op.inputs() {
            if input.index() >= index {
                return Err(RelationalAssertionPlanError::RelationCycle {
                    relation: relation.name.clone(),
                });
            }
        }
        validate_relation(plan, relation)?;
        validate_schema_columns_are_unique(relation)?;
    }

    for assertion in &plan.assertions {
        let Some(relation) = plan.relation(assertion.relation) else {
            return Err(RelationalAssertionPlanError::UnknownGroup {
                name: assertion.group.as_str().to_string(),
            });
        };
        if !matches!(relation.op, IrRelationOp::Group { .. }) {
            return Err(RelationalAssertionPlanError::UnknownGroup {
                name: assertion.group.as_str().to_string(),
            });
        }
        if relation.schema.index_of(&assertion.column).is_none() {
            return Err(RelationalAssertionPlanError::UnknownAggregate {
                group: assertion.group.as_str().to_string(),
                name: assertion.aggregate.as_str().to_string(),
            });
        }
    }

    Ok(())
}

fn validate_schema_columns_are_unique(
    relation: &IrRelation,
) -> Result<(), RelationalAssertionPlanError> {
    let mut seen = HashSet::new();
    for field in relation.schema.fields() {
        if !seen.insert(&field.column) {
            return Err(RelationalAssertionPlanError::RepeatedJoinBinding {
                binding: field.column.qualifier.clone(),
            });
        }
    }
    Ok(())
}

fn validate_relation(
    plan: &RelationalPlanIr,
    relation: &IrRelation,
) -> Result<(), RelationalAssertionPlanError> {
    match &relation.op {
        IrRelationOp::Source { binding, domain } => {
            let expected = super::ir::domain_schema(binding.as_str(), *domain);
            if expected != relation.schema {
                return Err(RelationalAssertionPlanError::UnknownField {
                    binding: binding.as_str().to_string(),
                    field: "<schema>".to_string(),
                });
            }
        }
        IrRelationOp::Expand {
            input,
            binding,
            step,
            domain,
        } => {
            let source = plan
                .relation(*input)
                .expect("input ids are checked before the operator is validated");
            let source_domain = relation_domain(source).ok_or_else(|| {
                RelationalAssertionPlanError::ExpansionDomainUnavailable {
                    binding: binding.as_str().to_string(),
                    step: step.label(),
                }
            })?;
            if super::ir::expansion_result_domain(source_domain, *step) != Some(*domain) {
                return Err(RelationalAssertionPlanError::ExpansionDomainUnavailable {
                    binding: binding.as_str().to_string(),
                    step: step.label(),
                });
            }
        }
        IrRelationOp::Project { input, columns } => {
            let input_schema = &input_relation(plan, *input).schema;
            for projection in columns {
                column_type(input_schema, &projection.source)?;
            }
        }
        IrRelationOp::Filter { input, predicates } => {
            let input_schema = &input_relation(plan, *input).schema;
            for predicate in predicates {
                validate_predicate(input_schema, predicate)?;
            }
        }
        IrRelationOp::Join {
            left,
            right,
            kind: _,
            on,
        } => {
            let left_schema = &input_relation(plan, *left).schema;
            let right_schema = &input_relation(plan, *right).schema;
            if on.is_empty() {
                return Err(RelationalAssertionPlanError::EmptyJoin {
                    left: input_relation(plan, *left).name.clone(),
                    right: input_relation(plan, *right).name.clone(),
                });
            }
            for key in on {
                let left_type = column_type(left_schema, &key.left)?;
                let right_type = column_type(right_schema, &key.right)?;
                if left_type != right_type {
                    return Err(RelationalAssertionPlanError::JoinTypeMismatch {
                        left: key.left.to_string(),
                        left_type,
                        right: key.right.to_string(),
                        right_type,
                    });
                }
            }
        }
        IrRelationOp::Group {
            input,
            by,
            aggregates,
        } => {
            let input_schema = &input_relation(plan, *input).schema;
            if by.is_empty() {
                return Err(RelationalAssertionPlanError::EmptyGroupKey {
                    group: relation.name.clone(),
                });
            }
            for column in by {
                column_type(input_schema, column)?;
            }
            for aggregate in aggregates {
                validate_aggregate(input_schema, &relation.name, aggregate)?;
            }
        }
    }
    Ok(())
}

/// The row domain a relation publishes, when it is a row-domain relation at
/// all. Only source and expansion relations are expandable further.
fn relation_domain(
    relation: &IrRelation,
) -> Option<brokk_bifrost_rql::structural::search::DetailedCodeQueryDomain> {
    match &relation.op {
        IrRelationOp::Source { domain, .. } | IrRelationOp::Expand { domain, .. } => Some(*domain),
        _ => None,
    }
}

fn input_relation(plan: &RelationalPlanIr, id: super::ir::IrRelationId) -> &IrRelation {
    plan.relation(id)
        .expect("input ids are checked before the operator is validated")
}

fn column_type(
    schema: &IrSchema,
    column: &IrColumn,
) -> Result<CodeQueryRowScalarType, RelationalAssertionPlanError> {
    column_field(schema, column).map(|field| field.scalar_type)
}

fn column_field<'a>(
    schema: &'a IrSchema,
    column: &IrColumn,
) -> Result<&'a super::ir::IrField, RelationalAssertionPlanError> {
    schema
        .field(column)
        .ok_or_else(|| RelationalAssertionPlanError::UnknownField {
            binding: column.qualifier.clone(),
            field: column.name.clone(),
        })
}

/// Reject a literal a `ConstrainedEnum` column can never hold.
///
/// The registry publishes the finite label set of every enum-typed column, so a
/// mistyped label is an authoring error the loader can name -- rather than a
/// filter that matches nothing while the run reports `complete; clean`
/// (issue #2515). A column whose domain is explicitly not enumerable admits
/// every label, by that domain's own statement.
fn validate_enum_literal(
    field: &super::ir::IrField,
    column: &IrColumn,
    literal: &RowLiteral,
) -> Result<(), RelationalAssertionPlanError> {
    let RowLiteral::ConstrainedEnum(label) = literal else {
        return Ok(());
    };
    let Some(domain) = field.value_domain else {
        return Ok(());
    };
    let Some(legal) = domain.labels() else {
        return Ok(());
    };
    if legal.contains(&label.as_str()) {
        return Ok(());
    }
    Err(RelationalAssertionPlanError::UnknownEnumLabel {
        field: column.to_string(),
        label: label.clone(),
        legal,
    })
}

fn validate_predicate(
    schema: &IrSchema,
    predicate: &IrPredicate,
) -> Result<(), RelationalAssertionPlanError> {
    match predicate {
        IrPredicate::Compare { left, op, right } => {
            let left_field = column_field(schema, left)?;
            let left_type = left_field.scalar_type;
            match right {
                IrOperand::Column(right) => {
                    let right_type = column_type(schema, right)?;
                    if left_type != right_type {
                        return Err(RelationalAssertionPlanError::ComparisonTypeMismatch {
                            left: left.to_string(),
                            left_type,
                            right: right.to_string(),
                            right_type,
                        });
                    }
                }
                IrOperand::Literal(literal) => {
                    if !literal_matches_type(literal, left_type) {
                        return Err(RelationalAssertionPlanError::PredicateTypeMismatch {
                            field: left.to_string(),
                            actual: left_type,
                            literal: row_literal_kind(literal),
                        });
                    }
                    validate_enum_literal(left_field, left, literal)?;
                }
            }
            if op.is_ordered() && left_type != CodeQueryRowScalarType::Integer {
                return Err(RelationalAssertionPlanError::UnorderedComparison {
                    field: left.to_string(),
                    operator: op.label(),
                    actual: left_type,
                });
            }
        }
        IrPredicate::IsNull { column, .. } => {
            let field =
                schema
                    .field(column)
                    .ok_or_else(|| RelationalAssertionPlanError::UnknownField {
                        binding: column.qualifier.clone(),
                        field: column.name.clone(),
                    })?;
            if !field.nullable {
                return Err(RelationalAssertionPlanError::NullTestOnRequiredField {
                    field: column.to_string(),
                });
            }
        }
        IrPredicate::InSet { column, values } => {
            let field = column_field(schema, column)?;
            let column_type = field.scalar_type;
            if values.is_empty() || values.len() > MAX_IR_SET_MEMBERS {
                return Err(RelationalAssertionPlanError::InvalidSetMembership {
                    field: column.to_string(),
                    count: values.len(),
                    max: MAX_IR_SET_MEMBERS,
                });
            }
            for literal in values {
                if !literal_matches_type(literal, column_type) {
                    return Err(RelationalAssertionPlanError::PredicateTypeMismatch {
                        field: column.to_string(),
                        actual: column_type,
                        literal: row_literal_kind(literal),
                    });
                }
                validate_enum_literal(field, column, literal)?;
            }
        }
    }
    Ok(())
}

fn validate_aggregate(
    schema: &IrSchema,
    group: &str,
    aggregate: &IrAggregate,
) -> Result<(), RelationalAssertionPlanError> {
    let names = || (group.to_string(), aggregate.name.as_str().to_string());
    match (aggregate.op.reads_value(), aggregate.value.as_ref()) {
        (true, None) => {
            let (group, name) = names();
            return Err(RelationalAssertionPlanError::AggregateValueRequired {
                group,
                aggregate: name,
            });
        }
        (false, Some(_)) => {
            let (group, name) = names();
            return Err(RelationalAssertionPlanError::AggregateValueForbidden {
                group,
                aggregate: name,
            });
        }
        _ => {}
    }
    if let Some(value) = aggregate.value.as_ref() {
        let actual = column_type(schema, value)?;
        if let Some(expected) = aggregate.op.required_value_type()
            && expected != actual
        {
            let (group, name) = names();
            // `min` keeps its own error because it is the one fold the
            // authoring surface can already spell.
            return Err(if aggregate.op == super::ir::IrAggregateOp::Min {
                RelationalAssertionPlanError::InvalidMinType {
                    group,
                    aggregate: name,
                    actual,
                }
            } else {
                RelationalAssertionPlanError::InvalidAggregateValueType {
                    group,
                    aggregate: name,
                    aggregate_op: aggregate.op.label(),
                    expected,
                    actual,
                }
            });
        }
    }
    validate_ordered_sequences(schema, group, aggregate)?;
    for predicate in &aggregate.predicates {
        validate_predicate(schema, predicate)?;
    }
    Ok(())
}

/// An ordered comparison is only defined when both sides state an integer
/// position and the two value columns hold the same scalar type. Anything else
/// is rejected before a workspace query runs, because a comparison across
/// scalar types would silently be false at every position rather than being an
/// authoring mistake.
fn validate_ordered_sequences(
    schema: &IrSchema,
    group: &str,
    aggregate: &IrAggregate,
) -> Result<(), RelationalAssertionPlanError> {
    let names = || (group.to_string(), aggregate.name.as_str().to_string());
    let sequences = match (aggregate.op, aggregate.sequences.as_ref()) {
        (super::ir::IrAggregateOp::OrderedEqual, Some(sequences)) => sequences,
        (super::ir::IrAggregateOp::OrderedEqual, None) => {
            let (group, name) = names();
            return Err(RelationalAssertionPlanError::OrderedSequencesRequired {
                group,
                aggregate: name,
            });
        }
        (_, None) => return Ok(()),
        (_, Some(_)) => {
            let (group, name) = names();
            return Err(RelationalAssertionPlanError::OrderedSequencesForbidden {
                group,
                aggregate: name,
            });
        }
    };
    for sequence in [&sequences.left, &sequences.right] {
        let position = column_type(schema, &sequence.position)?;
        if position != CodeQueryRowScalarType::Integer {
            let (group, name) = names();
            return Err(RelationalAssertionPlanError::InvalidOrderedPositionType {
                group,
                aggregate: name,
                field: sequence.position.to_string(),
                actual: position,
            });
        }
    }
    let left_type = column_type(schema, &sequences.left.value)?;
    let right_type = column_type(schema, &sequences.right.value)?;
    if left_type != right_type {
        let (group, name) = names();
        return Err(RelationalAssertionPlanError::OrderedValueTypeMismatch {
            group,
            aggregate: name,
            left_type,
            right_type,
        });
    }
    Ok(())
}

/// Which literal spellings address which registry scalar types.
///
/// Identity-bearing scalars are addressed by their string spelling, because a
/// policy states an identity as text.
pub(super) fn literal_matches_type(
    literal: &RowLiteral,
    scalar_type: CodeQueryRowScalarType,
) -> bool {
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

pub(super) fn row_literal_kind(literal: &RowLiteral) -> &'static str {
    match literal {
        RowLiteral::String(_) => "string",
        RowLiteral::Integer(_) => "integer",
        RowLiteral::Boolean(_) => "boolean",
        RowLiteral::ConstrainedEnum(_) => "constrained-enum",
    }
}

/// The comparison operators are exhaustive over the IR's operator set; this
/// assertion exists so a new operator cannot be added without deciding whether
/// it is ordered.
#[cfg(test)]
mod tests {
    use super::super::ir::IrCompareOp;

    #[test]
    fn only_the_four_ordered_operators_require_an_order() {
        for op in [
            IrCompareOp::Eq,
            IrCompareOp::Ne,
            IrCompareOp::Lt,
            IrCompareOp::Le,
            IrCompareOp::Gt,
            IrCompareOp::Ge,
        ] {
            assert_eq!(
                op.is_ordered(),
                matches!(
                    op,
                    IrCompareOp::Lt | IrCompareOp::Le | IrCompareOp::Gt | IrCompareOp::Ge
                )
            );
        }
    }
}
