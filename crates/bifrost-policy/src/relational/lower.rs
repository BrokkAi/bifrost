//! Lowering the authored plan into the internal IR.
//!
//! The authored model is a flat record set: named query bindings, a join list,
//! group records, and assertions. The IR is a dependency
//! graph. Lowering is where that translation happens once, so neither the
//! validator nor the evaluator has to re-derive "which rows does this group
//! actually see".
//!
//! Lowering only builds structure and resolves row domains. Typing is the
//! validator's job, so a lowered plan is well-formed but not yet known to be
//! type-correct.

use std::collections::HashSet;

use crate::definition::{
    PolicySelector, RelationalAssertionPlan, RowAggregate, RowAggregateOp, RowBinding,
    RowBindingSource, RowFieldRef, RowJoin, RowJoinKind, RowPredicate, RowPredicateOp,
    RowPredicateOperand,
};

use super::ir::{
    IrAggregate, IrAggregateOp, IrAssertion, IrColumn, IrCompareOp, IrEquiKey, IrJoinKind,
    IrLimits, IrOperand, IrOrderedSequence, IrOrderedSequencePair, IrPredicate, IrRelation,
    IrRelationId, IrRelationOp, IrSchema, RelationalPlanIr, group_schema, join_schema,
    query_schema,
};
use super::validate::RelationalAssertionPlanError;

/// One name the plan can still address, and the relation it currently stands
/// for.
///
struct RelationSlot {
    name: String,
    id: IrRelationId,
}

fn lower_bindings(
    bindings: &[RowBinding],
) -> Result<(Vec<IrRelation>, Vec<RelationSlot>), RelationalAssertionPlanError> {
    let mut relations: Vec<IrRelation> = Vec::new();
    let mut slots: Vec<RelationSlot> = Vec::new();

    for binding in bindings {
        let name = binding.name.as_str().to_string();
        if slots.iter().any(|slot| slot.name == name) {
            return Err(RelationalAssertionPlanError::DuplicateBinding { name });
        }
        let id = IrRelationId(relations.len());
        let (op, schema) = match &binding.source {
            RowBindingSource::Query(PolicySelector::Inline { query, .. }) => {
                let (_, fields) = query.validate_row_fields().map_err(|error| {
                    RelationalAssertionPlanError::InvalidQuery {
                        binding: name.clone(),
                        message: error.to_string(),
                    }
                })?;
                let schema = query_schema(&name, &fields);
                (
                    IrRelationOp::Source {
                        binding: binding.name.clone(),
                        schema: schema.clone(),
                    },
                    schema,
                )
            }
            RowBindingSource::Query(PolicySelector::File { .. }) => {
                return Err(RelationalAssertionPlanError::DeferredSelectorDomain { binding: name });
            }
        };
        relations.push(IrRelation {
            id,
            name: name.clone(),
            op,
            schema,
        });
        slots.push(RelationSlot { name, id });
    }

    if bindings.is_empty() {
        return Err(RelationalAssertionPlanError::EmptyPlan);
    }

    Ok((relations, slots))
}

fn lower_joins(
    relations: &mut Vec<IrRelation>,
    slots: &[RelationSlot],
    joins: &[RowJoin],
) -> Result<(IrRelationId, IrSchema), RelationalAssertionPlanError> {
    let mut chain = slots[0].id;
    let mut chain_schema = relations[chain.index()].schema.clone();

    for join in joins {
        let left = join.left.as_str();
        let right = join.right.as_str();
        if !schema_binds(&chain_schema, left) {
            return Err(RelationalAssertionPlanError::DisconnectedBinding {
                binding: left.to_string(),
            });
        }
        if schema_binds(&chain_schema, right) {
            return Err(RelationalAssertionPlanError::RepeatedJoinBinding {
                binding: right.to_string(),
            });
        }
        let Some(right_id) = slots
            .iter()
            .find(|slot| slot.name == right)
            .map(|slot| slot.id)
        else {
            return Err(RelationalAssertionPlanError::UnknownBinding {
                name: right.to_string(),
            });
        };
        let kind = match join.kind {
            RowJoinKind::Inner => IrJoinKind::Inner,
            RowJoinKind::Semi => IrJoinKind::Semi,
            RowJoinKind::Anti => IrJoinKind::Anti,
        };
        let on = join
            .on
            .iter()
            .map(|condition| IrEquiKey {
                left: IrColumn::new(left, condition.left_field.clone()),
                right: IrColumn::new(right, condition.right_field.clone()),
            })
            .collect::<Vec<_>>();
        chain_schema = join_schema(&chain_schema, &relations[right_id.index()].schema, kind);
        let id = IrRelationId(relations.len());
        relations.push(IrRelation {
            id,
            name: format!("{left}-{}-{right}", kind.label()),
            op: IrRelationOp::Join {
                left: chain,
                right: right_id,
                kind,
                on,
            },
            schema: chain_schema.clone(),
        });
        chain = id;
    }

    Ok((chain, chain_schema))
}

/// Lower one authored relational plan into its IR.
///
/// The lowering is total over well-formed authored plans: every authored
/// binding becomes a source relation, the authored join list becomes one
/// left-deep join chain seeded by the first remaining relation, and every
/// authored group becomes one group relation over that chain.
pub fn lower_relational_assertion_plan(
    plan: &RelationalAssertionPlan,
) -> Result<RelationalPlanIr, RelationalAssertionPlanError> {
    let (mut relations, slots) = lower_bindings(&plan.bindings)?;

    let (chain, chain_schema) = lower_joins(&mut relations, &slots, &plan.joins)?;

    let mut group_relations: Vec<(String, IrRelationId)> = Vec::new();
    for group in &plan.groups {
        let name = group.name.as_str().to_string();
        if group_relations.iter().any(|(bound, _)| bound == &name) {
            return Err(RelationalAssertionPlanError::DuplicateGroup { name });
        }
        if group.by.is_empty() {
            return Err(RelationalAssertionPlanError::EmptyGroupKey { group: name });
        }
        let mut by = Vec::with_capacity(group.by.len());
        for field in &group.by {
            by.push(lower_field(&chain_schema, field)?);
        }
        let mut aggregate_names = HashSet::new();
        let mut aggregates = Vec::with_capacity(group.aggregates.len());
        for aggregate in &group.aggregates {
            if !aggregate_names.insert(aggregate.name.as_str()) {
                return Err(RelationalAssertionPlanError::DuplicateAggregate {
                    group: name.clone(),
                    name: aggregate.name.as_str().to_string(),
                });
            }
            aggregates.push(lower_aggregate(&chain_schema, &name, aggregate)?);
        }
        let schema = group_schema(&chain_schema, &by, &aggregates)
            .expect("a lowered group key column is a column of its input");
        let id = IrRelationId(relations.len());
        relations.push(IrRelation {
            id,
            name: name.clone(),
            op: IrRelationOp::Group {
                input: chain,
                by,
                aggregates,
            },
            schema,
        });
        group_relations.push((name, id));
    }

    let mut assertion_ids = HashSet::new();
    let mut assertions = Vec::with_capacity(plan.assertions.len());
    for assertion in &plan.assertions {
        if !assertion_ids.insert(assertion.id.as_str()) {
            return Err(RelationalAssertionPlanError::DuplicateAssertion {
                id: assertion.id.as_str().to_string(),
            });
        }
        let Some(relation) = group_relations
            .iter()
            .find(|(name, _)| name == assertion.group.as_str())
            .map(|(_, id)| *id)
        else {
            return Err(RelationalAssertionPlanError::UnknownGroup {
                name: assertion.group.as_str().to_string(),
            });
        };
        let column = IrColumn::new(assertion.group.as_str(), assertion.aggregate.as_str());
        if relations[relation.index()]
            .schema
            .index_of(&column)
            .is_none()
        {
            return Err(RelationalAssertionPlanError::UnknownAggregate {
                group: assertion.group.as_str().to_string(),
                name: assertion.aggregate.as_str().to_string(),
            });
        }
        assertions.push(IrAssertion {
            id: assertion.id.clone(),
            relation,
            group: assertion.group.clone(),
            aggregate: assertion.aggregate.clone(),
            column,
            cardinality: assertion.cardinality,
        });
    }

    Ok(RelationalPlanIr {
        relations,
        assertions,
        limits: IrLimits::from(plan.limits),
    })
}

/// Whether any column of this schema comes from the named binding.
fn schema_binds(schema: &IrSchema, qualifier: &str) -> bool {
    schema
        .fields()
        .iter()
        .any(|field| field.column.qualifier == qualifier)
}

/// Resolve one authored `binding.field` reference against the rows the groups
/// actually see.
///
/// A reference to a binding the join chain never brought in is rejected here
/// rather than at evaluation: the rows it names cannot reach the group, so no
/// row set makes the plan answerable.
fn lower_field(
    chain_schema: &IrSchema,
    field: &RowFieldRef,
) -> Result<IrColumn, RelationalAssertionPlanError> {
    let column = IrColumn::new(field.binding.as_str(), field.field.clone());
    if !schema_binds(chain_schema, &column.qualifier) {
        return Err(RelationalAssertionPlanError::DisconnectedBinding {
            binding: column.qualifier,
        });
    }
    if chain_schema.field(&column).is_none() {
        return Err(RelationalAssertionPlanError::UnknownField {
            known_fields: chain_schema.field_names_of(&column.qualifier),
            binding: column.qualifier,
            field: column.name,
        });
    }
    Ok(column)
}

fn lower_aggregate(
    chain_schema: &IrSchema,
    group: &str,
    aggregate: &RowAggregate,
) -> Result<IrAggregate, RelationalAssertionPlanError> {
    let op = match aggregate.op {
        RowAggregateOp::Min => IrAggregateOp::Min,
        RowAggregateOp::Max => IrAggregateOp::Max,
        RowAggregateOp::Count => IrAggregateOp::Count,
        RowAggregateOp::CountDistinct => IrAggregateOp::CountDistinct,
        RowAggregateOp::Any => IrAggregateOp::Any,
        RowAggregateOp::All => IrAggregateOp::All,
        RowAggregateOp::OrderedEqual => IrAggregateOp::OrderedEqual,
        RowAggregateOp::SetEqual => IrAggregateOp::SetEqual,
        RowAggregateOp::Subset => IrAggregateOp::Subset,
    };
    let value = aggregate
        .value
        .as_ref()
        .map(|field| lower_field(chain_schema, field))
        .transpose()?;
    let sequences = aggregate
        .sequences
        .as_ref()
        .map(|pair| {
            Ok::<_, RelationalAssertionPlanError>(IrOrderedSequencePair {
                left: IrOrderedSequence {
                    position: lower_field(chain_schema, &pair.left.position)?,
                    value: lower_field(chain_schema, &pair.left.value)?,
                },
                right: IrOrderedSequence {
                    position: lower_field(chain_schema, &pair.right.position)?,
                    value: lower_field(chain_schema, &pair.right.value)?,
                },
            })
        })
        .transpose()?;
    let predicates = aggregate
        .predicate
        .iter()
        .map(|predicate| lower_predicate(chain_schema, predicate))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(IrAggregate {
        name: aggregate.name.clone(),
        op,
        value,
        sequences,
        sets: aggregate
            .sets
            .as_ref()
            .map(|(left, right)| {
                Ok((
                    lower_field(chain_schema, left)?,
                    lower_field(chain_schema, right)?,
                ))
            })
            .transpose()?,
        predicates,
        output: IrColumn::new(group, aggregate.name.as_str()),
    })
}

/// Lower one authored row test.
///
/// Which operand an operator takes is fixed, and the decoder only builds the
/// admitted pairings. A hand-built authoring model that pairs them differently
/// is rejected here rather than silently reinterpreted.
fn lower_predicate(
    chain_schema: &IrSchema,
    predicate: &RowPredicate,
) -> Result<IrPredicate, RelationalAssertionPlanError> {
    let left = lower_field(chain_schema, &predicate.field)?;
    match (predicate.op, &predicate.operand) {
        (RowPredicateOp::IsNull, RowPredicateOperand::None) => Ok(IrPredicate::IsNull {
            column: left,
            negated: false,
        }),
        (RowPredicateOp::IsNotNull, RowPredicateOperand::None) => Ok(IrPredicate::IsNull {
            column: left,
            negated: true,
        }),
        (RowPredicateOp::In, RowPredicateOperand::Set(values)) => Ok(IrPredicate::InSet {
            column: left,
            values: values.clone(),
        }),
        (RowPredicateOp::In, RowPredicateOperand::ResolvedIdentitySet(identities)) => {
            Ok(IrPredicate::ResolvedIdentitySet {
                column: left,
                identities: identities.clone(),
            })
        }
        (op, RowPredicateOperand::Literal(value)) => Ok(IrPredicate::Compare {
            left,
            op: compare_op(op, &predicate.field)?,
            right: IrOperand::Literal(value.clone()),
        }),
        (op, RowPredicateOperand::Field(field)) => {
            let right = lower_field(chain_schema, field)?;
            Ok(IrPredicate::Compare {
                left,
                op: compare_op(op, &predicate.field)?,
                right: IrOperand::Column(right),
            })
        }
        (op, _) => Err(RelationalAssertionPlanError::MalformedPredicate {
            field: format!("{}.{}", predicate.field.binding, predicate.field.field),
            operator: op.label(),
        }),
    }
}

/// The IR comparison one authored operator names, for the operators that
/// compare two values at all.
fn compare_op(
    op: RowPredicateOp,
    field: &RowFieldRef,
) -> Result<IrCompareOp, RelationalAssertionPlanError> {
    match op {
        RowPredicateOp::Eq => Ok(IrCompareOp::Eq),
        RowPredicateOp::Ne => Ok(IrCompareOp::Ne),
        RowPredicateOp::Lt => Ok(IrCompareOp::Lt),
        RowPredicateOp::Le => Ok(IrCompareOp::Le),
        RowPredicateOp::Gt => Ok(IrCompareOp::Gt),
        RowPredicateOp::Ge => Ok(IrCompareOp::Ge),
        RowPredicateOp::IsNull | RowPredicateOp::IsNotNull | RowPredicateOp::In => {
            Err(RelationalAssertionPlanError::MalformedPredicate {
                field: format!("{}.{}", field.binding, field.field),
                operator: op.label(),
            })
        }
    }
}
