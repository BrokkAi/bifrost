//! Lowering the authored plan into the internal IR.
//!
//! The authored model is a flat record set: named bindings, derivations that
//! refine them, a join list, group records, assertions. The IR is a dependency
//! graph. Lowering is where that translation happens once, so neither the
//! validator nor the evaluator has to re-derive "which rows does this group
//! actually see".
//!
//! Lowering only builds structure and resolves row domains. Typing is the
//! validator's job, so a lowered plan is well-formed but not yet known to be
//! type-correct.

use std::collections::HashSet;

use brokk_bifrost_rql::structural::search::DetailedCodeQueryDomain;

use crate::definition::{
    PolicySelector, RelationalAssertionPlan, RowAggregate, RowAggregateOp, RowBinding,
    RowBindingName, RowBindingSource, RowDerivation, RowFieldRef, RowFilter, RowFilterEvidence,
    RowJoin, RowJoinKind, RowLiteral, RowPredicate, RowPredicateOp, RowPredicateOperand,
    RowProjection, RowSelectorPlan,
};

use super::ir::{
    IrAggregate, IrAggregateOp, IrAssertion, IrColumn, IrCompareOp, IrEquiKey, IrField, IrJoinKind,
    IrLimits, IrOperand, IrOrderedSequence, IrOrderedSequencePair, IrPredicate, IrProjection,
    IrRelation, IrRelationId, IrRelationOp, IrSchema, RelationalPlanIr, domain_schema,
    expansion_result_domain, group_schema, join_schema,
};
use super::validate::RelationalAssertionPlanError;

/// One name the plan can still address, and the relation it currently stands
/// for.
///
/// A derivation replaces its input's slot in place rather than appending a new
/// one, so a refined relation keeps the position the relation it refines held.
/// That is what keeps the join chain's seed -- the first slot -- the same
/// relation before and after a filter, and what makes the name a derivation
/// consumed unaddressable afterwards.
struct RelationSlot {
    name: String,
    id: IrRelationId,
    domain: Option<DetailedCodeQueryDomain>,
}

/// A row-selector plan lowered onto the same typed IR as relational assertions.
///
/// `output` is the filtered relation the endpoint consumes. `upstream` is the
/// source or expansion relation behind it before any derivation ran. Keeping
/// both identities is what lets endpoint selection retain incomplete producer
/// evidence even when an authored filter removes the row that carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredRowSelector {
    pub plan: RelationalPlanIr,
    pub relation: IrRelationId,
    pub output_relation: IrRelationId,
    pub upstream: IrRelationId,
    pub output_binding: RowBindingName,
    pub upstream_binding: RowBindingName,
    pub declared_call_binding: Option<RowBindingName>,
    pub declared_call_model_id: Option<String>,
}

fn lower_bindings_and_derivations(
    bindings: &[RowBinding],
    derivations: &[RowDerivation],
) -> Result<(Vec<IrRelation>, Vec<RelationSlot>), RelationalAssertionPlanError> {
    let mut relations: Vec<IrRelation> = Vec::new();
    let mut slots: Vec<RelationSlot> = Vec::new();

    for binding in bindings {
        let name = binding.name.as_str().to_string();
        if slots.iter().any(|slot| slot.name == name) {
            return Err(RelationalAssertionPlanError::DuplicateBinding { name });
        }
        let id = IrRelationId(relations.len());
        let (op, domain) = match &binding.source {
            RowBindingSource::Query(PolicySelector::Inline { query, .. }) => {
                let domain = query
                    .validate_steps()
                    .map(DetailedCodeQueryDomain::from_query_value_kind)
                    .map_err(|error| RelationalAssertionPlanError::InvalidQuery {
                        binding: name.clone(),
                        message: error.to_string(),
                    })?;
                (
                    IrRelationOp::Source {
                        binding: binding.name.clone(),
                        domain,
                    },
                    domain,
                )
            }
            RowBindingSource::Query(PolicySelector::File { .. }) => {
                return Err(RelationalAssertionPlanError::DeferredSelectorDomain { binding: name });
            }
            RowBindingSource::Query(PolicySelector::Rows { .. }) => {
                return Err(RelationalAssertionPlanError::NestedRowSelector { binding: name });
            }
            RowBindingSource::Expansion { from, step } => {
                let Some((source_id, source_domain)) = slots
                    .iter()
                    .find(|slot| slot.name == from.as_str())
                    .and_then(|slot| slot.domain.map(|domain| (slot.id, domain)))
                else {
                    return Err(RelationalAssertionPlanError::ForwardBinding {
                        binding: name,
                        referenced: from.as_str().to_string(),
                    });
                };
                let Some(domain) = expansion_result_domain(source_domain, *step) else {
                    return Err(RelationalAssertionPlanError::ExpansionDomainUnavailable {
                        binding: name,
                        step: step.label(),
                    });
                };
                (
                    IrRelationOp::Expand {
                        input: source_id,
                        binding: binding.name.clone(),
                        step: *step,
                        domain,
                    },
                    domain,
                )
            }
        };
        relations.push(IrRelation {
            id,
            name: name.clone(),
            op,
            schema: domain_schema(&name, domain),
        });
        slots.push(RelationSlot {
            name,
            id,
            domain: Some(domain),
        });
    }

    if bindings.is_empty() {
        return Err(RelationalAssertionPlanError::EmptyPlan);
    }

    for derivation in derivations {
        match derivation {
            RowDerivation::Filter(filter) => {
                lower_filter(&mut relations, &mut slots, filter)?;
            }
            RowDerivation::Project(projection) => {
                lower_projection(&mut relations, &mut slots, projection)?;
            }
        }
    }

    Ok((relations, slots))
}

/// Lower one endpoint row selector onto the shared typed relational IR.
pub fn lower_row_selector_plan(
    selector: &RowSelectorPlan,
) -> Result<LoweredRowSelector, RelationalAssertionPlanError> {
    let declared_call = selector.derivations.iter().find_map(|derivation| {
        let RowDerivation::Filter(filter) = derivation else {
            return None;
        };
        if !matches!(filter.evidence, Some(RowFilterEvidence::DeclaredCall)) {
            return None;
        }
        let model_id = filter.predicates.iter().find_map(|predicate| {
            if predicate.field.field != "model_id" || !matches!(predicate.op, RowPredicateOp::Eq) {
                return None;
            }
            let RowPredicateOperand::Literal(RowLiteral::String(model_id)) = &predicate.operand
            else {
                return None;
            };
            Some(model_id.clone())
        });
        Some((filter.over.clone(), model_id))
    });
    let (mut relations, slots) =
        lower_bindings_and_derivations(&selector.bindings, &selector.derivations)?;
    let Some(output_relation) = slots
        .iter()
        .find(|slot| slot.name == selector.output.as_str())
        .map(|slot| slot.id)
    else {
        return Err(RelationalAssertionPlanError::UnknownBinding {
            name: selector.output.as_str().to_string(),
        });
    };
    let mut upstream = output_relation;
    loop {
        upstream = match &relations[upstream.index()].op {
            IrRelationOp::Filter { input, .. } | IrRelationOp::Project { input, .. } => *input,
            IrRelationOp::Source { .. } | IrRelationOp::Expand { .. } => break,
            IrRelationOp::Join { .. } | IrRelationOp::Group { .. } => {
                unreachable!("row selectors cannot author joins or groups")
            }
        };
    }
    let upstream_binding = match &relations[upstream.index()].op {
        IrRelationOp::Source { binding, .. } | IrRelationOp::Expand { binding, .. } => {
            binding.clone()
        }
        IrRelationOp::Filter { .. }
        | IrRelationOp::Project { .. }
        | IrRelationOp::Join { .. }
        | IrRelationOp::Group { .. } => {
            unreachable!("upstream row-selector relation is a source or expansion")
        }
    };
    let (relation, schema) = lower_joins(&mut relations, &slots, &selector.joins)?;
    if !schema_binds(&schema, selector.output.as_str()) {
        return Err(RelationalAssertionPlanError::DisconnectedBinding {
            binding: selector.output.as_str().to_string(),
        });
    }
    Ok(LoweredRowSelector {
        plan: RelationalPlanIr {
            relations,
            assertions: Vec::new(),
            limits: IrLimits::default(),
        },
        relation,
        output_relation,
        upstream,
        output_binding: selector.output.clone(),
        upstream_binding,
        declared_call_binding: declared_call.as_ref().map(|(binding, _)| binding.clone()),
        declared_call_model_id: declared_call.and_then(|(_, model_id)| model_id),
    })
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
/// binding becomes a source or expansion relation, every derivation refines
/// one of those relations in place, the authored join list becomes one
/// left-deep join chain seeded by the first remaining relation, and every
/// authored group becomes one group relation over that chain.
pub fn lower_relational_assertion_plan(
    plan: &RelationalAssertionPlan,
) -> Result<RelationalPlanIr, RelationalAssertionPlanError> {
    let (mut relations, slots) = lower_bindings_and_derivations(&plan.bindings, &plan.derivations)?;

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

/// Lower one `(filter ...)` record.
///
/// The filtered relation keeps its name, its columns and its column
/// qualifier: a filter states which rows belong, and nothing else. Later
/// records therefore read the same `NAME.FIELD` columns whether or not a
/// filter stands between them and the binding.
fn lower_filter(
    relations: &mut Vec<IrRelation>,
    slots: &mut [RelationSlot],
    filter: &RowFilter,
) -> Result<(), RelationalAssertionPlanError> {
    let name = filter.over.as_str();
    let Some(slot) = slots.iter_mut().find(|slot| slot.name == name) else {
        return Err(RelationalAssertionPlanError::UnknownBinding {
            name: name.to_string(),
        });
    };
    let input = slot.id;
    let schema = relations[input.index()].schema.clone();
    let predicates = filter
        .predicates
        .iter()
        .map(|predicate| lower_predicate(&schema, predicate))
        .collect::<Result<Vec<_>, _>>()?;
    let id = IrRelationId(relations.len());
    relations.push(IrRelation {
        id,
        name: name.to_string(),
        op: IrRelationOp::Filter { input, predicates },
        schema,
    });
    slot.id = id;
    // A filtered relation is no longer an expandable row domain: the analyzer
    // steps consume a query's own rows, not a policy-narrowed subset of them.
    slot.domain = None;
    Ok(())
}

/// Lower one `(project ...)` record.
///
/// The projection publishes its own name, so every column it carries is
/// requalified under that name and the relation it read is no longer
/// addressable. One relation name is one column qualifier throughout the IR,
/// and a projection that kept its input's qualifier would break that.
fn lower_projection(
    relations: &mut Vec<IrRelation>,
    slots: &mut [RelationSlot],
    projection: &RowProjection,
) -> Result<(), RelationalAssertionPlanError> {
    let from = projection.from.as_str();
    let name = projection.name.as_str();
    if slots.iter().any(|slot| slot.name == name) {
        return Err(RelationalAssertionPlanError::DuplicateBinding {
            name: name.to_string(),
        });
    }
    let Some(index) = slots.iter().position(|slot| slot.name == from) else {
        return Err(RelationalAssertionPlanError::UnknownBinding {
            name: from.to_string(),
        });
    };
    let input = slots[index].id;
    let input_schema = relations[input.index()].schema.clone();

    let mut columns = Vec::with_capacity(projection.columns.len());
    let mut fields = Vec::with_capacity(projection.columns.len());
    for column in &projection.columns {
        let source = lower_field(&input_schema, &column.source)?;
        let output = IrColumn::new(name, column.name.clone());
        if fields
            .iter()
            .any(|field: &IrField| field.column.name == output.name)
        {
            return Err(RelationalAssertionPlanError::DuplicateProjectionColumn {
                relation: name.to_string(),
                column: output.name.clone(),
            });
        }
        let field = input_schema
            .field(&source)
            .expect("a lowered projection source is a column of its input");
        fields.push(IrField {
            column: output.clone(),
            scalar_type: field.scalar_type,
            nullable: field.nullable,
            value_domain: field.value_domain,
        });
        columns.push(IrProjection { source, output });
    }

    let id = IrRelationId(relations.len());
    relations.push(IrRelation {
        id,
        name: name.to_string(),
        op: IrRelationOp::Project { input, columns },
        schema: IrSchema::new(fields),
    });
    slots[index] = RelationSlot {
        name: name.to_string(),
        id,
        domain: None,
    };
    Ok(())
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
