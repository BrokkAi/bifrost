//! Occurrence authoring sugar lowered without changing its canonical policy
//! or subject-based finding projection.

use brokk_bifrost_rql::structural::search::DetailedCodeQueryDomain;

use crate::definition::{
    OccurrenceAssert, RowAggregateName, RowBindingName, RowGroupName, RowLiteral,
};

use super::ir::{
    IrAggregate, IrAggregateOp, IrAssertion, IrColumn, IrCompareOp, IrEquiKey, IrJoinKind,
    IrOperand, IrPredicate, IrRelation, IrRelationId, IrRelationOp, RelationalPlanIr,
    domain_schema, group_schema, join_schema,
};

/// One subject's captures joined to occurrence rows. The source adapter gives
/// every capture the subject's same `id`, so a multi-capture assertion counts
/// all its tokens in one group. A left join retains zero as an assertable count.
/// The driver supplies only complete file partitions, as it did before lowering.
pub(crate) fn lower_occurrence_assert(assertion: &OccurrenceAssert) -> RelationalPlanIr {
    let capture = RowBindingName::new("capture").expect("static binding name");
    let occurrence = RowBindingName::new("occurrence").expect("static binding name");
    let group = RowGroupName::new("subject").expect("static group name");
    let count = RowAggregateName::new("count").expect("static aggregate name");
    let source = |id, binding: &RowBindingName, domain| IrRelation {
        id: IrRelationId(id),
        name: binding.as_str().to_owned(),
        op: IrRelationOp::Source {
            binding: binding.clone(),
            schema: domain_schema(binding.as_str(), domain),
        },
        schema: domain_schema(binding.as_str(), domain),
    };
    let captures = source(0, &capture, DetailedCodeQueryDomain::StructuralMatch);
    let occurrences = source(1, &occurrence, DetailedCodeQueryDomain::Occurrence);
    let equals = |field, value: &str| IrPredicate::Compare {
        left: IrColumn::new("occurrence", field),
        op: IrCompareOp::Eq,
        right: IrOperand::Literal(RowLiteral::ConstrainedEnum(value.to_owned())),
    };
    // The source decoder validates the expected class against the role. Just
    // as in the original assertion, `expect` controls presentation and the
    // default cardinality; the role determines which occurrence rows count.
    let mut predicates = vec![equals("role", assertion.role.label())];
    if let Some(namespace) = assertion.namespace {
        predicates.push(equals("namespace", namespace.label()));
    }
    if assertion.require_target {
        predicates.push(equals("target_kind", "resolved"));
    }
    let filtered = IrRelation {
        id: IrRelationId(2),
        name: "matching-occurrences".to_owned(),
        schema: occurrences.schema.clone(),
        op: IrRelationOp::Filter {
            input: occurrences.id,
            predicates,
        },
    };
    let joined = IrRelation {
        id: IrRelationId(3),
        name: "capture-occurrences".to_owned(),
        schema: join_schema(&captures.schema, &filtered.schema, IrJoinKind::Left),
        op: IrRelationOp::Join {
            left: captures.id,
            right: filtered.id,
            kind: IrJoinKind::Left,
            on: vec![IrEquiKey {
                left: IrColumn::new("capture", "ast_id"),
                right: IrColumn::new("occurrence", "ast_id"),
            }],
        },
    };
    let by = vec![IrColumn::new("capture", "id")];
    let column = IrColumn::new("subject", "count");
    let aggregates = vec![IrAggregate {
        name: count.clone(),
        op: IrAggregateOp::Count,
        value: None,
        sequences: None,
        sets: None,
        predicates: vec![IrPredicate::IsNull {
            column: IrColumn::new("occurrence", "ast_id"),
            negated: true,
        }],
        output: column.clone(),
    }];
    let grouped = IrRelation {
        id: IrRelationId(4),
        name: group.as_str().to_owned(),
        schema: group_schema(&joined.schema, &by, &aggregates)
            .expect("the subject key belongs to the capture relation"),
        op: IrRelationOp::Group {
            input: joined.id,
            by,
            aggregates,
        },
    };
    RelationalPlanIr {
        assertions: vec![IrAssertion {
            id: assertion.id.clone(),
            relation: grouped.id,
            group,
            aggregate: count,
            column,
            cardinality: assertion.cardinality,
        }],
        relations: vec![captures, occurrences, filtered, joined, grouped],
        limits: Default::default(),
    }
}
