use super::*;

#[test]
fn cancelled_authored_plan_reports_cancellation() {
    let plan = valid_plan();
    let rows = vec![occurrence("read", "ast")];
    let inputs = vec![
        RelationalInput {
            binding: &plan.bindings[0].name,
            rows: &rows,
            coverage: RelationCoverage::exhaustive(),
        },
        RelationalInput {
            binding: &plan.bindings[1].name,
            rows: &rows,
            coverage: RelationCoverage::exhaustive(),
        },
    ];
    let live = evaluate_relational_assertion_rows(&plan, &inputs, None).unwrap();
    assert!(live.violations.is_empty());
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let stopped = evaluate_relational_assertion_rows(&plan, &inputs, Some(&cancellation)).unwrap();
    assert!(!stopped.exhaustive);
    assert!(stopped.violations.is_empty());
    assert!(
        stopped
            .incomplete_reasons
            .contains(&crate::finding::PolicyIncompleteReason::Cancelled)
    );
}

#[test]
fn filtering_joins_reject_right_hand_group_columns() {
    let mut plan = valid_plan();
    plan.groups[0].by[0].binding = name("candidate");
    validate_relational_assertion_plan(&plan).unwrap();
    for kind in [RowJoinKind::Semi, RowJoinKind::Anti] {
        plan.joins[0].kind = kind;
        assert!(
            matches!(validate_relational_assertion_plan(&plan), Err(RelationalAssertionPlanError::DisconnectedBinding { binding }) if binding == "candidate")
        );
    }
}

#[test]
fn source_rows_use_the_source_budget_independently_of_group_budget() {
    let mut plan = valid_plan();
    plan.bindings.truncate(1);
    plan.joins.clear();
    plan.limits.max_source_rows = 2;
    plan.limits.max_groups = 8;
    let rows = [
        occurrence("a", "a"),
        occurrence("b", "b"),
        occurrence("c", "c"),
    ];
    for count in [2, 3] {
        let inputs = [RelationalInput {
            binding: &plan.bindings[0].name,
            rows: &rows[..count],
            coverage: RelationCoverage::exhaustive(),
        }];
        let result = evaluate_relational_assertion_rows(&plan, &inputs, None).unwrap();
        assert_eq!(
            result.incomplete_reasons.is_empty(),
            count == 2,
            "{result:?}"
        );
        // A cut may retain any subset; every retained violation still has to be true.
        assert!(
            result.violations.is_empty(),
            "each distinct ast has exactly one row"
        );
    }
}

#[test]
fn authored_comparison_and_null_predicates_select_the_expected_rows() {
    use crate::definition::{RowLiteral, RowPredicate, RowPredicateOp, RowPredicateOperand};
    let mut plan = valid_plan();
    plan.bindings.truncate(1);
    plan.bindings[0].source = RowBindingSource::Query(call_argument_selector());
    plan.joins.clear();
    plan.groups[0].by[0].field = "site_id".into();
    plan.assertions[0].cardinality = AssertCardinality::AtMost(0);
    // Asymmetric sides distinguish >= from <= as well as < from <=.
    let rows = [
        call_argument("same", 0, "a"),
        call_argument("same", 1, "b"),
        call_argument("same", 2, "c"),
    ];
    for (op, expected) in [
        (RowPredicateOp::Ge, 1),
        (RowPredicateOp::Le, 3),
        (RowPredicateOp::IsNull, 3),
    ] {
        plan.groups[0].aggregates[0].predicate = vec![RowPredicate {
            field: RowFieldRef {
                binding: name("site"),
                field: if op == RowPredicateOp::IsNull {
                    "literal_value"
                } else {
                    "argument_index"
                }
                .into(),
                source_range: None,
            },
            op,
            operand: if op == RowPredicateOp::IsNull {
                RowPredicateOperand::None
            } else {
                RowPredicateOperand::Literal(RowLiteral::Integer(2))
            },
            source_range: None,
        }];
        let inputs = [RelationalInput {
            binding: &plan.bindings[0].name,
            rows: &rows,
            coverage: RelationCoverage::exhaustive(),
        }];
        let result = evaluate_relational_assertion_rows(&plan, &inputs, None).unwrap();
        assert_eq!(
            result.violations.iter().map(|v| v.actual).sum::<u64>(),
            expected,
            "{result:?}"
        );
    }
}

#[test]
fn aggregate_counts_can_be_compared_with_integer_literals() {
    use crate::definition::RowLiteral;
    use crate::relational::{
        IrColumn, IrCompareOp, IrOperand, IrPredicate, IrRelation, IrRelationId, IrRelationOp,
        evaluate_plan_ir, lower_relational_assertion_plan, validate_plan_ir,
    };
    let authored = valid_plan();
    let mut ir = lower_relational_assertion_plan(&authored).unwrap();
    let grouped = ir.relations.last().unwrap();
    let selected = IrRelation {
        id: IrRelationId(ir.relations.len()),
        name: "selected".into(),
        op: IrRelationOp::Filter {
            input: grouped.id,
            predicates: vec![IrPredicate::Compare {
                left: IrColumn::new("by-site", "count"),
                op: IrCompareOp::Gt,
                right: IrOperand::Literal(RowLiteral::Integer(1)),
            }],
        },
        schema: grouped.schema.clone(),
    };
    ir.relations.push(selected);
    validate_plan_ir(&ir).unwrap();
    let rows = [occurrence("read", "ast")];
    let inputs = [
        RelationalInput {
            binding: &authored.bindings[0].name,
            rows: &rows,
            coverage: RelationCoverage::exhaustive(),
        },
        RelationalInput {
            binding: &authored.bindings[1].name,
            rows: &rows,
            coverage: RelationCoverage::exhaustive(),
        },
    ];
    let result = evaluate_plan_ir(&ir, &inputs, None).unwrap();
    assert!(result.exhaustive);
    assert!(result.violations.is_empty());
}
