use super::*;
use crate::relational::{CoveragePartition, CoverageRoot};
use brokk_bifrost_test_macros::hardwon;

fn blocked(coverage: RelationCoverage) -> RelationalAssertionEvaluation {
    evaluate(
        &counting_plan(AssertCardinality::AtMost(1)),
        &[("arg", &indexed_rows()[..1], coverage)],
    )
}

fn named(names: &[&str]) -> RelationCoverage {
    names.iter().fold(
        RelationCoverage::incomplete(vec![PolicyIncompleteReason::Cancelled]),
        |coverage, name| {
            coverage.meet(
                RelationCoverage::incomplete(vec![PolicyIncompleteReason::Cancelled]).in_partition(
                    CoveragePartition::of_root(CoverageRoot {
                        family: DetailedCodeQueryDomain::FlowEndpoint,
                        root: (*name).into(),
                    }),
                ),
            )
        },
    )
}

#[test]
#[hardwon("848e424a8eeb: duplicate roots falsely marked coverage truncated")]
fn duplicate_roots_at_the_reporting_bound_do_not_claim_omission() {
    let coverage = named(&["a", "b", "c", "d", "e", "f", "g", "h"]);
    let result = blocked(coverage.clone().meet(coverage));
    let partition = &result.unmet_obligations[0].partition;
    assert_eq!(partition.roots().len(), 8);
    assert!(!partition.truncated());
}

#[test]
fn omitted_root_names_are_reported_and_survive_query_scope() {
    let left = named(&["b", "c", "d", "e", "f", "g", "h", "i"]);
    let right = named(&["a"]);
    for coverage in [left.clone().meet(right.clone()), right.meet(left)] {
        for coverage in [coverage.clone().meet(named(&[])), named(&[]).meet(coverage)] {
            let result = blocked(coverage);
            let partition = &result.unmet_obligations[0].partition;
            assert_eq!(partition.roots().len(), 8);
            assert!(
                partition
                    .roots()
                    .iter()
                    .all(|r| ["a", "b", "c", "d", "e", "f", "g", "h", "i"]
                        .contains(&r.root.as_ref()))
            );
            assert!(partition.truncated());
        }
    }
}

#[test]
#[hardwon("848e424a8eeb: exhaustive row roots silently disappeared at the cap")]
fn exhaustive_root_omission_is_reported_when_absence_is_blocked() {
    let rows = (0..9)
        .map(|i| {
            flow_endpoint(
                &format!("endpoint-{i}"),
                &format!("plan-{i}"),
                CodeQueryFlowStatus::Complete,
            )
        })
        .collect::<Vec<_>>();
    let coverage = envelope_of_complete_query(&rows);
    // An equally exhaustive empty scope preserves the published partition.
    // The coverage is also exposed on the assertion input when no obligation is needed.
    assert_eq!(coverage.partition().roots().len(), 8);
    assert!(coverage.partition().truncated());
    let result = evaluate(
        &flow_counting_plan(AssertCardinality::AtMost(0)),
        &[("flow", &rows, coverage)],
    );
    assert!(!result.violations.is_empty());
}

#[test]
fn independent_coverage_causes_remain_actionable() {
    let coverage = RelationCoverage::incomplete(vec![PolicyIncompleteReason::Cancelled])
        .meet(RelationCoverage::row_budget());
    let result = blocked(coverage);
    let reasons = &result.unmet_obligations[0].reasons;
    assert_eq!(reasons.len(), 2, "{reasons:?}");
    assert!(
        reasons.contains(&PolicyIncompleteReason::Cancelled),
        "{reasons:?}"
    );
    assert!(
        reasons.contains(&PolicyIncompleteReason::PipelineRowBudget),
        "{reasons:?}"
    );
}

#[test]
fn suppressed_row_sets_name_the_relational_capability() {
    let unsupported = RelationCoverage::unsupported_row_set();
    assert!(format!("{:?}", unsupported.extent()).contains("relational"));
    let result = blocked(unsupported);
    assert_eq!(
        result.unmet_obligations[0].reasons,
        vec![PolicyIncompleteReason::CapabilityIncomplete]
    );
}

#[test]
fn obligation_retention_admits_exactly_the_documented_bound() {
    // MAX_RETAINED_RELATIONAL_OBLIGATIONS documents the reporting bound of 64.
    for n in [63, 64, 65] {
        let mut plan = counting_plan(AssertCardinality::AtMost(1));
        let template = plan.assertions[0].clone();
        plan.assertions = (0..n)
            .map(|i| {
                let mut a = template.clone();
                a.id = PolicyAssertId::from_str(&format!("assert-{i}")).unwrap();
                a
            })
            .collect();
        let result = evaluate(
            &plan,
            &[(
                "arg",
                &indexed_rows()[..1],
                RelationCoverage::proven_subset(),
            )],
        );
        assert_eq!(result.unmet_obligations.len(), n.min(64));
        assert_eq!(
            result.omitted_obligations_lower_bound,
            n.saturating_sub(64) as u64
        );
        assert_eq!(result.obligations_truncated, n > 64);
    }
}

#[test]
fn integer_minimum_includes_zero_and_maximum_includes_the_last_position() {
    for (op, expected) in [(IrAggregateOp::Min, 0), (IrAggregateOp::Max, 2)] {
        let input = source(0, "arg");
        let grouped = group(
            1,
            "positions",
            &input,
            vec![column("arg", "site_id")],
            vec![fold(
                "positions",
                "value",
                op,
                Some(column("arg", "argument_index")),
            )],
        );
        let assertion = assertion(
            "position",
            &grouped,
            "value",
            AssertCardinality::Exactly(expected),
        );
        let plan = plan(vec![input, grouped], vec![assertion]);
        let result = evaluate(
            &plan,
            &[("arg", &indexed_rows(), RelationCoverage::exhaustive())],
        );
        assert!(result.violations.is_empty(), "{result:?}");
        assert!(result.exhaustive);
    }
}

#[test]
fn integer_filters_use_membership_and_complement() {
    let col = column("arg", "argument_index");
    assert_eq!(
        filtered_count(
            vec![IrPredicate::InSet {
                column: col.clone(),
                values: vec![RowLiteral::Integer(0), RowLiteral::Integer(2)]
            }],
            &indexed_rows()
        ),
        2
    );
    for (op, count) in [(IrCompareOp::Eq, 1), (IrCompareOp::Ne, 2)] {
        assert_eq!(
            filtered_count(
                vec![IrPredicate::Compare {
                    left: col.clone(),
                    op,
                    right: IrOperand::Literal(RowLiteral::Integer(0))
                }],
                &indexed_rows()
            ),
            count
        );
    }
}

#[test]
fn distinct_may_evidence_is_retained_once_per_reason() {
    let mut rows = indexed_rows();
    for (row, reason) in rows.iter_mut().zip([
        "first alternative",
        "second alternative",
        "first alternative",
    ]) {
        row.fields.push(UnitRowField {
            name: "certainty".into(),
            value: UnitRowScalar::ConstrainedEnum("possible".into()),
        });
        row.fields.push(UnitRowField {
            name: "reason".into(),
            value: UnitRowScalar::String(reason.into()),
        });
    }
    let result = evaluate(
        &counting_plan(AssertCardinality::AtMost(0)),
        &[("arg", &rows, RelationCoverage::exhaustive())],
    );
    assert_eq!(
        result.violations[0].certainty,
        crate::finding::FindingCertainty::possible(
            ["first alternative", "second alternative"]
                .into_iter()
                .map(|reason| crate::finding::CertaintyReason::MayEvidence {
                    reason: reason.into()
                })
                .collect()
        )
        .unwrap()
    );
}

#[test]
fn restricted_and_truncated_queries_cannot_certify_absence() {
    let rows = indexed_rows();
    for (completion, truncated) in [
        (CodeQueryCompletion::Complete, true),
        (CodeQueryCompletion::ProvenSubset { codes: vec![] }, false),
    ] {
        let coverage = RelationCoverage::from_query(&rows[..1], &completion, truncated);
        let result = blocked(coverage);
        assert!(!result.exhaustive);
        assert_eq!(result.unmet_obligations.len(), 1);
    }
    let result = blocked(RelationCoverage::from_query(
        &rows[..1],
        &CodeQueryCompletion::Complete,
        false,
    ));
    assert!(result.exhaustive);
    assert!(result.unmet_obligations.is_empty());
}

#[test]
fn renamed_projection_retains_the_source_integer() {
    use crate::relational::{IrProjection, IrSchema};
    let input = source(0, "arg");
    let original = column("arg", "argument_index");
    let renamed = column("projected", "index");
    let mut field = input.schema.field(&original).unwrap().clone();
    field.column = renamed.clone();
    let projected = IrRelation {
        id: IrRelationId(1),
        name: "projected".into(),
        op: IrRelationOp::Project {
            input: input.id,
            columns: vec![IrProjection {
                source: original,
                output: renamed.clone(),
            }],
        },
        schema: IrSchema::new(vec![field]),
    };
    let grouped = group(
        2,
        "minimum",
        &projected,
        vec![renamed.clone()],
        vec![fold("minimum", "value", IrAggregateOp::Min, Some(renamed))],
    );
    let assertion = assertion("zero", &grouped, "value", AssertCardinality::Exactly(0));
    let result = evaluate(
        &plan(vec![input, projected, grouped], vec![assertion]),
        &[("arg", &indexed_rows()[..1], RelationCoverage::exhaustive())],
    );
    assert!(result.violations.is_empty());
    assert!(result.exhaustive);
}

#[test]
fn contributors_follow_declarations_across_reordered_joins() {
    let a = source(0, "a");
    let b = source(1, "b");
    let c = source(2, "c");
    let ac = join(
        3,
        &a,
        &c,
        IrJoinKind::Inner,
        vec![IrEquiKey {
            left: column("a", "site_id"),
            right: column("c", "site_id"),
        }],
    );
    let abc = join(
        4,
        &ac,
        &b,
        IrJoinKind::Inner,
        vec![IrEquiKey {
            left: column("a", "site_id"),
            right: column("b", "site_id"),
        }],
    );
    let grouped = group(
        5,
        "calls",
        &abc,
        vec![column("a", "site_id")],
        vec![fold("calls", "count", IrAggregateOp::Count, None)],
    );
    let assertion = assertion("no-calls", &grouped, "count", AssertCardinality::AtMost(0));
    let rows = &indexed_rows()[..1];
    let result = evaluate(
        &plan(vec![a, b, c, ac, abc, grouped], vec![assertion]),
        &[
            ("a", rows, RelationCoverage::exhaustive()),
            ("b", rows, RelationCoverage::exhaustive()),
            ("c", rows, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(
        result.violations[0].representatives[0]
            .iter()
            .map(|r| r.binding.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b", "c"]
    );
}

#[test]
fn equal_sequences_preserve_positions_of_repeated_values() {
    use crate::relational::{IrOrderedSequence, IrOrderedSequencePair};
    let input = source(0, "arg");
    let sequence = IrOrderedSequence {
        position: column("arg", "argument_index"),
        value: column("arg", "name"),
    };
    let mut aggregate = fold("sequences", "equal", IrAggregateOp::OrderedEqual, None);
    aggregate.sequences = Some(IrOrderedSequencePair {
        left: sequence.clone(),
        right: sequence,
    });
    let grouped = group(
        1,
        "sequences",
        &input,
        vec![column("arg", "site_id")],
        vec![aggregate],
    );
    let assertion = assertion("equal", &grouped, "equal", AssertCardinality::Exactly(1));
    let plan = plan(vec![input, grouped], vec![assertion]);
    let rows = (0..16)
        .map(|i| argument("site", &format!("arg-{i}"), i, Some("repeated"), false))
        .collect::<Vec<_>>();
    for _ in 0..8 {
        let result = evaluate(&plan, &[("arg", &rows, RelationCoverage::exhaustive())]);
        assert!(result.violations.is_empty(), "{result:?}");
        assert!(result.exhaustive);
    }
}

#[test]
fn row_diagnostics_retain_budget_and_capability_causes() {
    use brokk_bifrost_rql::structural::CodeQueryDiagnosticCode;
    let mut rows = vec![flow_endpoint(
        "endpoint",
        "plan",
        CodeQueryFlowStatus::Complete,
    )];
    rows[0].coverage.as_mut().unwrap().extent =
        brokk_bifrost_rql::structural::search::CodeQueryRowCoverageExtent::Incomplete {
            codes: vec![
                CodeQueryDiagnosticCode::PipelineBudgetExhausted,
                CodeQueryDiagnosticCode::CallShapeCoverageIncomplete,
            ],
        };
    let coverage = envelope_of_complete_query(&rows);
    let result = evaluate(
        &flow_counting_plan(AssertCardinality::AtMost(1)),
        &[("flow", &rows, coverage)],
    );
    assert_eq!(
        result.unmet_obligations[0].reasons,
        vec![
            PolicyIncompleteReason::PipelineRowBudget,
            PolicyIncompleteReason::CapabilityIncomplete
        ]
    );
}

#[test]
fn complete_partition_names_render_in_identity_order() {
    for coverage in [named(&["z", "a"]), named(&["a", "z"])] {
        let result = blocked(coverage);
        let partition = &result.unmet_obligations[0].partition;
        assert_eq!(
            partition
                .roots()
                .iter()
                .map(|r| r.root.as_ref())
                .collect::<Vec<_>>(),
            vec!["a", "z"]
        );
        assert!(!partition.truncated());
    }
}
