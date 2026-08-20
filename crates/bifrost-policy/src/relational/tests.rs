//! Unit coverage for the relational IR: the verdict truth table, the coverage
//! transfer rules, the operators the syntax cannot spell yet, every plan bound,
//! and determinism.
//!
//! The plans here are built as IR directly rather than through the authoring
//! model, because that is the only way to exercise the capabilities milestone 2
//! will make authorable. The lowering path is covered by the seam's own tests in
//! `crate::assertion_policy`.

use std::str::FromStr;

use brokk_bifrost_analysis::analyzer::structural::search::{
    CodeQueryCallShapeArgument, CodeQueryResultItem, DetailedCodeQueryDomain,
};
use brokk_bifrost_analysis::analyzer::structural::{CodeQueryRange, CodeQueryResultValue};

use crate::definition::{AssertCardinality, PolicyAssertId, RowBindingName, RowLiteral};
use crate::finding::PolicyIncompleteReason;

use super::coverage::{RelationCoverage, RelationalInput, RelationalObligationKind};
use super::eval::{RelationalAssertionEvaluation, evaluate_plan_ir};
use super::ir::{
    IrAggregate, IrAggregateOp, IrAssertion, IrColumn, IrCompareOp, IrEquiKey, IrJoinKind,
    IrLimits, IrOperand, IrPredicate, IrRelation, IrRelationId, IrRelationOp, RelationalPlanIr,
    RowScalar, domain_schema, group_schema, join_schema,
};
use super::validate::{RelationalAssertionPlanError, validate_plan_ir};

const DOMAIN: DetailedCodeQueryDomain = DetailedCodeQueryDomain::CallArgument;

fn binding(name: &str) -> RowBindingName {
    RowBindingName::from_str(name).expect("valid binding name")
}

fn column(qualifier: &str, name: &str) -> IrColumn {
    IrColumn::new(qualifier, name)
}

/// One call-argument row. That domain is used throughout because it is the one
/// registry domain carrying an identity, an integer, a nullable string and a
/// boolean at once, which is exactly the typing surface under test.
fn argument(
    site: &str,
    id: &str,
    index: usize,
    name: Option<&str>,
    spread: bool,
) -> CodeQueryResultItem {
    CodeQueryResultItem {
        value: CodeQueryResultValue::CallArgument {
            value: Box::new(CodeQueryCallShapeArgument {
                id: id.to_string(),
                group_id: format!("{site}-group"),
                site_id: site.to_string(),
                path: "app.py".to_string(),
                range: CodeQueryRange {
                    start_line: 1,
                    start_column: 1,
                    end_line: 1,
                    end_column: 2,
                },
                argument_index: index,
                name: name.map(str::to_string),
                spread,
            }),
        },
        provenance: Vec::new(),
        provenance_truncated: false,
    }
}

fn source(id: usize, name: &str) -> IrRelation {
    IrRelation {
        id: IrRelationId(id),
        name: name.to_string(),
        op: IrRelationOp::Source {
            binding: binding(name),
            domain: DOMAIN,
        },
        schema: domain_schema(name, DOMAIN),
    }
}

fn filter(id: usize, name: &str, input: &IrRelation, predicates: Vec<IrPredicate>) -> IrRelation {
    IrRelation {
        id: IrRelationId(id),
        name: name.to_string(),
        op: IrRelationOp::Filter {
            input: input.id,
            predicates,
        },
        schema: input.schema.clone(),
    }
}

fn join(
    id: usize,
    left: &IrRelation,
    right: &IrRelation,
    kind: IrJoinKind,
    on: Vec<IrEquiKey>,
) -> IrRelation {
    IrRelation {
        id: IrRelationId(id),
        name: format!("{}-{}-{}", left.name, kind.label(), right.name),
        op: IrRelationOp::Join {
            left: left.id,
            right: right.id,
            kind,
            on,
        },
        schema: join_schema(&left.schema, &right.schema, kind),
    }
}

fn fold(group: &str, name: &str, op: IrAggregateOp, value: Option<IrColumn>) -> IrAggregate {
    IrAggregate {
        name: FromStr::from_str(name).expect("valid aggregate name"),
        op,
        value,
        sequences: None,
        predicates: Vec::new(),
        output: column(group, name),
    }
}

fn group(
    id: usize,
    name: &str,
    input: &IrRelation,
    by: Vec<IrColumn>,
    aggregates: Vec<IrAggregate>,
) -> IrRelation {
    let schema =
        group_schema(&input.schema, &by, &aggregates).expect("group keys are input columns");
    IrRelation {
        id: IrRelationId(id),
        name: name.to_string(),
        op: IrRelationOp::Group {
            input: input.id,
            by,
            aggregates,
        },
        schema,
    }
}

fn assertion(
    id: &str,
    relation: &IrRelation,
    aggregate: &str,
    cardinality: AssertCardinality,
) -> IrAssertion {
    IrAssertion {
        id: PolicyAssertId::from_str(id).expect("valid assert id"),
        relation: relation.id,
        group: FromStr::from_str(&relation.name).expect("valid group name"),
        aggregate: FromStr::from_str(aggregate).expect("valid aggregate name"),
        column: column(&relation.name, aggregate),
        cardinality,
    }
}

fn plan(relations: Vec<IrRelation>, assertions: Vec<IrAssertion>) -> RelationalPlanIr {
    RelationalPlanIr {
        relations,
        assertions,
        limits: IrLimits::default(),
    }
}

/// One source binding, grouped by call site, counting its rows.
fn counting_plan(cardinality: AssertCardinality) -> RelationalPlanIr {
    let arg = source(0, "arg");
    let grouped = group(
        1,
        "by-site",
        &arg,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let assert = assertion("one-call", &grouped, "calls", cardinality);
    plan(vec![arg, grouped], vec![assert])
}

fn evaluate(
    plan: &RelationalPlanIr,
    inputs: &[(&str, &[CodeQueryResultItem], RelationCoverage)],
) -> RelationalAssertionEvaluation {
    validate_plan_ir(plan).expect("the plan under test validates");
    let names = inputs
        .iter()
        .map(|(name, _, _)| binding(name))
        .collect::<Vec<_>>();
    let inputs = inputs
        .iter()
        .zip(&names)
        .map(|((_, rows, coverage), name)| RelationalInput {
            binding: name,
            rows,
            coverage: coverage.clone(),
        })
        .collect::<Vec<_>>();
    evaluate_plan_ir(plan, &inputs).expect("evaluation concludes")
}

/// The observed key/value pairs of every published violation.
fn verdicts(evaluation: &RelationalAssertionEvaluation) -> Vec<(String, u64)> {
    evaluation
        .violations
        .iter()
        .map(|violation| {
            let key = violation
                .key
                .iter()
                .map(|scalar| match scalar {
                    Some(RowScalar::StableId(value)) => value.clone(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join("|");
            (key, violation.actual)
        })
        .collect()
}

fn two_rows_at_one_site() -> Vec<CodeQueryResultItem> {
    vec![
        argument("site", "arg-0", 0, Some("name"), false),
        argument("site", "arg-1", 1, Some("greeting"), false),
    ]
}

// ---------------------------------------------------------------------------
// The verdict truth table.
// ---------------------------------------------------------------------------

/// A count above an upper bound is positive evidence: the rows that produced it
/// were read, and unread rows could only raise it further.
#[test]
fn an_exceeded_upper_bound_is_published_from_a_proven_subset() {
    let plan = counting_plan(AssertCardinality::AtMost(1));
    let rows = two_rows_at_one_site();
    for coverage in [
        RelationCoverage::Exhaustive,
        RelationCoverage::ProvenSubset,
        RelationCoverage::incomplete(vec![PolicyIncompleteReason::Cancelled]),
    ] {
        let evaluation = evaluate(&plan, &[("arg", &rows, coverage.clone())]);
        assert_eq!(
            verdicts(&evaluation),
            vec![("site".to_string(), 2)],
            "{coverage:?}"
        );
        assert!(evaluation.unmet_obligations.is_empty(), "{coverage:?}");
    }
}

/// The same rule for `exactly`, whose upper bound is the half that can be
/// exceeded.
#[test]
fn an_exceeded_exact_bound_is_published_from_a_proven_subset() {
    let plan = counting_plan(AssertCardinality::Exactly(1));
    let rows = two_rows_at_one_site();
    let evaluation = evaluate(&plan, &[("arg", &rows, RelationCoverage::ProvenSubset)]);
    assert_eq!(verdicts(&evaluation), vec![("site".to_string(), 2)]);
    assert!(evaluation.unmet_obligations.is_empty());
}

/// A clean upper-bound verdict states that no further row exists, which only an
/// exhaustive relation can support.
#[test]
fn a_clean_upper_bound_needs_exhaustive_coverage() {
    let plan = counting_plan(AssertCardinality::AtMost(2));
    let rows = two_rows_at_one_site();

    let exhaustive = evaluate(&plan, &[("arg", &rows, RelationCoverage::Exhaustive)]);
    assert!(exhaustive.violations.is_empty());
    assert!(exhaustive.unmet_obligations.is_empty());

    let subset = evaluate(&plan, &[("arg", &rows, RelationCoverage::ProvenSubset)]);
    assert!(subset.violations.is_empty());
    assert_eq!(subset.unmet_obligations.len(), 1);
    assert_eq!(
        subset.unmet_obligations[0].kind,
        RelationalObligationKind::AbsenceRequiresExhaustiveCoverage
    );
    assert_eq!(
        subset.unmet_obligations[0].reasons,
        vec![PolicyIncompleteReason::PartialDiscovery]
    );
}

/// Zero is the sharpest absence claim and is treated identically.
#[test]
fn a_clean_zero_verdict_needs_exhaustive_coverage() {
    let plan = counting_plan(AssertCardinality::Exactly(0));
    let rows: Vec<CodeQueryResultItem> = Vec::new();

    let exhaustive = evaluate(&plan, &[("arg", &rows, RelationCoverage::Exhaustive)]);
    assert!(exhaustive.unmet_obligations.is_empty());

    // No group exists at all, so the clean verdict is a claim about rows nobody
    // read.
    let subset = evaluate(&plan, &[("arg", &rows, RelationCoverage::ProvenSubset)]);
    assert_eq!(subset.violations.len(), 0);
    assert_eq!(subset.unmet_obligations.len(), 1);
    assert!(subset.unmet_obligations[0].key.is_empty());
}

/// Too few rows is an absence claim, so it is published only from an exhaustive
/// relation.
#[test]
fn a_lower_bound_violation_needs_exhaustive_coverage() {
    for cardinality in [AssertCardinality::AtLeast(3), AssertCardinality::Exactly(3)] {
        let plan = counting_plan(cardinality);
        let rows = two_rows_at_one_site();

        let exhaustive = evaluate(&plan, &[("arg", &rows, RelationCoverage::Exhaustive)]);
        assert_eq!(verdicts(&exhaustive), vec![("site".to_string(), 2)]);
        assert!(exhaustive.unmet_obligations.is_empty());

        let subset = evaluate(&plan, &[("arg", &rows, RelationCoverage::ProvenSubset)]);
        assert!(subset.violations.is_empty(), "{cardinality:?}");
        assert_eq!(
            subset.unmet_obligations[0].kind,
            RelationalObligationKind::AbsenceRequiresExhaustiveCoverage
        );
    }
}

/// A satisfied lower bound is positive evidence and needs no exhaustive
/// relation: rows nobody read cannot take the observed rows away.
#[test]
fn a_clean_lower_bound_is_conclusive_from_a_proven_subset() {
    let plan = counting_plan(AssertCardinality::AtLeast(2));
    let rows = two_rows_at_one_site();
    let subset = evaluate(&plan, &[("arg", &rows, RelationCoverage::ProvenSubset)]);
    assert!(subset.violations.is_empty());
    assert!(
        subset.unmet_obligations.is_empty(),
        "{:?}",
        subset.unmet_obligations
    );
}

/// An unsupported relation is not a partial one: nothing it produces supports a
/// verdict either way.
#[test]
fn an_unsupported_relation_blocks_the_clean_verdict_with_a_capability_reason() {
    let plan = counting_plan(AssertCardinality::AtMost(2));
    let rows = two_rows_at_one_site();
    let evaluation = evaluate(
        &plan,
        &[("arg", &rows, RelationCoverage::unsupported_row_set())],
    );
    assert_eq!(
        evaluation.unmet_obligations[0].reasons,
        vec![PolicyIncompleteReason::CapabilityIncomplete]
    );
}

// ---------------------------------------------------------------------------
// Joins.
// ---------------------------------------------------------------------------

fn join_plan(kind: IrJoinKind, cardinality: AssertCardinality) -> RelationalPlanIr {
    let left = source(0, "arg");
    let right = source(1, "other");
    let joined = join(
        2,
        &left,
        &right,
        kind,
        vec![IrEquiKey {
            left: column("arg", "site_id"),
            right: column("other", "site_id"),
        }],
    );
    let grouped = group(
        3,
        "by-site",
        &joined,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let assert = assertion("joined", &grouped, "calls", cardinality);
    plan(vec![left, right, joined, grouped], vec![assert])
}

/// A semi join filters without multiplying: two partners on the right keep the
/// left row once, where an inner join would report it twice.
#[test]
fn a_semi_join_keeps_each_left_row_once() {
    let left = vec![argument("site", "arg-0", 0, None, false)];
    let right = vec![
        argument("site", "other-0", 0, None, false),
        argument("site", "other-1", 1, None, false),
    ];
    let semi = evaluate(
        &join_plan(IrJoinKind::Semi, AssertCardinality::AtMost(0)),
        &[
            ("arg", &left, RelationCoverage::Exhaustive),
            ("other", &right, RelationCoverage::Exhaustive),
        ],
    );
    assert_eq!(verdicts(&semi), vec![("site".to_string(), 1)]);

    let inner = evaluate(
        &join_plan(IrJoinKind::Inner, AssertCardinality::AtMost(0)),
        &[
            ("arg", &left, RelationCoverage::Exhaustive),
            ("other", &right, RelationCoverage::Exhaustive),
        ],
    );
    assert_eq!(verdicts(&inner), vec![("site".to_string(), 2)]);
}

/// A left row with no partner is dropped by a semi join and kept by an anti
/// join.
#[test]
fn semi_and_anti_joins_select_opposite_row_sets() {
    let left = vec![argument("site", "arg-0", 0, None, false)];
    let right = vec![argument("elsewhere", "other-0", 0, None, false)];
    let inputs: &[(&str, &[CodeQueryResultItem], RelationCoverage)] = &[
        ("arg", &left, RelationCoverage::Exhaustive),
        ("other", &right, RelationCoverage::Exhaustive),
    ];
    let semi = evaluate(
        &join_plan(IrJoinKind::Semi, AssertCardinality::AtMost(0)),
        inputs,
    );
    assert!(semi.violations.is_empty(), "no left row has a partner");
    let anti = evaluate(
        &join_plan(IrJoinKind::Anti, AssertCardinality::AtMost(0)),
        inputs,
    );
    assert_eq!(verdicts(&anti), vec![("site".to_string(), 1)]);
}

/// Anti-join output over a non-exhaustive right relation exists only because
/// nothing was found to remove it, so it can support no verdict at all.
#[test]
fn anti_join_output_is_witness_unsound_over_a_partial_right_relation() {
    let left = vec![argument("site", "arg-0", 0, None, false)];
    let right = vec![argument("elsewhere", "other-0", 0, None, false)];
    let evaluation = evaluate(
        &join_plan(IrJoinKind::Anti, AssertCardinality::AtMost(0)),
        &[
            ("arg", &left, RelationCoverage::Exhaustive),
            ("other", &right, RelationCoverage::ProvenSubset),
        ],
    );
    assert!(
        evaluation.violations.is_empty(),
        "an unmatched row is not evidence when the right relation was a subset"
    );
    assert_eq!(
        evaluation.unmet_obligations[0].kind,
        RelationalObligationKind::VerdictRequiresWitnessedRows
    );
    assert_eq!(
        evaluation.unmet_obligations[0].reasons,
        vec![PolicyIncompleteReason::PartialDiscovery]
    );
}

/// The left side's own coverage is unaffected by the right side of an anti
/// join, so an exhaustive left relation whose rows all matched still concludes
/// cleanly.
#[test]
fn an_anti_join_that_removed_every_row_still_concludes() {
    let left = vec![argument("site", "arg-0", 0, None, false)];
    let right = vec![argument("site", "other-0", 0, None, false)];
    let evaluation = evaluate(
        &join_plan(IrJoinKind::Anti, AssertCardinality::AtMost(0)),
        &[
            ("arg", &left, RelationCoverage::Exhaustive),
            ("other", &right, RelationCoverage::Exhaustive),
        ],
    );
    assert!(evaluation.violations.is_empty());
    assert!(evaluation.unmet_obligations.is_empty());
    assert!(evaluation.exhaustive);
}

/// An inner join is no more covered than its weaker side.
#[test]
fn an_inner_join_meets_both_coverages() {
    let rows = vec![argument("site", "arg-0", 0, None, false)];
    let evaluation = evaluate(
        &join_plan(IrJoinKind::Inner, AssertCardinality::AtMost(1)),
        &[
            ("arg", &rows, RelationCoverage::Exhaustive),
            ("other", &rows, RelationCoverage::ProvenSubset),
        ],
    );
    assert!(evaluation.violations.is_empty());
    assert_eq!(
        evaluation.unmet_obligations[0].kind,
        RelationalObligationKind::AbsenceRequiresExhaustiveCoverage,
        "the clean verdict inherits the weaker side's coverage"
    );
}

/// An expansion is no better covered than the rows it expands: its own query
/// can be complete while the sites it expanded were a subset.
#[test]
fn an_expansion_inherits_the_coverage_of_the_rows_it_expands() {
    let site = IrRelation {
        id: IrRelationId(0),
        name: "site".to_string(),
        op: IrRelationOp::Source {
            binding: binding("site"),
            domain: DetailedCodeQueryDomain::Occurrence,
        },
        schema: domain_schema("site", DetailedCodeQueryDomain::Occurrence),
    };
    let selection = IrRelation {
        id: IrRelationId(1),
        name: "sel".to_string(),
        op: IrRelationOp::Expand {
            input: site.id,
            binding: binding("sel"),
            step: crate::definition::RowExpansionStep::MemberSelection,
            domain: DetailedCodeQueryDomain::MemberSelection,
        },
        schema: domain_schema("sel", DetailedCodeQueryDomain::MemberSelection),
    };
    let grouped = group(
        2,
        "by-site",
        &selection,
        vec![column("sel", "site_ast_id")],
        vec![fold("by-site", "rows", IrAggregateOp::Count, None)],
    );
    let assert = assertion("rows", &grouped, "rows", AssertCardinality::AtMost(0));
    let plan = plan(vec![site, selection, grouped], vec![assert]);

    let empty: Vec<CodeQueryResultItem> = Vec::new();
    let complete = evaluate(
        &plan,
        &[
            ("site", &empty, RelationCoverage::Exhaustive),
            ("sel", &empty, RelationCoverage::Exhaustive),
        ],
    );
    assert!(complete.unmet_obligations.is_empty());

    let partial_sites = evaluate(
        &plan,
        &[
            ("site", &empty, RelationCoverage::ProvenSubset),
            ("sel", &empty, RelationCoverage::Exhaustive),
        ],
    );
    assert_eq!(
        partial_sites.unmet_obligations.len(),
        1,
        "an expansion of a subset of sites is itself a subset"
    );
}

// ---------------------------------------------------------------------------
// Bounds.
// ---------------------------------------------------------------------------

#[test]
fn the_source_bound_truncates_and_degrades_coverage() {
    let mut plan = counting_plan(AssertCardinality::AtMost(2));
    plan.limits.max_source_rows = 1;
    let rows = two_rows_at_one_site();
    let evaluation = evaluate(&plan, &[("arg", &rows, RelationCoverage::Exhaustive)]);
    assert!(evaluation.limit_exceeded);
    assert!(!evaluation.exhaustive);
    assert_eq!(
        evaluation.unmet_obligations[0].reasons,
        vec![PolicyIncompleteReason::PipelineRowBudget]
    );
}

#[test]
fn the_comparison_and_joined_row_bounds_truncate() {
    let rows = two_rows_at_one_site();
    for limits in [
        |limits: &mut IrLimits| limits.max_join_comparisons = 1,
        |limits: &mut IrLimits| limits.max_joined_rows = 1,
    ] {
        let mut plan = join_plan(IrJoinKind::Inner, AssertCardinality::AtMost(0));
        limits(&mut plan.limits);
        let evaluation = evaluate(
            &plan,
            &[
                ("arg", &rows, RelationCoverage::Exhaustive),
                ("other", &rows, RelationCoverage::Exhaustive),
            ],
        );
        assert!(evaluation.limit_exceeded);
        assert!(!evaluation.exhaustive);
    }
}

#[test]
fn the_group_bound_truncates_the_group_relation() {
    let mut plan = counting_plan(AssertCardinality::AtMost(0));
    plan.limits.max_groups = 1;
    let rows = vec![
        argument("site-a", "arg-0", 0, None, false),
        argument("site-b", "arg-1", 0, None, false),
    ];
    let evaluation = evaluate(&plan, &[("arg", &rows, RelationCoverage::Exhaustive)]);
    assert!(evaluation.limit_exceeded);
    assert_eq!(
        evaluation.violations.len(),
        1,
        "the group that was formed is still evidence"
    );
}

/// Per-group truncation degrades exactly the group it truncated. The other
/// group's verdict is untouched, which is the whole point of tracking the
/// witness per group rather than per run.
#[test]
fn a_truncated_group_loses_its_verdict_and_no_other_group_does() {
    let mut plan = counting_plan(AssertCardinality::AtMost(0));
    plan.limits.max_values_per_group = 1;
    let rows = vec![
        argument("site-a", "arg-0", 0, None, false),
        argument("site-a", "arg-1", 1, None, false),
        argument("site-b", "arg-2", 0, None, false),
    ];
    let evaluation = evaluate(&plan, &[("arg", &rows, RelationCoverage::Exhaustive)]);
    assert_eq!(verdicts(&evaluation), vec![("site-b".to_string(), 1)]);
    assert_eq!(evaluation.unmet_obligations.len(), 1);
    assert_eq!(
        evaluation.unmet_obligations[0].kind,
        RelationalObligationKind::VerdictRequiresWitnessedRows
    );
    assert_eq!(
        evaluation.unmet_obligations[0].key,
        vec![Some(RowScalar::StableId("site-a".to_string()))]
    );
}

// ---------------------------------------------------------------------------
// Determinism.
// ---------------------------------------------------------------------------

/// Group order is one sort over keys, so the published sequence does not depend
/// on the order rows arrived in.
#[test]
fn published_verdicts_do_not_depend_on_input_row_order() {
    let plan = counting_plan(AssertCardinality::AtMost(0));
    // Rows are respecified rather than cloned: a query result item is not
    // `Clone`, which is also why the evaluator never holds one twice.
    let specification = [
        ("site-a", "arg-0", 0),
        ("site-b", "arg-1", 0),
        ("site-b", "arg-2", 1),
        ("site-c", "arg-3", 0),
    ];
    let build = |rotation: usize| {
        (0..specification.len())
            .map(|index| specification[(index + rotation) % specification.len()])
            .map(|(site, id, position)| argument(site, id, position, None, false))
            .collect::<Vec<_>>()
    };
    let ordered = build(0);
    let expected = verdicts(&evaluate(
        &plan,
        &[("arg", &ordered, RelationCoverage::Exhaustive)],
    ));
    assert_eq!(
        expected,
        vec![
            ("site-a".to_string(), 1),
            ("site-b".to_string(), 2),
            ("site-c".to_string(), 1),
        ]
    );
    for rotation in 1..specification.len() {
        let shuffled = build(rotation);
        assert_eq!(
            verdicts(&evaluate(
                &plan,
                &[("arg", &shuffled, RelationCoverage::Exhaustive)]
            )),
            expected,
            "rotation {rotation}"
        );
    }
}

// ---------------------------------------------------------------------------
// Predicates the syntax cannot spell yet.
// ---------------------------------------------------------------------------

/// Count the rows a filter admits.
fn filtered_count(predicates: Vec<IrPredicate>, rows: &[CodeQueryResultItem]) -> u64 {
    let arg = source(0, "arg");
    let filtered = filter(1, "kept", &arg, predicates);
    let grouped = group(
        2,
        "by-site",
        &filtered,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let assert = assertion("kept", &grouped, "calls", AssertCardinality::AtMost(0));
    let plan = plan(vec![arg, filtered, grouped], vec![assert]);
    let evaluation = evaluate(&plan, &[("arg", rows, RelationCoverage::Exhaustive)]);
    evaluation
        .violations
        .first()
        .map(|violation| violation.actual)
        .unwrap_or(0)
}

fn indexed_rows() -> Vec<CodeQueryResultItem> {
    vec![
        argument("site", "arg-0", 0, Some("name"), false),
        argument("site", "arg-1", 1, None, true),
        argument("site", "arg-2", 2, Some("greeting"), false),
    ]
}

#[test]
fn ordered_comparisons_select_integer_ranges() {
    let rows = indexed_rows();
    let cases = [
        (IrCompareOp::Lt, 1_u64, 1_u64),
        (IrCompareOp::Le, 1, 2),
        (IrCompareOp::Gt, 1, 1),
        (IrCompareOp::Ge, 1, 2),
        (IrCompareOp::Eq, 1, 1),
        (IrCompareOp::Ne, 1, 2),
    ];
    for (op, bound, expected) in cases {
        assert_eq!(
            filtered_count(
                vec![IrPredicate::Compare {
                    left: column("arg", "argument_index"),
                    op,
                    right: IrOperand::Literal(RowLiteral::Integer(bound)),
                }],
                &rows,
            ),
            expected,
            "{}",
            op.label()
        );
    }
}

/// An absent value satisfies no comparison, including `ne`. The row whose name
/// is absent is not counted as "not equal to name".
#[test]
fn an_absent_value_satisfies_no_comparison() {
    let rows = indexed_rows();
    assert_eq!(
        filtered_count(
            vec![IrPredicate::Compare {
                left: column("arg", "name"),
                op: IrCompareOp::Ne,
                right: IrOperand::Literal(RowLiteral::String("name".to_string())),
            }],
            &rows,
        ),
        1,
        "only the row that states a different name qualifies"
    );
}

#[test]
fn null_tests_select_absent_and_present_values() {
    let rows = indexed_rows();
    assert_eq!(
        filtered_count(
            vec![IrPredicate::IsNull {
                column: column("arg", "name"),
                negated: false,
            }],
            &rows,
        ),
        1
    );
    assert_eq!(
        filtered_count(
            vec![IrPredicate::IsNull {
                column: column("arg", "name"),
                negated: true,
            }],
            &rows,
        ),
        2
    );
}

#[test]
fn set_membership_admits_any_listed_literal() {
    let rows = indexed_rows();
    assert_eq!(
        filtered_count(
            vec![IrPredicate::InSet {
                column: column("arg", "name"),
                values: vec![
                    RowLiteral::String("name".to_string()),
                    RowLiteral::String("greeting".to_string()),
                ],
            }],
            &rows,
        ),
        2
    );
}

/// A comparison between two columns of one joined relation.
#[test]
fn a_field_to_field_comparison_reads_both_sides() {
    let left = source(0, "arg");
    let right = source(1, "other");
    let joined = join(
        2,
        &left,
        &right,
        IrJoinKind::Inner,
        vec![IrEquiKey {
            left: column("arg", "site_id"),
            right: column("other", "site_id"),
        }],
    );
    let filtered = filter(
        3,
        "aligned",
        &joined,
        vec![IrPredicate::Compare {
            left: column("arg", "argument_index"),
            op: IrCompareOp::Lt,
            right: IrOperand::Column(column("other", "argument_index")),
        }],
    );
    let grouped = group(
        4,
        "by-site",
        &filtered,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "pairs", IrAggregateOp::Count, None)],
    );
    let assert = assertion("pairs", &grouped, "pairs", AssertCardinality::AtMost(0));
    let plan = plan(vec![left, right, joined, filtered, grouped], vec![assert]);
    let rows = vec![
        argument("site", "arg-0", 0, None, false),
        argument("site", "arg-1", 1, None, false),
    ];
    let evaluation = evaluate(
        &plan,
        &[
            ("arg", &rows, RelationCoverage::Exhaustive),
            ("other", &rows, RelationCoverage::Exhaustive),
        ],
    );
    assert_eq!(
        verdicts(&evaluation),
        vec![("site".to_string(), 1)],
        "exactly the ordered pair (0, 1) qualifies"
    );
}

// ---------------------------------------------------------------------------
// Folds the syntax cannot spell yet.
// ---------------------------------------------------------------------------

fn folded(op: IrAggregateOp, value: &str, rows: &[CodeQueryResultItem]) -> u64 {
    let arg = source(0, "arg");
    let grouped = group(
        1,
        "by-site",
        &arg,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "value", op, Some(column("arg", value)))],
    );
    // `at-most 0` publishes the fold's exact value as the violation's actual.
    let assert = assertion("value", &grouped, "value", AssertCardinality::AtMost(0));
    let plan = plan(vec![arg, grouped], vec![assert]);
    let evaluation = evaluate(&plan, &[("arg", rows, RelationCoverage::Exhaustive)]);
    evaluation
        .violations
        .first()
        .map(|violation| violation.actual)
        .unwrap_or(0)
}

#[test]
fn max_and_min_fold_an_integer_column() {
    let rows = indexed_rows();
    assert_eq!(folded(IrAggregateOp::Max, "argument_index", &rows), 2);
    assert_eq!(folded(IrAggregateOp::Min, "argument_index", &rows), 0);
}

#[test]
fn any_and_all_fold_a_boolean_column() {
    let mixed = indexed_rows();
    assert_eq!(folded(IrAggregateOp::Any, "spread", &mixed), 1);
    assert_eq!(folded(IrAggregateOp::All, "spread", &mixed), 0);

    let every = vec![
        argument("site", "arg-0", 0, None, true),
        argument("site", "arg-1", 1, None, true),
    ];
    assert_eq!(folded(IrAggregateOp::All, "spread", &every), 1);
    assert_eq!(folded(IrAggregateOp::Any, "spread", &every), 1);

    let none = vec![argument("site", "arg-0", 0, None, false)];
    assert_eq!(folded(IrAggregateOp::Any, "spread", &none), 0);
}

#[test]
fn count_distinct_folds_repeated_values_once() {
    let rows = vec![
        argument("site", "arg-0", 0, Some("name"), false),
        argument("site", "arg-1", 0, Some("name"), false),
        argument("site", "arg-2", 1, Some("name"), false),
    ];
    assert_eq!(
        folded(IrAggregateOp::CountDistinct, "argument_index", &rows),
        2
    );
}

// ---------------------------------------------------------------------------
// Validation.
// ---------------------------------------------------------------------------

#[test]
fn a_group_key_that_is_not_a_column_is_rejected() {
    let arg = source(0, "arg");
    let mut grouped = group(
        1,
        "by-site",
        &arg,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let IrRelationOp::Group { by, .. } = &mut grouped.op else {
        panic!("the relation under test is a group");
    };
    by[0] = column("arg", "source_range");
    let assert = assertion("calls", &grouped, "calls", AssertCardinality::AtMost(0));
    assert_eq!(
        validate_plan_ir(&plan(vec![arg, grouped], vec![assert])),
        Err(RelationalAssertionPlanError::UnknownField {
            binding: "arg".to_string(),
            field: "source_range".to_string(),
        })
    );
}

/// One filter predicate under test, validated rather than evaluated.
fn validate_predicate(predicate: IrPredicate) -> Result<(), RelationalAssertionPlanError> {
    let arg = source(0, "arg");
    let filtered = filter(1, "kept", &arg, vec![predicate]);
    let grouped = group(
        2,
        "by-site",
        &filtered,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let assert = assertion("calls", &grouped, "calls", AssertCardinality::AtMost(0));
    validate_plan_ir(&plan(vec![arg, filtered, grouped], vec![assert]))
}

#[test]
fn comparing_two_different_scalar_types_is_rejected() {
    assert!(matches!(
        validate_predicate(IrPredicate::Compare {
            left: column("arg", "site_id"),
            op: IrCompareOp::Eq,
            right: IrOperand::Column(column("arg", "argument_index")),
        }),
        Err(RelationalAssertionPlanError::ComparisonTypeMismatch { .. })
    ));
}

#[test]
fn an_ordered_comparison_over_an_unordered_scalar_is_rejected() {
    assert!(matches!(
        validate_predicate(IrPredicate::Compare {
            left: column("arg", "site_id"),
            op: IrCompareOp::Gt,
            right: IrOperand::Column(column("arg", "group_id")),
        }),
        Err(RelationalAssertionPlanError::UnorderedComparison { .. })
    ));
}

#[test]
fn a_literal_of_the_wrong_kind_is_rejected() {
    assert!(matches!(
        validate_predicate(IrPredicate::Compare {
            left: column("arg", "argument_index"),
            op: IrCompareOp::Eq,
            right: IrOperand::Literal(RowLiteral::String("zero".to_string())),
        }),
        Err(RelationalAssertionPlanError::PredicateTypeMismatch { .. })
    ));
}

/// A null test over a field the registry always populates is a constant, not a
/// question. The same test over the nullable field is admitted.
#[test]
fn a_null_test_is_admitted_only_over_a_nullable_field() {
    assert_eq!(
        validate_predicate(IrPredicate::IsNull {
            column: column("arg", "site_id"),
            negated: false,
        }),
        Err(RelationalAssertionPlanError::NullTestOnRequiredField {
            field: "arg.site_id".to_string(),
        })
    );
    assert_eq!(
        validate_predicate(IrPredicate::IsNull {
            column: column("arg", "name"),
            negated: false,
        }),
        Ok(())
    );
}

#[test]
fn an_empty_membership_test_is_rejected() {
    assert!(matches!(
        validate_predicate(IrPredicate::InSet {
            column: column("arg", "name"),
            values: Vec::new(),
        }),
        Err(RelationalAssertionPlanError::InvalidSetMembership { .. })
    ));
}

#[test]
fn folds_reject_a_value_column_of_the_wrong_type() {
    let cases = [
        (IrAggregateOp::Max, "name"),
        (IrAggregateOp::Any, "argument_index"),
        (IrAggregateOp::All, "site_id"),
    ];
    for (op, value) in cases {
        let arg = source(0, "arg");
        let grouped = group(
            1,
            "by-site",
            &arg,
            vec![column("arg", "site_id")],
            vec![fold("by-site", "value", op, Some(column("arg", value)))],
        );
        let assert = assertion("value", &grouped, "value", AssertCardinality::AtMost(0));
        assert!(
            matches!(
                validate_plan_ir(&plan(vec![arg, grouped], vec![assert])),
                Err(RelationalAssertionPlanError::InvalidAggregateValueType { .. })
            ),
            "{} over {value}",
            op.label()
        );
    }
}

#[test]
fn a_fold_that_reads_no_column_rejects_one() {
    let arg = source(0, "arg");
    let grouped = group(
        1,
        "by-site",
        &arg,
        vec![column("arg", "site_id")],
        vec![fold(
            "by-site",
            "calls",
            IrAggregateOp::Count,
            Some(column("arg", "argument_index")),
        )],
    );
    let assert = assertion("calls", &grouped, "calls", AssertCardinality::AtMost(0));
    assert!(matches!(
        validate_plan_ir(&plan(vec![arg, grouped], vec![assert])),
        Err(RelationalAssertionPlanError::AggregateValueForbidden { .. })
    ));
}

/// An operator that reads a relation defined after it has no evaluation order,
/// so it is rejected before any row is read.
#[test]
fn a_relation_that_reads_a_later_relation_is_rejected() {
    let arg = source(0, "arg");
    let mut grouped = group(
        1,
        "by-site",
        &arg,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let IrRelationOp::Group { input, .. } = &mut grouped.op else {
        panic!("the relation under test is a group");
    };
    *input = IrRelationId(1);
    let assert = assertion("calls", &grouped, "calls", AssertCardinality::AtMost(0));
    assert_eq!(
        validate_plan_ir(&plan(vec![arg, grouped], vec![assert])),
        Err(RelationalAssertionPlanError::RelationCycle {
            relation: "by-site".to_string(),
        })
    );
}

#[test]
fn a_join_without_equality_keys_is_rejected() {
    let left = source(0, "arg");
    let right = source(1, "other");
    let joined = join(2, &left, &right, IrJoinKind::Inner, Vec::new());
    let grouped = group(
        3,
        "by-site",
        &joined,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let assert = assertion("calls", &grouped, "calls", AssertCardinality::AtMost(0));
    assert!(matches!(
        validate_plan_ir(&plan(vec![left, right, joined, grouped], vec![assert])),
        Err(RelationalAssertionPlanError::EmptyJoin { .. })
    ));
}

#[test]
fn a_zero_bound_is_rejected() {
    let mut plan = counting_plan(AssertCardinality::AtMost(0));
    plan.limits.max_groups = 0;
    assert_eq!(
        validate_plan_ir(&plan),
        Err(RelationalAssertionPlanError::ZeroLimit { name: "max_groups" })
    );
}
