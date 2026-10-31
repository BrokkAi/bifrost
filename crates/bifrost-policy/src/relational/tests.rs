//! Unit coverage for the relational IR: the verdict truth table, the coverage
//! transfer rules, the operators the syntax cannot spell yet, every plan bound,
//! and determinism.
//!
//! The plans here are built as IR directly rather than through the authoring
//! model, because that is the only way to exercise the capabilities milestone 2
//! will make authorable. The lowering path is covered by the seam's own tests in
//! `crate::assertion_policy`.

use std::str::FromStr;

use brokk_bifrost_rql::structural::search::{
    CodeQueryCallShapeArgument, CodeQueryClassSetRow, CodeQueryFlowCarrierSymbol,
    CodeQueryFlowCertainty, CodeQueryFlowEndpoint, CodeQueryFlowEvent, CodeQueryFlowReachability,
    CodeQueryFlowStatus, CodeQueryFlowSymbolSite, CodeQueryResultItem,
    CodeQuerySemanticCompleteness, CodeQuerySemanticEvidence, CodeQuerySemanticProof,
    CodeQuerySourceSite, CodeQueryTaintFinding, CodeQueryTypestateCertainty,
    CodeQueryTypestateFinding, CodeQueryTypestateFindingKind, CodeQueryTypestateSubject,
    DetailedCodeQueryDomain, UnitRowField, UnitRowItem, UnitRowScalar,
};
use brokk_bifrost_rql::structural::{CodeQueryCompletion, CodeQueryRange, CodeQueryResultValue};

use brokk_bifrost_flow::type_flow::ClassSetStatus;

use crate::definition::{AssertCardinality, PolicyAssertId, RowBindingName, RowLiteral};
use crate::finding::PolicyIncompleteReason;

use super::coverage::{RelationCoverage, RelationalInput, RelationalObligationKind};
use super::eval::{RelationalAssertionEvaluation, RelationalViolationRow, evaluate_plan_ir};
use super::ir::{
    IrAggregate, IrAggregateOp, IrAssertion, IrColumn, IrCompareOp, IrEquiKey, IrJoinKind,
    IrLimits, IrOperand, IrPredicate, IrRelation, IrRelationId, IrRelationOp, RelationalPlanIr,
    RowScalar, domain_schema, group_schema, join_schema,
};
use super::validate::{RelationalAssertionPlanError, validate_plan_ir};

fn ten_matching_join_pairs() -> (Vec<UnitRowItem>, Vec<UnitRowItem>) {
    let left = vec![
        argument("site", "arg-0", 0, None, false),
        argument("site", "arg-1", 1, None, false),
    ];
    let right = (0..5)
        .map(|index| argument("site", &format!("other-{index}"), index, None, false))
        .collect();
    (left, right)
}

fn indexed_rows() -> Vec<UnitRowItem> {
    vec![
        argument("site", "arg-0", 0, Some("name"), false),
        argument("site", "arg-1", 1, None, true),
        argument("site", "arg-2", 2, Some("greeting"), false),
    ]
}

fn filtered_count(predicates: Vec<IrPredicate>, rows: &[UnitRowItem]) -> u64 {
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
    let evaluation = evaluate(&plan, &[("arg", rows, RelationCoverage::exhaustive())]);
    evaluation
        .violations
        .first()
        .map(|violation| violation.actual)
        .unwrap_or(0)
}

fn flow_counting_plan(cardinality: AssertCardinality) -> RelationalPlanIr {
    let flow = IrRelation {
        id: IrRelationId(0),
        name: "flow".to_string(),
        op: IrRelationOp::Source {
            binding: binding("flow"),
            schema: domain_schema("flow", DetailedCodeQueryDomain::FlowEndpoint),
        },
        schema: domain_schema("flow", DetailedCodeQueryDomain::FlowEndpoint),
    };
    let grouped = group(
        1,
        "by-plan",
        &flow,
        vec![column("flow", "plan_ref")],
        vec![fold("by-plan", "endpoints", IrAggregateOp::Count, None)],
    );
    let assert = assertion("flow-endpoints", &grouped, "endpoints", cardinality);
    plan(vec![flow, grouped], vec![assert])
}

/// Anti join one call-site relation against the flow endpoints reaching it, and
/// assert that no site is left unmatched. `(at-most 0)` over the anti join is
/// the shape a "no unguarded sink" policy takes.
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
fn argument(site: &str, id: &str, index: usize, name: Option<&str>, spread: bool) -> UnitRowItem {
    UnitRowItem::project(&CodeQueryResultItem {
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
                literal_value: None,
                spread,
            }),
        },
        provenance: Vec::new(),
        provenance_truncated: false,
        row_projection: Vec::new(),
    })
}

fn source(id: usize, name: &str) -> IrRelation {
    IrRelation {
        id: IrRelationId(id),
        name: name.to_string(),
        op: IrRelationOp::Source {
            binding: binding(name),
            schema: domain_schema(name, DOMAIN),
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
        sets: None,
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
    inputs: &[(&str, &[UnitRowItem], RelationCoverage)],
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
    evaluate_plan_ir(plan, &inputs, None).expect("evaluation concludes")
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

fn two_rows_at_one_site() -> Vec<UnitRowItem> {
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
        RelationCoverage::exhaustive(),
        RelationCoverage::proven_subset(),
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

/// A clean upper-bound verdict states that no further row exists, which only an
/// exhaustive relation can support.
#[test]
fn a_clean_upper_bound_needs_exhaustive_coverage() {
    let plan = counting_plan(AssertCardinality::AtMost(2));
    let rows = two_rows_at_one_site();

    let exhaustive = evaluate(&plan, &[("arg", &rows, RelationCoverage::exhaustive())]);
    assert!(exhaustive.violations.is_empty());
    assert!(exhaustive.unmet_obligations.is_empty());

    let subset = evaluate(&plan, &[("arg", &rows, RelationCoverage::proven_subset())]);
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
    let rows: Vec<UnitRowItem> = Vec::new();

    let exhaustive = evaluate(&plan, &[("arg", &rows, RelationCoverage::exhaustive())]);
    assert!(exhaustive.unmet_obligations.is_empty());

    // No group exists at all, so the clean verdict is a claim about rows nobody
    // read.
    let subset = evaluate(&plan, &[("arg", &rows, RelationCoverage::proven_subset())]);
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

        let exhaustive = evaluate(&plan, &[("arg", &rows, RelationCoverage::exhaustive())]);
        assert_eq!(verdicts(&exhaustive), vec![("site".to_string(), 2)]);
        assert!(exhaustive.unmet_obligations.is_empty());

        let subset = evaluate(&plan, &[("arg", &rows, RelationCoverage::proven_subset())]);
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
    let subset = evaluate(&plan, &[("arg", &rows, RelationCoverage::proven_subset())]);
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
    join_plan_with_keys(
        kind,
        cardinality,
        vec![IrEquiKey {
            left: column("arg", "site_id"),
            right: column("other", "site_id"),
        }],
    )
}

fn join_plan_with_keys(
    kind: IrJoinKind,
    cardinality: AssertCardinality,
    on: Vec<IrEquiKey>,
) -> RelationalPlanIr {
    let left = source(0, "arg");
    let right = source(1, "other");
    let joined = join(2, &left, &right, kind, on);
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
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&semi), vec![("site".to_string(), 1)]);

    let inner = evaluate(
        &join_plan(IrJoinKind::Inner, AssertCardinality::AtMost(0)),
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&inner), vec![("site".to_string(), 2)]);
}

/// A left join retains a left row with a null right side when no key matches.
/// The null test also proves that the right schema was widened, including for
/// a field that is required in the source domain.
#[test]
fn a_left_join_keeps_an_unmatched_left_row_with_null_right_fields() {
    let left = source(0, "arg");
    let right = source(1, "other");
    let joined = join(
        2,
        &left,
        &right,
        IrJoinKind::Left,
        vec![IrEquiKey {
            left: column("arg", "site_id"),
            right: column("other", "site_id"),
        }],
    );
    assert!(
        !right
            .schema
            .field(&column("other", "argument_index"))
            .expect("call-argument schema has argument_index")
            .nullable
    );
    assert!(
        joined
            .schema
            .field(&column("other", "argument_index"))
            .expect("left join carries the right schema")
            .nullable
    );
    let filtered = filter(
        3,
        "unmatched",
        &joined,
        vec![IrPredicate::IsNull {
            column: column("other", "argument_index"),
            negated: false,
        }],
    );
    let grouped = group(
        4,
        "by-site",
        &filtered,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let assertion = assertion("left-zero", &grouped, "calls", AssertCardinality::AtMost(0));
    let plan = plan(
        vec![left, right, joined, filtered, grouped],
        vec![assertion],
    );
    let left_rows = vec![argument("site", "arg-0", 0, None, false)];
    let right_rows = vec![argument("elsewhere", "other-0", 0, None, false)];

    let evaluation = evaluate(
        &plan,
        &[
            ("arg", &left_rows, RelationCoverage::exhaustive()),
            ("other", &right_rows, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&evaluation), vec![("site".to_string(), 1)]);
    assert_eq!(
        evaluation.violations[0].representatives,
        vec![vec![RelationalViolationRow {
            binding: binding("arg"),
            row: 0,
        }]]
    );
}

/// A matching left row still expands once per duplicate right row, just like
/// an inner join, while an unmatched row would expand only once.
#[test]
fn a_left_join_retains_each_matching_right_duplicate() {
    let left = vec![argument("site", "arg-0", 0, None, false)];
    let right = vec![
        argument("site", "other-0", 0, None, false),
        argument("site", "other-1", 1, None, false),
    ];
    let evaluation = evaluate(
        &join_plan(IrJoinKind::Left, AssertCardinality::AtMost(0)),
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&evaluation), vec![("site".to_string(), 2)]);
    assert_eq!(evaluation.violations[0].representatives.len(), 2);
}

/// An unmatched left row is only a witness when the right relation was
/// exhaustively searched, because an unseen right row could have matched it.
#[test]
fn an_unmatched_left_join_row_is_witness_unsound_over_a_partial_right_relation() {
    let left = vec![argument("site", "arg-0", 0, None, false)];
    let right = vec![argument("elsewhere", "other-0", 0, None, false)];
    let evaluation = evaluate(
        &join_plan(IrJoinKind::Left, AssertCardinality::AtMost(0)),
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::proven_subset()),
        ],
    );
    assert!(evaluation.violations.is_empty());
    assert_eq!(evaluation.unmet_obligations.len(), 1);
    assert_eq!(
        evaluation.unmet_obligations[0].kind,
        RelationalObligationKind::VerdictRequiresWitnessedRows
    );
    assert_eq!(
        evaluation.unmet_obligations[0].reasons,
        vec![PolicyIncompleteReason::PartialDiscovery]
    );
}

/// A matched pair can still carry an unsound right tuple from an earlier
/// derivation. A left join keeps both that witness reason and its own partial
/// coverage reason when it blocks the resulting verdict.
#[test]
fn a_left_join_retains_right_witness_and_coverage_reasons() {
    let arg = source(0, "arg");
    let other = source(1, "other");
    let blocker = source(2, "blocker");
    let right = join(
        3,
        &other,
        &blocker,
        IrJoinKind::Anti,
        vec![IrEquiKey {
            left: column("other", "site_id"),
            right: column("blocker", "site_id"),
        }],
    );
    let joined = join(
        4,
        &arg,
        &right,
        IrJoinKind::Left,
        vec![IrEquiKey {
            left: column("arg", "site_id"),
            right: column("other", "site_id"),
        }],
    );
    let grouped = group(
        5,
        "by-site",
        &joined,
        vec![column("arg", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let assertion = assertion(
        "left-reasons",
        &grouped,
        "calls",
        AssertCardinality::AtMost(0),
    );
    let plan = plan(
        vec![arg, other, blocker, right, joined, grouped],
        vec![assertion],
    );
    let arg_rows = vec![argument("site", "arg-0", 0, None, false)];
    let other_rows = vec![argument("site", "other-0", 0, None, false)];
    let blocker_rows = vec![argument("elsewhere", "blocker-0", 0, None, false)];

    let evaluation = evaluate(
        &plan,
        &[
            ("arg", &arg_rows, RelationCoverage::exhaustive()),
            ("other", &other_rows, RelationCoverage::proven_subset()),
            (
                "blocker",
                &blocker_rows,
                RelationCoverage::incomplete(vec![PolicyIncompleteReason::Cancelled]),
            ),
        ],
    );
    assert!(evaluation.violations.is_empty());
    assert_eq!(evaluation.unmet_obligations.len(), 1);
    assert_eq!(
        evaluation.unmet_obligations[0].kind,
        RelationalObligationKind::VerdictRequiresWitnessedRows
    );
    assert_eq!(
        evaluation.unmet_obligations[0].reasons,
        vec![
            PolicyIncompleteReason::Cancelled,
            PolicyIncompleteReason::PartialDiscovery,
        ]
    );
}

/// A composite key only joins when every equality component matches; matching
/// the site while differing in argument position is a near miss.
#[test]
fn a_composite_key_rejects_a_partial_match() {
    let left = vec![
        argument("site", "arg-0", 0, None, false),
        argument("site", "arg-1", 1, None, false),
    ];
    let right = vec![
        argument("site", "other-0", 0, None, false),
        argument("site", "other-1", 2, None, false),
    ];
    let evaluation = evaluate(
        &join_plan_with_keys(
            IrJoinKind::Inner,
            AssertCardinality::AtMost(0),
            vec![
                IrEquiKey {
                    left: column("arg", "site_id"),
                    right: column("other", "site_id"),
                },
                IrEquiKey {
                    left: column("arg", "argument_index"),
                    right: column("other", "argument_index"),
                },
            ],
        ),
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&evaluation), vec![("site".to_string(), 1)]);
}

/// `None` is a real equality-key value, just as it was in the nested loop.
#[test]
fn nullable_join_keys_use_option_equality() {
    let left = vec![argument("site", "arg-0", 0, None, false)];
    let right = vec![argument("site", "other-0", 0, None, false)];
    let evaluation = evaluate(
        &join_plan_with_keys(
            IrJoinKind::Inner,
            AssertCardinality::AtMost(0),
            vec![IrEquiKey {
                left: column("arg", "name"),
                right: column("other", "name"),
            }],
        ),
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&evaluation), vec![("site".to_string(), 1)]);
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
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::proven_subset()),
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

/// An inner join is no more covered than its weaker side.
#[test]
fn an_inner_join_meets_both_coverages() {
    let rows = vec![argument("site", "arg-0", 0, None, false)];
    let evaluation = evaluate(
        &join_plan(IrJoinKind::Inner, AssertCardinality::AtMost(1)),
        &[
            ("arg", &rows, RelationCoverage::exhaustive()),
            ("other", &rows, RelationCoverage::proven_subset()),
        ],
    );
    assert!(evaluation.violations.is_empty());
    assert_eq!(
        evaluation.unmet_obligations[0].kind,
        RelationalObligationKind::AbsenceRequiresExhaustiveCoverage,
        "the clean verdict inherits the weaker side's coverage"
    );
}

// ---------------------------------------------------------------------------
// Bounds.
// ---------------------------------------------------------------------------

/// Duplicate matches can produce a Cartesian number of output rows without
/// consuming one comparison budget unit per pair.
#[test]
fn the_probe_budget_allows_a_large_duplicate_cartesian_output() {
    let left = vec![
        argument("site", "arg-0", 0, None, false),
        argument("site", "arg-1", 0, None, false),
    ];
    let right = vec![
        argument("site", "other-0", 0, None, false),
        argument("site", "other-1", 0, None, false),
    ];
    let mut plan = join_plan(IrJoinKind::Inner, AssertCardinality::AtMost(0));
    plan.limits.max_join_comparisons = 2;
    let evaluation = evaluate(
        &plan,
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&evaluation), vec![("site".to_string(), 4)]);
    assert!(!evaluation.limit_exceeded);
    assert!(evaluation.exhaustive);
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
    let evaluation = evaluate(&plan, &[("arg", &rows, RelationCoverage::exhaustive())]);
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
        &[("arg", &ordered, RelationCoverage::exhaustive())],
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
                &[("arg", &shuffled, RelationCoverage::exhaustive())]
            )),
            expected,
            "rotation {rotation}"
        );
    }
}

// ---------------------------------------------------------------------------
// Predicates the syntax cannot spell yet.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Folds the syntax cannot spell yet.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Validation.
// ---------------------------------------------------------------------------

/// Cancel at each checkpoint until execution completes. The work ledger shows
/// which operator was interrupted, without timers or races with another thread.
fn cancellation_witness(
    plan: &RelationalPlanIr,
    inputs: &[RelationalInput<'_>],
    interrupted: impl Fn(&super::eval::RelationalEvaluationWork) -> bool,
) -> usize {
    use brokk_bifrost_analysis::CancellationToken;
    validate_plan_ir(plan).unwrap();
    let mut witnessed = 0;
    for checks in 1..2048 {
        let token = CancellationToken::cancel_after_checks_for_test(checks);
        let result = evaluate_plan_ir(plan, inputs, Some(&token)).unwrap();
        if result.exhaustive {
            assert!(witnessed > 0, "never cancelled during the target operator");
            return witnessed;
        }
        assert!(
            result.violations.is_empty(),
            "cancelled evaluation leaked findings: {result:?}"
        );
        assert!(!result.limit_exceeded);
        assert!(!result.unmet_obligations.is_empty());
        assert!(
            result
                .unmet_obligations
                .iter()
                .all(|o| o.reasons == vec![PolicyIncompleteReason::Cancelled])
        );
        witnessed += usize::from(interrupted(&result.work));
    }
    panic!("bounded fixture never completed");
}

#[test]
fn cancellation_during_source_discards_partial_rows() {
    let plan = counting_plan(AssertCardinality::Exactly(0));
    let rows = two_rows_at_one_site();
    let name = binding("arg");
    let inputs = [RelationalInput {
        binding: &name,
        rows: &rows,
        coverage: RelationCoverage::exhaustive(),
    }];
    cancellation_witness(&plan, &inputs, |work| {
        work.input_rows == 1 && work.materialized_rows == 0
    });
}

#[test]
fn cancellation_during_filter_discards_partial_rows() {
    let arg = source(0, "arg");
    let filtered = filter(
        1,
        "filtered",
        &arg,
        vec![IrPredicate::Compare {
            left: column("arg", "spread"),
            op: IrCompareOp::Eq,
            right: IrOperand::Literal(RowLiteral::Boolean(false)),
        }],
    );
    let grouped = group(
        2,
        "site",
        &filtered,
        vec![column("arg", "site_id")],
        vec![fold("site", "count", IrAggregateOp::Count, None)],
    );
    let assertion = assertion("empty", &grouped, "count", AssertCardinality::Exactly(0));
    let plan = plan(vec![arg, filtered, grouped], vec![assertion]);
    let rows = two_rows_at_one_site();
    let name = binding("arg");
    let inputs = [RelationalInput {
        binding: &name,
        rows: &rows,
        coverage: RelationCoverage::exhaustive(),
    }];
    let checkpoints = cancellation_witness(&plan, &inputs, |work| {
        work.input_rows == 2 && work.materialized_rows == 2
    });
    assert!(checkpoints >= 3, "filter must check within the row loop");
}

#[test]
fn cancellation_during_join_discards_partial_matches() {
    let left = source(0, "left");
    let right = source(1, "right");
    let joined = join(
        2,
        &left,
        &right,
        IrJoinKind::Inner,
        vec![IrEquiKey {
            left: column("left", "site_id"),
            right: column("right", "site_id"),
        }],
    );
    let grouped = group(
        3,
        "site",
        &joined,
        vec![column("left", "site_id")],
        vec![fold("site", "count", IrAggregateOp::Count, None)],
    );
    let assertion = assertion("empty", &grouped, "count", AssertCardinality::Exactly(0));
    let plan = plan(vec![left, right, joined, grouped], vec![assertion]);
    let rows = two_rows_at_one_site();
    let left = binding("left");
    let right = binding("right");
    let inputs = [
        RelationalInput {
            binding: &left,
            rows: &rows,
            coverage: RelationCoverage::exhaustive(),
        },
        RelationalInput {
            binding: &right,
            rows: &rows,
            coverage: RelationCoverage::exhaustive(),
        },
    ];
    let checkpoints = cancellation_witness(&plan, &inputs, |work| {
        work.join_key_probes == 1 && work.materialized_rows == 4
    });
    assert!(
        checkpoints >= 3,
        "join must check while emitting one key's matches"
    );
}

#[test]
fn cancellation_during_group_discards_partial_groups() {
    let plan = counting_plan(AssertCardinality::Exactly(0));
    let rows = two_rows_at_one_site();
    let name = binding("arg");
    let inputs = [RelationalInput {
        binding: &name,
        rows: &rows,
        coverage: RelationCoverage::exhaustive(),
    }];
    cancellation_witness(&plan, &inputs, |work| {
        work.produced_groups == 1 && work.materialized_rows == 2
    });
}

#[test]
fn cancellation_during_assertion_discards_already_computed_violations() {
    let plan = counting_plan(AssertCardinality::Exactly(0));
    let rows = vec![
        argument("first", "a", 0, None, false),
        argument("second", "b", 0, None, false),
    ];
    let name = binding("arg");
    let inputs = [RelationalInput {
        binding: &name,
        rows: &rows,
        coverage: RelationCoverage::exhaustive(),
    }];
    cancellation_witness(&plan, &inputs, |work| work.assertion_checks == 1);
}

/// Certainty must come from all contributing rows, not the bounded source
/// locations retained for display. Coverage limits remain independent.
#[test]
fn may_evidence_survives_grouping_beyond_retained_representatives() {
    let mut rows = two_rows_at_one_site();
    rows[1].fields.push(UnitRowField {
        name: "certainty".into(),
        value: UnitRowScalar::ConstrainedEnum("possible".into()),
    });
    rows[1].fields.push(UnitRowField {
        name: "reason".into(),
        value: UnitRowScalar::String("An explicitly modeled alternative".into()),
    });
    let mut plan = counting_plan(AssertCardinality::AtMost(0));
    plan.limits.max_representative_tuples = 1;
    let result = evaluate(&plan, &[("arg", &rows, RelationCoverage::exhaustive())]);
    assert_eq!(result.violations.len(), 1);
    assert_eq!(result.violations[0].representatives.len(), 1);
    assert_eq!(
        result.violations[0].certainty,
        crate::finding::FindingCertainty::possible(vec![
            crate::finding::CertaintyReason::MayEvidence {
                reason: "An explicitly modeled alternative".to_string(),
            }
        ])
        .unwrap()
    );
    assert!(result.exhaustive);

    plan.limits.max_values_per_group = 1;
    let truncated = evaluate(&plan, &[("arg", &rows, RelationCoverage::exhaustive())]);
    assert!(truncated.violations.is_empty());
    assert!(!truncated.unmet_obligations.is_empty());
    assert!(!truncated.exhaustive);
}

// ---------------------------------------------------------------------------
// Flow, taint, typestate and type-flow rows in the coverage envelope (#3205).
//
// These families run a solver, and the solver's outcome is a statement about
// the partition it enumerated, not about the row set the query returned. A
// query can therefore complete cleanly over rows whose solve abstained, ran out
// of budget, or retained only part of a finding's evidence. Before #3205 the
// envelope was derived from `CodeQueryCompletion` alone, so exactly those runs
// read as exhaustive and an absence verdict over them passed clean.
// ---------------------------------------------------------------------------

fn range() -> CodeQueryRange {
    CodeQueryRange {
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 2,
    }
}

fn flow_symbol_site(id: &str) -> CodeQueryFlowSymbolSite {
    CodeQueryFlowSymbolSite {
        id: id.to_string(),
        path: "app.py".to_string(),
        language: "python",
        declaration: Vec::new(),
        role: "value",
        start_byte: 0,
        end_byte: 1,
        occurrence: 0,
        range: range(),
    }
}

fn flow_event(id: &str, phase: &'static str) -> CodeQueryFlowEvent {
    CodeQueryFlowEvent {
        id: id.to_string(),
        site: flow_symbol_site(id),
        path: "app.py".to_string(),
        range: range(),
        phase,
        ordinal: 0,
        carrier: CodeQueryFlowCarrierSymbol::Value {
            id: format!("{id}-carrier"),
            site: flow_symbol_site(id),
            role: "value".to_string(),
            ordinal: None,
        },
    }
}

/// One value-flow endpoint row exactly as the projector publishes it, so the
/// coverage under test is derived from the real row, not from a hand-written
/// envelope.
fn flow_endpoint(id: &str, plan_ref: &str, status: CodeQueryFlowStatus) -> UnitRowItem {
    UnitRowItem::project(&CodeQueryResultItem {
        value: CodeQueryResultValue::FlowEndpoint {
            value: Box::new(CodeQueryFlowEndpoint {
                id: id.to_string(),
                plan_ref: plan_ref.to_string(),
                source: Some(flow_event(&format!("{id}-source"), "source")),
                sink: flow_event(&format!("{id}-sink"), "sink"),
                reachability: CodeQueryFlowReachability::Reached,
                certainty: Some(CodeQueryFlowCertainty::Exact),
                ambiguous: false,
                status,
                reason: None,
                path: "app.py".to_string(),
                language: "python",
                range: range(),
                path_qualities: Vec::new(),
                retained_witnesses: 0,
                omitted_witnesses: 0,
            }),
        },
        provenance: Vec::new(),
        provenance_truncated: false,
        row_projection: Vec::new(),
    })
}

fn typestate_finding(
    id: &str,
    protocol_ref: &str,
    analysis_complete: bool,
    abstained: bool,
) -> UnitRowItem {
    UnitRowItem::project(&CodeQueryResultItem {
        value: CodeQueryResultValue::TypestateFinding {
            value: Box::new(CodeQueryTypestateFinding {
                id: id.to_string(),
                protocol_ref: protocol_ref.to_string(),
                protocol_hash: "protocol-hash".to_string(),
                binding_plan_hash: "binding-hash".to_string(),
                subject: CodeQueryTypestateSubject {
                    class: "Resource".to_string(),
                    identity: "app.Resource".to_string(),
                },
                finding_kind: CodeQueryTypestateFindingKind::TerminalExpectation {
                    expectation: "closed".to_string(),
                    actual_states: vec!["open".to_string()],
                },
                certainty: CodeQueryTypestateCertainty::May,
                path: "app.py".to_string(),
                language: "python",
                range: range(),
                path_proven: true,
                path_complete: true,
                analysis_complete,
                uncertainty: Vec::new(),
                abstained,
                retained_witnesses: 0,
                omitted_witnesses: 0,
            }),
        },
        provenance: Vec::new(),
        provenance_truncated: false,
        row_projection: Vec::new(),
    })
}

fn taint_finding(id: &str, sink_event_id: &str, origins_truncated: bool) -> UnitRowItem {
    let complete = !origins_truncated;
    UnitRowItem::project(&CodeQueryResultItem {
        value: CodeQueryResultValue::TaintFinding {
            value: Box::new(CodeQueryTaintFinding {
                id: id.to_string(),
                path: "app.py".to_string(),
                language: "python",
                range: range(),
                sink_event_id: sink_event_id.to_string(),
                sink: CodeQuerySourceSite {
                    path: "app.py".to_string(),
                    range: range(),
                },
                reached_labels: vec!["tainted".to_string()],
                origins: Vec::new(),
                origins_truncated,
                witnesses: Vec::new(),
                witnesses_truncated: false,
                evidence: CodeQuerySemanticEvidence::new(
                    CodeQuerySemanticProof::Proven,
                    if complete {
                        CodeQuerySemanticCompleteness::Complete
                    } else {
                        CodeQuerySemanticCompleteness::Partial
                    },
                    None,
                ),
                ambiguous: false,
            }),
        },
        provenance: Vec::new(),
        provenance_truncated: false,
        row_projection: Vec::new(),
    })
}

fn class_set_row(id: &str, status: ClassSetStatus) -> UnitRowItem {
    UnitRowItem::project(&CodeQueryResultItem {
        value: CodeQueryResultValue::ClassSetRow {
            value: Box::new(CodeQueryClassSetRow {
                id: id.to_string(),
                file: "app.py".to_string(),
                range: range(),
                member: "close".to_string(),
                class: Some("app.Resource".to_string()),
                origin: "workspace".to_string(),
                status: status.label(),
                guard_only: Some(false),
            }),
        },
        provenance: Vec::new(),
        provenance_truncated: false,
        row_projection: Vec::new(),
    })
}

/// The envelope the relational seam builds for one executed binding, with the
/// query envelope a clean run hands it.
fn envelope_of_complete_query(rows: &[UnitRowItem]) -> RelationCoverage {
    RelationCoverage::from_query(rows, &CodeQueryCompletion::Complete, false)
}

/// The regression. A value-flow binding whose solve stopped against the solver
/// budget publishes rows the query returned in full; the envelope must still
/// refuse to call the relation exhaustive, and must name the plan it is about.
#[test]
fn a_flow_solve_that_stopped_against_a_budget_is_not_an_exhaustive_relation() {
    let rows = vec![
        flow_endpoint("endpoint-0", "plan-a", CodeQueryFlowStatus::Complete),
        flow_endpoint(
            "endpoint-1",
            "plan-b",
            CodeQueryFlowStatus::SolverBudgetExhausted,
        ),
    ];
    let coverage = envelope_of_complete_query(&rows);
    assert!(
        !coverage.is_exhaustive(),
        "a complete query over an unfinished solve is not an exhaustive relation"
    );
    assert_eq!(
        coverage.incomplete_reasons(),
        vec![PolicyIncompleteReason::PartialDiscovery]
    );
    let named = coverage
        .partition()
        .roots()
        .iter()
        .map(|root| (root.family.label(), root.root.as_ref()))
        .collect::<Vec<_>>();
    assert_eq!(
        named,
        vec![("flow_endpoint", "plan-b")],
        "the envelope names the plan whose solve did not finish, not the one that did"
    );
}

/// Every other flow status that is not `complete` is a frontier, a limit or a
/// stop, and none of them establishes the endpoint set.
#[test]
fn only_a_complete_flow_status_establishes_the_endpoint_set() {
    for status in [
        CodeQueryFlowStatus::Partial,
        CodeQueryFlowStatus::Ambiguous,
        CodeQueryFlowStatus::Unknown,
        CodeQueryFlowStatus::Unproven,
        CodeQueryFlowStatus::Unsupported,
        CodeQueryFlowStatus::SemanticBudgetExhausted,
        CodeQueryFlowStatus::SolverBudgetExhausted,
        CodeQueryFlowStatus::SemanticCancelled,
        CodeQueryFlowStatus::SolverCancelled,
        CodeQueryFlowStatus::QueryCancelled,
    ] {
        let rows = vec![flow_endpoint("endpoint", "plan-a", status)];
        assert!(
            !envelope_of_complete_query(&rows).is_exhaustive(),
            "{}",
            status.label()
        );
    }
    let complete = vec![flow_endpoint(
        "endpoint",
        "plan-a",
        CodeQueryFlowStatus::Complete,
    )];
    assert!(
        envelope_of_complete_query(&complete).is_exhaustive(),
        "a finished solve over a complete query is exhaustive"
    );
}

/// The typestate report's completeness and a finding's own abstention are both
/// per-partition facts that a clean query envelope does not carry.
#[test]
fn an_abstained_or_incomplete_typestate_finding_is_not_an_exhaustive_relation() {
    let complete = vec![typestate_finding("finding", "protocol-a", true, false)];
    assert!(envelope_of_complete_query(&complete).is_exhaustive());

    for (analysis_complete, abstained) in [(false, false), (true, true), (false, true)] {
        let rows = vec![typestate_finding(
            "finding",
            "protocol-a",
            analysis_complete,
            abstained,
        )];
        let coverage = envelope_of_complete_query(&rows);
        assert!(
            !coverage.is_exhaustive(),
            "analysis_complete={analysis_complete} abstained={abstained}"
        );
        assert_eq!(
            coverage
                .partition()
                .roots()
                .iter()
                .map(|root| (root.family.label(), root.root.as_ref()))
                .collect::<Vec<_>>(),
            vec![("typestate_finding", "protocol-a")]
        );
    }
}

/// A taint finding's retained origins are bounded per finding, so a projection
/// that dropped some of them leaves the query envelope complete while this
/// sink's evidence set is not.
#[test]
fn a_taint_finding_with_truncated_origins_is_not_an_exhaustive_relation() {
    let complete = vec![taint_finding("finding", "sink-a", false)];
    assert!(envelope_of_complete_query(&complete).is_exhaustive());

    let truncated = vec![taint_finding("finding", "sink-a", true)];
    let coverage = envelope_of_complete_query(&truncated);
    assert!(!coverage.is_exhaustive());
    assert_eq!(
        coverage
            .partition()
            .roots()
            .iter()
            .map(|root| (root.family.label(), root.root.as_ref()))
            .collect::<Vec<_>>(),
        vec![("taint_finding", "sink-a")]
    );
}

/// A class set that is anything but fully known is missing atoms, so the member
/// access it describes cannot support an absence claim.
#[test]
fn only_a_known_class_set_establishes_the_receiver_atoms() {
    let known = vec![class_set_row("row", ClassSetStatus::Known)];
    assert!(envelope_of_complete_query(&known).is_exhaustive());

    for status in [
        ClassSetStatus::Partial,
        ClassSetStatus::NoInformation,
        ClassSetStatus::Inconclusive,
    ] {
        let rows = vec![class_set_row("row", status)];
        assert!(
            !envelope_of_complete_query(&rows).is_exhaustive(),
            "{}",
            status.label()
        );
    }
}

/// Anti join one call-site relation against the flow endpoints reaching it, and
/// assert that no site is left unmatched. `(at-most 0)` over the anti join is
/// the shape a "no unguarded sink" policy takes.
fn flow_anti_join_plan() -> RelationalPlanIr {
    let sites = IrRelation {
        id: IrRelationId(0),
        name: "sites".to_string(),
        op: IrRelationOp::Source {
            binding: binding("sites"),
            schema: domain_schema("sites", DOMAIN),
        },
        schema: domain_schema("sites", DOMAIN),
    };
    let flow = IrRelation {
        id: IrRelationId(1),
        name: "flow".to_string(),
        op: IrRelationOp::Source {
            binding: binding("flow"),
            schema: domain_schema("flow", DetailedCodeQueryDomain::FlowEndpoint),
        },
        schema: domain_schema("flow", DetailedCodeQueryDomain::FlowEndpoint),
    };
    let joined = join(
        2,
        &sites,
        &flow,
        IrJoinKind::Anti,
        vec![IrEquiKey {
            left: column("sites", "id"),
            right: column("flow", "id"),
        }],
    );
    let grouped = group(
        3,
        "by-site",
        &joined,
        vec![column("sites", "site_id")],
        vec![fold("by-site", "unmatched", IrAggregateOp::Count, None)],
    );
    let assert = assertion(
        "no-unmatched-site",
        &grouped,
        "unmatched",
        AssertCardinality::AtMost(0),
    );
    plan(vec![sites, flow, joined, grouped], vec![assert])
}

/// An anti join is a claim about the right relation's absent rows, so an
/// unfinished flow solve on that side blocks the verdict -- and the obligation
/// names the flow partition, not the exhaustive left side it was joined from.
#[test]
fn an_anti_join_over_an_unfinished_flow_solve_names_the_flow_partition() {
    let plan = flow_anti_join_plan();
    let sites = vec![argument("site", "arg-0", 0, Some("name"), false)];

    let complete = vec![flow_endpoint(
        "other-endpoint",
        "plan-a",
        CodeQueryFlowStatus::Complete,
    )];
    let clean = evaluate(
        &plan,
        &[
            ("sites", &sites, RelationCoverage::exhaustive()),
            ("flow", &complete, envelope_of_complete_query(&complete)),
        ],
    );
    assert_eq!(
        verdicts(&clean),
        vec![("site".to_string(), 1)],
        "a finished solve establishes the unmatched row, which is the violation"
    );
    assert!(clean.unmet_obligations.is_empty());

    let stopped = vec![flow_endpoint(
        "other-endpoint",
        "plan-a",
        CodeQueryFlowStatus::SolverBudgetExhausted,
    )];
    let blocked = evaluate(
        &plan,
        &[
            ("sites", &sites, RelationCoverage::exhaustive()),
            ("flow", &stopped, envelope_of_complete_query(&stopped)),
        ],
    );
    assert!(
        blocked.violations.is_empty(),
        "an unmatched row over an unfinished right relation is not a witness"
    );
    let obligation = blocked
        .unmet_obligations
        .first()
        .expect("the blocked verdict is reported as an obligation");
    assert_eq!(
        obligation.kind,
        RelationalObligationKind::VerdictRequiresWitnessedRows
    );
    assert_eq!(
        obligation
            .partition
            .roots()
            .iter()
            .map(|root| (root.family.label(), root.root.as_ref()))
            .collect::<Vec<_>>(),
        vec![("flow_endpoint", "plan-a")],
        "the anti join names the right relation's solve, not the left relation's scope"
    );
}

#[test]
fn an_inner_join_preserves_duplicate_order_and_contributors() {
    let left = vec![
        argument("site", "arg-0", 0, None, false),
        argument("site", "arg-1", 0, None, false),
    ];
    let right = vec![
        argument("site", "other-0", 0, None, false),
        argument("site", "other-1", 0, None, false),
    ];
    let evaluation = evaluate(
        &join_plan(IrJoinKind::Inner, AssertCardinality::AtMost(0)),
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&evaluation), vec![("site".to_string(), 4)]);
    assert_eq!(
        evaluation.violations[0].representatives,
        vec![
            vec![
                RelationalViolationRow {
                    binding: binding("arg"),
                    row: 0,
                },
                RelationalViolationRow {
                    binding: binding("other"),
                    row: 0,
                },
            ],
            vec![
                RelationalViolationRow {
                    binding: binding("arg"),
                    row: 0,
                },
                RelationalViolationRow {
                    binding: binding("other"),
                    row: 1,
                },
            ],
            vec![
                RelationalViolationRow {
                    binding: binding("arg"),
                    row: 1,
                },
                RelationalViolationRow {
                    binding: binding("other"),
                    row: 0,
                },
            ],
            vec![
                RelationalViolationRow {
                    binding: binding("arg"),
                    row: 1,
                },
                RelationalViolationRow {
                    binding: binding("other"),
                    row: 1,
                },
            ],
        ]
    );
}

#[test]
fn the_source_bound_truncates_and_degrades_coverage() {
    let mut plan = counting_plan(AssertCardinality::AtMost(2));
    plan.limits.max_source_rows = 1;
    let rows = two_rows_at_one_site();
    let evaluation = evaluate(&plan, &[("arg", &rows, RelationCoverage::exhaustive())]);
    assert!(evaluation.limit_exceeded);
    assert!(!evaluation.exhaustive);
    assert_eq!(
        evaluation.unmet_obligations[0].reasons,
        vec![PolicyIncompleteReason::PipelineRowBudget]
    );
}

#[test]
fn too_many_left_probes_still_truncate_the_join() {
    let left = vec![
        argument("site-a", "arg-0", 0, None, false),
        argument("site-b", "arg-1", 0, None, false),
        argument("site-c", "arg-2", 0, None, false),
    ];
    let right = Vec::new();
    let mut plan = join_plan(IrJoinKind::Semi, AssertCardinality::AtMost(0));
    plan.limits.max_join_comparisons = 2;
    let evaluation = evaluate(
        &plan,
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert!(evaluation.limit_exceeded);
    assert!(!evaluation.exhaustive);
}

#[test]
fn representative_tuple_retention_defaults_to_eight() {
    assert_eq!(IrLimits::default().max_representative_tuples, 8);
    let (left, right) = ten_matching_join_pairs();
    let evaluation = evaluate(
        &join_plan(IrJoinKind::Inner, AssertCardinality::AtMost(0)),
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&evaluation), vec![("site".to_string(), 10)]);
    assert_eq!(evaluation.violations[0].representatives.len(), 8);
}

#[test]
fn representative_tuple_retention_accepts_a_bound_above_eight() {
    let (left, right) = ten_matching_join_pairs();
    let mut plan = join_plan(IrJoinKind::Inner, AssertCardinality::AtMost(0));
    plan.limits.max_representative_tuples = 12;
    let evaluation = evaluate(
        &plan,
        &[
            ("arg", &left, RelationCoverage::exhaustive()),
            ("other", &right, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(verdicts(&evaluation), vec![("site".to_string(), 10)]);
    assert_eq!(evaluation.violations[0].representatives.len(), 10);
}

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
fn cancellation_without_assertions_still_reports_cancelled() {
    let mut plan = counting_plan(AssertCardinality::Exactly(0));
    plan.assertions.clear();
    let token = brokk_bifrost_analysis::CancellationToken::new();
    token.cancel();
    let result = evaluate_plan_ir(&plan, &[], Some(&token)).unwrap();
    assert!(!result.exhaustive);
    assert!(result.violations.is_empty());
    assert_eq!(
        result.incomplete_reasons,
        vec![PolicyIncompleteReason::Cancelled]
    );
}

#[test]
fn an_unsupported_flow_capability_dominates_the_relation_envelope() {
    let rows = vec![
        flow_endpoint("endpoint-0", "plan-a", CodeQueryFlowStatus::Complete),
        flow_endpoint("endpoint-1", "plan-b", CodeQueryFlowStatus::Unsupported),
    ];
    let coverage = envelope_of_complete_query(&rows);
    assert_eq!(
        coverage.incomplete_reasons(),
        vec![PolicyIncompleteReason::CapabilityIncomplete]
    );
    assert!(matches!(
        coverage.extent(),
        super::coverage::CoverageExtent::Unsupported { .. }
    ));
}

#[test]
fn the_flow_backed_truth_table_matches_the_row_set_table() {
    let plan_exceeded = flow_counting_plan(AssertCardinality::AtMost(1));
    let plan_clean = flow_counting_plan(AssertCardinality::AtMost(5));
    for status in [
        CodeQueryFlowStatus::Complete,
        CodeQueryFlowStatus::SolverBudgetExhausted,
    ] {
        let rows = vec![
            flow_endpoint("endpoint-0", "plan-a", status),
            flow_endpoint("endpoint-1", "plan-a", status),
        ];
        let coverage = envelope_of_complete_query(&rows);

        let exceeded = evaluate(&plan_exceeded, &[("flow", &rows, coverage.clone())]);
        assert_eq!(
            verdicts(&exceeded),
            vec![("plan-a".to_string(), 2)],
            "{}",
            status.label()
        );
        assert!(exceeded.unmet_obligations.is_empty(), "{}", status.label());

        let clean = evaluate(&plan_clean, &[("flow", &rows, coverage)]);
        assert!(clean.violations.is_empty(), "{}", status.label());
        match status {
            CodeQueryFlowStatus::Complete => {
                assert!(clean.unmet_obligations.is_empty(), "{}", status.label());
                assert!(clean.exhaustive);
            }
            _ => {
                let obligation = clean
                    .unmet_obligations
                    .first()
                    .expect("an unenumerated partition blocks the clean upper bound");
                assert_eq!(
                    obligation.kind,
                    RelationalObligationKind::AbsenceRequiresExhaustiveCoverage
                );
                assert_eq!(
                    obligation
                        .partition
                        .roots()
                        .iter()
                        .map(|root| (root.family.label(), root.root.as_ref()))
                        .collect::<Vec<_>>(),
                    vec![("flow_endpoint", "plan-a")],
                    "the blocked verdict names the flow partition that blocked it"
                );
                assert!(!clean.exhaustive);
            }
        }
    }
}

#[test]
fn a_persisted_row_replays_the_coverage_the_live_row_published() {
    let rows = vec![
        flow_endpoint("endpoint-0", "plan-a", CodeQueryFlowStatus::Complete),
        flow_endpoint(
            "endpoint-1",
            "plan-b",
            CodeQueryFlowStatus::SolverBudgetExhausted,
        ),
        typestate_finding("finding", "protocol-a", true, true),
        taint_finding("taint", "sink-a", true),
        class_set_row("class-set", ClassSetStatus::Partial),
    ];
    let encoded = serde_json::to_string(&rows).expect("a unit product serializes");
    let replayed: Vec<UnitRowItem> =
        serde_json::from_str(&encoded).expect("a published unit product is readable");
    assert_eq!(
        replayed
            .iter()
            .map(|row| row.coverage.clone())
            .collect::<Vec<_>>(),
        rows.iter()
            .map(|row| row.coverage.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        envelope_of_complete_query(&replayed),
        envelope_of_complete_query(&rows)
    );
}

#[test]
fn unavailable_conversion_inputs_survive_join_without_a_definite_assertion() {
    use brokk_bifrost_analysis::analyzer::usages::call_conversion::ConversionUnknown;
    use brokk_bifrost_rql::structural::search::{
        CodeQueryRowFieldUnknownReason, UnitRowUnknownField,
    };

    let source = |id, name: &str| {
        let schema = domain_schema(name, DetailedCodeQueryDomain::CallBinding);
        IrRelation {
            id: IrRelationId(id),
            name: name.into(),
            op: IrRelationOp::Source {
                binding: binding(name),
                schema: schema.clone(),
            },
            schema,
        }
    };
    let left = source(0, "left");
    let right = source(1, "right");
    let joined = join(
        2,
        &left,
        &right,
        IrJoinKind::Inner,
        vec![IrEquiKey {
            left: column("left", "conversion"),
            right: column("right", "conversion"),
        }],
    );
    let grouped = group(
        3,
        "by-site",
        &joined,
        vec![column("left", "site_id")],
        vec![fold("by-site", "calls", IrAggregateOp::Count, None)],
    );
    let assertion = assertion("unknown", &grouped, "calls", AssertCardinality::Exactly(1));
    let plan = plan(vec![left, right, joined, grouped], vec![assertion]);
    let rows = (0..2)
        .map(|index| UnitRowItem {
            domain: DetailedCodeQueryDomain::CallBinding,
            path: "app.cs".into(),
            range: None,
            evidence: None,
            coverage: None,
            fields: vec![UnitRowField {
                name: "site_id".into(),
                value: UnitRowScalar::StableId(format!("site-{index}").into()),
            }],
            projected_field_names: vec![],
            unknown_fields: vec![UnitRowUnknownField {
                name: "conversion".into(),
                reason: CodeQueryRowFieldUnknownReason::CallConversion(
                    ConversionUnknown::UnresolvedSourceType,
                ),
            }],
            terminal: None,
            provenance: vec![],
            provenance_truncated: false,
        })
        .collect::<Vec<_>>();
    let result = evaluate(
        &plan,
        &[
            ("left", &rows, RelationCoverage::exhaustive()),
            ("right", &rows, RelationCoverage::exhaustive()),
        ],
    );
    assert_eq!(result.work.input_rows, 4, "{result:?}");
    assert!(!result.exhaustive, "{result:?}");
    assert!(result.violations.is_empty(), "{result:?}");
    assert!(result.vacuous_assertions.is_empty(), "{result:?}");
    assert!(!result.unmet_obligations.is_empty(), "{result:?}");
    assert_eq!(
        result.incomplete_reasons,
        vec![PolicyIncompleteReason::CapabilityIncomplete],
        "{result:?}"
    );
}
