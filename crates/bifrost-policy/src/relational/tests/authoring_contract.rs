//! Public validation diagnostics and the inclusive membership limit.
use super::*;

fn predicate_plan(predicates: Vec<IrPredicate>) -> RelationalPlanIr {
    let input = source(0, "arg");
    let selected = filter(1, "selected", &input, predicates);
    plan(vec![input, selected], vec![])
}

#[test]
fn unknown_columns_report_only_the_addressed_binding_fields() {
    let left = source(0, "arg");
    let mut right = source(1, "other");
    let other_schema = domain_schema("other", DetailedCodeQueryDomain::Occurrence);
    right.schema = other_schema.clone();
    right.op = IrRelationOp::Source {
        binding: binding("other"),
        schema: other_schema,
    };
    let joined = join(
        2,
        &left,
        &right,
        IrJoinKind::Inner,
        vec![IrEquiKey {
            left: column("arg", "site_id"),
            right: column("other", "ast_id"),
        }],
    );
    let selected = filter(
        3,
        "selected",
        &joined,
        vec![IrPredicate::IsNull {
            column: column("arg", "misspelled"),
            negated: false,
        }],
    );
    let error = validate_plan_ir(&plan(vec![left, right, joined, selected], vec![])).unwrap_err();
    assert_eq!(
        error,
        RelationalAssertionPlanError::UnknownField {
            binding: "arg".into(),
            field: "misspelled".into(),
            known_fields: vec![
                "id",
                "group_id",
                "site_id",
                "argument_index",
                "name",
                "literal_value",
                "spread"
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        }
    );
}

#[test]
fn group_limit_must_be_positive() {
    let mut limits = IrLimits {
        max_groups: 0,
        ..IrLimits::default()
    };
    assert_eq!(
        super::super::validate_limits(&limits),
        Err(RelationalAssertionPlanError::ZeroLimit { name: "max_groups" })
    );
    limits.max_groups = 1;
    assert!(super::super::validate_limits(&limits).is_ok());
}

#[test]
fn first_aggregate_predicate_is_type_checked() {
    let input = source(0, "arg");
    let mut aggregate = fold("counts", "n", IrAggregateOp::Count, None);
    aggregate.predicates.push(IrPredicate::Compare {
        left: column("arg", "argument_index"),
        op: IrCompareOp::Eq,
        right: IrOperand::Literal(RowLiteral::String("not an integer".into())),
    });
    let grouped = group(
        1,
        "counts",
        &input,
        vec![column("arg", "site_id")],
        vec![aggregate],
    );
    assert!(matches!(
        validate_plan_ir(&plan(vec![input, grouped], vec![])),
        Err(RelationalAssertionPlanError::PredicateTypeMismatch { .. })
    ));
}

#[test]
fn membership_admits_the_limit_and_rejects_one_more() {
    // MAX_IR_SET_MEMBERS is the public inclusive bound (64).
    for size in [63, 64, 65] {
        let predicate = IrPredicate::InSet {
            column: column("arg", "argument_index"),
            values: (0..size).map(RowLiteral::Integer).collect(),
        };
        let candidate = predicate_plan(vec![predicate.clone()]);
        if size == 65 {
            assert!(matches!(
                validate_plan_ir(&candidate),
                Err(RelationalAssertionPlanError::InvalidSetMembership {
                    count: 65,
                    max: 64,
                    ..
                })
            ));
        } else {
            validate_plan_ir(&candidate).unwrap();
            let rows = vec![argument("site", "last", (size - 1) as usize, None, false)];
            assert_eq!(filtered_count(vec![predicate], &rows), 1);
        }
    }
}

#[test]
fn illegal_enum_label_reports_the_authored_value() {
    let schema = domain_schema("occ", DetailedCodeQueryDomain::Occurrence);
    let input = IrRelation {
        id: IrRelationId(0),
        name: "occ".into(),
        op: IrRelationOp::Source {
            binding: binding("occ"),
            schema: schema.clone(),
        },
        schema,
    };
    let selected = filter(
        1,
        "selected",
        &input,
        vec![IrPredicate::Compare {
            left: column("occ", "role"),
            op: IrCompareOp::Eq,
            right: IrOperand::Literal(RowLiteral::ConstrainedEnum("misspelled-role".into())),
        }],
    );
    let error = validate_plan_ir(&plan(vec![input, selected], vec![])).unwrap_err();
    match error {
        RelationalAssertionPlanError::UnknownEnumLabel {
            field,
            label,
            legal,
        } => {
            assert_eq!(field, "occ.role");
            assert_eq!(label, "misspelled-role");
            assert!(legal.contains(&"member_position"));
        }
        other => panic!("unexpected authoring diagnostic: {other}"),
    }
}

#[test]
fn catalog_publishes_vocabulary_cross_domain_steps_and_label_order() {
    let catalog = crate::relational::relation_schema_catalog();
    assert!(
        catalog
            .domains
            .iter()
            .any(|domain| domain.domain == "structural_match")
    );
    let occurrence = catalog
        .domains
        .iter()
        .find(|domain| domain.domain == "occurrence")
        .unwrap();
    let role = occurrence
        .fields
        .iter()
        .find(|field| field.name == "role")
        .unwrap();
    assert!(role.values.unwrap().contains(&"member_position"));
    let mut cross_domain = false;
    for domain in &catalog.domains {
        assert!(
            domain
                .expansions
                .windows(2)
                .all(|pair| pair[0].step < pair[1].step)
        );
        for expansion in &domain.expansions {
            if expansion.step == "receiver_outcome" {
                assert_eq!(expansion.result_domain, "receiver_outcome");
                cross_domain = true;
            }
        }
    }
    assert!(
        cross_domain,
        "catalog must advertise receiver-outcome expansion"
    );
}

#[test]
fn ordered_sequence_checks_the_right_position_type() {
    use crate::relational::{IrOrderedSequence, IrOrderedSequencePair};
    let input = source(0, "arg");
    let mut aggregate = fold("ordered", "equal", IrAggregateOp::OrderedEqual, None);
    aggregate.sequences = Some(IrOrderedSequencePair {
        left: IrOrderedSequence {
            value: column("arg", "id"),
            position: column("arg", "argument_index"),
        },
        right: IrOrderedSequence {
            value: column("arg", "id"),
            position: column("arg", "name"),
        },
    });
    let grouped = group(
        1,
        "ordered",
        &input,
        vec![column("arg", "site_id")],
        vec![aggregate],
    );
    let error = validate_plan_ir(&plan(vec![input, grouped], vec![])).unwrap_err();
    assert!(
        matches!(
            error,
            RelationalAssertionPlanError::InvalidOrderedPositionType { .. }
        ),
        "{error}"
    );
    assert!(error.to_string().contains("arg.name"), "{error}");
}

#[test]
fn projected_enum_alias_keeps_its_validation_domain() {
    let fields = DetailedCodeQueryDomain::Occurrence.row_fields();
    let role = *fields.iter().find(|field| field.name == "role").unwrap();
    let schema = crate::relational::query_schema("occ", &[("renamed_role".into(), role)]);
    let input = IrRelation {
        id: IrRelationId(0),
        name: "occ".into(),
        op: IrRelationOp::Source {
            binding: binding("occ"),
            schema: schema.clone(),
        },
        schema,
    };
    let selected = filter(
        1,
        "selected",
        &input,
        vec![IrPredicate::Compare {
            left: column("occ", "renamed_role"),
            op: IrCompareOp::Eq,
            right: IrOperand::Literal(RowLiteral::ConstrainedEnum("misspelled-role".into())),
        }],
    );
    let error = validate_plan_ir(&plan(vec![input, selected], vec![])).unwrap_err();
    assert!(
        matches!(error, RelationalAssertionPlanError::UnknownEnumLabel { .. }),
        "{error}"
    );
}
