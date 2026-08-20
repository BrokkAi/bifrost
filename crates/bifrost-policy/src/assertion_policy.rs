//! The seam between authored assertion policies and the relational engine.
//!
//! Policy source decoding builds the authoring model in `definition`; this
//! module is the two-function boundary the decoder and the evaluator call. Both
//! functions lower the authored plan into the internal IR (`crate::relational`)
//! and then validate or evaluate that, so the authored record set is never the
//! thing being executed.
//!
//! The relational types stay re-exported here because they are this crate's
//! published relational surface and every existing caller addresses them
//! through this module.

use crate::definition::RelationalAssertionPlan;
use crate::relational::{
    IrLimits, evaluate_plan_ir, lower_relational_assertion_plan, validate_limits, validate_plan_ir,
};

pub use crate::relational::{
    RelationalAssertionEvaluation, RelationalAssertionEvaluationError,
    RelationalAssertionPlanError, RelationalInput, RelationalViolationRow, RowScalar,
};

/// Validate names, dependency order, row fields, scalar types and aggregate
/// shapes before any workspace query executes.
///
/// Called from the source decoder, so every rejection here is an authoring
/// error reported at load time rather than a runtime failure.
pub fn validate_relational_assertion_plan(
    plan: &RelationalAssertionPlan,
) -> Result<(), RelationalAssertionPlanError> {
    validate_limits(&IrLimits::from(plan.limits))?;
    let ir = lower_relational_assertion_plan(plan)?;
    validate_plan_ir(&ir)
}

/// Evaluate a validated relational plan over already executed CodeQuery row
/// sets, one per bound relation.
///
/// The result separates what the rows prove from what they do not: violations
/// are the verdicts the coverage rules admit, and every verdict those rules
/// blocked is reported as an unmet obligation instead of being silently
/// dropped.
pub fn evaluate_relational_assertion_rows(
    plan: &RelationalAssertionPlan,
    inputs: &[RelationalInput<'_>],
) -> Result<RelationalAssertionEvaluation, RelationalAssertionEvaluationError> {
    let invalid =
        |error: RelationalAssertionPlanError| RelationalAssertionEvaluationError::InvalidPlan {
            message: error.to_string(),
        };
    let ir = lower_relational_assertion_plan(plan).map_err(invalid)?;
    validate_plan_ir(&ir).map_err(invalid)?;
    evaluate_plan_ir(&ir, inputs)
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::str::FromStr;

    use brokk_bifrost_analysis::analyzer::structural::search::{
        CodeQueryOccurrence, CodeQueryOccurrenceTarget, CodeQueryResultItem,
    };
    use brokk_bifrost_analysis::analyzer::structural::{
        CodeQuery, CodeQueryRange, CodeQueryResultValue, CodeQueryRowScalarType,
    };
    use brokk_bifrost_analysis::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
    use serde_json::json;

    use super::*;
    use crate::definition::{
        AssertCardinality, PolicyAssertId, PolicySelector, RelationalAssertionLimits, RowAggregate,
        RowAggregateName, RowAggregateOp, RowAssertion, RowBinding, RowBindingName,
        RowBindingSource, RowFieldRef, RowGroup, RowGroupName, RowJoin, RowJoinCondition,
        RowJoinKind,
    };
    use crate::relational::RelationCoverage;

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
            derivations: Vec::new(),
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

    /// A group can only read rows the join chain actually brings in. Without
    /// the join, the second binding's rows never meet the first one's, so no
    /// row set could answer the plan.
    #[test]
    fn rejects_a_group_over_a_binding_the_joins_never_bring_in() {
        let mut plan = valid_plan();
        plan.joins.clear();
        plan.groups[0].by[0] = RowFieldRef {
            binding: name("candidate"),
            field: "ast_id".to_string(),
        };
        assert_eq!(
            validate_relational_assertion_plan(&plan),
            Err(RelationalAssertionPlanError::DisconnectedBinding {
                binding: "candidate".to_string(),
            })
        );
    }

    /// Joining one binding in twice would give its columns two meanings in the
    /// same row.
    #[test]
    fn rejects_joining_one_binding_in_twice() {
        let mut plan = valid_plan();
        let repeated = plan.joins[0].clone();
        plan.joins.push(repeated);
        assert_eq!(
            validate_relational_assertion_plan(&plan),
            Err(RelationalAssertionPlanError::RepeatedJoinBinding {
                binding: "candidate".to_string(),
            })
        );
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
            derivations: Vec::new(),
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
                    coverage: RelationCoverage::Exhaustive,
                },
                RelationalInput {
                    binding: candidate,
                    rows: &one_candidate,
                    coverage: RelationCoverage::Exhaustive,
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
                    coverage: RelationCoverage::Exhaustive,
                },
                RelationalInput {
                    binding: candidate,
                    rows: &two_candidates,
                    coverage: RelationCoverage::Exhaustive,
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
                    coverage: RelationCoverage::Exhaustive,
                },
                RelationalInput {
                    binding: candidate,
                    rows: &one_candidate,
                    coverage: RelationCoverage::incomplete(Vec::new()),
                },
            ],
        )
        .unwrap();
        assert!(incomplete.violations.is_empty());
        assert!(!incomplete.exhaustive);
    }

    /// The authored `(filter ...)` and `(project ...)` records change what the
    /// evaluation sees, not only what the plan says.
    ///
    /// Both plans read the same two rows. Without a derivation the group
    /// counts both and violates; a filter that keeps one row makes the same
    /// group satisfy the same assertion, and a projection that renames the
    /// filtered relation's columns changes nothing about the answer.
    #[test]
    fn authored_filters_and_projections_change_the_evaluated_rows() {
        fn plan_with(derivation: &str, right: &str) -> RelationalAssertionPlan {
            let source = format!(
                r#"(policy
                  :id "test.relational.derivation" :name "Derivation" :message "M"
                  :severity warning
                  :analysis (analysis :type assertion
                    (bind :name site :query
                      (rql (occurrences :role [member_position])))
                    (bind :name cand :query
                      (rql (occurrences :role [member_position])))
                    {derivation}
                    (join :left site :right {right} :on ((ast_id ast_id)))
                    (group :name by-site :by (site.ast_id)
                      (aggregate :name winners :op count))
                    (assert :group by-site :value winners
                      :cardinality (exactly 1))))"#
            );
            let parsed = crate::parse_rqlp_source(
                &source,
                crate::PolicySourceIdentity::new("test:derivation"),
            )
            .expect("the derivation policy parses");
            let crate::RqlpDocument::Policy { definition } = parsed.document() else {
                panic!("expected policy")
            };
            let crate::PolicyAnalysis::Assertion { spec } = &definition.analysis else {
                panic!("expected assertion policy")
            };
            spec.relational.clone().expect("relational plan")
        }

        let site_rows = vec![occurrence("site", "ast-1")];
        let candidate_rows = vec![
            occurrence("candidate-1", "ast-1"),
            occurrence("candidate-2", "ast-1"),
        ];
        let evaluate = |plan: &RelationalAssertionPlan| {
            let inputs = vec![
                RelationalInput {
                    binding: &plan.bindings[0].name,
                    rows: &site_rows,
                    coverage: RelationCoverage::Exhaustive,
                },
                RelationalInput {
                    binding: &plan.bindings[1].name,
                    rows: &candidate_rows,
                    coverage: RelationCoverage::Exhaustive,
                },
            ];
            evaluate_relational_assertion_rows(plan, &inputs).expect("evaluation")
        };

        let plain = evaluate(&plan_with("", "cand"));
        assert_eq!(plain.violations.len(), 1);
        assert_eq!(plain.violations[0].actual, 2, "both rows reach the group");

        let filtered = evaluate(&plan_with(
            r#"(filter :over cand :where ((cand.id eq "candidate-1")))"#,
            "cand",
        ));
        assert!(
            filtered.violations.is_empty(),
            "the filter removed the second row before the join: {:?}",
            filtered.violations
        );
        assert!(filtered.exhaustive);

        let projected = evaluate(&plan_with(
            r#"(filter :over cand :where ((cand.id eq "candidate-1")))
                    (project :name narrow :from cand :columns (cand.ast_id (cand.id key)))"#,
            "narrow",
        ));
        assert!(
            projected.violations.is_empty(),
            "a projection carries the filtered rows under its own name: {:?}",
            projected.violations
        );
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
            derivations: Vec::new(),
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
                    coverage: RelationCoverage::Exhaustive,
                },
                RelationalInput {
                    binding: &plan.bindings[1].name,
                    rows: &parameter_rows,
                    coverage: RelationCoverage::Exhaustive,
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
                    coverage: RelationCoverage::Exhaustive,
                },
                RelationalInput {
                    binding: &plan.bindings[1].name,
                    rows: &candidates,
                    coverage: RelationCoverage::Exhaustive,
                },
            ],
        )
        .unwrap();
        assert!(outcome.limit_exceeded);
        assert!(!outcome.exhaustive);
    }
}
