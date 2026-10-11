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
use brokk_bifrost_analysis::CancellationToken;

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
    cancellation: Option<&CancellationToken>,
) -> Result<RelationalAssertionEvaluation, RelationalAssertionEvaluationError> {
    let invalid =
        |error: RelationalAssertionPlanError| RelationalAssertionEvaluationError::InvalidPlan {
            message: error.to_string(),
        };
    let ir = lower_relational_assertion_plan(plan).map_err(invalid)?;
    validate_plan_ir(&ir).map_err(invalid)?;
    evaluate_plan_ir(&ir, inputs, cancellation)
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::str::FromStr;

    use brokk_bifrost_analysis::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
    use brokk_bifrost_rql::structural::search::{
        CodeQueryOccurrence, CodeQueryOccurrenceTarget, CodeQueryResultItem, UnitRowItem,
    };
    use brokk_bifrost_rql::structural::{CodeQuery, CodeQueryRange, CodeQueryResultValue};
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
            resolved_locators: Vec::new(),
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

    /// One rendered row as every evaluation path carries it: projected, which
    /// is what the plan evaluation reads on both the whole and the sliced
    /// path.
    fn item(value: CodeQueryResultValue) -> UnitRowItem {
        UnitRowItem::project(&CodeQueryResultItem {
            value,
            provenance: Vec::new(),
            provenance_truncated: false,
            row_projection: Vec::new(),
        })
    }

    fn occurrence(id: &str, ast_id: &str) -> UnitRowItem {
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
                    source_range: None,
                },
                RowBinding {
                    name: candidate.clone(),
                    source: RowBindingSource::Query(occurrence_selector()),
                    source_range: None,
                },
            ],
            joins: vec![RowJoin {
                left: site.clone(),
                right: candidate.clone(),
                kind: RowJoinKind::Inner,
                on: vec![RowJoinCondition {
                    left_field: "ast_id".to_string(),
                    right_field: "ast_id".to_string(),
                    source_range: None,
                }],
                source_range: None,
            }],
            groups: vec![RowGroup {
                name: group.clone(),
                by: vec![RowFieldRef {
                    binding: site,
                    field: "ast_id".to_string(),
                    source_range: None,
                }],
                aggregates: vec![RowAggregate {
                    name: count.clone(),
                    op: RowAggregateOp::Count,
                    value: None,
                    sequences: None,
                    sets: None,
                    predicate: Vec::new(),
                    source_range: None,
                }],
                source_range: None,
            }],
            assertions: vec![RowAssertion {
                id: name::<PolicyAssertId>("one-candidate"),
                group,
                aggregate: count,
                cardinality: AssertCardinality::Exactly(1),
                source_range: None,
            }],
            limits: RelationalAssertionLimits::default(),
        }
    }

    #[test]
    fn binding_initializer_site_ast_id_is_a_typed_call_effect_join_key() {
        let initializer = CodeQuery::from_source(
            r#"(language rust
              (binding-initializer-calls-of
                (state-events-of :class [establish] :subject [binding]
                  (procedure-of (function :async true)))))"#,
        )
        .expect("binding initializer relation query");
        let effects = CodeQuery::from_source("(language rust (call-effects (call-shape (call))))")
            .expect("call effect query");
        let selector = |query| PolicySelector::Inline {
            schema: SchemaVersionResolution {
                version: 8,
                origin: SchemaVersionOrigin::Explicit,
            },
            query,
            resolved_locators: Vec::new(),
        };

        let mut plan = valid_plan();
        plan.bindings[0].source = RowBindingSource::Query(selector(initializer));
        plan.bindings[1].source = RowBindingSource::Query(selector(effects));
        plan.joins[0].on[0] = RowJoinCondition {
            left_field: "site_ast_id".to_string(),
            right_field: "site_ast_id".to_string(),
            source_range: None,
        };
        plan.groups[0].by[0].field = "site_ast_id".to_string();
        validate_relational_assertion_plan(&plan)
            .expect("initializer and call-effect rows share a typed AST identity");

        plan.joins[0].on[0].right_field = "callee_id".to_string();
        assert!(matches!(
            validate_relational_assertion_plan(&plan),
            Err(RelationalAssertionPlanError::JoinTypeMismatch { .. })
        ));
    }

    /// Equal field values prove no relation between a code row and a
    /// configuration row (#3274, #3284). Joining them is refused at load time;
    /// the registered `correlate` operator is the only composition that may
    /// pair them, and only structurally.
    #[test]
    fn rejects_joining_code_rows_with_configuration_rows() {
        let mut plan = valid_plan();
        plan.bindings[1].source = RowBindingSource::Query(inline_selector(json!({
            "schema_version": 1,
            "configuration_facts": { "formats": ["properties"] }
        })));
        // Both columns are stable ids, so the join is type-correct; it is
        // refused for pairing two domains, not for its field types.
        plan.joins[0].on[0] = RowJoinCondition {
            left_field: "id".to_string(),
            right_field: "id".to_string(),
            source_range: None,
        };
        let error = validate_relational_assertion_plan(&plan)
            .expect_err("a code binding must not join a configuration binding");
        assert_eq!(
            error,
            RelationalAssertionPlanError::CrossDomainJoin {
                left: "site".to_string(),
                right: "candidate".to_string(),
            }
        );
        assert!(error.to_string().contains("`correlate`"), "{error}");
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
                    coverage: RelationCoverage::exhaustive(),
                },
                RelationalInput {
                    binding: candidate,
                    rows: &one_candidate,
                    coverage: RelationCoverage::exhaustive(),
                },
            ],
            None,
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
                    coverage: RelationCoverage::exhaustive(),
                },
                RelationalInput {
                    binding: candidate,
                    rows: &two_candidates,
                    coverage: RelationCoverage::exhaustive(),
                },
            ],
            None,
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
                    coverage: RelationCoverage::exhaustive(),
                },
                RelationalInput {
                    binding: candidate,
                    rows: &one_candidate,
                    coverage: RelationCoverage::incomplete(Vec::new()),
                },
            ],
            None,
        )
        .unwrap();
        assert!(incomplete.violations.is_empty());
        assert!(!incomplete.exhaustive);
    }

    fn call_argument(site: &str, index: usize, name: &str) -> UnitRowItem {
        item(CodeQueryResultValue::CallArgument {
            value: Box::new(
                brokk_bifrost_rql::structural::search::CodeQueryCallShapeArgument {
                    id: format!("{site}-arg-{index}"),
                    group_id: format!("{site}-group"),
                    site_id: site.to_string(),
                    path: "app.py".to_string(),
                    range: unit_range(),
                    argument_index: index,
                    name: Some(name.to_string()),
                    literal_value: None,
                    spread: false,
                },
            ),
        })
    }

    fn signature_parameter(signature: &str, index: usize, label: &str) -> UnitRowItem {
        item(CodeQueryResultValue::SignatureParameter {
            value: Box::new(
                brokk_bifrost_rql::structural::search::CodeQuerySignatureParameter {
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
                    source_range: None,
                },
                RowBinding {
                    name: param.clone(),
                    source: RowBindingSource::Query(signature_parameter_selector()),
                    source_range: None,
                },
            ],
            joins: vec![RowJoin {
                left: arg.clone(),
                right: param.clone(),
                kind: RowJoinKind::Inner,
                on: vec![RowJoinCondition {
                    left_field: "site_id".to_string(),
                    right_field: "signature_id".to_string(),
                    source_range: None,
                }],
                source_range: None,
            }],
            groups: vec![RowGroup {
                name: group.clone(),
                by: vec![RowFieldRef {
                    binding: arg.clone(),
                    field: "site_id".to_string(),
                    source_range: None,
                }],
                aggregates: vec![RowAggregate {
                    name: parity.clone(),
                    op: RowAggregateOp::OrderedEqual,
                    sets: None,
                    value: None,
                    sequences: Some(crate::definition::RowOrderedSequencePair {
                        left: crate::definition::RowOrderedSequence {
                            position: RowFieldRef {
                                binding: arg,
                                field: "argument_index".to_string(),
                                source_range: None,
                            },
                            value: RowFieldRef {
                                binding: name("arg"),
                                field: "name".to_string(),
                                source_range: None,
                            },
                        },
                        right: crate::definition::RowOrderedSequence {
                            position: RowFieldRef {
                                binding: param.clone(),
                                field: "parameter_index".to_string(),
                                source_range: None,
                            },
                            value: RowFieldRef {
                                binding: param,
                                field: "label".to_string(),
                                source_range: None,
                            },
                        },
                    }),
                    predicate: Vec::new(),
                    source_range: None,
                }],
                source_range: None,
            }],
            assertions: vec![RowAssertion {
                id: name::<PolicyAssertId>("argument-order"),
                group,
                aggregate: parity,
                cardinality: AssertCardinality::Exactly(1),
                source_range: None,
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
                    coverage: RelationCoverage::exhaustive(),
                },
                RelationalInput {
                    binding: &plan.bindings[1].name,
                    rows: &parameter_rows,
                    coverage: RelationCoverage::exhaustive(),
                },
            ],
            None,
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
}
