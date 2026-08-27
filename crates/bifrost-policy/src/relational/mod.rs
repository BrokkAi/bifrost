//! Internal relational plan IR, typed validation, coverage envelope, and
//! bounded evaluation for relational assertion policies.
//!
//! Three representations, deliberately separate:
//!
//! * the **source model** (`crate::definition::RelationalAssertionPlan`) is what
//!   an agent authors and what the semantic hash is computed from. Its shape is
//!   frozen by every existing baseline and suppression, so nothing here changes
//!   it;
//! * the **IR** (`ir`) is what is validated and evaluated. It is a dependency
//!   graph of typed operators, and it admits capabilities the syntax cannot
//!   spell yet;
//! * the **evaluation state** (`eval`) is materialized rows, budgets and
//!   coverage. It exists only for the duration of one run.
//!
//! Lowering runs source -> IR (`lower`). Nothing lowers back, and nothing
//! hashes the IR.
//!
//! Tracked by issue #2433.

mod coverage;
mod eval;
mod introspect;
mod ir;
mod lower;
mod validate;

pub use coverage::{
    MAX_RETAINED_RELATIONAL_OBLIGATIONS, RelationCoverage, RelationalInput, RelationalObligation,
    RelationalObligationKind,
};
pub use eval::{
    MAX_VIOLATION_REPRESENTATIVE_TUPLES, RelationalAssertionEvaluation,
    RelationalAssertionEvaluationError, RelationalAssertionViolation, RelationalRowSelection,
    RelationalViolationRow, evaluate_plan_ir, evaluate_row_selector_ir,
};
pub use introspect::{
    RELATION_SCHEMA_FORMAT, RelationDomainSchema, RelationExpansionSchema, RelationFieldSchema,
    RelationSchemaCatalog, admitted_expansions, relation_schema_catalog,
};
pub use ir::{
    ALL_ROW_EXPANSION_STEPS, IrAggregate, IrAggregateOp, IrAssertion, IrColumn, IrCompareOp,
    IrEquiKey, IrField, IrJoinKind, IrLimits, IrOperand, IrOrderedSequence, IrOrderedSequencePair,
    IrPredicate, IrProjection, IrRelation, IrRelationId, IrRelationOp, IrSchema,
    MAX_IR_SET_MEMBERS, RelationalPlanIr, RowScalar, domain_schema, expansion_result_domain,
};
pub use lower::{LoweredRowSelector, lower_relational_assertion_plan, lower_row_selector_plan};
pub use validate::{RelationalAssertionPlanError, validate_limits, validate_plan_ir};

use brokk_bifrost_rql::structural::search::DetailedCodeQueryDomain;

use crate::definition::{RowLiteral, RowSelectorPlan};

fn row_selector_output_predicates(lowered: &LoweredRowSelector) -> Vec<&IrPredicate> {
    let mut predicates = Vec::new();
    let mut relation = lowered.output_relation;
    loop {
        match &lowered
            .plan
            .relation(relation)
            .expect("row-selector output lineage belongs to its plan")
            .op
        {
            IrRelationOp::Filter {
                input,
                predicates: filter,
            } => {
                predicates.extend(filter);
                relation = *input;
            }
            IrRelationOp::Project { input, .. } => relation = *input,
            IrRelationOp::Source { .. } | IrRelationOp::Expand { .. } => break,
            IrRelationOp::Join { .. } | IrRelationOp::Group { .. } => {
                unreachable!("row-selector output binding lineage has no join or group")
            }
        }
    }
    predicates
}

fn has_literal_predicate(
    predicates: &[&IrPredicate],
    field: &str,
    expected: impl Fn(&RowLiteral) -> bool,
) -> bool {
    predicates.iter().any(|predicate| {
        matches!(
            predicate,
            IrPredicate::Compare {
                left,
                op: IrCompareOp::Eq,
                right: IrOperand::Literal(value),
            } if left.name == field && expected(value)
        )
    })
}

fn has_not_null_predicate(predicates: &[&IrPredicate], field: &str) -> bool {
    predicates.iter().any(|predicate| {
        matches!(
            predicate,
            IrPredicate::IsNull { column, negated: true } if column.name == field
        )
    })
}

/// Lower and validate one non-asserting row selector, including the output
/// identity required by the production endpoint compiler.
pub fn validate_row_selector_plan(
    selector: &RowSelectorPlan,
) -> Result<LoweredRowSelector, RelationalAssertionPlanError> {
    let lowered = lower_row_selector_plan(selector)?;
    validate_plan_ir(&lowered.plan)?;

    let upstream = lowered
        .plan
        .relation(lowered.upstream)
        .expect("lowered row-selector upstream belongs to its plan");
    let domain = match &upstream.op {
        IrRelationOp::Source { domain, .. } | IrRelationOp::Expand { domain, .. } => *domain,
        IrRelationOp::Filter { .. }
        | IrRelationOp::Project { .. }
        | IrRelationOp::Join { .. }
        | IrRelationOp::Group { .. } => {
            unreachable!("lowered row-selector upstream is a source or expansion")
        }
    };
    if domain != DetailedCodeQueryDomain::CallBinding {
        return Err(RelationalAssertionPlanError::InvalidRowSelectorOutput {
            detail: format!(
                "`{}` originates from {}, not call_binding rows",
                lowered.output_binding.as_str(),
                domain.label()
            ),
        });
    }

    let output = lowered
        .plan
        .relation(lowered.relation)
        .expect("lowered row-selector output belongs to its plan");
    for field in ["id", "site_id", "site_ast_id", "argument_id"] {
        let column = IrColumn::new(lowered.output_binding.as_str(), field);
        if output.schema.index_of(&column).is_none() {
            return Err(RelationalAssertionPlanError::InvalidRowSelectorOutput {
                detail: format!(
                    "`{}` does not retain required call-binding field `{field}`",
                    lowered.output_binding.as_str()
                ),
            });
        }
    }
    let exposed_call_bindings = lowered
        .plan
        .relations
        .iter()
        .filter_map(|relation| match &relation.op {
            IrRelationOp::Source { binding, domain }
            | IrRelationOp::Expand {
                binding, domain, ..
            } if *domain == DetailedCodeQueryDomain::CallBinding
                && ["id", "site_id", "site_ast_id", "argument_id"]
                    .into_iter()
                    .all(|field| {
                        output
                            .schema
                            .index_of(&IrColumn::new(binding.as_str(), field))
                            .is_some()
                    }) =>
            {
                Some(binding.as_str())
            }
            IrRelationOp::Source { .. }
            | IrRelationOp::Expand { .. }
            | IrRelationOp::Filter { .. }
            | IrRelationOp::Project { .. }
            | IrRelationOp::Join { .. }
            | IrRelationOp::Group { .. } => None,
        })
        .collect::<Vec<_>>();
    if exposed_call_bindings != [lowered.output_binding.as_str()] {
        return Err(RelationalAssertionPlanError::InvalidRowSelectorOutput {
            detail: format!(
                "final relation exposes ambiguous call-binding identities {exposed_call_bindings:?}; expected only `{}`",
                lowered.output_binding.as_str()
            ),
        });
    }

    let predicates = row_selector_output_predicates(&lowered);
    let constrained = |field: &str, expected: &str| {
        has_literal_predicate(
            &predicates,
            field,
            |literal| matches!(literal, RowLiteral::ConstrainedEnum(value) if value == expected),
        )
    };
    let integer = |field: &str, expected: u64| {
        has_literal_predicate(
            &predicates,
            field,
            |literal| matches!(literal, RowLiteral::Integer(value) if *value == expected),
        )
    };
    let boolean = |field: &str, expected: bool| {
        has_literal_predicate(
            &predicates,
            field,
            |literal| matches!(literal, RowLiteral::Boolean(value) if *value == expected),
        )
    };
    let model = has_literal_predicate(
        &predicates,
        "model_id",
        |literal| matches!(literal, RowLiteral::String(value) if !value.is_empty()),
    );
    let formal = has_literal_predicate(
        &predicates,
        "formal_name",
        |literal| matches!(literal, RowLiteral::String(value) if !value.is_empty()),
    ) || has_literal_predicate(&predicates, "formal_index", |literal| {
        matches!(literal, RowLiteral::Integer(_))
    });
    let requirements = [
        ("model_id eq stable model identity", model),
        (
            "semantic_target_id is-not-null",
            has_not_null_predicate(&predicates, "semantic_target_id"),
        ),
        (
            "signature_id is-not-null",
            has_not_null_predicate(&predicates, "signature_id"),
        ),
        (
            "dispatch_outcome eq resolved",
            constrained("dispatch_outcome", "resolved"),
        ),
        (
            "dispatch_coverage eq exhaustive",
            constrained("dispatch_coverage", "exhaustive"),
        ),
        (
            "dispatch_proof eq proven",
            constrained("dispatch_proof", "proven"),
        ),
        (
            "dispatch_completeness eq complete",
            constrained("dispatch_completeness", "complete"),
        ),
        (
            "dispatch_target_count eq 1",
            integer("dispatch_target_count", 1),
        ),
        (
            "dispatch_targets_truncated eq false",
            boolean("dispatch_targets_truncated", false),
        ),
        ("formal_name or formal_index exact selector", formal),
        ("mapping eq exact", constrained("mapping", "exact")),
        (
            "coverage eq exhaustive",
            constrained("coverage", "exhaustive"),
        ),
        ("terminal eq false", boolean("terminal", false)),
        (
            "argument_id is-not-null",
            has_not_null_predicate(&predicates, "argument_id"),
        ),
    ];
    let missing = requirements
        .into_iter()
        .filter_map(|(requirement, present)| (!present).then_some(requirement))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(RelationalAssertionPlanError::InvalidRowSelectorOutput {
            detail: format!(
                "`{}` lacks required exact call-binding predicates: {}",
                lowered.output_binding.as_str(),
                missing.join(", ")
            ),
        });
    }
    Ok(lowered)
}

#[cfg(test)]
mod tests;
