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
    RelationalAssertionEvaluationError, RelationalAssertionViolation, RelationalViolationRow,
    evaluate_plan_ir,
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
pub use lower::lower_relational_assertion_plan;
pub use validate::{RelationalAssertionPlanError, validate_limits, validate_plan_ir};

#[cfg(test)]
mod tests;
