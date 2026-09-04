//! Whether a plan's rows can be produced one seed file at a time.
//!
//! An incremental policy evaluation executes a sliceable plan once per seed
//! file and merges the per-seed row vectors in seed order (issue:
//! impact-sliced `--diff-base`, Milestone 2). That merge reproduces the whole
//! execution's row vector because the pipeline is input-row-major and its
//! dedup is first-writer-wins, so the classification here is a property of the
//! plan's structure alone -- never of the policy that authored it.

use super::ir::{CodeQueryPlan, CodeQueryPlanSource};
use super::schema::QueryStepOp;

/// How one plan's execution may be partitioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanPartitioning {
    /// The plan's rows are the concatenation, in seed order, of the rows of one
    /// execution per seed file, deduplicated first-writer-wins.
    BySeed,
    /// The plan must be executed once over the whole workspace.
    Whole,
}

impl PlanPartitioning {
    /// Classify `plan` from its source kind and its steps.
    ///
    /// Three shapes are `Whole`:
    ///
    /// - A `Set` source. A set node gives each branch a fair share of the live
    ///   budget, re-runs a starved branch, and drops truncated seed results
    ///   before that retry, so a branch's row set depends on what earlier
    ///   branches consumed. Nothing about a per-seed execution reproduces that.
    /// - A `decorator_bindings` step. Its rows carry
    ///   `DetailedCodeQueryDecoratedParameterEvidence`, runtime-only semantic
    ///   identity that is deliberately outside the serializable row model, so a
    ///   unit product cannot carry it.
    /// - A registration-dependent step ([`QueryStepOp::is_registration_dependent`]).
    ///   Those steps read the interprocedural graph and the summary repository
    ///   through funnels that record no read key today, so a per-seed unit over
    ///   one would carry a read set that names none of what decided its rows and
    ///   would be reused whenever the files it did name held still.
    ///
    /// Everything else is `BySeed`, including derived-value steps (whose answer
    /// is a whole-workspace relation the unit's read set records) and batched
    /// steps (whose only reordering is a stable sort by artifact file over
    /// seed-major input).
    pub fn classify(plan: &CodeQueryPlan) -> Self {
        if matches!(plan.source, CodeQueryPlanSource::Set { .. }) {
            return Self::Whole;
        }
        if plan.steps.iter().any(|step| {
            step.op() == QueryStepOp::DecoratorBindings || step.op().is_registration_dependent()
        }) {
            return Self::Whole;
        }
        Self::BySeed
    }

    /// Whether this plan may be executed one seed file at a time.
    pub const fn is_by_seed(self) -> bool {
        matches!(self, Self::BySeed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::ir::CodeQuery;
    use crate::query::schema::QueryStepShape;
    use serde_json::{Value, json};

    fn plan(query: Value) -> CodeQueryPlan {
        CodeQuery::from_json(&query)
            .expect("query should parse")
            .plan
    }

    #[test]
    fn a_seed_only_plan_is_partitioned_by_seed() {
        assert_eq!(
            PlanPartitioning::classify(&plan(json!({ "match": { "kind": "function" } }))),
            PlanPartitioning::BySeed
        );
    }

    #[test]
    fn every_non_structural_seed_source_is_partitioned_by_seed() {
        for source in [
            json!({ "occurrences": { "class": "reference" } }),
            json!({ "scopes": {} }),
            json!({ "bindings": {} }),
            json!({ "paths": {} }),
            json!({ "generation_sites": {} }),
            json!({ "exports": {} }),
        ] {
            assert_eq!(
                PlanPartitioning::classify(&plan(source.clone())),
                PlanPartitioning::BySeed,
                "{source} is a per-file seed enumeration"
            );
        }
    }

    #[test]
    fn a_row_local_step_keeps_a_plan_by_seed() {
        let plan = plan(json!({
            "match": { "kind": "function" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "file_of" }]
        }));
        assert!(
            plan.steps
                .iter()
                .all(|step| step.op().shape() == QueryStepShape::RowLocal)
        );
        assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::BySeed);
    }

    #[test]
    fn a_derived_value_step_keeps_a_plan_by_seed() {
        let plan = plan(json!({
            "match": { "kind": "function" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "callers" }]
        }));
        assert_eq!(
            plan.steps[1].op().shape(),
            QueryStepShape::DerivedValue,
            "callers resolves a workspace call relation"
        );
        assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::BySeed);
    }

    #[test]
    fn a_batched_result_contract_step_keeps_a_plan_by_seed() {
        let plan = plan(json!({
            "match": { "kind": "call" },
            "steps": [{ "op": "call_shape" }, { "op": "result_contract_calls" }]
        }));
        assert_eq!(
            plan.steps[1].op().shape(),
            QueryStepShape::Batched,
            "result_contract_calls opens per-file semantic windows"
        );
        assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::BySeed);
    }

    #[test]
    fn a_decorator_bindings_step_forces_a_whole_plan() {
        let plan = plan(json!({
            "match": { "kind": "parameter" },
            "steps": [{ "op": "decorator_bindings" }]
        }));
        assert_eq!(plan.steps[0].op().shape(), QueryStepShape::Batched);
        assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::Whole);
    }

    /// Every registration-dependent step forces a whole plan, whatever its
    /// declared driver shape: the rows come from an analysis a host
    /// registered, read through funnels that record nothing, so a per-seed
    /// unit over one could never state what its rows depend on.
    #[test]
    fn every_registration_dependent_step_forces_a_whole_plan() {
        // Every one of them consumes a procedure, and the witness projection
        // consumes what one of the others produced, so each is spelled with
        // the shortest plan its own signature admits.
        for steps in [
            json!([
                { "op": "procedure_of" },
                { "op": "typestate", "protocol_ref": "test:protocol" }
            ]),
            json!([
                { "op": "procedure_of" },
                { "op": "value_flow", "plan_ref": "test:plan" }
            ]),
            json!([
                { "op": "procedure_of" },
                { "op": "taint", "taint_ref": "test:result" }
            ]),
            json!([
                { "op": "procedure_of" },
                { "op": "typestate", "protocol_ref": "test:protocol" },
                { "op": "witness" }
            ]),
        ] {
            let plan = plan(json!({ "match": { "kind": "function" }, "steps": steps }));
            assert!(
                plan.steps
                    .iter()
                    .any(|step| step.op().is_registration_dependent()),
                "{steps} names a registration-dependent step"
            );
            assert_eq!(
                PlanPartitioning::classify(&plan),
                PlanPartitioning::Whole,
                "{steps} cannot be sliced by seed"
            );
        }
    }

    /// The registration-dependent set is exactly those four operations, so a
    /// new step declared beside them cannot join it by accident and a step
    /// that leaves it cannot do so silently.
    #[test]
    fn the_registration_dependent_operations_are_the_four_declared_ones() {
        let registration_dependent = crate::query::schema::ALL_QUERY_STEP_OPS
            .iter()
            .copied()
            .filter(|op| op.is_registration_dependent())
            .map(QueryStepOp::label)
            .collect::<Vec<_>>();
        assert_eq!(
            registration_dependent,
            vec!["typestate", "value_flow", "taint", "witness"]
        );
    }

    #[test]
    fn a_set_source_forces_a_whole_plan() {
        let plan = plan(json!({
            "union": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "class" } }
            ]
        }));
        assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::Whole);
    }
}
