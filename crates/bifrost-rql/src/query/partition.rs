//! Whether a plan's rows can be produced one seed file at a time.
//!
//! An incremental policy evaluation executes a sliceable plan once per seed
//! file. Ordinary plans merge in seed order; eligible unions restore authored
//! branch order before seed order and first-writer deduplication. Eligibility
//! is a property of the plan structure, never of the policy that authored it.
//! The caller must also prove cumulative budget headroom before using a merge.

use super::ir::{CodeQueryPlan, CodeQueryPlanSource};
use super::schema::QueryStepOp;

/// How one plan's execution may be partitioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanPartitioning {
    /// The plan's rows are the concatenation, in seed order, of the rows of one
    /// execution per seed file, deduplicated first-writer-wins.
    BySeed,
    /// The plan is an all-union composition whose leaves may be executed per
    /// seed file and merged in branch order before first-writer deduplication.
    BySeedUnion,
    /// The plan must be executed once over the whole workspace.
    Whole,
}

impl PlanPartitioning {
    /// Classify `plan` from its source kind and its steps.
    ///
    /// Set plans are `Whole` unless they are unions whose leaves are all
    /// seed-partitionable, use one comparator family, and whose only set-node
    /// suffixes are typed row filters or projections. Those two operations
    /// distribute over union because they inspect or rename one row without
    /// consulting any other row. The remaining shapes are `Whole`:
    ///
    /// - An intersect/except source, or a union with a non-distributive suffix.
    ///   Those operators consume cross-seed membership or a deduplicated set
    ///   of branch rows, so their result cannot be reconstructed from
    ///   independent seed rows.
    ///   A union with an `absent_member` step is also whole because its root
    ///   evidence payload is merged by representative selection rather than by
    ///   traces alone. Eligible unions handle their fair-budget retry boundary
    ///   in the merged unit cap proof below.
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
        if matches!(&plan.source, CodeQueryPlanSource::Set { .. }) {
            return Self::classify_union(plan).map_or(Self::Whole, |_| Self::BySeedUnion);
        }
        Self::classify_leaf(plan)
    }

    /// Whether this plan may be executed one seed file at a time.
    pub const fn is_by_seed(self) -> bool {
        matches!(self, Self::BySeed | Self::BySeedUnion)
    }

    /// Whether this plan is an eligible all-union composition.
    pub const fn is_seed_union(self) -> bool {
        matches!(self, Self::BySeedUnion)
    }

    fn classify_leaf(plan: &CodeQueryPlan) -> Self {
        if plan.steps.iter().any(|step| {
            step.op() == QueryStepOp::DecoratorBindings || step.op().is_registration_dependent()
        }) {
            Self::Whole
        } else {
            Self::BySeed
        }
    }

    /// Validate the restricted union shape and return its checked fair-share
    /// divisor. Every set node must be a union with only distributive row-local
    /// suffixes, and every leaf must be a seed-partitionable plan with the same
    /// seed ordering family.
    pub(crate) fn classify_union(plan: &CodeQueryPlan) -> Option<usize> {
        let CodeQueryPlanSource::Set { .. } = &plan.source else {
            return None;
        };

        let mut pending = vec![(plan, 1usize)];
        let mut maximum_divisor = 1usize;
        let mut leaves = 0usize;
        let mut comparator = None;
        while let Some((current, divisor)) = pending.pop() {
            match &current.source {
                CodeQueryPlanSource::Set { op, branches } => {
                    if *op != super::ir::SetOperator::Union
                        || current.steps.iter().any(|step| {
                            !matches!(step.op(), QueryStepOp::Filter | QueryStepOp::Project)
                        })
                    {
                        return None;
                    }
                    let next_divisor = divisor.checked_mul(branches.len())?;
                    for branch in branches.iter().rev() {
                        pending.push((branch, next_divisor));
                    }
                    maximum_divisor = maximum_divisor.max(next_divisor);
                }
                _ => {
                    if !Self::classify_leaf(current).is_by_seed()
                        || current
                            .steps
                            .iter()
                            .any(|step| step.op() == QueryStepOp::AbsentMember)
                    {
                        return None;
                    }
                    let leaf_comparator = matches!(&current.source, CodeQueryPlanSource::Seed(_));
                    if comparator.is_some_and(|known| known != leaf_comparator) {
                        return None;
                    }
                    comparator = Some(leaf_comparator);
                    leaves = leaves.checked_add(1)?;
                }
            }
        }
        if leaves == 0 {
            return None;
        }
        Some(maximum_divisor)
    }

    /// Return the non-set leaves and their full branch paths for an eligible
    /// union. Distributive set-node suffixes are appended to each descendant
    /// leaf in execution order, so unit execution applies the same row-local
    /// transformation before the global branch-order merge. The traversal is
    /// iterative so query depth cannot consume the Rust call stack.
    pub(crate) fn union_leaf_plans(
        plan: &CodeQueryPlan,
    ) -> Option<Vec<(CodeQueryPlan, Vec<usize>)>> {
        Self::classify_union(plan)?;
        let mut pending = vec![(plan, Vec::new(), Vec::new())];
        let mut leaves = Vec::new();
        while let Some((current, path, inherited_steps)) = pending.pop() {
            match &current.source {
                CodeQueryPlanSource::Set { branches, .. } => {
                    let mut suffix = current.steps.clone();
                    suffix.extend(inherited_steps);
                    for (index, branch) in branches.iter().enumerate().rev() {
                        let mut branch_path = path.clone();
                        branch_path.push(index);
                        pending.push((branch, branch_path, suffix.clone()));
                    }
                }
                _ => {
                    let mut leaf = current.clone();
                    leaf.steps.extend(inherited_steps);
                    leaves.push((leaf, path));
                }
            }
        }
        assert!(
            !leaves.is_empty(),
            "an eligible union has at least one leaf"
        );
        Some(leaves)
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
    fn a_suffix_free_union_is_partitioned_by_seed() {
        let plan = plan(json!({
            "union": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "class" } }
            ]
        }));
        assert_eq!(
            PlanPartitioning::classify(&plan),
            PlanPartitioning::BySeedUnion
        );
        assert!(PlanPartitioning::classify(&plan).is_by_seed());
        assert!(PlanPartitioning::classify(&plan).is_seed_union());
    }

    #[test]
    fn a_nested_suffix_free_union_is_partitioned_by_seed() {
        let plan = plan(json!({
            "union": [
                {
                    "union": [
                        { "match": { "kind": "function" } },
                        { "match": { "kind": "class" } }
                    ]
                },
                { "match": { "kind": "method" } }
            ]
        }));
        assert_eq!(
            PlanPartitioning::classify(&plan),
            PlanPartitioning::BySeedUnion
        );
    }

    #[test]
    fn typed_row_steps_on_a_union_are_distributed_to_its_leaves() {
        let plan = plan(json!({
            "union": [
                { "occurrences": { "class": "reference" } },
                { "occurrences": { "class": "reference" } }
            ],
            "steps": [
                {
                    "op": "filter",
                    "where": [{ "field": "target_id", "op": "is_not_null" }]
                },
                {
                    "op": "project",
                    "columns": [{ "source": "id", "name": "site" }]
                }
            ]
        }));
        assert_eq!(
            PlanPartitioning::classify(&plan),
            PlanPartitioning::BySeedUnion
        );
        let leaves = PlanPartitioning::union_leaf_plans(&plan).expect("union is sliceable");
        assert_eq!(leaves.len(), 2);
        for (leaf, _) in leaves {
            assert_eq!(
                leaf.steps.iter().map(|step| step.op()).collect::<Vec<_>>(),
                vec![QueryStepOp::Filter, QueryStepOp::Project]
            );
        }
    }

    #[test]
    fn mixed_seed_comparators_keep_a_union_whole() {
        let plan = plan(json!({
            "union": [
                { "match": { "kind": "function" }, "steps": [{ "op": "file_of" }] },
                { "occurrences": { "class": "reference" }, "steps": [{ "op": "file_of" }] }
            ]
        }));
        assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::Whole);
    }

    #[test]
    fn a_union_with_a_set_suffix_stays_whole() {
        let plan = plan(json!({
            "union": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "class" } }
            ],
            "steps": [{ "op": "file_of" }]
        }));
        assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::Whole);
    }

    #[test]
    fn intersect_and_except_stay_whole() {
        let intersect = json!({
            "intersect": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "function" } }
            ]
        });
        let except = json!({
            "except": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "function" } }
            ]
        });
        for query in [intersect, except] {
            let plan = plan(query);
            assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::Whole);
        }
    }

    #[test]
    fn registration_and_absence_steps_keep_union_whole() {
        for steps in [
            json!([
                { "op": "procedure_of" },
                { "op": "typestate", "protocol_ref": "test:protocol" }
            ]),
            json!([
                { "op": "procedure_of" },
                { "op": "absent_member" }
            ]),
        ] {
            let query = json!({
                "union": [
                    { "match": { "kind": "function" }, "steps": steps.clone() },
                    { "match": { "kind": "function" }, "steps": steps }
                ]
            });
            let plan = plan(query);
            assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::Whole);
        }
    }
}
