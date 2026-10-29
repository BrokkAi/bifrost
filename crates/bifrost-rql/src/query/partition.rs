//! Whether a plan's rows can be produced one seed file at a time.
//!
//! An incremental policy evaluation executes a sliceable plan once per seed
//! file. Ordinary plans merge in seed order; eligible unions restore authored
//! branch order before seed order and first-writer deduplication. Eligibility
//! is a property of the plan structure, never of the policy that authored it.
//! The caller must also prove cumulative budget headroom before using a merge.

use super::ir::{CodeQueryPlan, CodeQueryPlanSource, QueryValueKind, SetOperator};
use super::schema::QueryStepOp;

impl CodeQueryPlan {
    /// Whether execution needs the class-set workspace field-index prepass.
    ///
    /// This is an execution requirement, separate from whether result rows
    /// distribute over seeds. Until that prepass can be shared with complete
    /// dependency and budget replay, running each seed independently repeats
    /// the whole workspace preparation.
    pub fn requires_workspace_field_index(&self) -> Option<PlanWidenDetail> {
        let mut pending = vec![self];
        while let Some(plan) = pending.pop() {
            if plan
                .steps
                .iter()
                .any(|step| step.op() == QueryStepOp::ClassSet)
            {
                return Some(PlanWidenDetail::ClassSetWorkspacePreparation);
            }
            if plan
                .steps
                .iter()
                .any(|step| step.op() == QueryStepOp::AbsentMember)
            {
                return Some(PlanWidenDetail::AbsentMemberWorkspacePreparation);
            }
            pending.extend(plan.source.child_plans());
        }
        None
    }
}

/// How one plan's execution may be partitioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanPartitioning {
    /// The plan's rows are the concatenation, in seed order, of the rows of one
    /// execution per seed file, deduplicated first-writer-wins.
    BySeed,
    /// The plan is an all-union composition whose leaves may be executed per
    /// seed file and merged in branch order before first-writer deduplication.
    BySeedUnion,
    /// The plan is `A except B...` over rows whose set-difference key names
    /// their file. Its rows are the minuend's rows in the minuend's seed order,
    /// so one execution per seed file merges exactly as a `BySeed` plan's
    /// does, with the fair-share proof a set source needs.
    BySeedExcept,
    /// The plan must be executed once over the whole workspace.
    Whole(PlanWidenDetail),
}

/// Why a plan cannot be partitioned by seed, or why typestate rejects its
/// selector source before applying the ordinary partitioning rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanWidenDetail {
    Intersect,
    CrossDomainSource,
    DecoratorBindings,
    RegistrationDependentStep,
    FilePublicationSource,
    UnionNonProjectSuffix,
    UnionMixedComparatorFamilies,
    UnionAbsentMemberLeaf,
    UnionNestedSet,
    ExceptNonLeafMinuend,
    ExceptNonSeedBranch,
    ExceptRowsLeaveSeedFile,
    ExceptNonFileKeyedRows,
    ExceptNonLocalSuffix,
    DivisorOverflow,
    ClassSetWorkspacePreparation,
    AbsentMemberWorkspacePreparation,
    TypestateSetSource,
}

impl PlanWidenDetail {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Intersect => "intersect",
            Self::CrossDomainSource => "cross_domain_source",
            Self::DecoratorBindings => "decorator_bindings",
            Self::RegistrationDependentStep => "registration_dependent_step",
            Self::FilePublicationSource => "file_publication_source",
            Self::UnionNonProjectSuffix => "union_non_project_suffix",
            Self::UnionMixedComparatorFamilies => "union_mixed_comparator_families",
            Self::UnionAbsentMemberLeaf => "union_absent_member_leaf",
            Self::UnionNestedSet => "union_nested_set",
            Self::ExceptNonLeafMinuend => "except_non_leaf_minuend",
            Self::ExceptNonSeedBranch => "except_non_seed_branch",
            Self::ExceptRowsLeaveSeedFile => "except_rows_leave_seed_file",
            Self::ExceptNonFileKeyedRows => "except_non_file_keyed_rows",
            Self::ExceptNonLocalSuffix => "except_non_local_suffix",
            Self::DivisorOverflow => "divisor_overflow",
            Self::ClassSetWorkspacePreparation => "class_set_workspace_preparation",
            Self::AbsentMemberWorkspacePreparation => "absent_member_workspace_preparation",
            Self::TypestateSetSource => "typestate_set_source",
        }
    }
}

impl serde::Serialize for PlanWidenDetail {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.stable_label())
    }
}

impl PlanPartitioning {
    /// Classify `plan` from its source kind and its steps.
    ///
    /// Set plans are `Whole` unless they are unions whose leaves are all
    /// seed-partitionable, use one comparator family, and whose only set-node
    /// suffixes are projections. Projection retains the first representative's
    /// payload and only renames its fields. A filter must run after identity
    /// deduplication and evidence merging: even compatible branch schemas can
    /// expose different values for the same identity. Leaf-local filters still
    /// run before the set and remain eligible. The remaining shapes are `Whole`:
    ///
    /// - An intersect source, an except that [`Self::classify_except`] does not
    ///   accept, or a union with a non-distributive suffix. Those operators
    ///   consume cross-seed membership or a deduplicated set of branch rows, so
    ///   their result cannot be reconstructed from independent seed rows.
    ///   A union with an `absent_member` step is also whole because its root
    ///   evidence payload is merged by representative selection rather than by
    ///   traces alone. Eligible unions handle their fair-budget retry boundary
    ///   in the merged unit cap proof below.
    /// - A `decorator_bindings` step. Its rows carry
    ///   `DetailedCodeQueryDecoratedParameterEvidence`, runtime-only semantic
    ///   identity that is deliberately outside the serializable row model, so a
    ///   unit product cannot carry it.
    /// - A cross-domain source (`correlate`, `require_both`). A correlation
    ///   pairs rows from different files and a satisfaction check reads both
    ///   whole inputs, so neither result is a concatenation of per-seed rows.
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
        match &plan.source {
            CodeQueryPlanSource::Set {
                op: SetOperator::Intersect,
                ..
            } => Self::Whole(PlanWidenDetail::Intersect),
            CodeQueryPlanSource::Set {
                op: SetOperator::Except,
                ..
            } => match Self::classify_except_with_detail(plan) {
                Ok(_) => Self::BySeedExcept,
                Err(detail) => Self::Whole(detail),
            },
            CodeQueryPlanSource::Set { .. } => match Self::classify_union_with_detail(plan) {
                Ok(_) => Self::BySeedUnion,
                Err(detail) => Self::Whole(detail),
            },
            _ => Self::classify_leaf(plan),
        }
    }

    /// Whether one file's rows of `plan` are the rows of `plan` executed with
    /// its seed enumeration narrowed to that file, for a consumer that reads
    /// one file's rows at a time and merges nothing across files: the taint
    /// composition's frontier, which binds the endpoints of one blob.
    ///
    /// This differs from [`Self::classify`] on purpose. A unit's per-seed
    /// rows must merge into the whole execution's rows exactly, with their
    /// order, first-writer deduplication and cross-seed membership, so units
    /// accept only the excepts whose merged order is a seed order
    /// ([`Self::classify_except`]). A
    /// consumer of one file needs only that file's rows. A set-difference key
    /// that names the row's file (structural matches, occurrences, bindings,
    /// files: `PipelineKey` in `structural/search/mod.rs`; Python rule facts,
    /// whose ids fold the row file's path) makes `A except B`
    /// restricted to one file the difference of `A` and `B` restricted to that
    /// file, so the narrowed execution answers it when both branches do.
    /// Every other plan answers it exactly when [`Self::classify`] slices it.
    /// The reading that a by-seed plan's rows of one file are the rows of
    /// that file's seeds is the one the frontier already takes for a plan
    /// without sets.
    /// It holds only while each row lies in the file of the seed that
    /// produced it, so a plan with a step that can move its rows out
    /// of the seed file ([`QueryStepOp::rows_may_leave_seed_file`]) in any branch is not
    /// restricted: the consumer evaluates it once over the workspace and
    /// indexes the rows by where they lie.
    pub fn restricts_to_seed_file(plan: &CodeQueryPlan) -> bool {
        let mut pending = vec![plan];
        while let Some(current) = pending.pop() {
            // A step whose rows can lie in another file than their seed's
            // makes file F's rows not the rows of F's seeds, so the narrowed
            // execution of F answers a different question.
            if current
                .steps
                .iter()
                .any(|step| step.op().rows_may_leave_seed_file())
            {
                return false;
            }
            match &current.source {
                CodeQueryPlanSource::Set {
                    op: SetOperator::Except,
                    branches,
                } => {
                    let row_local_suffix = current.steps.iter().all(|step| {
                        matches!(step.op(), QueryStepOp::Filter | QueryStepOp::Project)
                    });
                    let file_keyed = matches!(
                        branches
                            .first()
                            .expect("a set operation has branches")
                            .value_kind(),
                        QueryValueKind::StructuralMatch
                            | QueryValueKind::Occurrence
                            | QueryValueKind::Binding
                            | QueryValueKind::File
                            | QueryValueKind::PythonRuleFact
                    );
                    if !(row_local_suffix && file_keyed) {
                        return false;
                    }
                    pending.extend(branches);
                }
                _ => {
                    if !Self::classify(current).is_by_seed() {
                        return false;
                    }
                    pending.extend(current.source.child_plans());
                }
            }
        }
        true
    }

    /// Whether this plan may be executed one seed file at a time.
    pub const fn is_by_seed(self) -> bool {
        matches!(self, Self::BySeed | Self::BySeedUnion | Self::BySeedExcept)
    }

    /// Whether this plan is an eligible all-union composition.
    pub const fn is_seed_union(self) -> bool {
        matches!(self, Self::BySeedUnion)
    }

    fn classify_leaf(plan: &CodeQueryPlan) -> Self {
        if plan.source.uses_only_file_facts()
            || matches!(
                &plan.source,
                CodeQueryPlanSource::Correlate(_) | CodeQueryPlanSource::RequireBoth(_)
            )
            || plan.steps.iter().any(|step| {
                step.op() == QueryStepOp::DecoratorBindings || step.op().is_registration_dependent()
            })
        {
            Self::Whole(if plan.source.uses_only_file_facts() {
                PlanWidenDetail::FilePublicationSource
            } else if matches!(
                &plan.source,
                CodeQueryPlanSource::Correlate(_) | CodeQueryPlanSource::RequireBoth(_)
            ) {
                PlanWidenDetail::CrossDomainSource
            } else if plan
                .steps
                .iter()
                .any(|step| step.op() == QueryStepOp::DecoratorBindings)
            {
                PlanWidenDetail::DecoratorBindings
            } else {
                PlanWidenDetail::RegistrationDependentStep
            })
        } else {
            Self::BySeed
        }
    }

    /// Validate the restricted union shape and return its checked fair-share
    /// divisor. Every set node must be a union with only projection suffixes,
    /// and every leaf must be a seed-partitionable plan with the same
    /// seed ordering family.
    pub(crate) fn classify_union(plan: &CodeQueryPlan) -> Option<usize> {
        Self::classify_union_with_detail(plan).ok()
    }

    fn classify_union_with_detail(plan: &CodeQueryPlan) -> Result<usize, PlanWidenDetail> {
        let CodeQueryPlanSource::Set { .. } = &plan.source else {
            unreachable!("union classifier requires a set source");
        };

        let mut pending = vec![(plan, true)];
        let mut leaves = 0usize;
        let mut comparator = None;
        while let Some((current, root)) = pending.pop() {
            match &current.source {
                CodeQueryPlanSource::Set { op, branches } => {
                    if *op != SetOperator::Union {
                        return Err(if root {
                            PlanWidenDetail::Intersect
                        } else {
                            PlanWidenDetail::UnionNestedSet
                        });
                    }
                    if current
                        .steps
                        .iter()
                        .any(|step| step.op() != QueryStepOp::Project)
                    {
                        return Err(PlanWidenDetail::UnionNonProjectSuffix);
                    }
                    pending.extend(branches.iter().rev().map(|branch| (branch, false)));
                }
                _ => {
                    if current
                        .steps
                        .iter()
                        .any(|step| step.op() == QueryStepOp::AbsentMember)
                    {
                        return Err(PlanWidenDetail::UnionAbsentMemberLeaf);
                    }
                    if let Self::Whole(detail) = Self::classify_leaf(current) {
                        return Err(detail);
                    }
                    let leaf_comparator = matches!(&current.source, CodeQueryPlanSource::Seed(_));
                    if comparator.is_some_and(|known| known != leaf_comparator) {
                        return Err(PlanWidenDetail::UnionMixedComparatorFamilies);
                    }
                    comparator = Some(leaf_comparator);
                    leaves = leaves
                        .checked_add(1)
                        .ok_or(PlanWidenDetail::DivisorOverflow)?;
                }
            }
        }
        assert_ne!(leaves, 0, "a parsed set source has at least one leaf");
        Self::fair_share_divisor(plan).ok_or(PlanWidenDetail::DivisorOverflow)
    }

    fn classify_except_with_detail(plan: &CodeQueryPlan) -> Result<usize, PlanWidenDetail> {
        let Some(minuend) = Self::except_minuend_leaf(plan) else {
            unreachable!("except classifier requires an except source");
        };
        if matches!(&minuend.source, CodeQueryPlanSource::Set { .. }) {
            return Err(PlanWidenDetail::ExceptNonLeafMinuend);
        }
        if let Self::Whole(detail) = Self::classify_leaf(minuend) {
            return Err(detail);
        }
        let mut pending = vec![plan];
        while let Some(current) = pending.pop() {
            if current
                .steps
                .iter()
                .any(|step| step.op().rows_may_leave_seed_file())
            {
                return Err(PlanWidenDetail::ExceptRowsLeaveSeedFile);
            }
            if let CodeQueryPlanSource::Set {
                op: SetOperator::Except,
                branches,
            } = &current.source
            {
                if current
                    .steps
                    .iter()
                    .any(|step| !matches!(step.op(), QueryStepOp::Filter | QueryStepOp::Project))
                {
                    return Err(PlanWidenDetail::ExceptNonLocalSuffix);
                }
                let file_keyed = matches!(
                    branches
                        .first()
                        .expect("a set operation has branches")
                        .value_kind(),
                    QueryValueKind::StructuralMatch
                        | QueryValueKind::Occurrence
                        | QueryValueKind::Binding
                        | QueryValueKind::File
                        | QueryValueKind::PythonRuleFact
                );
                if !file_keyed {
                    return Err(PlanWidenDetail::ExceptNonFileKeyedRows);
                }
                pending.extend(branches);
            } else {
                if !Self::classify(current).is_by_seed() {
                    return Err(PlanWidenDetail::ExceptNonSeedBranch);
                }
                pending.extend(current.source.child_plans());
            }
        }
        Self::fair_share_divisor(plan).ok_or(PlanWidenDetail::DivisorOverflow)
    }

    /// The plan whose rows an `except` keeps, following nested excepts through
    /// their minuends, or `None` when `plan` is not an except. Every except
    /// keeps its minuend's rows in its minuend's order, so this plan's seed
    /// family orders the whole difference.
    pub(crate) fn except_minuend_leaf(plan: &CodeQueryPlan) -> Option<&CodeQueryPlan> {
        let CodeQueryPlanSource::Set {
            op: SetOperator::Except,
            ..
        } = &plan.source
        else {
            return None;
        };
        let mut minuend = plan;
        while let CodeQueryPlanSource::Set {
            op: SetOperator::Except,
            branches,
        } = &minuend.source
        {
            minuend = branches.first().expect("a set operation has branches");
        }
        Some(minuend)
    }

    /// The largest product of branch counts along any path from `plan` to a
    /// non-set leaf.
    ///
    /// The executor gives each set branch a fair share of the cumulative
    /// limits left when it starts, so a branch nested under these sets can be
    /// cut at a `1/divisor` share of a lane. Merged units below that share
    /// prove no branch of the whole execution reached its own.
    pub(crate) fn fair_share_divisor(plan: &CodeQueryPlan) -> Option<usize> {
        let mut pending = vec![(plan, 1usize)];
        let mut maximum_divisor = 1usize;
        while let Some((current, divisor)) = pending.pop() {
            if let CodeQueryPlanSource::Set { branches, .. } = &current.source {
                let next_divisor = divisor.checked_mul(branches.len())?;
                maximum_divisor = maximum_divisor.max(next_divisor);
                pending.extend(branches.iter().map(|branch| (branch, next_divisor)));
            }
        }
        Some(maximum_divisor)
    }

    /// Return the non-set leaves and their full branch paths for an eligible
    /// union. Project-only set-node suffixes are appended to each descendant
    /// leaf in execution order, so unit execution applies the same row-local
    /// transformation before the global branch-order merge. Each tuple also
    /// carries the inherited suffix length: diagnostic selection must preserve
    /// the original leaf boundary even though those steps now execute locally.
    /// The traversal is
    /// iterative so query depth cannot consume the Rust call stack.
    pub(crate) fn union_leaf_plans(
        plan: &CodeQueryPlan,
    ) -> Option<Vec<(CodeQueryPlan, Vec<usize>, usize)>> {
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
                    let inherited_suffix_steps = inherited_steps.len();
                    leaf.steps.extend(inherited_steps);
                    leaves.push((leaf, path, inherited_suffix_steps));
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
    use brokk_bifrost_test_macros::hardwon;
    use serde_json::{Value, json};

    fn plan(query: Value) -> CodeQueryPlan {
        CodeQuery::from_json(&query)
            .expect("query should parse")
            .plan
    }

    #[test]
    #[hardwon("#3394+#2586: field-index work must be hoisted without disabling seed partitioning")]
    fn field_index_requirement_is_separate_from_seed_partitionability() {
        for operation in ["class_set", "absent_member"] {
            let plan = plan(json!({
                "match": { "kind": "function" },
                "steps": [{ "op": "procedure_of" }, { "op": operation }]
            }));
            assert!(plan.requires_workspace_field_index().is_some());
            assert_eq!(PlanPartitioning::classify(&plan), PlanPartitioning::BySeed);
        }
    }

    #[test]
    #[hardwon("#3394+#2586: a nested field-index branch must trigger one workspace prepass")]
    fn nested_set_branch_retains_its_workspace_field_requirement() {
        let field = json!({
            "match": { "kind": "function" },
            "steps": [{ "op": "procedure_of" }, { "op": "class_set" }, { "op": "file_of" }]
        });
        let simple = json!({ "match": { "kind": "function" }, "steps": [{ "op": "file_of" }] });
        let plan = plan(json!({
            "union": [simple.clone(), { "union": [simple, field] }]
        }));
        assert!(plan.requires_workspace_field_index().is_some());
        assert_eq!(
            PlanPartitioning::classify(&plan),
            PlanPartitioning::BySeedUnion
        );
    }

    #[test]
    #[hardwon("#3394+#2586: ordinary sliced derivations must not trigger the field-index prepass")]
    fn ordinary_derived_queries_do_not_require_workspace_field_preparation() {
        let plan = plan(json!({
            "union": [
                { "match": { "kind": "function" }, "steps": [{ "op": "enclosing_decl" }, { "op": "callers" }, { "op": "file_of" }] },
                { "match": { "kind": "function" }, "steps": [{ "op": "file_of" }] }
            ]
        }));
        assert!(plan.requires_workspace_field_index().is_none());
        assert_eq!(
            PlanPartitioning::classify(&plan),
            PlanPartitioning::BySeedUnion
        );
    }

    #[test]
    #[hardwon("#5294+#5310: project-only union decomposition must retain original leaf boundaries")]
    fn union_projections_preserve_leaf_filters_and_boundaries() {
        let plan = plan(json!({
            "union": [
                {
                    "occurrences": { "class": "reference" },
                    "steps": [{ "op": "filter", "where": [{ "field": "target_id", "op": "is_not_null" }] }]
                },
                {
                    "occurrences": { "class": "reference" },
                    "steps": [{ "op": "filter", "where": [{ "field": "target_id", "op": "is_not_null" }] }]
                }
            ],
            "steps": [
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
        for (leaf, _, inherited_suffix_steps) in leaves {
            assert_eq!(inherited_suffix_steps, 1);
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
        assert!(matches!(
            PlanPartitioning::classify(&plan),
            PlanPartitioning::Whole(_)
        ));
    }

    #[test]
    #[hardwon("#5310: filters at any union node must observe merged first-writer representatives")]
    fn filters_at_root_or_nested_union_nodes_require_whole_execution() {
        let leaf = json!({ "match": { "kind": "function" } });
        let filtered = json!({
            "union": [leaf.clone(), leaf.clone()],
            "steps": [{ "op": "filter", "where": [{ "field": "name", "op": "is_not_null" }] }]
        });
        for query in [filtered.clone(), json!({ "union": [filtered, leaf] })] {
            let plan = plan(query);
            assert!(matches!(
                PlanPartitioning::classify(&plan),
                PlanPartitioning::Whole(_)
            ));
            assert!(PlanPartitioning::union_leaf_plans(&plan).is_none());
        }
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
        assert!(matches!(
            PlanPartitioning::classify(&plan),
            PlanPartitioning::Whole(_)
        ));
    }

    #[test]
    fn an_except_partitions_only_when_its_minuend_orders_file_keyed_rows_by_seed() {
        let leaf = json!({ "match": { "kind": "function" } });
        let intersect = plan(json!({ "intersect": [leaf.clone(), leaf.clone()] }));
        assert!(matches!(
            PlanPartitioning::classify(&intersect),
            PlanPartitioning::Whole(_)
        ));

        let except = plan(json!({ "except": [leaf.clone(), leaf.clone()] }));
        assert_eq!(
            PlanPartitioning::classify(&except),
            PlanPartitioning::BySeedExcept
        );
        assert_eq!(PlanPartitioning::fair_share_divisor(&except), Some(2));
        // A union subtrahend is only a membership set, so it may nest; the
        // fair share divides along the deepest path.
        let union_subtrahend = plan(json!({
            "except": [leaf.clone(), { "union": [leaf.clone(), leaf.clone(), leaf.clone()] }]
        }));
        assert_eq!(
            PlanPartitioning::classify(&union_subtrahend),
            PlanPartitioning::BySeedExcept
        );
        assert_eq!(
            PlanPartitioning::fair_share_divisor(&union_subtrahend),
            Some(6)
        );

        // A nested except keeps its own minuend's rows in seed order.
        let nested_minuend = plan(json!({
            "except": [{ "except": [leaf.clone(), leaf.clone()] }, leaf.clone()]
        }));
        assert_eq!(
            PlanPartitioning::classify(&nested_minuend),
            PlanPartitioning::BySeedExcept
        );
        assert_eq!(
            PlanPartitioning::fair_share_divisor(&nested_minuend),
            Some(4)
        );

        // A union minuend orders its rows branch-major across every file, and
        // a declaration's identity does not name its file.
        let union_minuend = plan(json!({
            "except": [{ "union": [leaf.clone(), leaf.clone()] }, leaf.clone()]
        }));
        assert!(PlanPartitioning::restricts_to_seed_file(&union_minuend));
        assert!(matches!(
            PlanPartitioning::classify(&union_minuend),
            PlanPartitioning::Whole(_)
        ));
        let declaration = json!({
            "match": { "kind": "function" },
            "steps": [{ "op": "enclosing_decl" }]
        });
        let declarations = plan(json!({ "except": [declaration.clone(), declaration] }));
        assert!(matches!(
            PlanPartitioning::classify(&declarations),
            PlanPartitioning::Whole(_)
        ));
    }

    #[test]
    fn an_except_of_file_keyed_rows_restricts_to_one_seed_file() {
        let leaf = json!({ "match": { "kind": "function" } });
        let except = plan(json!({ "except": [leaf.clone(), leaf.clone()] }));
        assert!(PlanPartitioning::restricts_to_seed_file(&except));
        let nested = plan(json!({
            "except": [{ "union": [leaf.clone(), leaf.clone()] }, { "except": [leaf.clone(), leaf.clone()] }]
        }));
        assert!(PlanPartitioning::restricts_to_seed_file(&nested));
        // A row whose identity does not name its file can be excluded by a
        // row of another file, and an intersection stays whole.
        let declarations = plan(json!({
            "except": [
                { "match": { "kind": "function" }, "steps": [{ "op": "enclosing_decl" }] },
                { "match": { "kind": "function" }, "steps": [{ "op": "enclosing_decl" }] }
            ]
        }));
        assert!(!PlanPartitioning::restricts_to_seed_file(&declarations));
        let intersect = plan(json!({ "intersect": [leaf.clone(), leaf] }));
        assert!(!PlanPartitioning::restricts_to_seed_file(&intersect));
    }

    #[test]
    #[hardwon(
        "#4863: a call-sites-to selector sliced by blob returned no rows at the callers' files"
    )]
    fn a_step_that_moves_rows_out_of_the_seed_file_does_not_restrict_to_one_seed_file() {
        let call_sites = plan(json!({
            "match": { "kind": "function" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "call_sites_to" }]
        }));
        assert_eq!(
            PlanPartitioning::classify(&call_sites),
            PlanPartitioning::BySeed
        );
        assert!(!PlanPartitioning::restricts_to_seed_file(&call_sites));
        let in_file = json!({
            "match": { "kind": "function" },
            "steps": [{ "op": "enclosing_decl" }]
        });
        assert!(PlanPartitioning::restricts_to_seed_file(&plan(
            in_file.clone()
        )));
        // A forward relation yields the related declaration, which can lie in
        // another file than the seed.
        for op in ["callers", "callees", "uses"] {
            let moved = json!({
                "match": { "kind": "function" },
                "steps": [{ "op": "enclosing_decl" }, { "op": op }]
            });
            assert!(
                !PlanPartitioning::restricts_to_seed_file(&plan(moved.clone())),
                "{op}"
            );
            let union = plan(json!({ "union": [in_file.clone(), moved] }));
            assert!(!PlanPartitioning::restricts_to_seed_file(&union), "{op}");
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
            assert!(matches!(
                PlanPartitioning::classify(&plan),
                PlanPartitioning::Whole(_)
            ));
        }
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
        assert!(matches!(
            PlanPartitioning::classify(&plan),
            PlanPartitioning::Whole(_)
        ));
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
            assert!(
                matches!(
                    PlanPartitioning::classify(&plan),
                    PlanPartitioning::Whole(_)
                ),
                "{steps} cannot be sliced by seed"
            );
        }
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
}
