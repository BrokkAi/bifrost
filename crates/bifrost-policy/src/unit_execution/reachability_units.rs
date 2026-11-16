//! Operand receipts own selection reads; continuations bind only typed outputs.
use super::*;
use brokk_bifrost_rql::query::{CodeQueryPlan, CodeQueryPlanSource};
use brokk_bifrost_rql::structural::search::{
    CallReachabilityOperands, CallReachabilitySourceProduct, execute_call_reachability_source,
};

fn question(query: &CodeQuery, budget: PolicyBudget, depth_opt_in: bool) -> StableDigest {
    // replay_caps exhaustively destructures every cap, including every semantic
    // and solver dimension. No pointer or operation-local identity enters this key.
    let grant = crate::budget::PolicyBatchBudget::default()
        .with_scaled_per_policy(budget)
        .replay_caps(Default::default());
    StableDigest::sha256(
        serde_json::to_vec(&(
            "bifrost.rql.call_reachability.source.question.v3",
            query.to_canonical_query_plan_json(),
            grant,
            depth_opt_in,
        ))
        .expect("canonical operand question is JSON"),
    )
}

fn output_digest(rows: &UnitExecutionResult) -> StableDigest {
    // Completeness and its typed causes belong to the output, unlike work,
    // timing and input receipts. A partial output can never bind as complete.
    let causes: Vec<_> = rows
        .diagnostics
        .iter()
        .map(|diagnostic| match diagnostic.incompleteness {
            brokk_bifrost_rql::Incompleteness::Content => "content",
            brokk_bifrost_rql::Incompleteness::ConfiguredCap => "configured_cap",
            brokk_bifrost_rql::Incompleteness::Operational(cause) => match cause {
                brokk_bifrost_rql::DiagnosticExecutionCause::Budget => "budget",
                brokk_bifrost_rql::DiagnosticExecutionCause::Cancelled => "cancelled",
                brokk_bifrost_rql::DiagnosticExecutionCause::Snapshot => "snapshot",
                brokk_bifrost_rql::DiagnosticExecutionCause::Provider => "provider",
            },
        })
        .collect();
    StableDigest::sha256(
        serde_json::to_vec(&(
            "bifrost.rql.operand.output.v1",
            &rows.rows,
            &rows.completion,
            rows.truncated,
            rows.depth_bound_status,
            &rows.depth_answers,
            &rows.diagnostics,
            causes,
        ))
        .expect("typed operand output is JSON"),
    )
}

type Product = CallReachabilitySourceProduct;

struct OperandSlice<'a> {
    query: &'a CodeQuery,
    execution: &'a UnitQueryExecution<'a>,
    prepared: Option<&'a Arc<CallReachabilityOperands>>,
}

impl UnitSlice for OperandSlice<'_> {
    type Capture<'a> = AnalyzerQueryScope<'a>;
    type Seed = Option<ProjectFile>;
    type Prefix = Product;
    type Error = std::convert::Infallible;
    type BudgetState = (
        brokk_bifrost_rql::structural::search::CodeQueryExecutionWork,
        brokk_bifrost_rql::structural::CodeQueryBudgetedWork,
    );
    type Allowance = CodeQueryExecutionLimits;
    type Merged = Vec<Product>;
    type Output = (Vec<Product>, usize);

    fn remaining(&self, state: &Self::BudgetState) -> Option<Self::Allowance> {
        remaining_unit_limits(self.execution.limits, &state.0, &state.1)
    }
    fn prefix(
        &self,
        seed: &Self::Seed,
        allowance: Self::Allowance,
    ) -> Result<Product, Self::Error> {
        let scope = match seed {
            Some(seed) => CodeQueryExecutionScope::for_seed_files(
                std::slice::from_ref(seed),
                self.execution.workspace_files,
            ),
            None => CodeQueryExecutionScope::whole_workspace(),
        }
        .with_depth_bound_status(self.execution.depth_opt_in);
        let scope = match self.prepared {
            Some(prepared) => scope.with_call_reachability_operands(Arc::clone(prepared)),
            None => scope,
        };
        Ok(execute_call_reachability_source(
            self.execution.analyzer,
            self.execution.flow_state.clone(),
            self.execution.workspace,
            self.query,
            allowance,
            self.execution.cancellation,
            scope,
        ))
    }

    fn decode(
        &self,
        seed: &Self::Seed,
        product: PolicyUnitProduct,
        reads: &[ReadKey],
    ) -> Result<Product, UnitDecodeError> {
        let PolicyUnitProduct::Prefix(json) = product else {
            return Err(UnitDecodeError::Corrupt);
        };
        let json = serde_json::from_str(&json).map_err(|_| UnitDecodeError::Corrupt)?;
        CallReachabilitySourceProduct::decode(
            self.execution.analyzer,
            self.execution.workspace,
            self.execution.limits,
            &self.query.plan,
            seed.clone().ok_or(UnitDecodeError::Corrupt)?,
            reads.to_vec(),
            json,
        )
        .map_err(|_| UnitDecodeError::Corrupt)
    }
    fn encode(&self, product: &Product) -> PolicyUnitProduct {
        let json = product
            .encode(&self.query.plan)
            .expect("publishable source has a native encoding");
        PolicyUnitProduct::Prefix(json.to_string())
    }

    fn charge(&self, state: &mut Self::BudgetState, product: &Product) {
        charge_shared_slice_budget(state, product.result.work, &product.result.budgeted_work);
    }
    fn fits(&self, state: &Self::BudgetState, product: &Product) -> bool {
        self.remaining(state).is_some_and(|grant| {
            product
                .result
                .reached_ordinary_plan_limit(self.query, &grant)
                .is_none()
        })
    }
    fn capture<'a>(&self, analyzer: &'a dyn IAnalyzer) -> Self::Capture<'a> {
        AnalyzerQueryScope::capturing_read_incompleteness(analyzer)
    }
    fn after_recompute(
        &self,
        product: &mut Product,
        scope: &Self::Capture<'_>,
        cancellation: Option<&CancellationToken>,
    ) {
        fold_unit_execution_state(&mut product.result, scope, cancellation);
    }
    fn set_reads(&self, product: &mut Product, reads: &[ReadKey]) {
        product.set_reads(reads);
    }
    fn publishable(&self, product: &Product) -> bool {
        product.result.completion == brokk_bifrost_rql::CodeQueryCompletion::Complete
            && check_exhaustive_rows(&product.result).is_ok()
            && product.encode(&self.query.plan).is_ok()
    }

    fn reuse_verdict(&self, result: &Result<Product, Self::Error>) -> ReuseVerdict {
        match result {
            Ok(product) => product.result.reuse,
            Err(error) => match *error {},
        }
    }
    fn failure(&self, error: Self::Error, _: Vec<Product>) -> Self::Output {
        match error {}
    }
    fn merge(&self, products: impl IntoIterator<Item = Product>) -> Self::Merged {
        products.into_iter().collect()
    }
    fn suffix(&self, products: Self::Merged, skipped: usize) -> Self::Output {
        (products, skipped)
    }
}

// Intermediate rows stay with the typed operand. The final merge needs only
// its work and completion, rather than another copy of all selected endpoints.
fn work_metadata(rows: &UnitExecutionResult) -> UnitExecutionResult {
    UnitExecutionResult {
        except_left_complete_empty: rows.except_left_complete_empty,
        rows: Vec::new(),
        work: rows.work,
        budgeted_work: rows.budgeted_work.clone(),
        completion: rows.completion.clone(),
        depth_bound_status: rows.depth_bound_status,
        depth_answers: rows.depth_answers.clone(),
        diagnostics: rows.diagnostics.clone(),
        truncated: rows.truncated,
        reuse: rows.reuse,
    }
}

fn ordinary_query(query: &CodeQuery, plan: &CodeQueryPlan) -> CodeQuery {
    CodeQuery {
        plan: plan.clone(),
        limit: usize::MAX,
        result_detail: brokk_bifrost_rql::query::CodeQueryResultDetail::Full,
        execution_mode: brokk_bifrost_rql::query::CodeQueryExecutionMode::Results,
        ..query.clone()
    }
}

fn operators(plan: &CodeQueryPlan) -> Vec<&brokk_bifrost_rql::query::CallReachability> {
    let mut pending = vec![plan];
    let mut operators = Vec::new();
    while let Some(plan) = pending.pop() {
        if let CodeQueryPlanSource::CallReachability(operator) = &plan.source {
            operators.push(operator.as_ref());
            // Each sink is an independent ordinary-plan operand; it owns any
            // projecting operators inside that plan. Source-side operators
            // share the same sink questions and are prepared bottom-up.
            pending.push(&operator.sources);
        } else {
            pending.extend(plan.source.child_plans().into_iter().rev());
        }
    }
    operators
}

pub(super) fn has_operator(plan: &CodeQueryPlan) -> bool {
    !operators(plan).is_empty()
}

fn seed_key(
    file: &ProjectFile,
    prefix: (StableDigest, StableDigest),
    reuse: &UnitReuse<'_>,
    partition: &impl Fn(SeedPartition) -> UnitPartition,
    policy: &LoadedPolicy,
) -> Result<PolicyUnitKey, WidenReason> {
    let language = language_for_file(file);
    let rel_path = rel_path_string(file);
    let blob = reuse
        .incremental
        .changed()
        .head_blob(language, &rel_path)
        .ok_or(WidenReason::ReverseDependencyEvidenceMissing)?;
    Ok(reuse.incremental.inputs().unit_key(
        policy,
        partition(SeedPartition {
            language,
            rel_path,
            blob,
            prefix: Some(prefix),
        }),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn sliced(
    policy: &LoadedPolicy,
    query: &CodeQuery,
    reuse: &mut UnitReuse<'_>,
    execution: &UnitQueryExecution<'_>,
    partition: impl Fn(SeedPartition) -> UnitPartition,
    attempt: &mut UnitAttempt,
    seeds: &[ProjectFile],
) -> Result<SlicedQuery, WidenReason> {
    #[cfg(feature = "test-support")]
    if brokk_bifrost_rql::structural::search::call_reachability_global_reference_active(
        execution.analyzer.project().root(),
    ) {
        return Err(WidenReason::WorkspacePreparationRequired);
    }
    if query.plan.requires_shared_reachability_dependencies() {
        // Reuse the established whole-policy funnel. Native dependency rows
        // must not cross independent semantic contexts or repeat per seed.
        // The policy-substrate epoch and canonical policy plan key this route.
        return Err(WidenReason::WorkspacePreparationRequired);
    }
    let operators = operators(&query.plan);
    let budget = PolicyBudget::builder()
        .with_query_limits(execution.limits)
        .expect("validated query grant")
        .build()
        .expect("validated policy grant");
    let mut state = Default::default();
    let mut keys = Vec::new();
    let mut skipped = 0;
    let mut operand_rows = Vec::new();
    let mut source_units_attempted = 0usize;
    let mut source_units_skipped = 0usize;

    // Select sources before admitting any traversal or sink dependency work.
    // Each continuation owns the demanded sink reads it actually consumes.
    let source_cut = StableDigest::sha256("bifrost.rql.call_reachability.source.v2");
    let continuation_cut = StableDigest::sha256("bifrost.rql.call_reachability.continuation.v2");
    let mut continuations = Vec::new();
    for file in seeds {
        let mut prepared = Arc::new(CallReachabilityOperands::default());
        let mut source_digests = Vec::new();
        let mut source_questions = HashMap::default();
        let mut seed_complete = true;
        let mut empty = true;
        let mut missing_source = false;
        for operator in operators.iter().rev() {
            let ordinary = ordinary_query(query, &operator.sources);
            let question = question(&ordinary, budget, execution.depth_opt_in);
            if source_questions.insert(question, ()).is_some() {
                continue;
            }
            let input = if has_operator(&ordinary.plan) {
                StableDigest::sha256(
                    serde_json::to_vec(&(question, &source_digests))
                        .expect("nested source operands bind validated child outputs"),
                )
            } else {
                question
            };
            let key = seed_key(file, (source_cut, input), reuse, &partition, policy)?;
            reuse.prefetch(std::slice::from_ref(&key), None)?;
            let slice = OperandSlice {
                query: &ordinary,
                execution,
                prepared: Some(&prepared),
            };
            source_units_attempted += 1;
            let (products, omitted) = evaluate_reusable_slice_with_state(
                &slice,
                [(Some(file.clone()), &key)],
                &mut state,
                reuse,
                attempt,
                execution.analyzer,
                execution.cancellation,
            )?;
            skipped += omitted;
            source_units_skipped += omitted;
            keys.push(key);
            let Some(product) = products.into_iter().next() else {
                missing_source = true;
                continue;
            };
            empty &= product.result.rows.is_empty();
            seed_complete &=
                product.result.completion == brokk_bifrost_rql::CodeQueryCompletion::Complete;
            source_digests.push(output_digest(&product.result));
            operand_rows.push(work_metadata(&product.result));
            Arc::get_mut(&mut prepared)
                .expect("operand execution releases its scope")
                .insert_source(&operator.sources, product);
        }
        // Only the bare operator is guaranteed empty from empty sources.
        // Independent set branches and suffixes must still execute.
        let exact_empty = empty
            && seed_complete
            && matches!(query.plan.source, CodeQueryPlanSource::CallReachability(_))
            && query.plan.steps.is_empty();
        if missing_source || skipped > 0 || exact_empty {
            continue;
        }
        let input = StableDigest::sha256(
            serde_json::to_vec(&source_digests).expect("typed operand outputs serialize"),
        );
        let key = seed_key(file, (continuation_cut, input), reuse, &partition, policy)?;
        let complete = seed_complete;
        reuse.prefetch(
            std::slice::from_ref(&key),
            Some(brokk_bifrost_rql::structural::unit_plan_node_count(query)),
        )?;
        let slice = FileQuerySlice {
            query,
            execution,
            execute: |(file, grant)| {
                execute_code_query_unit(
                    execution.analyzer,
                    execution.flow_state.clone(),
                    execution.workspace,
                    query,
                    grant,
                    execution.cancellation,
                    CodeQueryExecutionScope::for_seed_files(
                        std::slice::from_ref(file),
                        execution.workspace_files,
                    )
                    .with_depth_bound_status(execution.depth_opt_in)
                    .with_call_reachability_operands(Arc::clone(&prepared)),
                )
            },
        };
        let guarded = ContinuationSlice {
            inner: slice,
            complete,
        };
        let (products, omitted) = evaluate_reusable_slice_with_state(
            &guarded,
            [(file, &key)],
            &mut state,
            reuse,
            attempt,
            execution.analyzer,
            execution.cancellation,
        )?;
        skipped += omitted;
        continuations.extend(products);
        keys.push(key);
    }
    brokk_bifrost_core::profiling::note_with(|| {
        format!(
            "call_reachability.source_units files={} attempted={source_units_attempted} completed={} skipped={source_units_skipped} continuation_products={} continuation_skipped={}",
            seeds.len(),
            operand_rows.len(),
            continuations.len(),
            skipped.saturating_sub(source_units_skipped),
        )
    });
    // The retained union merger requires authored representative-branch paths.
    // Non-structural ordinary branches may legitimately have no provenance.
    // Refuse that merge through the established full-execution funnel; never
    // invent a branch, reorder the first writer, or silently omit its row.
    let partitioning = PlanPartitioning::classify(&query.plan);
    if (partitioning.is_seed_union() || partitioning == PlanPartitioning::BySeedSetUnion)
        && continuations
            .iter()
            .flat_map(|product| &product.rows)
            .any(|row| {
                row.item
                    .provenance
                    .first()
                    .is_none_or(|trace| trace.branch.is_empty())
            })
    {
        return Err(WidenReason::PlanCrossesSeeds);
    }
    // Fold only continuation rows. Operand work and incompleteness remain
    // visible, but their intermediate selected rows are never final answers.
    let mut merged = merge_unit_rows_in_scope(
        query,
        continuations,
        CodeQueryExecutionScope::whole_workspace().with_depth_bound_status(execution.depth_opt_in),
    );
    for result in operand_rows {
        merged.work = merged.work.saturating_add(result.work);
        let mut shared = result.budgeted_work;
        shared.step_outputs = match (&shared.step_outputs, &merged.budgeted_work.step_outputs) {
            (Some(_), Some(counts)) => Some(vec![0; counts.len()]),
            _ => None,
        };
        merged.budgeted_work = merged.budgeted_work.saturating_add(&shared);
        merged.diagnostics.extend(result.diagnostics);
        if let Some(observed) = result.depth_bound_status {
            merged.depth_bound_status = Some(
                merged
                    .depth_bound_status
                    .map_or(observed, |prior| prior.join(observed)),
            );
        }
        if result.truncated || result.completion != brokk_bifrost_rql::CodeQueryCompletion::Complete
        {
            merged.mark_truncated();
        }
    }
    if skipped > 0 {
        merged.mark_truncated();
        push_skipped_unit_diagnostic(
            &mut merged.diagnostics,
            skipped,
            execution.limits,
            &merged.work,
            &merged.budgeted_work,
        );
    }
    // Each source ran as an independent query, so their counts add up to the
    // whole plan's census only when every operator sits on the anchor spine:
    // the root source, then the source of that source, and so on. An operator
    // inside a set operand may be an excluded one (the right side of an except)
    // or overlap another branch's sources, and the sum cannot tell. Say that
    // the count was not measured rather than publish a number that could show
    // candidates the rule can never report.
    let mut spine = 0;
    let mut cursor = &query.plan;
    while let CodeQueryPlanSource::CallReachability(operator) = &cursor.source {
        spine += 1;
        cursor = &operator.sources;
    }
    if spine != operators.len() {
        merged.budgeted_work.candidate_sites = None;
    }
    merged.apply_result_limit(query.limit);
    Ok(SlicedQuery { merged, keys })
}

/// The usual final-row slice with one extra admission condition: every bound
/// operand is complete. Own traversal receipts are captured by the usual slice.
struct ContinuationSlice<'a, F> {
    inner: FileQuerySlice<'a, F>,
    complete: bool,
}

impl<'a, F> UnitSlice for ContinuationSlice<'a, F>
where
    F: Fn((&'a ProjectFile, CodeQueryExecutionLimits)) -> UnitExecutionResult,
{
    type Capture<'b> = AnalyzerQueryScope<'b>;
    type Seed = &'a ProjectFile;
    type Prefix = UnitExecutionResult;
    type Error = std::convert::Infallible;
    type BudgetState = (
        brokk_bifrost_rql::structural::search::CodeQueryExecutionWork,
        brokk_bifrost_rql::structural::CodeQueryBudgetedWork,
    );
    type Allowance = CodeQueryExecutionLimits;
    type Merged = Vec<UnitExecutionResult>;
    type Output = (Vec<UnitExecutionResult>, usize);
    fn remaining(&self, state: &Self::BudgetState) -> Option<Self::Allowance> {
        self.inner.remaining(state)
    }
    fn prefix(
        &self,
        seed: &Self::Seed,
        grant: Self::Allowance,
    ) -> Result<Self::Prefix, Self::Error> {
        self.inner.prefix(seed, grant)
    }
    fn decode(
        &self,
        seed: &Self::Seed,
        product: PolicyUnitProduct,
        reads: &[ReadKey],
    ) -> Result<Self::Prefix, UnitDecodeError> {
        if !self.complete {
            return Err(UnitDecodeError::Corrupt);
        }
        self.inner.decode(seed, product, reads)
    }
    fn encode(&self, product: &Self::Prefix) -> PolicyUnitProduct {
        self.inner.encode(product)
    }
    fn charge(&self, state: &mut Self::BudgetState, product: &Self::Prefix) {
        self.inner.charge(state, product);
    }
    fn fits(&self, state: &Self::BudgetState, product: &Self::Prefix) -> bool {
        self.inner.fits(state, product)
    }
    fn capture<'b>(&self, analyzer: &'b dyn IAnalyzer) -> Self::Capture<'b> {
        self.inner.capture(analyzer)
    }
    fn after_recompute(
        &self,
        product: &mut Self::Prefix,
        scope: &Self::Capture<'_>,
        cancel: Option<&CancellationToken>,
    ) {
        self.inner.after_recompute(product, scope, cancel);
    }
    fn publishable(&self, product: &Self::Prefix) -> bool {
        self.complete && self.inner.publishable(product)
    }
    fn reuse_verdict(&self, result: &Result<Self::Prefix, Self::Error>) -> ReuseVerdict {
        self.inner.reuse_verdict(result)
    }
    fn failure(&self, error: Self::Error, _: Vec<Self::Prefix>) -> Self::Output {
        match error {}
    }
    fn merge(&self, products: impl IntoIterator<Item = Self::Prefix>) -> Self::Merged {
        products.into_iter().collect()
    }
    fn suffix(&self, products: Self::Merged, skipped: usize) -> Self::Output {
        (products, skipped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use std::hash::{Hash, Hasher};

    #[test]
    #[hardwon("#11552: different ordinary questions or grants must not share an operand unit")]
    fn source_questions_bind_plan_and_every_grant() {
        let query = CodeQuery::from_sexp("(language rust (function :name \"root\"))").unwrap();
        let other = CodeQuery::from_sexp("(language rust (function :name \"other\"))").unwrap();
        let full = PolicyBudget::default();
        let small = PolicyBudget::builder()
            .with_query_limits(CodeQueryExecutionLimits {
                max_scanned_files: 2,
                ..full.query_limits()
            })
            .unwrap()
            .build()
            .unwrap();
        let original = question(&query, full, false);
        assert_eq!(original, question(&query.clone(), full, false));
        assert_ne!(original, question(&other, full, false));
        assert_ne!(original, question(&query, small, false));
    }

    #[test]
    #[hardwon("#11552: a partial sink output must never bind as a complete operand")]
    fn operand_output_identity_includes_completeness_but_excludes_work() {
        let rows = UnitExecutionResult {
            except_left_complete_empty: None,
            rows: Vec::new(),
            work: Default::default(),
            budgeted_work: Default::default(),
            completion: brokk_bifrost_rql::CodeQueryCompletion::Complete,
            depth_bound_status: None,
            depth_answers: Vec::new(),
            diagnostics: Vec::new(),
            truncated: false,
            reuse: Default::default(),
        };
        let complete = output_digest(&rows);
        let mut changed = rows.clone();
        changed.work.scanned_files = 17;
        assert_eq!(complete, output_digest(&changed));
        changed.completion = brokk_bifrost_rql::CodeQueryCompletion::Incomplete {
            codes: vec![brokk_bifrost_rql::CodeQueryDiagnosticCode::ExecutionBudgetExhausted],
        };
        assert_ne!(complete, output_digest(&changed));
    }

    #[derive(Default)]
    struct Bytes(Vec<u8>);
    impl Hasher for Bytes {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    #[test]
    #[hardwon("#11552: adding Operand must leave existing root-cut prefix key bytes unchanged")]
    fn existing_root_cut_partition_key_bytes_stay_identical() {
        let language = Language::Rust;
        let rel_path: Box<str> = "src/root.rs".into();
        let blob = Oid::from_bytes(&[3; 20]).unwrap();
        let cut = StableDigest::sha256("bifrost.rql.root_set.cut.v2");
        let input = StableDigest::sha256("existing authored operand plans");
        let key = UnitPartition::Prefix {
            language,
            rel_path: rel_path.clone(),
            blob,
            cut,
            input,
        };
        // Prefix was discriminant 5 before Operand was appended. The original
        // field order and authored input digest are the old key byte contract.
        let mut before = Bytes::default();
        before.write_isize(5);
        language.hash(&mut before);
        rel_path.hash(&mut before);
        blob.hash(&mut before);
        cut.hash(&mut before);
        input.hash(&mut before);
        let mut after = Bytes::default();
        key.hash(&mut after);
        assert_eq!(before.0, after.0);
    }
}
