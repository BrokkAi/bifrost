//! Complete subject selections shared inside one serial coordinator batch.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

use brokk_bifrost_analysis::analyzer::ReadKey;
use brokk_bifrost_analysis::analyzer::capture_query_reads;
use brokk_bifrost_analysis::analyzer::content_identity::WorkspaceContentIdentity;
use brokk_bifrost_rql::structural::search::UnitExecutionResult;

use super::*;

/// A repeated query's identity inside the batch: its canonical JSON and whether
/// its consumer opts into depth-bound probing.
///
/// The same query text runs with the depth-bound subproduct for a match policy
/// that declares `inconclusive-on [depth_bound_reached]`, and without it for
/// every other consumer. A product computed without the subproduct must never
/// satisfy an opt-in consumer, so the opt-in bit is part of the key.
type QueryKey = (String, bool);

/// Bound to one immutable analyzer and the coordinator's pinned model scope.
///
/// A subject is the query a policy selects its rows with: a non-relational
/// assertion policy's subject selector, or a match policy's executable
/// selector. The full canonical query includes captures, authored union order,
/// filters, projection and execution controls. All query limits must also
/// match. The execution scope is always the whole workspace, or one seed file
/// of it on the unit path, and the selected AST-id set is always unrestricted:
/// this entry point cannot accept a row-family session or source selection. In
/// particular, consumer-correlated occurrence and scope products never enter
/// this cache.
///
/// Only queries with multiple consumers retain a product. Aggregate retained
/// rows, evidence records and dependency keys share one weight budget, bounded
/// by the batch's pipeline-row limit; exceeding it simply executes normally.
/// Rc shares the immutable subject rows without copying their owned evidence.
/// A reused product replays its dependency reads into every consumer's open
/// ledgers, so a unit served from here is published under exactly the reads
/// that its own execution would have recorded.
pub(crate) struct SubjectQueryBatch<'a> {
    analyzer: &'a dyn IAnalyzer,
    content: Option<WorkspaceContentIdentity>,
    limits: brokk_bifrost_rql::structural::CodeQueryExecutionLimits,
    repeated: HashSet<QueryKey>,
    retained: Mutex<RetainedProducts>,
}

/// Every product the batch holds, behind one lock so that reserving weight and
/// inserting a product are one critical section: two workers that both passed
/// the cap check would otherwise retain past the bound.
#[derive(Default)]
struct RetainedProducts {
    subjects: HashMap<QueryKey, Arc<SubjectProduct<Arc<ExecutedQueryRows>>>>,
    /// A match selector's unit executions, keyed by the seed file a sliced
    /// unit covers, or by `None` for the whole-workspace unit a widened match
    /// policy runs.
    units: HashMap<(QueryKey, Option<ProjectFile>), Arc<SubjectProduct<UnitExecutionResult>>>,
    weight: usize,
}

struct SubjectProduct<T> {
    rows: T,
    reads: Vec<ReadKey>,
    persistence_refusals: usize,
}

/// What the batch needs to know about a product to decide whether to keep it.
trait RetainableRows: Clone {
    /// Whether these rows are the whole answer: complete, untruncated and
    /// diagnostic-free. Nothing else is ever served to a second consumer.
    fn exhaustive(&self) -> bool;
    /// Retained rows plus evidence records, before dependency keys.
    fn weight(&self) -> usize;
}

impl RetainableRows for Arc<ExecutedQueryRows> {
    fn exhaustive(&self) -> bool {
        self.completion == CodeQueryCompletion::Complete
            && !self.truncated
            && self.diagnostics.is_empty()
    }

    fn weight(&self) -> usize {
        self.items.len().saturating_add(self.evidence.len())
    }
}

impl RetainableRows for UnitExecutionResult {
    fn exhaustive(&self) -> bool {
        self.completion == CodeQueryCompletion::Complete
            && !self.truncated
            && self.diagnostics.is_empty()
    }

    fn weight(&self) -> usize {
        // One unit row carries both its item and its evidence.
        self.rows
            .len()
            .saturating_mul(2)
            .saturating_add(self.depth_answer_row_count())
    }
}

/// The batch's handle on one repeated match selector's unit executions.
pub(crate) struct SharedQueryUnits<'b> {
    batch: &'b SubjectQueryBatch<'b>,
    query: QueryKey,
}

impl SharedQueryUnits<'_> {
    /// `execute`'s unit product for `seed` (`None` is the whole workspace),
    /// executed once for every consumer of this selector.
    pub(crate) fn execute(
        &self,
        seed: Option<&ProjectFile>,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&CancellationToken>,
        execute: impl FnOnce() -> UnitExecutionResult,
    ) -> UnitExecutionResult {
        self.batch.reuse_or_execute(
            analyzer,
            cancellation,
            |retained| &mut retained.units,
            (self.query.clone(), seed.cloned()),
            execute,
        )
    }
}

impl<'a> SubjectQueryBatch<'a> {
    pub(crate) fn new<'p>(
        analyzer: &'a dyn IAnalyzer,
        policies: impl Iterator<Item = &'p LoadedPolicy>,
        budget: &PolicyBudget,
    ) -> Self {
        let mut consumers = HashMap::<QueryKey, usize>::new();
        for policy in policies {
            // Invalid selectors still fail in the ordinary evaluator. Planning
            // reuse must neither replace nor preempt that policy-local result.
            // Only a match policy can opt into depth-bound probing; an assertion
            // subject query never does.
            let (query, depth_opt_in) = match &policy.definition().analysis {
                PolicyAnalysis::Assertion { spec } if spec.relational.is_none() => {
                    (assertion_subject_query(policy, budget).ok(), false)
                }
                PolicyAnalysis::Match { .. } => (
                    match_policy_query(policy)
                        .ok()
                        .and_then(|query| executable_match_query(query, budget).ok()),
                    policy.definition().completion_on_depth_bound_reached,
                ),
                _ => (None, false),
            };
            if let Some(query) = query {
                *consumers
                    .entry((query.to_canonical_json().to_string(), depth_opt_in))
                    .or_default() += 1;
            }
        }
        Self {
            analyzer,
            content: analyzer.workspace_content_identity(),
            limits: budget.query_limits(),
            repeated: consumers
                .into_iter()
                .filter_map(|(query, count)| (count > 1).then_some(query))
                .collect(),
            retained: Mutex::new(RetainedProducts::default()),
        }
    }

    pub(in crate::evaluator) fn execute(
        &self,
        query: &CodeQuery,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
        depth_opt_in: bool,
    ) -> Arc<ExecutedQueryRows> {
        let execute = || {
            let _timing = brokk_bifrost_analysis::profiling::scope("policy.subject_scan");
            let detailed = match context.workspace {
                Some(workspace) => execute_code_query_detailed_eager_index_workspace_in_scope(
                    workspace,
                    context.flow_resources(),
                    query,
                    budget.query_limits(),
                    context.cancellation,
                    CodeQueryExecutionScope::whole_workspace()
                        .with_depth_bound_status(depth_opt_in),
                ),
                None => execute_code_query_detailed_eager_index_in_scope(
                    context.analyzer,
                    context.flow_resources(),
                    query,
                    budget.query_limits(),
                    context.cancellation,
                    CodeQueryExecutionScope::whole_workspace()
                        .with_depth_bound_status(depth_opt_in),
                ),
            };
            Arc::new(ExecutedQueryRows::of_detailed(detailed))
        };
        match self.repeated_key(query, context.analyzer, budget.query_limits(), depth_opt_in) {
            Some(key) => self.reuse_or_execute(
                context.analyzer,
                context.cancellation,
                |retained| &mut retained.subjects,
                key,
                execute,
            ),
            None => execute(),
        }
    }

    /// The handle a match policy's unit executions of `query` go through, when
    /// another policy of this batch executes the same query with the same
    /// `depth_opt_in`.
    ///
    /// Unit products are executed with the workspace oracles, so every caller
    /// must hold them; a unit run without them answers a different question
    /// under the same key.
    pub(crate) fn query_units(
        &self,
        query: &CodeQuery,
        analyzer: &dyn IAnalyzer,
        workspace: Option<&WorkspaceAnalyzer>,
        limits: brokk_bifrost_rql::structural::CodeQueryExecutionLimits,
        depth_opt_in: bool,
    ) -> Option<SharedQueryUnits<'_>> {
        assert!(
            workspace.is_some(),
            "shared query units are executed with the workspace oracles"
        );
        self.repeated_key(query, analyzer, limits, depth_opt_in)
            .map(|query| SharedQueryUnits { batch: self, query })
    }

    /// `query`'s key when this batch may serve it: more than one policy
    /// consumes it with the same `depth_opt_in`, under this batch's limits and
    /// content snapshot.
    fn repeated_key(
        &self,
        query: &CodeQuery,
        analyzer: &dyn IAnalyzer,
        limits: brokk_bifrost_rql::structural::CodeQueryExecutionLimits,
        depth_opt_in: bool,
    ) -> Option<QueryKey> {
        assert!(
            std::ptr::addr_eq(self.analyzer, analyzer),
            "subject batches belong to exactly one analyzer snapshot"
        );
        if self.repeated.is_empty()
            || self.limits != limits
            || self.content.is_none()
            || self.content != analyzer.workspace_content_identity()
        {
            return None;
        }
        let key = (query.to_canonical_json().to_string(), depth_opt_in);
        self.repeated.contains(&key).then_some(key)
    }

    /// The retained product under `key`, its reads replayed, or `execute`'s
    /// rows, retained when they are exhaustive, bounded and within the weight
    /// budget.
    fn reuse_or_execute<K: Eq + Hash, T: RetainableRows>(
        &self,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&CancellationToken>,
        products: fn(&mut RetainedProducts) -> &mut HashMap<K, Arc<SubjectProduct<T>>>,
        key: K,
        execute: impl FnOnce() -> T,
    ) -> T {
        let cancelled = || {
            cancellation.is_some_and(CancellationToken::is_cancelled)
                || analyzer
                    .active_query_cancellation()
                    .is_some_and(|token| token.is_cancelled())
        };
        if cancelled() {
            return execute();
        }
        let cached = {
            let mut retained = self
                .retained
                .lock()
                .expect("policy subject batch products mutex poisoned");
            products(&mut retained).get(&key).cloned()
        };
        if let Some(product) = cached {
            // Replay through the analyzer, not the producer's closed ledger:
            // every currently open consumer ledger must observe these reads.
            brokk_bifrost_analysis::analyzer::replay_query_read_keys(
                analyzer,
                product.reads.iter().cloned(),
                0,
                product.persistence_refusals,
            );
            if cancelled() {
                return execute();
            }
            brokk_bifrost_analysis::profiling::note("policy.subject_query reused");
            return product.rows.clone();
        }

        let (rows, reads) = capture_query_reads(analyzer, execute);
        if rows.exhaustive() && !cancelled() && reads.is_bounded() {
            let persistence_refusals = reads.persistence_refusals();
            let reads = reads.keys();
            let weight = rows.weight().saturating_add(reads.len());
            let mut retained = self
                .retained
                .lock()
                .expect("policy subject batch products mutex poisoned");
            let total = retained.weight.saturating_add(weight);
            if total <= self.limits.max_pipeline_rows {
                retained.weight = total;
                products(&mut retained).insert(
                    key,
                    Arc::new(SubjectProduct {
                        rows: rows.clone(),
                        reads,
                        persistence_refusals,
                    }),
                );
            }
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    mod contract_tests;
    use brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger;
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, AnalyzerQueryScope, Language};
    use brokk_bifrost_test_macros::hardwon;

    use crate::PolicyRegistry;
    use crate::inline_project::InlineTestProject;

    use super::*;

    const SOURCE: &str = "fn work(mut values: Vec<i32>) { for _ in 0..2 { values.sort(); } }";

    fn registry() -> PolicyRegistry {
        let source = include_str!(
            "../../../policy-packs/bifrost.code-smells/policies/loop-invariant-sort.rqlp"
        );
        let sources = [
            (
                "test.first",
                source.replace("bifrost.performance.loop-invariant-sort", "test.first"),
            ),
            (
                "test.second",
                source.replace("bifrost.performance.loop-invariant-sort", "test.second"),
            ),
        ];
        crate::test_support::registry_with_policies(&sources, "valid production policy")
    }

    #[test]
    #[hardwon(
        "#2586: a reused subject result must replay its read dependencies into the consumer ledger"
    )]
    fn complete_subjects_replay_reads_to_the_consumers_ledger() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("lib.rs", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let registry = registry();
        let budget = PolicyBudget::default();
        let batch = SubjectQueryBatch::new(workspace.analyzer(), registry.policies(), &budget);
        let policy = registry.policies().next().unwrap();
        let query = assertion_subject_query(policy, &budget).unwrap();
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::default();
        let context = PolicyEvaluationContext {
            analyzer: workspace.analyzer(),
            workspace: Some(&workspace),
            flow_state: &flow_state,
            root_memo: None,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
            identifier_typos: None,
        };
        let first_reads = Arc::new(ReadLedger::new());
        let first = {
            let _scope = AnalyzerQueryScope::with_read_ledger(
                workspace.analyzer(),
                Arc::clone(&first_reads),
            );
            batch.execute(&query, &context, &budget, false)
        };
        let second_reads = Arc::new(ReadLedger::new());
        let second = {
            let _scope = AnalyzerQueryScope::with_read_ledger(
                workspace.analyzer(),
                Arc::clone(&second_reads),
            );
            batch.execute(&query, &context, &budget, false)
        };
        assert_eq!(first.completion, CodeQueryCompletion::Complete);
        assert!(!first.items.is_empty());
        assert!(Arc::ptr_eq(&first, &second), "execute one subject scan");
        assert!(!first_reads.is_empty(), "record actual source dependencies");
        assert!(first_reads.is_bounded());
        assert_eq!(first_reads.keys(), second_reads.keys());
        assert_eq!(
            first_reads.unattributed_reads(),
            second_reads.unattributed_reads()
        );
    }

    #[test]
    #[hardwon("#9737: a cached subject product lost its persistence refusal on replay")]
    fn cached_subject_replays_persistence_refusal() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("lib.rs", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let registry = registry();
        let budget = PolicyBudget::default();
        let batch = SubjectQueryBatch::new(workspace.analyzer(), registry.policies(), &budget);
        let policy = registry.policies().next().unwrap();
        let query = assertion_subject_query(policy, &budget).unwrap();
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::default();
        let context = PolicyEvaluationContext {
            analyzer: workspace.analyzer(),
            workspace: Some(&workspace),
            flow_state: &flow_state,
            root_memo: None,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
            identifier_typos: None,
        };
        let first_reads = Arc::new(ReadLedger::new());
        let first = {
            let _scope = AnalyzerQueryScope::with_read_ledger(
                workspace.analyzer(),
                Arc::clone(&first_reads),
            );
            batch.reuse_or_execute(
                workspace.analyzer(),
                None,
                |retained| &mut retained.subjects,
                (query.to_canonical_json().to_string(), false),
                || {
                    let detailed = brokk_bifrost_rql::structural::search::execute_code_query_detailed_eager_index_workspace(
                        &workspace,
                        context.flow_resources(),
                        &query,
                        budget.query_limits(),
                        context.cancellation,
                    );
                    brokk_bifrost_analysis::analyzer::i_analyzer::record_persistence_refusals(
                        workspace.analyzer(),
                        1,
                    );
                    Arc::new(ExecutedQueryRows::of_detailed(detailed))
                },
            )
        };
        let second_reads = Arc::new(ReadLedger::new());
        let second = {
            let _scope = AnalyzerQueryScope::with_read_ledger(
                workspace.analyzer(),
                Arc::clone(&second_reads),
            );
            batch.execute(&query, &context, &budget, false)
        };
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first_reads.persistence_refusals(), 1);
        assert_eq!(second_reads.persistence_refusals(), 1);
        assert_eq!(first_reads.keys(), second_reads.keys());
    }

    #[test]
    #[hardwon("#2586: a complete scan must not be reused under narrower budgets or cancellation")]
    fn cancellation_and_narrower_budgets_cannot_reuse_complete_subjects() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("lib.rs", SOURCE)
            .file("other.rs", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let registry = registry();
        let budget = PolicyBudget::default();
        let batch = SubjectQueryBatch::new(workspace.analyzer(), registry.policies(), &budget);
        let policy = registry.policies().next().unwrap();
        let query = assertion_subject_query(policy, &budget).unwrap();
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::default();
        let mut context = PolicyEvaluationContext {
            analyzer: workspace.analyzer(),
            workspace: Some(&workspace),
            flow_state: &flow_state,
            root_memo: None,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
            identifier_typos: None,
        };
        let complete = batch.execute(&query, &context, &budget, false);
        assert_eq!(complete.completion, CodeQueryCompletion::Complete);
        let mut limits = budget.query_limits();
        limits.max_scanned_source_bytes = 1;
        let narrow = PolicyBudget::builder()
            .with_query_limits(limits)
            .unwrap()
            .build()
            .unwrap();
        let bounded = batch.execute(&query, &context, &narrow, false);
        let independent = ExecutedQueryRows::of_detailed(
            brokk_bifrost_rql::structural::search::execute_code_query_detailed_eager_index(
                workspace.analyzer(),
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                &query,
                narrow.query_limits(),
                None,
            ),
        );
        assert_ne!(bounded.completion, CodeQueryCompletion::Complete);
        assert_eq!(bounded.completion, independent.completion);
        assert_eq!(bounded.work, independent.work);

        let token = CancellationToken::new();
        token.cancel();
        context.cancellation = Some(&token);
        let cancelled = batch.execute(&query, &context, &budget, false);
        assert_eq!(cancelled.completion, CodeQueryCompletion::Cancelled);
        assert!(!Arc::ptr_eq(&complete, &cancelled));
        context.cancellation = None;
        let _scope = AnalyzerQueryScope::with_cancellation(workspace.analyzer(), &token);
        let cancelled = batch.execute(&query, &context, &budget, false);
        assert!(!Arc::ptr_eq(&complete, &cancelled));
    }

    #[test]
    #[hardwon("#2586: incomplete subject scans must not become reusable products")]
    fn incomplete_subjects_are_not_published() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("lib.rs", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let registry = registry();
        let mut limits = PolicyBudget::default().query_limits();
        limits.max_scanned_source_bytes = 1;
        let budget = PolicyBudget::builder()
            .with_query_limits(limits)
            .unwrap()
            .build()
            .unwrap();
        let batch = SubjectQueryBatch::new(workspace.analyzer(), registry.policies(), &budget);
        let query = assertion_subject_query(registry.policies().next().unwrap(), &budget).unwrap();
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::default();
        let context = PolicyEvaluationContext {
            analyzer: workspace.analyzer(),
            workspace: Some(&workspace),
            flow_state: &flow_state,
            root_memo: None,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
            identifier_typos: None,
        };
        let rows = batch.execute(&query, &context, &budget, false);
        assert_ne!(rows.completion, CodeQueryCompletion::Complete);
        assert!(
            batch
                .retained
                .lock()
                .expect("policy subject batch products mutex poisoned")
                .subjects
                .is_empty()
        );
    }
}
