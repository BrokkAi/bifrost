//! Complete subject selections shared inside one serial coordinator batch.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use brokk_bifrost_analysis::analyzer::ReadKey;
use brokk_bifrost_analysis::analyzer::capture_query_reads;
use brokk_bifrost_analysis::analyzer::content_identity::WorkspaceContentIdentity;

use super::*;

/// Bound to one immutable analyzer and the coordinator's pinned model scope.
///
/// The full canonical query includes captures, authored union order, filters,
/// projection and execution controls. All query limits must also match. The
/// execution scope is always the whole workspace and the selected AST-id set
/// is always unrestricted: this entry point cannot accept a row-family session
/// or source selection. In particular, consumer-correlated occurrence and
/// scope products never enter this cache.
///
/// Only queries with multiple consumers retain a product. Aggregate retained
/// rows, evidence records and dependency keys share one weight budget, bounded
/// by the batch's pipeline-row limit; exceeding it simply executes normally.
/// Rc shares the immutable subject rows without copying their owned evidence.
pub(crate) struct SubjectQueryBatch<'a> {
    analyzer: &'a dyn IAnalyzer,
    content: Option<WorkspaceContentIdentity>,
    limits: brokk_bifrost_rql::structural::CodeQueryExecutionLimits,
    repeated: HashSet<String>,
    products: Mutex<HashMap<String, Arc<SubjectProduct>>>,
    retained_weight: AtomicUsize,
}

struct SubjectProduct {
    rows: Arc<ExecutedQueryRows>,
    reads: Vec<ReadKey>,
}

impl<'a> SubjectQueryBatch<'a> {
    pub(crate) fn new<'p>(
        analyzer: &'a dyn IAnalyzer,
        policies: impl Iterator<Item = &'p LoadedPolicy>,
        budget: &PolicyBudget,
    ) -> Self {
        let mut consumers = HashMap::<String, usize>::new();
        for policy in policies {
            let PolicyAnalysis::Assertion { spec } = &policy.definition().analysis else {
                continue;
            };
            if spec.relational.is_some() {
                continue;
            }
            // Invalid selectors still fail in the ordinary evaluator. Planning
            // reuse must neither replace nor preempt that policy-local result.
            if let Ok(query) = assertion_subject_query(policy, budget) {
                *consumers
                    .entry(query.to_canonical_json().to_string())
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
            products: Mutex::new(HashMap::new()),
            retained_weight: AtomicUsize::new(0),
        }
    }

    pub(super) fn execute(
        &self,
        query: &CodeQuery,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
    ) -> Arc<ExecutedQueryRows> {
        assert!(
            std::ptr::addr_eq(self.analyzer, context.analyzer),
            "subject batches belong to exactly one analyzer snapshot"
        );
        let execute = || {
            let _timing = brokk_bifrost_analysis::profiling::scope("policy.subject_scan");
            let detailed = match context.workspace {
                Some(workspace) => execute_code_query_detailed_eager_index_workspace(
                    workspace,
                    query,
                    budget.query_limits(),
                    context.cancellation,
                ),
                None => execute_code_query_detailed_eager_index(
                    context.analyzer,
                    query,
                    budget.query_limits(),
                    context.cancellation,
                ),
            };
            Arc::new(ExecutedQueryRows::of_detailed(detailed))
        };
        let cancelled = || {
            context
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
                || context
                    .analyzer
                    .active_query_cancellation()
                    .is_some_and(|token| token.is_cancelled())
        };
        if self.repeated.is_empty()
            || self.limits != budget.query_limits()
            || self.content.is_none()
            || self.content != context.analyzer.workspace_content_identity()
            || cancelled()
        {
            return execute();
        }
        let key = query.to_canonical_json().to_string();
        if !self.repeated.contains(&key) {
            return execute();
        }
        let cached = self
            .products
            .lock()
            .expect("policy subject batch products mutex poisoned")
            .get(&key)
            .cloned();
        if let Some(product) = cached {
            // Replay through the analyzer, not the producer's closed ledger:
            // every currently open consumer ledger must observe these reads.
            for read in &product.reads {
                context.analyzer.record_read(read.clone());
            }
            if cancelled() {
                return execute();
            }
            brokk_bifrost_analysis::profiling::note("policy.subject_query reused");
            return Arc::clone(&product.rows);
        }

        let (rows, reads) = capture_query_reads(context.analyzer, execute);
        if rows.completion == CodeQueryCompletion::Complete
            && !rows.truncated
            && rows.diagnostics.is_empty()
            && !cancelled()
            && reads.is_bounded()
        {
            let reads = reads.keys();
            let weight = rows
                .items
                .len()
                .saturating_add(rows.evidence.len())
                .saturating_add(reads.len());
            // Reserving the retained weight and inserting the product are one
            // critical section: two workers that both passed the cap check
            // would otherwise retain past the bound.
            let mut products = self
                .products
                .lock()
                .expect("policy subject batch products mutex poisoned");
            let retained = self
                .retained_weight
                .load(Ordering::Relaxed)
                .saturating_add(weight);
            if retained <= self.limits.max_pipeline_rows {
                products.insert(
                    key,
                    Arc::new(SubjectProduct {
                        rows: Arc::clone(&rows),
                        reads,
                    }),
                );
                self.retained_weight.store(retained, Ordering::Relaxed);
            }
        }
        rows
    }
}

#[cfg(test)]
mod tests {
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
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
        };
        let first_reads = Arc::new(ReadLedger::new());
        let first = {
            let _scope = AnalyzerQueryScope::with_read_ledger(
                workspace.analyzer(),
                Arc::clone(&first_reads),
            );
            batch.execute(&query, &context, &budget)
        };
        let second_reads = Arc::new(ReadLedger::new());
        let second = {
            let _scope = AnalyzerQueryScope::with_read_ledger(
                workspace.analyzer(),
                Arc::clone(&second_reads),
            );
            batch.execute(&query, &context, &budget)
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
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
        };
        let complete = batch.execute(&query, &context, &budget);
        assert_eq!(complete.completion, CodeQueryCompletion::Complete);
        let mut limits = budget.query_limits();
        limits.max_scanned_source_bytes = 1;
        let narrow = PolicyBudget::builder()
            .with_query_limits(limits)
            .unwrap()
            .build()
            .unwrap();
        let bounded = batch.execute(&query, &context, &narrow);
        let independent = ExecutedQueryRows::of_detailed(execute_code_query_detailed_eager_index(
            workspace.analyzer(),
            &query,
            narrow.query_limits(),
            None,
        ));
        assert_ne!(bounded.completion, CodeQueryCompletion::Complete);
        assert_eq!(bounded.completion, independent.completion);
        assert_eq!(bounded.work, independent.work);

        let token = CancellationToken::new();
        token.cancel();
        context.cancellation = Some(&token);
        let cancelled = batch.execute(&query, &context, &budget);
        assert_eq!(cancelled.completion, CodeQueryCompletion::Cancelled);
        assert!(!Arc::ptr_eq(&complete, &cancelled));
        context.cancellation = None;
        let _scope = AnalyzerQueryScope::with_cancellation(workspace.analyzer(), &token);
        let cancelled = batch.execute(&query, &context, &budget);
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
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
        };
        let rows = batch.execute(&query, &context, &budget);
        assert_ne!(rows.completion, CodeQueryCompletion::Complete);
        assert!(
            batch
                .products
                .lock()
                .expect("policy subject batch products mutex poisoned")
                .is_empty()
        );
    }
}
