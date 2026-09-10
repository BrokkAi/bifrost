//! Complete subject selections shared inside one serial coordinator batch.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

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
    products: RefCell<HashMap<String, Rc<SubjectProduct>>>,
    retained_weight: Cell<usize>,
}

struct SubjectProduct {
    rows: Rc<ExecutedQueryRows>,
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
            products: RefCell::new(HashMap::new()),
            retained_weight: Cell::new(0),
        }
    }

    pub(super) fn execute(
        &self,
        query: &CodeQuery,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
    ) -> Rc<ExecutedQueryRows> {
        assert!(
            std::ptr::addr_eq(self.analyzer, context.analyzer),
            "subject batches belong to exactly one analyzer snapshot"
        );
        let execute = || {
            let _timing = brokk_bifrost_analysis::profiling::scope("policy.subject_scan");
            Rc::new(ExecutedQueryRows::of_detailed(
                execute_code_query_detailed_eager_index(
                    context.analyzer,
                    query,
                    budget.query_limits(),
                    context.cancellation,
                ),
            ))
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
        let cached = self.products.borrow().get(&key).cloned();
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
            return Rc::clone(&product.rows);
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
            let retained = self.retained_weight.get().saturating_add(weight);
            if retained <= self.limits.max_pipeline_rows {
                self.products.borrow_mut().insert(
                    key,
                    Rc::new(SubjectProduct {
                        rows: Rc::clone(&rows),
                        reads,
                    }),
                );
                self.retained_weight.set(retained);
            }
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger;
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, AnalyzerQueryScope, Language};

    use crate::inline_project::InlineTestProject;
    use crate::{
        CatalogRegistryLimits, PolicyRegistry, PolicyRegistryLimits, PolicySourceIdentity,
        TaintCatalogRegistry,
    };

    use super::*;

    const SOURCE: &str = "fn work(mut values: Vec<i32>) { for _ in 0..2 { values.sort(); } }";

    fn registry() -> PolicyRegistry {
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        let source = include_str!(
            "../../../policy-packs/bifrost.code-smells/policies/loop-invariant-sort.rqlp"
        );
        for id in ["test.first", "test.second"] {
            registry
                .register_policy_bytes(
                    PolicySourceIdentity::new(id),
                    source
                        .replace("bifrost.performance.loop-invariant-sort", id)
                        .as_bytes(),
                )
                .expect("valid production policy");
        }
        registry
    }

    #[test]
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
        assert!(Rc::ptr_eq(&first, &second), "execute one subject scan");
        assert!(!first_reads.is_empty(), "record actual source dependencies");
        assert!(first_reads.is_bounded());
        assert_eq!(first_reads.keys(), second_reads.keys());
        assert_eq!(
            first_reads.unattributed_reads(),
            second_reads.unattributed_reads()
        );
    }

    #[test]
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
        assert!(!Rc::ptr_eq(&complete, &cancelled));
        context.cancellation = None;
        let _scope = AnalyzerQueryScope::with_cancellation(workspace.analyzer(), &token);
        let cancelled = batch.execute(&query, &context, &budget);
        assert!(!Rc::ptr_eq(&complete, &cancelled));
    }

    #[test]
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
        assert!(batch.products.borrow().is_empty());
    }
}
