//! Flow-analysis engines and host-owned reusable state for Bifrost.

// ProcedureHandle keys hash immutable identity; lazy callable-selection
// dominance is derived state and is excluded from equality and hashing.
#![allow(clippy::mutable_key_type)]

#[cfg(test)]
use brokk_bifrost_tools as _;
use std::sync::Arc;

pub use brokk_bifrost_analysis::analyzer;
pub use brokk_bifrost_analysis::path_utils;
pub use brokk_bifrost_core::{cancellation, hash, text_utils};

pub mod composition;
pub mod dataflow;
pub mod detached_task;
pub mod flow_state;
pub mod model_attribution;
mod ordering;
pub mod scalar_state;
mod semantic_summary;
pub mod taint;
pub mod type_flow;
pub mod typestate;
pub mod value_flow;

#[cfg(test)]
#[path = "../../../test-support/inline_project.rs"]
mod inline_project;

#[cfg(test)]
mod test_support;

pub use semantic_summary::{
    ExactProcedureSummaryBoundary, ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, ProcedureSummaryBindingError,
    bind_active_unmaterialized_procedure_summaries, bind_compiled_procedure_summaries,
    bind_compiled_receiver_adjustment_summary, bind_snapshot_unmaterialized_procedure_summaries,
    project_summary_endpoint,
};

/// Reusable flow caches owned by one logical workspace.
///
/// The keys inside both caches bind exact semantic content, so this state can
/// survive replacement of an analyzer generation without serving stale data.
#[derive(Debug, Clone)]
pub struct FlowWorkspaceState {
    value_flow: value_flow::ValueFlowCache,
    semantic_summaries: Arc<dataflow::ProductionSemanticSummaryStorage>,
    type_flow_summaries: type_flow::TypeFlowSummaryPartitions,
    typestate_summaries: Arc<typestate::ProductionTypestateSummaryStorage>,
}

impl Default for FlowWorkspaceState {
    fn default() -> Self {
        let semantic_summaries = Arc::new(dataflow::ProductionSemanticSummaryStorage::default());
        Self {
            value_flow: value_flow::ValueFlowCache::default(),
            type_flow_summaries: type_flow::TypeFlowSummaryPartitions::default(),
            typestate_summaries: Arc::new(
                typestate::ProductionTypestateSummaryStorage::with_shared_semantic_summaries(
                    typestate::TypestateSummaryRepositoryLimits::default(),
                    Arc::clone(&semantic_summaries),
                ),
            ),
            semantic_summaries,
        }
    }
}

impl FlowWorkspaceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn value_flow_cache(&self) -> value_flow::ValueFlowCache {
        self.value_flow.clone()
    }

    pub fn typestate_summaries(
        &self,
        workspace: &analyzer::WorkspaceAnalyzer,
    ) -> Arc<typestate::ProductionTypestateSummaryRepository> {
        Arc::new(self.typestate_summaries.reader(
            analyzer::workspace_authority::workspace_memo_attribution(workspace),
        ))
    }

    pub fn type_flow_summaries(&self) -> type_flow::TypeFlowSummaryPartitions {
        self.type_flow_summaries.clone()
    }

    pub fn semantic_summaries(
        &self,
        workspace: &analyzer::WorkspaceAnalyzer,
    ) -> Arc<dataflow::ProductionSemanticSummaryRepository> {
        Arc::new(self.semantic_summaries.reader(
            analyzer::workspace_authority::workspace_memo_attribution(workspace),
        ))
    }

    /// Observe the state reachable from this workspace owner for an explicit
    /// test-support census. This method is passive: it does not settle cache
    /// maintenance or alter retention. Allocation pins live only until the
    /// caller finishes this census.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn retention_census_for_test(
        &self,
        census: &mut brokk_bifrost_core::retention_census::RetentionCensus<'_>,
    ) {
        self.value_flow.retention_census_for_test(census);
        self.semantic_summaries
            .retention_census_for_test(census, "flow.semantic_summaries");
        self.type_flow_summaries.retention_census_for_test(census);
        self.typestate_summaries
            .retention_census_for_test(census, "flow.typestate");
    }
}
