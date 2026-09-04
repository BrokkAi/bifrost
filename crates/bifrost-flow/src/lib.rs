//! Flow-analysis engines and host-owned reusable state for Bifrost.

use std::sync::Arc;

pub use brokk_bifrost_analysis::analyzer;
pub use brokk_bifrost_analysis::path_utils;
pub use brokk_bifrost_core::{cancellation, hash, text_utils};

pub mod concurrency;
pub mod dataflow;
pub mod detached_task;
pub mod flow_state;
pub mod scalar_state;
mod semantic_summary;
pub mod taint;
pub mod type_flow;
pub mod typestate;
pub mod value_flow;

#[cfg(test)]
#[path = "../../../test-support/inline_project.rs"]
mod inline_project;

pub use semantic_summary::{
    ExactProcedureSummaryBoundary, ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, ProcedureSummaryBindingError,
    bind_active_unmaterialized_procedure_summaries, bind_compiled_procedure_summaries,
};

/// Reusable flow caches owned by one logical workspace.
///
/// The keys inside both caches bind exact semantic content, so this state can
/// survive replacement of an analyzer generation without serving stale data.
#[derive(Debug, Clone)]
pub struct FlowWorkspaceState {
    value_flow: value_flow::ValueFlowCache,
    semantic_summaries: Arc<dataflow::ProductionSemanticSummaryRepository>,
    typestate_summaries: Arc<typestate::ProductionTypestateSummaryRepository>,
}

impl Default for FlowWorkspaceState {
    fn default() -> Self {
        let semantic_summaries = Arc::new(dataflow::ProductionSemanticSummaryRepository::new());
        Self {
            value_flow: value_flow::ValueFlowCache::default(),
            typestate_summaries: Arc::new(
                typestate::ProductionTypestateSummaryRepository::with_shared_semantic_summaries(
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

    pub fn typestate_summaries(&self) -> Arc<typestate::ProductionTypestateSummaryRepository> {
        Arc::clone(&self.typestate_summaries)
    }

    pub fn semantic_summaries(&self) -> Arc<dataflow::ProductionSemanticSummaryRepository> {
        Arc::clone(&self.semantic_summaries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_flow_clients_share_one_semantic_summary_repository() {
        let state = FlowWorkspaceState::new();
        let workspace = state.semantic_summaries();
        let typestate = state.typestate_summaries().semantic_summaries();

        assert!(Arc::ptr_eq(&workspace, &typestate));
    }
}
