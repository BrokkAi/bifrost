//! Flow-analysis engines and host-owned reusable state for Bifrost.

use std::sync::Arc;

pub use brokk_bifrost_analysis::analyzer;
pub use brokk_bifrost_analysis::path_utils;
pub use brokk_bifrost_core::{cancellation, hash, text_utils};

pub mod dataflow;
pub mod flow_state;
mod semantic_summary;
pub mod taint;
pub mod typestate;
pub mod value_flow;

pub use semantic_summary::{
    ExactProcedureSummaryBoundary, ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, ProcedureSummaryBindingError,
    bind_compiled_procedure_summaries,
};

/// Reusable flow caches owned by one logical workspace.
///
/// The keys inside both caches bind exact semantic content, so this state can
/// survive replacement of an analyzer generation without serving stale data.
#[derive(Debug, Clone)]
pub struct FlowWorkspaceState {
    value_flow: value_flow::ValueFlowCache,
    typestate_summaries: Arc<typestate::ProductionTypestateSummaryRepository>,
}

impl Default for FlowWorkspaceState {
    fn default() -> Self {
        Self {
            value_flow: value_flow::ValueFlowCache::default(),
            typestate_summaries: Arc::new(typestate::ProductionTypestateSummaryRepository::new()),
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
}
