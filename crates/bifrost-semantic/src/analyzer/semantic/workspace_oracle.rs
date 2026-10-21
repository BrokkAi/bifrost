//! Workspace-backed implementations of the language-neutral semantic oracles.

#[doc(hidden)]
pub mod common;
#[doc(hidden)]
pub mod conversions;
#[doc(hidden)]
pub mod dispatch;
#[doc(hidden)]
pub mod heap;
#[doc(hidden)]
pub mod runtime_values;
#[doc(hidden)]
pub mod rust;

#[doc(hidden)]
pub mod source;

pub use crate::analyzer::semantic::workspace_oracle::runtime_values::RuntimeAccessKey;

pub use crate::analyzer::semantic::workspace_oracle::runtime_values::RuntimeKeyedReadEndpoint;

pub use crate::analyzer::semantic::workspace_oracle::runtime_values::RuntimeKeyedReadFilter;

pub use crate::analyzer::semantic::workspace_oracle::runtime_values::RuntimeKeyedReadKeyKind;

pub use crate::analyzer::semantic::workspace_oracle::runtime_values::RuntimeKeyedReadResult;

pub use crate::analyzer::semantic::workspace_oracle::runtime_values::RuntimeReadLimitation;

pub use crate::analyzer::semantic::workspace_oracle::runtime_values::RuntimeReadSourceOrigin;
#[doc(hidden)]
pub mod value_flow;

pub(crate) use crate::analyzer::semantic::workspace_oracle::common::Interruption;

pub(crate) use crate::analyzer::semantic::workspace_oracle::common::WorkStager;

pub(crate) use crate::analyzer::semantic::workspace_oracle::value_flow::project_procedure_relations;

pub(crate) use crate::analyzer::semantic::workspace_oracle::value_flow::LocalStoreBases;

pub(crate) use crate::analyzer::semantic::workspace_oracle::value_flow::RelationProjectionHost;

pub(crate) use crate::analyzer::semantic::workspace_oracle::value_flow::StrongUpdateStop;

pub(crate) use crate::analyzer::semantic::workspace_oracle::dispatch::semantic_locator_work;

pub use crate::analyzer::semantic::workspace_oracle::dispatch::ProcedureRangeLookupStatus;

pub use crate::analyzer::semantic::workspace_oracle::dispatch::procedures_for_source_ranges;

pub use crate::analyzer::semantic::workspace_oracle::dispatch::procedures_in_artifact;

// Policy lowering consumes this intentionally Rust-specific semantic API.

// Read-set verification replays dispatch on the head workspace and must fold
// the answer with the same helper the recording used, never a second copy.

pub use crate::analyzer::semantic::workspace_oracle::source::SourcePointsToResult;

// The value-flow plan re-applies these relevance rules when it decides
// whether a snapshot's residual openness was refined by its own complete
// call resolutions (#1952).

pub use crate::analyzer::semantic::workspace_oracle::value_flow::GapOpenness;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::ProcedureOpenness;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::abort_paths_run_user_code;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::abort_paths_run_user_code_bounded;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::allocation_call_is_dischargeable;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::call_target_refinement_call;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::classify_gap_openness;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::constructor_call_gap_is_discharged;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::gap_impacts_value_flow;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::implicit_abort_gap_is_discharged;

pub use crate::analyzer::semantic::workspace_oracle::value_flow::value_flow_capabilities_are_open;

#[doc(hidden)]
pub struct DispatchMaterializationTimer {
    #[doc(hidden)]
    pub nanos: Arc<std::sync::atomic::AtomicU64>,
    #[doc(hidden)]
    pub started: Option<std::time::Instant>,
}

impl Drop for DispatchMaterializationTimer {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            self.nanos.fetch_add(
                started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    }
}

// Own the diagnostics with the map, without adding a destructor to a facade
// that borrows the workspace (and hence changing its drop-check lifetimes).
#[derive(Default)]
#[doc(hidden)]
pub struct IncomingActualCache {
    #[doc(hidden)]
    pub actuals: std::sync::Mutex<
        brokk_bifrost_core::hash::HashMap<heap::IncomingActualKey, heap::IncomingActualSet>,
    >,
    #[doc(hidden)]
    pub dispatch_materialization_ns: Arc<std::sync::atomic::AtomicU64>,
}

impl std::ops::Deref for IncomingActualCache {
    type Target = std::sync::Mutex<
        brokk_bifrost_core::hash::HashMap<heap::IncomingActualKey, heap::IncomingActualSet>,
    >;
    fn deref(&self) -> &Self::Target {
        &self.actuals
    }
}

impl Drop for IncomingActualCache {
    fn drop(&mut self) {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "semantic.oracle.run_end incoming_actuals_artifact_bytes={} dispatch_materialization_seconds={:.9}",
                self.artifact_bytes(),
                self.dispatch_materialization_ns
                    .load(std::sync::atomic::Ordering::Relaxed) as f64
                    / 1e9
            )
        });
    }
}

use std::sync::Arc;
