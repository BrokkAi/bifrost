#![allow(hidden_glob_reexports)]
pub use crate::analyzer::store_bridge::fact_reference_edges;
pub use brokk_bifrost_store::analyzer::resolution::*;
pub use fact_reference_edges::FactCallableReceiverTargetAdmission;
pub use fact_reference_edges::FactCallableReceiverTargetProjection;
pub use fact_reference_edges::FactReferenceBindingShape;
pub use fact_reference_edges::FactReferenceEdgeBatch;
pub use fact_reference_edges::FactReferenceEdgeCatalog;
pub use fact_reference_edges::FactReferenceEdgeDeclarationDomain;
pub use fact_reference_edges::FactReferenceEdgeDomainStatus;
pub use fact_reference_edges::FactReferenceEdgeGap;
pub use fact_reference_edges::FactReferenceEdgeGapDomain;
pub use fact_reference_edges::FactReferenceEdgeSelectedFragment;
pub use fact_reference_edges::FactReferenceEdgeSummary;
pub use fact_reference_edges::FactReferenceGraphAdmission;
pub use fact_reference_edges::FactReferenceProjectionStatus;
pub use fact_reference_edges::FactReferenceTargetProjection;
pub(crate) use fact_reference_edges::NativeReferenceEdgeBatchProjector;
#[cfg(any(test, feature = "test-support"))]
pub use fact_reference_edges::SelectedReferenceInverseIndex;
#[cfg(any(test, feature = "test-support"))]
pub use fact_reference_edges::SelectedReferenceInverseIndexBuildOutcome;
#[cfg(any(test, feature = "test-support"))]
pub use fact_reference_edges::build_selected_reference_inverse_index;
pub use fact_reference_edges::classify_fact_reference_binding;
pub use fact_reference_edges::fact_callable_receiver_target_admission;
pub use fact_reference_edges::project_fact_callable_receiver_target;
pub use fact_reference_edges::project_fact_reference_edge_batch;
pub use fact_reference_edges::project_fact_reference_targets;
pub use fact_reference_edges::stage_selected_reference_edge_batches;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use fact_reference_edges::validate_selected_reference_edge_coverage;

// The recorder remains engine-owned; lower resolution queries it at each call.
#[unsafe(no_mangle)]
fn __brokk_bifrost_resolution_diagnostics_v1() -> &'static dyn ResolutionDiagnostics {
    crate::analyzer::usages::get_definition::trace::resolution_diagnostics()
}
