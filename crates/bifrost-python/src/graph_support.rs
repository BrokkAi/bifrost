//! Legacy usage-index source layered over the surviving Python source helpers.

pub use crate::source_support::*;
use crate::usage_index::PythonUsageIndex;
use brokk_bifrost_core::analyzer::ProjectFile;
use std::sync::Arc;

/// [`PythonSource`] plus the built usage index. Everything reached from
/// the export/importer walks needs it; the index build itself must not.
pub trait PythonUsageSource: PythonSource {
    fn usage_index(&self) -> Arc<PythonUsageIndex>;
    fn module_binding_timeline(
        &self,
        file: &ProjectFile,
        build: &mut dyn FnMut() -> crate::usage_index::ModuleBindingTimeline,
    ) -> Arc<crate::usage_index::ModuleBindingTimeline>;
    fn scope_facts(
        &self,
        file: &ProjectFile,
        build: &mut dyn FnMut() -> Option<crate::usage_index::PythonScopeFacts>,
    ) -> Option<Arc<crate::usage_index::PythonScopeFacts>>;

    /// A cancelled initialization publishes no partial index.
    fn usage_index_with_cancellation(
        &self,
        cancellation: &brokk_bifrost_core::CancellationToken,
    ) -> Option<Arc<PythonUsageIndex>>;
}
