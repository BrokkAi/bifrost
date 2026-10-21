//! Analyzer-store entry points into the shared cache GC driver.
//!
//! The driver itself is [`brokk_bifrost_core::cache_gc`]. Store wrappers read
//! the unified DB path from an [`crate::analyzer::store::AnalyzerStore`] and
//! are re-exported here at the existing engine paths.

pub use brokk_bifrost_core::cache_gc::{
    GC_AUTO_BLOB_THRESHOLD, GC_MIN_INTERVAL_SECS, GcOutcome, STORE_STATISTICS_ENV,
    VERSION_STORE_GRACE_SECS, force_gc as force_gc_for_path, force_gc as force_gc_for_semantic,
    maybe_gc as maybe_gc_for_semantic, planner_statistics_enabled, sweep_disused_version_stores,
};
// `PlannerStatisticsState` is here because the integration suites under the
// facade's `tests/` own EXPLAIN QUERY PLAN pins too, and every pin has to run
// in both planner-statistics states (issue #3016).
#[cfg(any(test, feature = "test-support"))]
pub use brokk_bifrost_core::cache_gc::{
    GcTuningGuard, PlannerStatisticsState, gc_accounting_for_test, set_accounting_for_test,
    set_tuning_for_test, total_blob_count_for_test,
};

pub use crate::analyzer::store::cache_gc::{force_gc_for_analyzer, maybe_gc_for_analyzer};
