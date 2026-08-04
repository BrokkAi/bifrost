//! Analyzer-store entry points into the shared cache GC driver.
//!
//! The driver itself is [`brokk_bifrost_core::cache_gc`]; it needs only the
//! unified DB path, so all that stays here is the pair of wrappers that read
//! that path off an [`AnalyzerStore`].

pub use brokk_bifrost_core::cache_gc::{
    GC_AUTO_BLOB_THRESHOLD, GC_MIN_INTERVAL_SECS, GcOutcome, GcTuningGuard,
    VERSION_STORE_GRACE_SECS, force_gc as force_gc_for_semantic, maybe_gc as maybe_gc_for_semantic,
    set_accounting_for_test, set_tuning_for_test, sweep_disused_version_stores,
    total_blob_count_for_test,
};

use brokk_bifrost_core::cache_gc::{force_gc, maybe_gc};
use git2::Repository;

use crate::analyzer::store::AnalyzerStore;

pub fn maybe_gc_for_analyzer(
    store: &AnalyzerStore,
    repo: &Repository,
) -> Result<GcOutcome, String> {
    let Some(db_path) = store.db_path() else {
        return Ok(GcOutcome::skipped(0));
    };
    maybe_gc(db_path, repo)
}

pub fn force_gc_for_analyzer(
    store: &AnalyzerStore,
    repo: &Repository,
) -> Result<GcOutcome, String> {
    let Some(db_path) = store.db_path() else {
        return Ok(GcOutcome::skipped(0));
    };
    force_gc(db_path, repo)
}
