use brokk_bifrost_core::cache_gc::GcOutcome;

use crate::analyzer::store::AnalyzerStore;
use brokk_bifrost_core::cache_gc::AnalyzerCacheBuildLock;
use brokk_bifrost_core::cache_gc::force_gc;
use brokk_bifrost_core::cache_gc::maybe_gc;
use git2::Repository;

pub fn maybe_gc_for_analyzer(
    store: &AnalyzerStore,
    repo: &Repository,
    workspace_root: &std::path::Path,
) -> Result<GcOutcome, String> {
    let Some(db_path) = store.db_path() else {
        return Ok(GcOutcome::skipped(0));
    };
    let outcome = maybe_gc(db_path, repo, workspace_root)?;
    // Core swept orphan summaries/topologies before collecting blobs. Reclaim
    // stale generations at the same cadence, only if no builder has acquired
    // the released build lock. Withdrawing stale versions can orphan more rows.
    let _build_lock = if outcome.ran {
        AnalyzerCacheBuildLock::try_acquire(db_path)?
    } else {
        None
    };
    let reclaimed = if _build_lock.is_some() {
        store
            .reclaim_stale_generations(i64::MAX as usize)
            .map_err(|error| format!("analyzer stale-generation GC failed: {error}"))?
    } else {
        0
    };
    if brokk_bifrost_core::cache_gc::planner_statistics_enabled() {
        if reclaimed > 0 {
            store
                .refresh_planner_statistics_if_stale()
                .map_err(|error| error.to_string())?;
        } else if outcome.analyzer_dropped > 0 {
            store
                .reload_planner_statistics()
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(outcome)
}

pub fn force_gc_for_analyzer(
    store: &AnalyzerStore,
    repo: &Repository,
    workspace_root: &std::path::Path,
) -> Result<GcOutcome, String> {
    let Some(db_path) = store.db_path() else {
        return Ok(GcOutcome::skipped(0));
    };
    let outcome = force_gc(db_path, repo, workspace_root)?;
    // Core swept orphan summaries/topologies under its collection lock. Stale
    // generation reclamation withdraws versions and must exclude builds too.
    let _build_lock = AnalyzerCacheBuildLock::acquire(db_path)?;
    let reclaimed = store
        .reclaim_stale_generations(i64::MAX as usize)
        .map_err(|error| format!("analyzer stale-generation GC failed: {error}"))?;
    if brokk_bifrost_core::cache_gc::planner_statistics_enabled() {
        if reclaimed > 0 {
            store
                .refresh_planner_statistics_if_stale()
                .map_err(|error| error.to_string())?;
        } else if outcome.analyzer_dropped > 0 {
            store
                .reload_planner_statistics()
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(outcome)
}
