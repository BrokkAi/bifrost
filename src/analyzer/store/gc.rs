//! Opportunistic garbage collection for the blob-keyed analyzer store.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::analyzer::store::AnalyzerStore;
use crate::gitblob;

/// Best-effort GC: drop cache entries no longer reachable from git refs or held
/// by any worktree's uncommitted working set.
fn run_gc(db_path: PathBuf, repo: &git2::Repository) -> Result<(), String> {
    let store = AnalyzerStore::open_persistent(&db_path).map_err(|err| err.to_string())?;
    crate::cache_gc::maybe_gc_for_analyzer(&store, repo).map(|_| ())
}

/// Run a throttled GC in the background after a persisted analyzer build/update.
/// Plain in-memory stores never GC.
pub(crate) fn maybe_gc_in_background(workspace_root: &Path, store: Arc<AnalyzerStore>) {
    let Some(db_path) = store.db_path().map(Path::to_path_buf) else {
        return;
    };
    let root = workspace_root.to_path_buf();
    let _ = std::thread::Builder::new()
        .name("bifrost-analyzer-store-gc".to_string())
        .spawn(move || {
            let Some(repo) = gitblob::discover(&root) else {
                return;
            };
            let _ = run_gc(db_path, &repo);
        });
}

#[doc(hidden)]
pub struct GcIntervalGuard {
    _inner: crate::cache_gc::GcTuningGuard,
}

#[doc(hidden)]
pub fn set_min_interval_secs_for_test(seconds: i64) -> GcIntervalGuard {
    GcIntervalGuard {
        _inner: crate::cache_gc::set_tuning_for_test(
            crate::cache_gc::GC_AUTO_BLOB_THRESHOLD,
            seconds,
        ),
    }
}
