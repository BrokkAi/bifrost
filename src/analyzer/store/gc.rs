//! Opportunistic garbage collection for the blob-keyed analyzer store.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::analyzer::store::AnalyzerStore;
use crate::gitblob;

/// Best-effort GC: drop cache entries no longer reachable from git refs or held
/// by any worktree's uncommitted working set.
fn run_gc(db_path: PathBuf, repo: &git2::Repository) -> Result<(), String> {
    let store = AnalyzerStore::open_persistent(&db_path).map_err(|err| err.to_string())?;
    crate::cache_gc::maybe_gc_for_analyzer(&store, repo).map(|_| ())
}

/// Owns best-effort analyzer cache GC tasks for one workspace lifetime.
///
/// The final store-context drop joins outstanding tasks, so callers can delete
/// a closed workspace without a detached GC thread recreating its cache files.
#[derive(Default)]
pub(crate) struct AnalyzerGcCoordinator {
    closing: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl AnalyzerGcCoordinator {
    /// Run a throttled GC after a persisted analyzer build/update.
    /// Plain in-memory stores never GC.
    pub(crate) fn schedule(self: &Arc<Self>, workspace_root: &Path, store: Arc<AnalyzerStore>) {
        let Some(db_path) = store.db_path().map(Path::to_path_buf) else {
            return;
        };
        if self.closing.load(Ordering::Acquire) {
            return;
        }
        self.reap_finished();
        let root = workspace_root.to_path_buf();
        let coordinator = Arc::downgrade(self);
        let Ok(handle) = std::thread::Builder::new()
            .name("bifrost-analyzer-store-gc".to_string())
            .spawn(move || {
                let _store = store;
                if !is_open(&coordinator) {
                    return;
                }
                let Some(repo) = gitblob::discover(&root) else {
                    return;
                };
                if !is_open(&coordinator) {
                    return;
                }
                let _ = run_gc(db_path, &repo);
            })
        else {
            return;
        };

        let mut tasks = self.tasks.lock().expect("analyzer GC task lock poisoned");
        if self.closing.load(Ordering::Acquire) {
            drop(tasks);
            let _ = handle.join();
        } else {
            tasks.push(handle);
        }
    }

    fn reap_finished(&self) {
        let mut tasks = self.tasks.lock().expect("analyzer GC task lock poisoned");
        let mut running = Vec::with_capacity(tasks.len());
        for task in std::mem::take(&mut *tasks) {
            if task.is_finished() {
                let _ = task.join();
            } else {
                running.push(task);
            }
        }
        *tasks = running;
    }
}

fn is_open(coordinator: &std::sync::Weak<AnalyzerGcCoordinator>) -> bool {
    coordinator
        .upgrade()
        .is_some_and(|coordinator| !coordinator.closing.load(Ordering::Acquire))
}

impl Drop for AnalyzerGcCoordinator {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::Release);
        let tasks = std::mem::take(
            self.tasks
                .get_mut()
                .expect("analyzer GC task lock poisoned"),
        );
        for task in tasks {
            let _ = task.join();
        }
    }
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
