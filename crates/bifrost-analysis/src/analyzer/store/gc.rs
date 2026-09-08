//! Opportunistic garbage collection for the blob-keyed analyzer store.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::analyzer::store::AnalyzerStore;
use crate::gitblob;

/// Best-effort GC: drop cache entries no longer reachable from git refs or held
/// by any worktree's uncommitted working set.
///
/// Runs against the workspace's own live store rather than a second handle on
/// the same file. Collection itself needs only the database path, but a
/// collection that dropped rows also refreshed the planner statistics, and the
/// readers that must be recycled for that belong to this store (issue #3029).
fn run_gc(
    store: &AnalyzerStore,
    repo: &git2::Repository,
    workspace_root: &Path,
) -> Result<crate::cache_gc::GcOutcome, String> {
    let outcome = crate::cache_gc::maybe_gc_for_analyzer(store, repo, workspace_root)?;
    // The refresh ran on the collection's own connection, so every reader this
    // store has already planned with is holding statistics that describe rows
    // the collection deleted.
    if outcome.analyzer_dropped > 0 && crate::cache_gc::planner_statistics_enabled() {
        store.recycle_readers_for_new_statistics();
    }
    Ok(outcome)
}

/// Owns best-effort analyzer cache GC tasks for one workspace lifetime.
///
/// The final store-context drop joins outstanding tasks, so callers can delete
/// a closed workspace without a detached GC thread recreating its cache files.
pub(crate) struct AnalyzerGcCoordinator {
    automatic: bool,
    closing: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Default for AnalyzerGcCoordinator {
    fn default() -> Self {
        Self {
            automatic: true,
            closing: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
        }
    }
}

impl AnalyzerGcCoordinator {
    pub(crate) fn disabled() -> Self {
        Self {
            automatic: false,
            closing: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
        }
    }

    /// Run a throttled GC after a persisted analyzer build/update.
    /// Plain in-memory stores never GC.
    pub(crate) fn schedule(self: &Arc<Self>, workspace_root: &Path, store: Arc<AnalyzerStore>) {
        if !self.automatic {
            return;
        }
        if store.db_path().is_none() {
            return;
        }
        if self.closing.load(Ordering::Acquire) {
            return;
        }
        self.reap_finished();
        let root = workspace_root.to_path_buf();
        let coordinator = Arc::downgrade(self);
        let Ok(handle) = std::thread::Builder::new()
            .name("bifrost-analyzer-store-gc".to_string())
            .spawn(move || {
                if !is_open(&coordinator) {
                    return;
                }
                let Some(repo) = gitblob::discover(&root) else {
                    return;
                };
                if !is_open(&coordinator) {
                    return;
                }
                let _ = run_gc(&store, &repo, &root);
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

#[cfg(any(test, feature = "test-support"))]
pub struct GcIntervalGuard {
    _inner: crate::cache_gc::GcTuningGuard,
}

#[cfg(any(test, feature = "test-support"))]
pub fn set_min_interval_secs_for_test(seconds: i64) -> GcIntervalGuard {
    GcIntervalGuard {
        _inner: crate::cache_gc::set_tuning_for_test(
            crate::cache_gc::GC_AUTO_BLOB_THRESHOLD,
            seconds,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{AnalyzerStore, run_gc};
    use crate::analyzer::store::WorkspaceId;
    use crate::analyzer::workspace::WorkspaceAnalyzer;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject};
    use crate::gitblob::test_repo::{commit_all, init_repo};

    /// A collection that dropped rows leaves this store's pooled readers
    /// planning against statistics the collection invalidated, so the
    /// collection recycles them (issue #3029).
    ///
    /// This is the case the build hook does not cover: the first `ANALYZE` of a
    /// store's life creates `sqlite_stat1`, which is a schema change every
    /// connection notices, while a collection rewrites rows in a table that
    /// already exists.
    ///
    /// The setup makes one persisted blob unreachable the same way
    /// `a_collection_that_drops_rows_refreshes_the_statistics` does: two
    /// commits, each built, then the branch moves back to the first and the
    /// working tree with it, and the retained workspace projection is released.
    #[test]
    fn a_collection_that_drops_rows_recycles_this_stores_readers() {
        let _statistics = brokk_bifrost_core::cache_gc::planner_statistics_test_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _tuning = crate::cache_gc::set_tuning_for_test(0, 0);
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first = "pub fn widget() -> u32 { 1 }\n";
        let second = "pub fn widget() -> u32 { 2 }\npub fn extra() -> u32 { 3 }\n";
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), first).unwrap();
        let repository = init_repo(&root);
        let first_commit = commit_all(&repository, "first content");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            Arc::clone(&project),
            AnalyzerConfig::default(),
        )
        .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);

        std::fs::write(root.join("app.rs"), second).unwrap();
        commit_all(&repository, "second content");
        drop(
            WorkspaceAnalyzer::build_persisted_without_automatic_gc(
                Arc::clone(&project),
                AnalyzerConfig::default(),
            )
            .expect("persisted analyzer should rebuild"),
        );

        let head = repository.head().unwrap();
        let branch = head.name().expect("a named branch").to_string();
        repository
            .reference(&branch, first_commit, true, "drop the second commit")
            .unwrap();
        std::fs::write(root.join("app.rs"), first).unwrap();

        let store = AnalyzerStore::open_persistent(&db_path).expect("open the collected store");
        // Both analyzers are gone. Release their retained revision history as
        // well as the Git roots; only the explicit collection may reclaim facts.
        assert!(
            store
                .delete_workspace_projection(&WorkspaceId::for_root(&root))
                .expect("release the workspace projection")
                > 0
        );
        drop(store.read_conn().expect("warm one pooled reader"));
        assert_eq!(
            store.readers.idle_len(),
            1,
            "the warmed reader must be back in the pool before the collection"
        );

        let outcome = run_gc(&store, &repository, &root).expect("collection");
        assert!(
            outcome.analyzer_dropped > 0,
            "the setup must leave the second content collectable: {outcome:?}"
        );
        assert_eq!(
            store.readers.idle_len(),
            0,
            "a collection that dropped {} rows must close the readers that planned before it",
            outcome.analyzer_dropped
        );
    }
}
