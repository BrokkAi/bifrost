//! Opportunistic garbage collection for the blob-keyed analyzer store.

use std::path::Path;
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
/// A scheduled collection always runs: once `schedule` has returned, the
/// worker attempts the collection whatever the coordinator does afterwards,
/// and the final store-context drop joins it. That join is the shutdown
/// boundary. A caller that closes a workspace can delete its directory as
/// soon as the close returns, because no maintenance write follows it -- and a
/// session too short to outlive its own build still advances the store's
/// collection cadence (issue #3349).
///
/// The worker therefore holds no reference to the coordinator at all. An
/// earlier design gave it a weak one and cancelled a collection whose final
/// owner had already gone away. That made the outcome of a close depend on
/// whether the worker thread had reached its first instruction yet, and it
/// carried a hazard of its own: a worker whose upgraded reference was the last
/// strong one would have run this drop on its own thread and joined itself.
pub(crate) struct AnalyzerGcCoordinator {
    automatic: bool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Parks a worker before it touches the repository or the store, so a test
    /// can order the final drop ahead of the collection deterministically.
    #[cfg(test)]
    hold_workers_for_test: Option<Arc<WorkerHold>>,
}

impl Default for AnalyzerGcCoordinator {
    fn default() -> Self {
        Self::new(true)
    }
}

impl AnalyzerGcCoordinator {
    pub(crate) fn disabled() -> Self {
        Self::new(false)
    }

    fn new(automatic: bool) -> Self {
        Self {
            automatic,
            tasks: Mutex::new(Vec::new()),
            #[cfg(test)]
            hold_workers_for_test: None,
        }
    }

    #[cfg(test)]
    fn holding_workers_for_test(hold: Arc<WorkerHold>) -> Self {
        let mut coordinator = Self::new(true);
        coordinator.hold_workers_for_test = Some(hold);
        coordinator
    }

    /// Run a throttled GC after a persisted analyzer build/update.
    /// Plain in-memory stores never GC.
    pub(crate) fn schedule(&self, workspace_root: &Path, store: Arc<AnalyzerStore>) {
        if !self.automatic {
            return;
        }
        if store.db_path().is_none() {
            return;
        }
        self.reap_finished();
        let root = workspace_root.to_path_buf();
        #[cfg(test)]
        let hold = self.hold_workers_for_test.clone();
        let spawned = std::thread::Builder::new()
            .name("bifrost-analyzer-store-gc".to_string())
            .spawn(move || {
                #[cfg(test)]
                if let Some(hold) = hold {
                    hold.park_until_released();
                }
                let Some(repo) = gitblob::discover(&root) else {
                    return;
                };
                if let Err(error) = run_gc(&store, &repo, &root) {
                    eprintln!("Bifrost cache GC failed: {error}");
                }
            });
        match spawned {
            Ok(handle) => self
                .tasks
                .lock()
                .expect("analyzer GC task lock poisoned")
                .push(handle),
            // Maintenance is best effort: the next build or update schedules
            // the collection again.
            Err(error) => {
                eprintln!("Bifrost cache GC skipped: could not start its thread: {error}")
            }
        }
    }

    fn reap_finished(&self) {
        let mut tasks = self.tasks.lock().expect("analyzer GC task lock poisoned");
        let mut running = Vec::with_capacity(tasks.len());
        for task in std::mem::take(&mut *tasks) {
            if task.is_finished() {
                join_task(task);
            } else {
                running.push(task);
            }
        }
        *tasks = running;
    }
}

/// Wait for a worker. A collection that panicked has already been reported by
/// the panic hook; this names the task so the report is attributable, and it
/// keeps the panic off the closing thread, which may be unwinding already.
fn join_task(task: JoinHandle<()>) {
    if let Err(payload) = task.join() {
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("non-string panic payload");
        eprintln!("Bifrost cache GC task panicked: {message}");
    }
}

impl Drop for AnalyzerGcCoordinator {
    fn drop(&mut self) {
        let tasks = std::mem::take(
            self.tasks
                .get_mut()
                .expect("analyzer GC task lock poisoned"),
        );
        for task in tasks {
            join_task(task);
        }
    }
}

/// A rendezvous between a test and the worker it schedules: the worker reports
/// that it has started and then waits until the test releases it.
///
/// The safety timeouts turn a regression into a failed test rather than a
/// wedged test binary.
#[cfg(test)]
#[derive(Default)]
struct WorkerHold {
    state: Mutex<WorkerHoldState>,
    changed: std::sync::Condvar,
}

#[cfg(test)]
#[derive(Default)]
struct WorkerHoldState {
    parked: bool,
    released: bool,
}

#[cfg(test)]
impl WorkerHold {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    fn park_until_released(&self) {
        let mut state = self.state.lock().expect("worker hold mutex poisoned");
        state.parked = true;
        self.changed.notify_all();
        let (_state, wait) = self
            .changed
            .wait_timeout_while(state, Self::TIMEOUT, |state| !state.released)
            .expect("worker hold mutex poisoned while parked");
        assert!(
            !wait.timed_out(),
            "the test never released its parked GC worker"
        );
    }

    fn wait_until_parked(&self) {
        let state = self.state.lock().expect("worker hold mutex poisoned");
        let (_state, wait) = self
            .changed
            .wait_timeout_while(state, Self::TIMEOUT, |state| !state.parked)
            .expect("worker hold mutex poisoned while waiting for workers");
        assert!(!wait.timed_out(), "the scheduled GC worker never started");
    }

    fn release(&self) {
        self.state
            .lock()
            .expect("worker hold mutex poisoned")
            .released = true;
        self.changed.notify_all();
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
    use std::path::Path;
    use std::sync::Arc;

    use super::{AnalyzerGcCoordinator, AnalyzerStore, WorkerHold, run_gc};
    use crate::analyzer::store::WorkspaceId;
    use crate::analyzer::workspace::WorkspaceAnalyzer;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject};
    use crate::gitblob::test_repo::{commit_all, init_repo};

    /// The store's `(last_gc_at, blobs_at_last_gc)` collection accounting.
    fn accounting(db_path: &Path) -> (i64, i64) {
        let conn = rusqlite::Connection::open(db_path).expect("read the store's accounting");
        conn.query_row(
            "SELECT last_gc_at, blobs_at_last_gc FROM cache_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("cache_state accounting")
    }

    /// Issue #3170: a store created moments ago is not overdue for collection.
    ///
    /// Collection is due when the store has grown and the time cadence has
    /// elapsed since the last one. A store whose `cache_state` row was written
    /// with `last_gc_at = 0` reads as overdue by the whole epoch, so the first
    /// build that persisted a blob scheduled a full sweep of a store it had
    /// just written -- and that sweep held the analyzer-cache build lock in
    /// front of the session's first diff-derived request.
    ///
    /// The tuning guard pins the production cadence rather than changing it:
    /// the default interval is the subject here.
    #[test]
    fn a_fresh_store_is_not_born_due_for_collection() {
        let _tuning = crate::cache_gc::set_tuning_for_test(
            crate::cache_gc::GC_AUTO_BLOB_THRESHOLD,
            crate::cache_gc::GC_MIN_INTERVAL_SECS,
        );
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), "pub fn widget() -> u32 { 1 }\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "first content");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            project,
            AnalyzerConfig::default(),
        )
        .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);

        let store = AnalyzerStore::open_persistent(&db_path).expect("open the built store");
        let outcome = run_gc(&store, &repository, &root).expect("scheduled collection");

        assert!(
            !outcome.ran,
            "a store created by this build must not already be due: {outcome:?}"
        );
        assert!(
            outcome.total_blobs_after > 0,
            "the build must persist blobs, or the scheduling condition is vacuous"
        );
        let (last_gc_at, blobs_at_last_gc) = accounting(&db_path);
        assert_eq!(
            blobs_at_last_gc, 0,
            "no collection ran, so the recorded blob count must still be the store's initial one"
        );
        assert!(
            last_gc_at > 0,
            "a created store starts its collection cadence at its creation time"
        );
    }

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

    /// Issue #3349: a collection scheduled by a build whose final owner goes
    /// away immediately afterwards still runs, and that owner's drop waits for
    /// it.
    ///
    /// This is what `SearchToolsService::close` does to a watched persisted
    /// session that is closed right after construction: the build has already
    /// scheduled a collection, and the close drops the last store context.
    /// The worker used to consult a weak reference to the coordinator before
    /// touching anything, so when the final drop began before the worker
    /// thread had run its first instruction the collection was cancelled and
    /// `cache_state` never advanced -- an outcome of thread scheduling, which
    /// is why the MCP regression flaked. The hold reproduces that ordering
    /// exactly: the worker is parked before it does anything until the final
    /// drop is already waiting for it.
    #[test]
    fn a_collection_scheduled_before_the_final_drop_still_runs_and_the_drop_waits() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), "pub fn widget() -> u32 { 1 }\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "first content");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            project,
            AnalyzerConfig::default(),
        )
        .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);
        // The MCP regression's setup: a store that holds blobs and is due.
        crate::cache_gc::set_accounting_for_test(&db_path, 0, 0).expect("make collection due");
        let store =
            Arc::new(AnalyzerStore::open_persistent(&db_path).expect("open the built store"));

        let hold = Arc::new(WorkerHold::default());
        let coordinator = Arc::new(AnalyzerGcCoordinator::holding_workers_for_test(Arc::clone(
            &hold,
        )));
        coordinator.schedule(&root, Arc::clone(&store));
        let final_drop = std::thread::spawn(move || drop(coordinator));
        hold.wait_until_parked();

        // The worker has done nothing yet, and the final owner cannot finish
        // dropping while the worker is parked: the drop is waiting for it.
        assert_eq!(accounting(&db_path), (0, 0));
        assert!(
            !final_drop.is_finished(),
            "the final drop must join the scheduled collection, not return around it"
        );

        hold.release();
        final_drop
            .join()
            .expect("the final drop must not panic while joining the collection");
        let (last_gc_at, blobs_at_last_gc) = accounting(&db_path);
        assert!(
            last_gc_at > 0,
            "the collection scheduled before the final drop must have run"
        );
        assert!(
            blobs_at_last_gc > 0,
            "the collection must have accounted for the store's blobs"
        );
    }
}
