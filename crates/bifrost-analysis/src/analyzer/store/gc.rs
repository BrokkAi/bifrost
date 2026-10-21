//! Opportunistic garbage collection for the blob-keyed analyzer store.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::analyzer::store::AnalyzerStore;
use crate::gitblob;

/// Best-effort GC: drop cache entries no longer reachable from git refs or held
/// by any worktree's uncommitted working set.
///
/// Use the workspace's live store so the shared collection entry point can
/// reload statistics and recycle its pooled readers after collection.
#[doc(hidden)]
pub fn run_gc(
    store: &AnalyzerStore,
    repo: &git2::Repository,
    workspace_root: &Path,
) -> Result<crate::cache_gc::GcOutcome, String> {
    crate::analyzer::store::cache_gc::maybe_gc_for_analyzer(store, repo, workspace_root)
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
#[doc(hidden)]
pub struct AnalyzerGcCoordinator {
    automatic: bool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Parks a worker before it touches the repository or the store, so a test
    /// can order the final drop ahead of the collection deterministically.
    #[cfg(any(test, feature = "test-support"))]
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
            #[cfg(any(test, feature = "test-support"))]
            hold_workers_for_test: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn holding_workers_for_test(hold: Arc<WorkerHold>) -> Self {
        let mut coordinator = Self::new(true);
        coordinator.hold_workers_for_test = Some(hold);
        coordinator
    }

    /// Run a throttled GC after a persisted analyzer build/update.
    /// Plain in-memory stores never GC.
    #[doc(hidden)]
    pub fn schedule(&self, workspace_root: &Path, store: Arc<AnalyzerStore>) {
        if !self.automatic {
            return;
        }
        if store.db_path().is_none() {
            return;
        }
        self.reap_finished();
        let root = workspace_root.to_path_buf();
        #[cfg(any(test, feature = "test-support"))]
        let hold = self.hold_workers_for_test.clone();
        let spawned = std::thread::Builder::new()
            .name("bifrost-analyzer-store-gc".to_string())
            .spawn(move || {
                #[cfg(any(test, feature = "test-support"))]
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
                report_gc_join(task);
            } else {
                running.push(task);
            }
        }
        *tasks = running;
    }
}

fn report_gc_join(task: JoinHandle<()>) {
    if let Err(panic) = task.join() {
        // The payload's own `Debug` is `Any { .. }`, which says nothing about
        // what failed; the message is the whole point of the report.
        let reported =
            brokk_bifrost_core::panic_report::reported_panic("analyzer cache GC thread", panic);
        eprintln!("{reported}");
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
            report_gc_join(task);
        }
    }
}

/// A rendezvous between a test and the worker it schedules: the worker reports
/// that it has started and then waits until the test releases it.
///
/// The safety timeouts turn a regression into a failed test rather than a
/// wedged test binary.
#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
#[doc(hidden)]
pub struct WorkerHold {
    state: Mutex<WorkerHoldState>,
    changed: std::sync::Condvar,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
struct WorkerHoldState {
    parked: bool,
    released: bool,
}

#[cfg(any(test, feature = "test-support"))]
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

    #[doc(hidden)]
    pub fn wait_until_parked(&self) {
        let state = self.state.lock().expect("worker hold mutex poisoned");
        let (_state, wait) = self
            .changed
            .wait_timeout_while(state, Self::TIMEOUT, |state| !state.parked)
            .expect("worker hold mutex poisoned while waiting for workers");
        assert!(!wait.timed_out(), "the scheduled GC worker never started");
    }

    #[doc(hidden)]
    pub fn release(&self) {
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
mod tests {}
