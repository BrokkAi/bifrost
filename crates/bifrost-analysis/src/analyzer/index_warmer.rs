//! Coalescing background warmer for the lazily built per-generation query
//! indexes (#1442, #1582).

use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

use crate::analyzer::without_project_reads;
use crate::analyzer::{WorkspaceAnalyzer, spawn_on_dedicated_build_pool};
use crate::profiling;

/// Coalescing background warmer for the lazily built per-generation query
/// indexes (#1442). The Rust type-hierarchy and usage indexes take double-
/// digit seconds to build on large workspaces, so a budgeted request that
/// triggers the build on demand exhausts its request budget. Every snapshot
/// installed after session start (watcher deltas, refresh, update_paths,
/// workspace activation, LSP `didOpen`) is instead warmed here, off the
/// request path; a request arriving mid-warm blocks on the analyzer's
/// one-time index initialization rather than double-building. At most one
/// warm thread runs per warmer, and snapshots installed while a warm is in
/// flight coalesce into a single trailing warm of the latest snapshot, so
/// continuous editing costs at most one superseded build rather than one per
/// delta. Sessions with deferred initial builds use the same path after the
/// complete base snapshot is published, so unrelated code-intelligence
/// operations do not wait for optional accelerators they never query (#1448).
pub struct IndexWarmer {
    state: Mutex<IndexWarmerState>,
    idle: Condvar,
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub panic_before_next_warm: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    forced_outstanding: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    clear_forced_after_warm: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    warm_attempts: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    pause_before_next_warm: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

#[derive(Default)]
struct IndexWarmerState {
    worker: Worker,
    claims: Claims,
}

/// The warm thread. A snapshot can wait only behind a running warm.
#[derive(Default)]
enum Worker {
    #[default]
    Idle,
    Running {
        pending: Option<Arc<WorkspaceAnalyzer>>,
    },
}

/// The index kinds already attempted for the most recently claimed snapshot.
/// A weak identity never holds a superseded workspace (or its SQLite handles).
#[derive(Default)]
struct Claims {
    snapshot: Weak<WorkspaceAnalyzer>,
    kinds: u8,
}

const QUERY: u8 = 1;
const STRUCTURAL: u8 = 2;

impl Claims {
    fn claim(&mut self, snapshot: &Arc<WorkspaceAnalyzer>, outstanding: u8) -> bool {
        if !self.snapshot.ptr_eq(&Arc::downgrade(snapshot)) {
            self.reset(snapshot);
        }
        let new_kinds = outstanding & !self.kinds;
        self.kinds |= outstanding;
        new_kinds != 0
    }

    fn reset(&mut self, snapshot: &Arc<WorkspaceAnalyzer>) {
        self.snapshot = Arc::downgrade(snapshot);
        self.kinds = 0;
    }
}

impl IndexWarmerState {
    /// Claims the snapshot's outstanding kinds. Returns true when the caller
    /// must start the warm thread; a running thread picks the snapshot up as
    /// its trailing warm instead.
    fn schedule(&mut self, snapshot: &Arc<WorkspaceAnalyzer>, outstanding: u8) -> bool {
        if !self.claims.claim(snapshot, outstanding) {
            return false;
        }
        match &mut self.worker {
            Worker::Running { pending } => {
                *pending = Some(Arc::clone(snapshot));
                false
            }
            Worker::Idle => {
                self.worker = Worker::Running { pending: None };
                true
            }
        }
    }

    /// Ends a warm of `current` that returned. Returns the snapshot to warm
    /// next, or `None` after the worker went idle.
    fn finish_warmed(
        &mut self,
        current: &Arc<WorkspaceAnalyzer>,
        outstanding: impl FnOnce() -> u8,
    ) -> Option<Arc<WorkspaceAnalyzer>> {
        if self.claims.snapshot.ptr_eq(&Arc::downgrade(current)) {
            // A retained index may become outstanding again on this
            // snapshot when a new structural posting is requested.
            // Refused indexes remain outstanding and keep their claim.
            self.claims.kinds &= outstanding();
        }
        let Worker::Running { pending } = &mut self.worker else {
            unreachable!("only the running warm thread finishes a warm");
        };
        let next = pending.take();
        if next.is_none() {
            self.worker = Worker::Idle;
        }
        next
    }

    /// Ends a warm of `current` that panicked. A panicking index build
    /// installs nothing, so the same panic resurfaces in whichever request
    /// first demands the index. Clear this snapshot's claim so a later
    /// schedule can retry. Restore its identity first: scheduling a pending
    /// snapshot may have moved the claim, and that pending snapshot must be
    /// able to reclaim on its next schedule.
    ///
    /// The worker goes idle and drops the pending snapshot rather than warming
    /// it: after a panic nothing is warmed until the next schedule
    /// (`pending_snapshot_can_reclaim_after_a_warm_panics`).
    fn finish_panicked(&mut self, current: &Arc<WorkspaceAnalyzer>) {
        self.claims.reset(current);
        assert!(matches!(self.worker, Worker::Running { .. }));
        self.worker = Worker::Idle;
    }
}

fn spawn_index_warm(task: impl FnOnce() + Send + 'static) {
    spawn_on_dedicated_build_pool(move || {
        without_project_reads(task);
    });
}

impl IndexWarmer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(IndexWarmerState::default()),
            idle: Condvar::new(),
            #[cfg(any(test, feature = "test-support"))]
            panic_before_next_warm: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            forced_outstanding: std::sync::atomic::AtomicU8::new(0),
            #[cfg(test)]
            clear_forced_after_warm: std::sync::atomic::AtomicU8::new(0),
            #[cfg(test)]
            warm_attempts: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            pause_before_next_warm: Mutex::new(None),
        })
    }

    /// Queue a background warm of the snapshot's lazy query indexes. Free
    /// when the snapshot is already warm (incremental updates whose sources
    /// were unchanged share the previous generation's indexes).
    ///
    /// A host may call this after every request, not only after the first: the
    /// structural posting indexes become outstanding when a structural query
    /// first asks for them, so what is left to warm is not fixed at session
    /// start (#2879).
    pub fn schedule(self: &Arc<Self>, snapshot: Arc<WorkspaceAnalyzer>) {
        let outstanding = self.outstanding(&snapshot);
        if outstanding == 0 {
            return;
        }
        let mut state = self.state.lock().expect("index warmer lock poisoned");
        if !state.schedule(&snapshot, outstanding) {
            return;
        }
        drop(state);
        let warmer = Arc::clone(self);
        // Keep background warming off the global Rayon pool used by
        // interactive request fan-out. Otherwise a small request can wait for
        // an unrelated workspace-scale warm to release a worker (#2464).
        spawn_index_warm(move || {
            let mut next = Some(snapshot);
            while let Some(current) = next.take() {
                #[cfg(test)]
                warmer
                    .warm_attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #[cfg(test)]
                    if let Some((entered, release)) =
                        warmer.pause_before_next_warm.lock().unwrap().take()
                    {
                        entered.wait();
                        release.wait();
                    }
                    #[cfg(any(test, feature = "test-support"))]
                    if warmer
                        .panic_before_next_warm
                        .swap(false, std::sync::atomic::Ordering::AcqRel)
                    {
                        panic!("injected index warm failure");
                    }
                    let _scope = profiling::scope("mcp_cold.query_index_construction");
                    // The two halves run together because neither may wait on
                    // the other, and because the structural half must claim
                    // its builds promptly: a request that arrives before it
                    // does would lead the build itself, inside the request
                    // (#2879).
                    //
                    // `rayon::join` and not an OS thread: this task already
                    // owns a worker of the dedicated build pool, and both
                    // halves reach that same pool for their own parallelism.
                    // A second thread that asked the pool to install work
                    // would wait for a worker this task is holding, which
                    // deadlocks whenever the pool has one worker
                    // (`BIFROST_PARALLELISM=1`). Joined branches instead run
                    // on the workers there are, concurrently when the pool has
                    // several and one after the other when it has one.
                    let carried =
                        brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
                    rayon::join(
                        || {
                            carried
                                .run(|| without_project_reads(|| current.warm_structural_indexes()))
                        },
                        || carried.run(|| without_project_reads(|| current.warm_query_indexes())),
                    );
                }));
                let mut state = warmer.state.lock().expect("index warmer lock poisoned");
                if let Err(panic) = outcome {
                    // The panic hook has already reported the original panic,
                    // and the contextual diagnostic below explains why the
                    // server remains alive rather than unwinding through
                    // Rayon's unowned spawn, which would abort the process.
                    state.finish_panicked(&current);
                    // Release the snapshot before publishing idle. On Windows,
                    // it can own SQLite handles that prevent temporary cleanup.
                    drop(current);
                    warmer.idle.notify_all();
                    drop(state);
                    let payload =
                        brokk_bifrost_core::panic_report::panic_payload_message(panic.as_ref());
                    eprintln!(
                        "background index warm failed: {payload}; failed index builds remain unpublished and can retry on demand"
                    );
                    return;
                }
                #[cfg(test)]
                warmer.forced_outstanding.fetch_and(
                    !warmer
                        .clear_forced_after_warm
                        .swap(0, std::sync::atomic::Ordering::AcqRel),
                    std::sync::atomic::Ordering::AcqRel,
                );
                next = state.finish_warmed(&current, || warmer.outstanding(&current));
                // Release the snapshot before publishing idle. On Windows,
                // it can own SQLite handles that prevent temporary cleanup.
                drop(current);
                if next.is_none() {
                    warmer.idle.notify_all();
                }
            }
        });
    }

    fn outstanding(&self, snapshot: &WorkspaceAnalyzer) -> u8 {
        let kinds = (u8::from(!snapshot.query_indexes_warm()) * QUERY)
            | (u8::from(!snapshot.structural_indexes_warm()) * STRUCTURAL);
        #[cfg(test)]
        let kinds = kinds
            | self
                .forced_outstanding
                .load(std::sync::atomic::Ordering::Relaxed);
        kinds
    }

    /// Block until no warm is running or queued. Panics if the warmer does not
    /// go idle within 30 seconds.
    pub fn wait_until_idle(&self) {
        let state = self.state.lock().expect("index warmer lock poisoned");
        let (state, timeout) = self
            .idle
            .wait_timeout_while(state, Duration::from_secs(30), |state| {
                matches!(state.worker, Worker::Running { .. })
            })
            .expect("index warmer lock poisoned while waiting for idle");
        assert!(
            !timeout.timed_out(),
            "background index warm did not complete"
        );
        assert!(matches!(state.worker, Worker::Idle));
    }
}

#[cfg(test)]
mod tests {

    use super::{IndexWarmer, QUERY, STRUCTURAL, spawn_index_warm};
    use crate::analyzer::workspace::EmptyAnalyzer;
    use crate::analyzer::{FilesystemProject, Project, WorkspaceAnalyzer};
    use brokk_bifrost_test_macros::hardwon;

    use rayon::prelude::*;

    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    #[hardwon("#8486: the warmer requeued a snapshot whose index cell refused retention, forever")]
    fn refused_index_is_attempted_once_until_another_kind_becomes_outstanding() {
        let root = tempfile::tempdir().unwrap();
        let snapshot = Arc::new(WorkspaceAnalyzer::Empty(EmptyAnalyzer::new(Arc::new(
            FilesystemProject::new(root.path()).unwrap(),
        ))));
        let warmer = IndexWarmer::new();
        warmer.forced_outstanding.store(QUERY, Ordering::Relaxed);
        warmer.schedule(Arc::clone(&snapshot));
        warmer.wait_until_idle();
        warmer.schedule(Arc::clone(&snapshot));
        warmer.wait_until_idle();
        assert_eq!(warmer.warm_attempts.load(Ordering::Relaxed), 1);
        warmer
            .forced_outstanding
            .store(QUERY | STRUCTURAL, Ordering::Relaxed);
        warmer
            .clear_forced_after_warm
            .store(STRUCTURAL, Ordering::Relaxed);
        warmer.schedule(Arc::clone(&snapshot));
        warmer.wait_until_idle();
        assert_eq!(warmer.warm_attempts.load(Ordering::Relaxed), 2);
        assert_eq!(warmer.forced_outstanding.load(Ordering::Relaxed), QUERY);
        warmer
            .forced_outstanding
            .store(QUERY | STRUCTURAL, Ordering::Relaxed);
        warmer.schedule(snapshot);
        warmer.wait_until_idle();
        assert_eq!(warmer.warm_attempts.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn panicked_index_retries_only_on_the_next_schedule() {
        let root = tempfile::tempdir().unwrap();
        let snapshot = Arc::new(WorkspaceAnalyzer::Empty(EmptyAnalyzer::new(Arc::new(
            FilesystemProject::new(root.path()).unwrap(),
        ))));
        let warmer = IndexWarmer::new();
        warmer.forced_outstanding.store(QUERY, Ordering::Relaxed);
        warmer
            .clear_forced_after_warm
            .store(QUERY, Ordering::Relaxed);
        warmer.panic_before_next_warm.store(true, Ordering::Relaxed);
        warmer.schedule(Arc::clone(&snapshot));
        warmer.wait_until_idle();
        assert_eq!(warmer.warm_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(warmer.forced_outstanding.load(Ordering::Relaxed), QUERY);

        warmer.schedule(snapshot);
        warmer.wait_until_idle();
        assert_eq!(warmer.warm_attempts.load(Ordering::Relaxed), 2);
        assert_eq!(warmer.forced_outstanding.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn pending_snapshot_can_reclaim_after_a_warm_panics() {
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(FilesystemProject::new(root.path()).unwrap());
        let snapshot = Arc::new(WorkspaceAnalyzer::Empty(EmptyAnalyzer::new(Arc::clone(
            &project,
        ))));
        let next_snapshot = Arc::new(WorkspaceAnalyzer::Empty(EmptyAnalyzer::new(project)));
        let warmer = IndexWarmer::new();
        warmer.forced_outstanding.store(QUERY, Ordering::Relaxed);
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *warmer.pause_before_next_warm.lock().unwrap() =
            Some((Arc::clone(&entered), Arc::clone(&release)));
        warmer.panic_before_next_warm.store(true, Ordering::Relaxed);
        warmer.schedule(snapshot);
        entered.wait();
        warmer.schedule(Arc::clone(&next_snapshot));
        release.wait();
        warmer.wait_until_idle();
        assert_eq!(warmer.warm_attempts.load(Ordering::Relaxed), 1);

        warmer.schedule(next_snapshot);
        warmer.wait_until_idle();
        assert_eq!(warmer.warm_attempts.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn nested_warm_parallelism_stays_off_the_global_rayon_pool() {
        let (sender, receiver) = mpsc::channel();
        spawn_index_warm(move || {
            let worker_names: Vec<_> = (0..rayon::current_num_threads().max(1))
                .into_par_iter()
                .map(|_| {
                    std::thread::current()
                        .name()
                        .unwrap_or("<unnamed>")
                        .to_string()
                })
                .collect();
            sender.send(worker_names).unwrap();
        });

        let worker_names = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("background warm should complete on the dedicated pool");
        assert!(!worker_names.is_empty());
        assert!(
            worker_names
                .iter()
                .all(|name| name.starts_with("bifrost-index-build-")),
            "nested warm parallelism escaped to non-build workers: {worker_names:?}"
        );
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    use crate::analyzer::{MultiAnalyzer, capture_query_reads};

    #[test]
    fn idle_warmer_state_is_coordination_without_source_inputs() {
        let analyzer = MultiAnalyzer::default();
        let warmer = IndexWarmer::new();
        let (_, reads) = capture_query_reads(&analyzer, || {
            warmer.wait_until_idle();
            assert!(matches!(warmer.state.lock().unwrap().worker, Worker::Idle));
        });
        assert!(reads.keys().is_empty());
    }
}
