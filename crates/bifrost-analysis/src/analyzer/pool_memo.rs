//! Pool-safe lazy memoization for analyzer-level caches.
//!
//! Analyzer-level lazy caches whose initializers use rayon must use
//! [`PoolSafeMemo`] rather than blocking primitives such as `OnceLock::get_or_init`.
//! These caches may be reached from inside rayon worker threads during whole-workspace
//! parallel scans. Blocking those workers while another initializer waits on rayon can
//! deadlock the pool. Whole-workspace `par_iter` scans should also pre-materialize any
//! such indexes they can touch before entering the scan.
//!
//! Callers *off* the pool can block safely, so they wait for an in-flight build
//! instead of duplicating it -- a background warmer and the first request no
//! longer race two whole-workspace builds against each other. Only rayon
//! workers fall back to a duplicate serial build (first write wins).
//!
//! A background warm can lift that last restriction with
//! [`PoolSafeMemo::get_or_build_on_dedicated_pool`]: the build runs on a pool of
//! this module's own, so it reaches completion without any global-pool worker
//! and a global-pool worker that reaches the same memo can wait for it. Without
//! that, a whole-workspace index build started off the request path is still
//! duplicated -- serially -- by the first request whose parallel fan-out
//! touches the index (issue #1757).

use std::cell::Cell;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

const CANCELLABLE_WAIT_INTERVAL: Duration = Duration::from_millis(10);

thread_local! {
    /// Set on every worker of [`dedicated_build_pool`]. Such a worker is running
    /// a dedicated build's own parallelism, so it must never park on a memo: the
    /// build it would wait for can be the very build whose jobs it is running
    /// (the issue #549 shape, one pool inwards).
    static ON_DEDICATED_BUILD_POOL: Cell<bool> = const { Cell::new(false) };
}

/// The rayon pool that background index builds run on.
///
/// A build here consumes no worker of the global pool, which is what lets a
/// global-pool worker park on it instead of duplicating it serially. Built once
/// per process; its workers sleep while no build is in flight.
fn dedicated_build_pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .thread_name(|index| format!("bifrost-index-build-{index}"))
            .start_handler(|_| ON_DEDICATED_BUILD_POOL.with(|flag| flag.set(true)))
            .build()
            .expect("dedicated index-build pool")
    })
}

/// Run `task` on [`dedicated_build_pool`] and return immediately.
///
/// The background half of the ExecPlan Milestone 3 Rust fact catch-up
/// (`.agents/plans/rust-usage-index-v2.md`): an above-threshold catch-up batch
/// must not be billed to the querying thread, and it must not consume a
/// global-pool worker either, because the query that scheduled it goes straight
/// back to its own parallel fan-out.
pub(crate) fn spawn_on_dedicated_build_pool(task: impl FnOnce() + Send + 'static) {
    dedicated_build_pool().spawn(task);
}

pub(crate) struct PoolSafeMemo<T> {
    state: Mutex<MemoState<T>>,
    ready: Condvar,
}

struct MemoState<T> {
    value: Option<Arc<T>>,
    builders: usize,
    /// Of `builders`, how many run on [`dedicated_build_pool`].
    dedicated_builders: usize,
}

impl<T> MemoState<T> {
    /// Whether the calling thread may park on an in-flight build.
    ///
    /// Off the rayon pool: always -- parking cannot starve a rayon build. On a
    /// global-pool worker: only while a dedicated-pool build is in flight,
    /// because that build reaches its value without this worker. On a
    /// dedicated-pool worker: never.
    fn parking_is_safe(&self) -> bool {
        if rayon::current_thread_index().is_none() {
            return true;
        }
        !ON_DEDICATED_BUILD_POOL.with(Cell::get) && self.dedicated_builders > 0
    }
}

/// Releases one builder claim and wakes waiters when a build finishes.
struct BuildingGuard<'a, T> {
    memo: &'a PoolSafeMemo<T>,
    dedicated: bool,
}

impl<T> Drop for BuildingGuard<'_, T> {
    fn drop(&mut self) {
        let mut state = self.memo.state.lock().expect("pool memo poisoned");
        assert!(state.builders > 0, "pool memo builder count underflow");
        state.builders -= 1;
        if self.dedicated {
            assert!(
                state.dedicated_builders > 0,
                "pool memo dedicated builder count underflow"
            );
            state.dedicated_builders -= 1;
        }
        self.memo.ready.notify_all();
    }
}

impl<T> PoolSafeMemo<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(MemoState {
                value: None,
                builders: 0,
                dedicated_builders: 0,
            }),
            ready: Condvar::new(),
        }
    }

    /// The stored value if a build has completed, without building. `None`
    /// both before any build and while one is in flight. Production warm-ness
    /// checks use [`Self::is_ready`]; tests use this to inspect the stored Arc.
    #[cfg(test)]
    pub(crate) fn get(&self) -> Option<Arc<T>> {
        self.state.lock().expect("pool memo poisoned").value.clone()
    }

    /// Whether a build has completed, without blocking behind an in-flight
    /// builder (`query_indexes_warm` polls this from request threads).
    pub(crate) fn is_ready(&self) -> bool {
        self.state
            .lock()
            .expect("pool memo poisoned")
            .value
            .is_some()
    }

    /// Wait for an in-flight build when this caller may block, or claim the
    /// builder role. Returns the value if one became available while waiting.
    /// A rayon worker only waits for a build running on
    /// [`dedicated_build_pool`]: parking a worker on a build whose `par_iter`
    /// join may steal a job that re-enters this memo deadlocks the pool, so
    /// otherwise it duplicates the build serially (first write wins).
    fn wait_or_claim_build(&self, claim: BuildClaim) -> Option<Arc<T>> {
        let mut state = self.state.lock().expect("pool memo poisoned");
        loop {
            if let Some(value) = state.value.as_ref() {
                return Some(Arc::clone(value));
            }
            if state.builders > 0 && state.parking_is_safe() {
                state = self.ready.wait(state).expect("pool memo poisoned");
                continue;
            }
            state.builders += 1;
            if claim == BuildClaim::Dedicated {
                state.dedicated_builders += 1;
            }
            return None;
        }
    }

    /// Wait for an in-flight build while `keep_going` permits the wait.
    ///
    /// A request must not remain parked behind a background index build after
    /// its cancellation token trips. The timed wait keeps normal builders on
    /// the condition-variable path and gives cancellation a bounded polling
    /// interval. Rayon workers retain the duplicate serial-build rule.
    fn wait_or_claim_build_while(&self, keep_going: &impl Fn() -> bool) -> Option<Option<Arc<T>>> {
        let mut state = self.state.lock().expect("pool memo poisoned");
        loop {
            if let Some(value) = state.value.as_ref() {
                return Some(Some(Arc::clone(value)));
            }
            if !keep_going() {
                return None;
            }
            if state.builders > 0 && state.parking_is_safe() {
                (state, _) = self
                    .ready
                    .wait_timeout(state, CANCELLABLE_WAIT_INTERVAL)
                    .expect("pool memo poisoned");
                continue;
            }
            state.builders += 1;
            return Some(None);
        }
    }

    pub(crate) fn get_or_build(
        &self,
        build_parallel: impl FnOnce() -> T,
        build_serial: impl FnOnce() -> T,
    ) -> Arc<T> {
        self.get_or_build_with_policy(build_parallel, build_serial, BuildPolicy::PoolSafe)
    }

    /// Build the value on [`dedicated_build_pool`], off the global rayon pool.
    ///
    /// No production caller since the Rust usage index stopped being built
    /// (ExecPlan Milestone 3); issue #1772 wants it for the type-hierarchy
    /// warm, which is the next whole-workspace build to move off the request
    /// path, so the mechanism and its #1757 regression test stay.
    ///
    /// Use from a background warm. While this build runs, a global-pool worker
    /// that reaches the same memo waits for it instead of duplicating it
    /// serially: the duplicate is a second whole-workspace build, billed to
    /// whichever request's parallel fan-out touched the index first (#1757).
    /// Returns an already-built or concurrently built value unchanged.
    #[allow(dead_code)]
    pub(crate) fn get_or_build_on_dedicated_pool(&self, build: impl FnOnce() -> T + Send) -> Arc<T>
    where
        T: Send,
    {
        if let Some(value) = self.wait_or_claim_build(BuildClaim::Dedicated) {
            return value;
        }
        let _guard = BuildingGuard {
            memo: self,
            dedicated: true,
        };

        let built = Arc::new(dedicated_build_pool().install(build));

        let mut state = self.state.lock().expect("pool memo poisoned");
        if let Some(existing) = state.value.as_ref() {
            return Arc::clone(existing);
        }
        state.value = Some(Arc::clone(&built));
        built
    }

    /// Build the value with the parallel builder even when called from a rayon
    /// worker. Use only from orchestration code that prewarms a cache before
    /// starting its own nested parallel scan.
    pub(crate) fn get_or_build_parallel(
        &self,
        build_parallel: impl FnOnce() -> T,
        build_serial: impl FnOnce() -> T,
    ) -> Arc<T> {
        self.get_or_build_with_policy(build_parallel, build_serial, BuildPolicy::ForceParallel)
    }

    fn get_or_build_with_policy(
        &self,
        build_parallel: impl FnOnce() -> T,
        build_serial: impl FnOnce() -> T,
        policy: BuildPolicy,
    ) -> Arc<T> {
        if let Some(value) = self.wait_or_claim_build(BuildClaim::Shared) {
            return value;
        }
        let _guard = BuildingGuard {
            memo: self,
            dedicated: false,
        };

        let built = Arc::new(match policy {
            BuildPolicy::ForceParallel => build_parallel(),
            BuildPolicy::PoolSafe if rayon::current_thread_index().is_some() => build_serial(),
            BuildPolicy::PoolSafe => build_parallel(),
        });

        let mut state = self.state.lock().expect("pool memo poisoned");
        if let Some(existing) = state.value.as_ref() {
            return Arc::clone(existing);
        }
        state.value = Some(Arc::clone(&built));
        built
    }

    pub(crate) fn get_or_try_build<E>(
        &self,
        build_parallel: impl FnOnce() -> Result<T, E>,
        build_serial: impl FnOnce() -> Result<T, E>,
    ) -> Result<Arc<T>, E> {
        if let Some(value) = self.wait_or_claim_build(BuildClaim::Shared) {
            return Ok(value);
        }
        let _guard = BuildingGuard {
            memo: self,
            dedicated: false,
        };

        let built = Arc::new(if rayon::current_thread_index().is_some() {
            build_serial()?
        } else {
            build_parallel()?
        });

        let mut state = self.state.lock().expect("pool memo poisoned");
        if let Some(existing) = state.value.as_ref() {
            return Ok(Arc::clone(existing));
        }
        state.value = Some(Arc::clone(&built));
        Ok(built)
    }

    /// Get or build a value while cooperative work is still permitted.
    ///
    /// The builders must use the same predicate for their own checkpoints.
    /// A stopped build is not published.
    pub(crate) fn get_or_build_while(
        &self,
        keep_going: &impl Fn() -> bool,
        build_parallel: impl FnOnce() -> Option<T>,
        build_serial: impl FnOnce() -> Option<T>,
    ) -> Option<Arc<T>> {
        if let Some(value) = self.wait_or_claim_build_while(keep_going)? {
            return Some(value);
        }
        let _guard = BuildingGuard {
            memo: self,
            dedicated: false,
        };

        let built = Arc::new(if rayon::current_thread_index().is_some() {
            build_serial()?
        } else {
            build_parallel()?
        });

        let mut state = self.state.lock().expect("pool memo poisoned");
        if let Some(existing) = state.value.as_ref() {
            return Some(Arc::clone(existing));
        }
        state.value = Some(Arc::clone(&built));
        Some(built)
    }

    #[allow(dead_code)]
    pub(crate) fn invalidate(&self) {
        self.state.lock().expect("pool memo poisoned").value = None;
    }
}

#[derive(Clone, Copy)]
enum BuildPolicy {
    PoolSafe,
    ForceParallel,
}

/// Which pool a claimed build will run on. A `Dedicated` claim is what tells
/// global-pool waiters that parking on this build is safe.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BuildClaim {
    Shared,
    Dedicated,
}

impl<T> Default for PoolSafeMemo<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::PoolSafeMemo;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn racing_builders_observe_one_stored_value() {
        let memo = Arc::new(PoolSafeMemo::new());
        let barrier = Arc::new(Barrier::new(2));

        let handles: Vec<_> = (0..2)
            .map(|value| {
                let memo = Arc::clone(&memo);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    memo.get_or_build(|| value, || value)
                })
            })
            .collect();

        let values: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread should finish"))
            .collect();
        let stored = memo.get().expect("memo should be populated");

        assert!(Arc::ptr_eq(&values[0], &stored));
        assert!(Arc::ptr_eq(&values[1], &stored));
    }

    #[test]
    fn selects_serial_builder_on_rayon_worker_and_parallel_off_pool() {
        let memo = PoolSafeMemo::new();
        let parallel_calls = AtomicUsize::new(0);
        let serial_calls = AtomicUsize::new(0);

        let value = memo.get_or_build(
            || {
                parallel_calls.fetch_add(1, Ordering::SeqCst);
                "parallel"
            },
            || {
                serial_calls.fetch_add(1, Ordering::SeqCst);
                "serial"
            },
        );
        assert_eq!(*value, "parallel");
        assert_eq!(parallel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(serial_calls.load(Ordering::SeqCst), 0);

        memo.invalidate();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("rayon pool");
        let value = pool.install(|| {
            memo.get_or_build(
                || {
                    parallel_calls.fetch_add(1, Ordering::SeqCst);
                    "parallel"
                },
                || {
                    serial_calls.fetch_add(1, Ordering::SeqCst);
                    "serial"
                },
            )
        });
        assert_eq!(*value, "serial");
        assert_eq!(parallel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(serial_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_build_is_not_published() {
        let memo = PoolSafeMemo::<usize>::new();

        let result = memo.get_or_try_build(|| Err("cancelled"), || Err("cancelled"));

        assert_eq!(result.unwrap_err(), "cancelled");
        assert!(memo.get().is_none());
    }

    #[test]
    fn invalidate_causes_rebuild() {
        let memo = PoolSafeMemo::new();
        let calls = AtomicUsize::new(0);

        let first = memo.get_or_build(
            || calls.fetch_add(1, Ordering::SeqCst),
            || calls.fetch_add(1, Ordering::SeqCst),
        );
        memo.invalidate();
        let second = memo.get_or_build(
            || calls.fetch_add(1, Ordering::SeqCst),
            || calls.fetch_add(1, Ordering::SeqCst),
        );

        assert_eq!(*first, 0);
        assert_eq!(*second, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// Regression guard for issue #549. With a blocking once-cell, this shape
    /// deadlocks unconditionally: the off-pool initializer waits for its own
    /// `par_iter` items, while those items — on pool threads — park on the cell
    /// the initializer holds. `PoolSafeMemo` must complete it instead: the
    /// re-entrant callers see an empty slot, build serially, and first-write-wins
    /// keeps every caller on one stored value.
    #[test]
    fn reentrant_build_from_inner_parallelism_completes() {
        use rayon::prelude::*;
        use std::time::Duration;

        let memo = Arc::new(PoolSafeMemo::new());
        let (tx, rx) = mpsc::channel();

        let builder_memo = Arc::clone(&memo);
        let builder = thread::spawn(move || {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(2)
                .build()
                .expect("rayon pool");
            let value = builder_memo.get_or_build(
                || {
                    let inner_memo = Arc::clone(&builder_memo);
                    pool.install(|| {
                        (0..64usize)
                            .into_par_iter()
                            .map(|_| *inner_memo.get_or_build(|| 7usize, || 7usize))
                            .sum::<usize>()
                    })
                },
                || 7usize,
            );
            tx.send(value).expect("send built value");
        });

        let value = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("re-entrant get_or_build deadlocked");
        let stored = memo.get().expect("memo should be populated");
        assert!(Arc::ptr_eq(&value, &stored));
        // The re-entrant inner calls each returned 7, so whichever build won
        // first-write-wins is either the inner serial 7 or the outer sum 448;
        // every later reader must observe that single stored value.
        assert!(*stored == 7 || *stored == 448);
        builder.join().expect("builder should finish");
    }

    /// An off-pool caller that arrives while another thread is building waits
    /// for that build instead of duplicating it: both observe the builder's
    /// value and the second builder is never invoked.
    #[test]
    fn off_pool_caller_waits_for_in_flight_build() {
        use std::time::Duration;

        let memo = Arc::new(PoolSafeMemo::new());
        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();

        let slow_memo = Arc::clone(&memo);
        let slow = thread::spawn(move || {
            slow_memo.get_or_build(
                || {
                    started_tx.send(()).expect("send start");
                    resume_rx.recv().expect("resume slow builder");
                    1
                },
                || 1,
            )
        });

        started_rx.recv().expect("slow builder should start");
        let waiter_memo = Arc::clone(&memo);
        let waiter = thread::spawn(move || {
            waiter_memo.get_or_build(|| panic!("waiter must not build"), || 1)
        });
        // Give the waiter time to park on the in-flight build before resuming.
        thread::sleep(Duration::from_millis(50));
        resume_tx.send(()).expect("resume slow builder");
        let slow = slow.join().expect("slow thread should finish");
        let waited = waiter.join().expect("waiter thread should finish");

        assert!(Arc::ptr_eq(&slow, &waited));
        assert!(Arc::ptr_eq(
            &slow,
            &memo.get().expect("memo should be populated")
        ));
        assert_eq!(*waited, 1);
    }

    #[test]
    fn cancelled_off_pool_waiter_leaves_in_flight_build_running() {
        use std::time::Duration;

        let memo = Arc::new(PoolSafeMemo::new());
        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();

        let builder_memo = Arc::clone(&memo);
        let builder = thread::spawn(move || {
            builder_memo.get_or_build(
                || {
                    started_tx.send(()).expect("send start");
                    resume_rx.recv().expect("resume builder");
                    7
                },
                || unreachable!("off-pool build takes the parallel branch"),
            )
        });
        started_rx.recv().expect("builder should start");

        let keep_going = Arc::new(AtomicBool::new(true));
        let waiter_memo = Arc::clone(&memo);
        let waiter_flag = Arc::clone(&keep_going);
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (waiter_tx, waiter_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let result = waiter_memo.get_or_build_while(
                &|| {
                    waiting_tx.send(()).expect("report wait checkpoint");
                    waiter_flag.load(Ordering::Acquire)
                },
                || panic!("waiter must not build"),
                || panic!("waiter must not build"),
            );
            waiter_tx.send(result).expect("send waiter result");
        });

        waiting_rx.recv().expect("waiter should reach checkpoint");
        keep_going.store(false, Ordering::Release);
        assert!(
            waiter_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("cancelled waiter did not stop")
                .is_none()
        );
        assert!(memo.get().is_none());
        waiter.join().expect("waiter should finish");

        resume_tx.send(()).expect("resume builder");
        assert_eq!(*builder.join().expect("builder should finish"), 7);
        assert_eq!(*memo.get().expect("builder should publish"), 7);
    }

    #[test]
    fn cancelled_pool_duplicate_does_not_release_primary_builder_claim() {
        use std::time::Duration;

        let memo = Arc::new(PoolSafeMemo::new());
        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let primary_memo = Arc::clone(&memo);
        let primary = thread::spawn(move || {
            primary_memo.get_or_build(
                || {
                    started_tx.send(()).expect("send start");
                    resume_rx.recv().expect("resume primary");
                    7
                },
                || unreachable!("off-pool build takes the parallel branch"),
            )
        });
        started_rx.recv().expect("primary should start");

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("rayon pool");
        let duplicate_memo = Arc::clone(&memo);
        assert!(
            pool.install(|| duplicate_memo.get_or_build_while(&|| true, || None, || None))
                .is_none()
        );

        let follower_memo = Arc::clone(&memo);
        let (follower_tx, follower_rx) = mpsc::channel();
        let follower = thread::spawn(move || {
            let value = follower_memo.get_or_build(
                || panic!("follower must wait for the primary"),
                || unreachable!("off-pool build takes the parallel branch"),
            );
            follower_tx.send(()).expect("send follower result");
            value
        });
        assert!(
            follower_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "follower did not wait for the primary builder"
        );

        resume_tx.send(()).expect("resume primary");
        let primary = primary.join().expect("primary should finish");
        let follower = follower.join().expect("follower should finish");
        assert!(Arc::ptr_eq(&primary, &follower));
    }

    /// The #1757 guarantee: while a dedicated-pool build is in flight, a
    /// global-pool worker that reaches the memo waits for that build instead
    /// of duplicating it. The duplicate is what billed a whole-workspace Rust
    /// usage-index build to a `get_symbol_sources` request's own fan-out.
    #[test]
    fn global_pool_worker_waits_for_a_dedicated_build_instead_of_duplicating() {
        use std::time::Duration;

        let memo = Arc::new(PoolSafeMemo::new());
        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();

        let warm_memo = Arc::clone(&memo);
        let warm = thread::spawn(move || {
            warm_memo.get_or_build_on_dedicated_pool(move || {
                started_tx.send(()).expect("send start");
                resume_rx.recv().expect("resume dedicated build");
                7usize
            })
        });
        started_rx.recv().expect("dedicated build should start");

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("rayon pool");
        let worker_memo = Arc::clone(&memo);
        let (worker_tx, worker_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let value = pool.install(|| {
                worker_memo.get_or_build(
                    || panic!("a waiting global-pool worker must not build"),
                    || panic!("a waiting global-pool worker must not build"),
                )
            });
            worker_tx.send(()).expect("send worker completion");
            value
        });
        assert!(
            worker_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "the pool worker returned without waiting for the dedicated build"
        );

        resume_tx.send(()).expect("resume dedicated build");
        let warmed = warm.join().expect("warm thread should finish");
        let waited = worker.join().expect("worker thread should finish");
        assert!(Arc::ptr_eq(&warmed, &waited));
        assert_eq!(*waited, 7);
    }

    /// The workers of the dedicated pool are the build's own parallelism, so
    /// they keep the duplicate-serial-build rule: re-entering the same memo
    /// from inside a dedicated build must complete, not deadlock (#549).
    #[test]
    fn reentrant_call_from_inside_a_dedicated_build_completes() {
        use rayon::prelude::*;
        use std::time::Duration;

        let memo = Arc::new(PoolSafeMemo::new());
        let (tx, rx) = mpsc::channel();

        let builder_memo = Arc::clone(&memo);
        let builder = thread::spawn(move || {
            let inner_memo = Arc::clone(&builder_memo);
            let value = builder_memo.get_or_build_on_dedicated_pool(move || {
                (0..64usize)
                    .into_par_iter()
                    .map(|_| *inner_memo.get_or_build(|| 7usize, || 7usize))
                    .sum::<usize>()
            });
            tx.send(value).expect("send built value");
        });

        let value = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("re-entrant dedicated build deadlocked");
        let stored = memo.get().expect("memo should be populated");
        assert!(Arc::ptr_eq(&value, &stored));
        assert!(*stored == 7 || *stored == 448);
        builder.join().expect("builder should finish");
    }

    /// A panicking build must wake waiters and leave the slot empty so a woken
    /// waiter becomes the builder instead of hanging forever.
    #[test]
    fn panicked_build_wakes_waiters_who_then_build() {
        use std::time::Duration;

        let memo = Arc::new(PoolSafeMemo::new());
        let (started_tx, started_rx) = mpsc::channel();

        let panicking_memo = Arc::clone(&memo);
        let panicking = thread::spawn(move || {
            panicking_memo.get_or_build(
                || -> usize {
                    started_tx.send(()).expect("send start");
                    thread::sleep(Duration::from_millis(50));
                    panic!("build failed");
                },
                || unreachable!("off-pool build takes the parallel branch"),
            )
        });

        started_rx.recv().expect("panicking builder should start");
        let value = memo.get_or_build(|| 7usize, || 7usize);
        assert!(panicking.join().is_err());
        assert_eq!(*value, 7);
    }
}
