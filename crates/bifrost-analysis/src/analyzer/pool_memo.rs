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

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const CANCELLABLE_WAIT_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) struct PoolSafeMemo<T> {
    state: Mutex<MemoState<T>>,
    ready: Condvar,
}

struct MemoState<T> {
    value: Option<Arc<T>>,
    builders: usize,
}

/// Releases one builder claim and wakes waiters when a build finishes.
struct BuildingGuard<'a, T> {
    memo: &'a PoolSafeMemo<T>,
}

impl<T> Drop for BuildingGuard<'_, T> {
    fn drop(&mut self) {
        let mut state = self.memo.state.lock().expect("pool memo poisoned");
        assert!(state.builders > 0, "pool memo builder count underflow");
        state.builders -= 1;
        self.memo.ready.notify_all();
    }
}

impl<T> PoolSafeMemo<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(MemoState {
                value: None,
                builders: 0,
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
    /// Rayon workers never wait: parking a worker on a build whose `par_iter`
    /// join may steal a job that re-enters this memo deadlocks the pool, so
    /// they duplicate the build serially instead (first write wins).
    fn wait_or_claim_build(&self) -> Option<Arc<T>> {
        let on_pool = rayon::current_thread_index().is_some();
        let mut state = self.state.lock().expect("pool memo poisoned");
        loop {
            if let Some(value) = state.value.as_ref() {
                return Some(Arc::clone(value));
            }
            if state.builders > 0 && !on_pool {
                state = self.ready.wait(state).expect("pool memo poisoned");
                continue;
            }
            state.builders += 1;
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
        let on_pool = rayon::current_thread_index().is_some();
        let mut state = self.state.lock().expect("pool memo poisoned");
        loop {
            if let Some(value) = state.value.as_ref() {
                return Some(Some(Arc::clone(value)));
            }
            if !keep_going() {
                return None;
            }
            if state.builders > 0 && !on_pool {
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
        if let Some(value) = self.wait_or_claim_build() {
            return value;
        }
        let _guard = BuildingGuard { memo: self };

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
        if let Some(value) = self.wait_or_claim_build() {
            return Ok(value);
        }
        let _guard = BuildingGuard { memo: self };

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
        let _guard = BuildingGuard { memo: self };

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
