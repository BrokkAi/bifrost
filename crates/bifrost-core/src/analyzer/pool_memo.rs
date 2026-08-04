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

pub struct PoolSafeMemo<T> {
    state: Mutex<MemoState<T>>,
    ready: Condvar,
}

struct MemoState<T> {
    value: Option<Arc<T>>,
    building: bool,
}

/// Resets `building` and wakes waiters when a build finishes, including by
/// panic: a waiter woken after a panicked build sees an empty slot and becomes
/// the builder itself instead of hanging forever.
struct BuildingGuard<'a, T> {
    memo: &'a PoolSafeMemo<T>,
}

impl<T> Drop for BuildingGuard<'_, T> {
    fn drop(&mut self) {
        self.memo.state.lock().expect("pool memo poisoned").building = false;
        self.memo.ready.notify_all();
    }
}

impl<T> PoolSafeMemo<T> {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MemoState {
                value: None,
                building: false,
            }),
            ready: Condvar::new(),
        }
    }

    /// The stored value if a build has completed, without building. `None`
    /// both before any build and while one is in flight. Production warm-ness
    /// checks use [`Self::is_ready`]; tests use this to inspect the stored Arc.
    #[cfg(test)]
    pub fn get(&self) -> Option<Arc<T>> {
        self.state.lock().expect("pool memo poisoned").value.clone()
    }

    /// Whether a build has completed, without blocking behind an in-flight
    /// builder (`query_indexes_warm` polls this from request threads).
    pub fn is_ready(&self) -> bool {
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
            if state.building && !on_pool {
                state = self.ready.wait(state).expect("pool memo poisoned");
                continue;
            }
            state.building = true;
            return None;
        }
    }

    pub fn get_or_build(
        &self,
        build_parallel: impl FnOnce() -> T,
        build_serial: impl FnOnce() -> T,
    ) -> Arc<T> {
        self.get_or_build_with_policy(build_parallel, build_serial, BuildPolicy::PoolSafe)
    }

    /// Build the value with the parallel builder even when called from a rayon
    /// worker. Use only from orchestration code that prewarms a cache before
    /// starting its own nested parallel scan.
    pub fn get_or_build_parallel(
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

    pub fn get_or_try_build<E>(
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

    #[allow(dead_code)]
    pub fn invalidate(&self) {
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
    use std::sync::atomic::{AtomicUsize, Ordering};
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
        thread::spawn(move || {
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
