//! Pool-safe lazy memoization for analyzer-level caches.
//!
//! Analyzer-level lazy caches whose initializers use rayon must use
//! [`PoolSafeMemo`] rather than blocking primitives such as `OnceLock::get_or_init`.
//! These caches may be reached from inside rayon worker threads during whole-workspace
//! parallel scans. Blocking those workers while another initializer waits on rayon can
//! deadlock the pool. Whole-workspace `par_iter` scans should also pre-materialize any
//! such indexes they can touch before entering the scan.

use std::sync::{Arc, Mutex};

pub(crate) struct PoolSafeMemo<T> {
    slot: Mutex<Option<Arc<T>>>,
}

impl<T> PoolSafeMemo<T> {
    pub(crate) fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    pub(crate) fn get(&self) -> Option<Arc<T>> {
        self.slot.lock().expect("pool memo poisoned").clone()
    }

    pub(crate) fn get_or_build(
        &self,
        build_parallel: impl FnOnce() -> T,
        build_serial: impl FnOnce() -> T,
    ) -> Arc<T> {
        if let Some(value) = self.get() {
            return value;
        }

        let built = Arc::new(if rayon::current_thread_index().is_some() {
            build_serial()
        } else {
            build_parallel()
        });

        let mut slot = self.slot.lock().expect("pool memo poisoned");
        if let Some(existing) = slot.as_ref() {
            return Arc::clone(existing);
        }
        *slot = Some(Arc::clone(&built));
        built
    }

    pub(crate) fn get_or_try_build<E>(
        &self,
        build_parallel: impl FnOnce() -> Result<T, E>,
        build_serial: impl FnOnce() -> Result<T, E>,
    ) -> Result<Arc<T>, E> {
        if let Some(value) = self.get() {
            return Ok(value);
        }

        let built = Arc::new(if rayon::current_thread_index().is_some() {
            build_serial()?
        } else {
            build_parallel()?
        });

        let mut slot = self.slot.lock().expect("pool memo poisoned");
        if let Some(existing) = slot.as_ref() {
            return Ok(Arc::clone(existing));
        }
        *slot = Some(Arc::clone(&built));
        Ok(built)
    }

    #[allow(dead_code)]
    pub(crate) fn invalidate(&self) {
        *self.slot.lock().expect("pool memo poisoned") = None;
    }
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

    #[test]
    fn losing_racer_returns_winning_arc() {
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
        let fast = memo.get_or_build(|| 2, || 2);
        resume_tx.send(()).expect("resume slow builder");
        let slow = slow.join().expect("slow thread should finish");

        assert!(Arc::ptr_eq(&slow, &fast));
        assert!(Arc::ptr_eq(
            &slow,
            &memo.get().expect("memo should be populated")
        ));
        assert_eq!(*fast, 2);
    }
}
