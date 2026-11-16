//! Returning freed C-heap memory to the OS when a warm process goes idle (#12661).
//!
//! SQLite, tree-sitter and the other C code in this process allocate through
//! the platform `malloc`. On glibc that heap is split into per-thread arenas
//! that keep freed memory after the work that needed it is done, so a warm
//! analyzer process stays large after a request. The `bifrost` binary sends
//! Rust allocations to jemalloc, so this is glibc slack and not live data.
//!
//! [`release_free_heap`] hands that memory back. [`IdleHeapRelease`] decides
//! when: once per idle period, after the last request and the last background
//! index warm have both finished, and only if some work happened since the
//! previous release. The release runs on its own short-lived thread, so it is
//! never on a response path.

use std::sync::{Arc, Condvar, Mutex, OnceLock};

use crate::profiling;

/// Ask the allocator to return free memory to the OS. Returns whether any was
/// released.
///
/// glibc only: `malloc_trim(0)` walks every arena, not just the caller's, so
/// it can be called from any thread. Other platforms keep their allocator's
/// own policy and this does nothing. It deliberately avoids `mallinfo2`, which
/// needs glibc 2.33 while the manylinux2014 wheels build against 2.17.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn release_free_heap() -> bool {
    // SAFETY: malloc_trim is glibc's thread-safe heap maintenance entry point;
    // it takes no pointers and does not invalidate any live allocation.
    unsafe { libc::malloc_trim(0) != 0 }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn release_free_heap() -> bool {
    false
}

/// What an idle release does. The process implementation trims the heap; a
/// test supplies a hand-written fake.
pub trait HeapReleaser: Send + Sync + 'static {
    /// Must not panic: a panic would leave the gate believing a release is
    /// still running.
    fn release(&self);
}

struct ProcessHeapReleaser;

impl HeapReleaser for ProcessHeapReleaser {
    fn release(&self) {
        if !profiling::enabled() {
            release_free_heap();
            return;
        }
        let before = resident_bytes();
        let started = std::time::Instant::now();
        let released = release_free_heap();
        let elapsed = started.elapsed();
        let after = resident_bytes();
        profiling::note_with(|| {
            let bytes =
                |value: Option<u64>| value.map_or("unavailable".to_owned(), |v| v.to_string());
            format!(
                "heap_release released={released} rss_before_bytes={} rss_after_bytes={} elapsed_us={}",
                bytes(before),
                bytes(after),
                elapsed.as_micros()
            )
        });
    }
}

/// Resident set size from `/proc/self/statm`, read only when timing is on.
#[cfg(target_os = "linux")]
fn resident_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // SAFETY: sysconf takes no pointers.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(page_size).ok().map(|size| pages * size)
}

#[cfg(not(target_os = "linux"))]
fn resident_bytes() -> Option<u64> {
    None
}

#[derive(Default)]
struct State {
    requests: usize,
    warms: usize,
    /// Work started since the last release was claimed.
    dirty: bool,
    releasing: bool,
}

impl State {
    fn idle(&self) -> bool {
        self.requests == 0 && self.warms == 0
    }

    /// Claim a release when the process is idle, something ran since the last
    /// one, and none is already running.
    fn claim(&mut self) -> bool {
        let claim = self.idle() && self.dirty && !self.releasing;
        if claim {
            self.dirty = false;
            self.releasing = true;
        }
        claim
    }
}

struct Shared {
    state: Mutex<State>,
    finished: Condvar,
    releaser: Box<dyn HeapReleaser>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("heap release state lock poisoned")
    }

    /// Run claimed releases until the process is no longer idle with new work.
    ///
    /// Work admitted after the claim but before the release starts cancels
    /// it: the release is put back as pending and runs when that work ends.
    /// A trim that has already started is not interrupted (malloc_trim cannot
    /// be), so work that starts during one runs beside it. Its allocations wait
    /// at most for the arena being trimmed, which is cheaper than holding every
    /// new request until the whole trim ends.
    fn release_loop(&self) {
        loop {
            {
                let mut state = self.lock();
                if !state.idle() {
                    state.releasing = false;
                    state.dirty = true;
                    self.finished.notify_all();
                    return;
                }
            }
            self.releaser.release();
            let mut state = self.lock();
            state.releasing = false;
            if !state.claim() {
                self.finished.notify_all();
                return;
            }
        }
    }
}

/// Tracks request and background-warm activity and releases the heap once per
/// idle period. See the module documentation.
#[derive(Clone)]
pub struct IdleHeapRelease {
    // None where no release is possible: guards then take no lock and start no
    // thread.
    shared: Option<Arc<Shared>>,
}

impl IdleHeapRelease {
    pub fn new(releaser: impl HeapReleaser) -> Self {
        Self {
            shared: Some(Arc::new(Shared {
                state: Mutex::new(State::default()),
                finished: Condvar::new(),
                releaser: Box::new(releaser),
            })),
        }
    }

    /// A gate that never releases, for platforms where release_free_heap()
    /// cannot return memory.
    pub fn inert() -> Self {
        Self { shared: None }
    }

    /// The gate of this process. Its requests and warms share one heap, so they
    /// share one gate.
    pub fn process() -> &'static Self {
        static PROCESS: OnceLock<IdleHeapRelease> = OnceLock::new();
        PROCESS.get_or_init(|| {
            if cfg!(all(target_os = "linux", target_env = "gnu")) {
                Self::new(ProcessHeapReleaser)
            } else {
                Self::inert()
            }
        })
    }

    /// A service request is running until the guard drops. Nested requests
    /// count separately, so only the outermost end can start a release.
    pub fn request(&self) -> ActivityGuard {
        self.begin(|state| &mut state.requests)
    }

    /// A background index warm is running until the guard drops. Take it where
    /// the warm is scheduled, not where it starts, so the request that
    /// scheduled it cannot end first and see an idle process.
    pub fn warm(&self) -> ActivityGuard {
        self.begin(|state| &mut state.warms)
    }

    fn begin(&self, counter: fn(&mut State) -> &mut usize) -> ActivityGuard {
        let Some(shared) = &self.shared else {
            return ActivityGuard {
                shared: None,
                counter,
            };
        };
        let mut state = shared.lock();
        *counter(&mut state) += 1;
        state.dirty = true;
        drop(state);
        ActivityGuard {
            shared: Some(Arc::clone(shared)),
            counter,
        }
    }

    /// Block until no release is running. For tests that assert a release
    /// count after the last event.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn settle(&self) {
        let Some(shared) = &self.shared else {
            return;
        };
        let state = shared.lock();
        drop(
            shared
                .finished
                .wait_while(state, |state| state.releasing)
                .expect("heap release state lock poisoned"),
        );
    }
}

/// Marks one request or warm as running. Dropping it may start a release.
pub struct ActivityGuard {
    shared: Option<Arc<Shared>>,
    counter: fn(&mut State) -> &mut usize,
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        let Some(gate) = &self.shared else {
            return;
        };
        let claimed = {
            let mut state = gate.lock();
            *(self.counter)(&mut state) -= 1;
            state.claim()
        };
        if !claimed {
            return;
        }
        let shared = Arc::clone(gate);
        let spawned = std::thread::Builder::new()
            .name("bifrost-heap-release".to_owned())
            .spawn(move || shared.release_loop());
        if let Err(error) = spawned {
            // Best effort: the next idle period tries again.
            let mut state = gate.lock();
            state.releasing = false;
            state.dirty = true;
            gate.finished.notify_all();
            profiling::note_with(|| format!("heap_release thread not started: {error}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Clone, Default)]
    struct CountingReleaser(Arc<AtomicUsize>);

    impl HeapReleaser for CountingReleaser {
        fn release(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn gate() -> (IdleHeapRelease, Arc<AtomicUsize>) {
        let releaser = CountingReleaser::default();
        let count = Arc::clone(&releaser.0);
        (IdleHeapRelease::new(releaser), count)
    }

    fn releases(gate: &IdleHeapRelease, count: &AtomicUsize) -> usize {
        gate.settle();
        count.load(Ordering::SeqCst)
    }

    #[test]
    fn a_request_alone_releases_once_when_it_ends() {
        let (gate, count) = gate();
        let request = gate.request();
        assert_eq!(releases(&gate, &count), 0, "not while the request runs");
        drop(request);
        assert_eq!(releases(&gate, &count), 1);
    }

    #[test]
    fn no_release_until_a_warm_that_outlasts_the_request_goes_idle() {
        let (gate, count) = gate();
        let request = gate.request();
        let warm = gate.warm();
        drop(request);
        assert_eq!(releases(&gate, &count), 0, "the warm is still running");
        drop(warm);
        assert_eq!(releases(&gate, &count), 1);
    }

    #[test]
    fn no_release_until_a_request_that_outlasts_the_warm_ends() {
        let (gate, count) = gate();
        let warm = gate.warm();
        let request = gate.request();
        drop(warm);
        assert_eq!(releases(&gate, &count), 0, "the request is still running");
        drop(request);
        assert_eq!(releases(&gate, &count), 1);
    }

    #[test]
    fn a_nested_request_does_not_release_before_the_outer_one_ends() {
        let (gate, count) = gate();
        let outer = gate.request();
        drop(gate.request());
        assert_eq!(releases(&gate, &count), 0);
        drop(outer);
        assert_eq!(releases(&gate, &count), 1);
    }

    #[test]
    fn an_idle_process_does_not_release_again_without_new_work() {
        let (gate, count) = gate();
        drop(gate.request());
        assert_eq!(releases(&gate, &count), 1);
        // Nothing re-evaluates an idle gate except new work.
        drop(gate.warm());
        assert_eq!(releases(&gate, &count), 2);
        assert_eq!(releases(&gate, &count), 2, "settling is not new work");
    }

    #[test]
    fn work_that_finishes_during_a_release_is_released_after_it() {
        struct Blocking {
            entered: std::sync::Barrier,
            proceed: std::sync::Barrier,
            count: Arc<AtomicUsize>,
        }
        impl HeapReleaser for Arc<Blocking> {
            fn release(&self) {
                // Only the first release blocks; the barriers are single-use.
                if self.count.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.entered.wait();
                    self.proceed.wait();
                }
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let blocking = Arc::new(Blocking {
            entered: std::sync::Barrier::new(2),
            proceed: std::sync::Barrier::new(2),
            count: Arc::clone(&count),
        });
        let gate = IdleHeapRelease::new(Arc::clone(&blocking));
        drop(gate.request());
        blocking.entered.wait();
        // A whole request runs and ends while the first release is in flight:
        // it must not start a concurrent release, and it must not be lost.
        drop(gate.request());
        blocking.proceed.wait();
        assert_eq!(releases(&gate, &count), 2);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12661: a claimed release still trimmed after new work was admitted before its thread ran"
    )]
    fn work_admitted_after_the_claim_cancels_the_release_until_it_ends() {
        let (gate, count) = gate();
        // The last activity ends and claims a release, as ActivityGuard::drop
        // does, but the release thread has not run yet.
        let shared = gate.shared.as_ref().expect("a releasing gate");
        {
            let mut state = shared.lock();
            state.dirty = true;
            assert!(state.claim());
        }
        let request = gate.request();
        shared.release_loop();
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "no release while the admitted request runs"
        );
        drop(request);
        assert_eq!(
            releases(&gate, &count),
            1,
            "the cancelled release runs when the request ends"
        );
    }
}
