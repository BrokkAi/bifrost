//! Profiling-only census of execution-dependence marks, for the migration to
//! an explicit reuse verdict (#10872).
//!
//! Nothing here runs unless `BIFROST_TIMING` enables profiling, and nothing
//! here is an input to admission, reuse or identity. Two things are measured:
//!
//! - Which call sites mark a capture execution dependent, and through which
//!   route. The record is keyed by distinct (call site, route) pairs, so its
//!   size is bounded by the number of marking sites in the code, never by the
//!   number of reads, captures or requests.
//! - How many captures a token latch would refuse that today's ambient channel
//!   keeps: a capture that saw no execution dependence itself, but during
//!   whose lifetime some cancellation token reported a stop. The process-wide
//!   stop counter makes this an upper bound for a per-token latch.
//!
//! The census is written to `<BIFROST_EXECUTION_CENSUS_DIR>/<pid>.tsv` when
//! the process exits (Unix only), and is available in process through
//! [`snapshot`] for tests.

use std::cell::Cell;
use std::panic::Location;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash::HashMap;

type Origin = (&'static Location<'static>, &'static str);

static ORIGINS: Mutex<Option<HashMap<Origin, u64>>> = Mutex::new(None);
static STOP_OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
static CAPTURES: AtomicU64 = AtomicU64::new(0);
static CAPTURES_KEPT: AtomicU64 = AtomicU64::new(0);
static CAPTURES_EXECUTION_DEPENDENT: AtomicU64 = AtomicU64::new(0);
static CAPTURES_LATCH_EXTRA: AtomicU64 = AtomicU64::new(0);

thread_local! {
    // The entry point that is marking on this thread. A ledger that receives
    // the mark attributes it to this origin instead of its own caller.
    static CURRENT: Cell<Option<Origin>> = const { Cell::new(None) };
}

/// Names the entry point of a mark while it reaches ledgers synchronously.
/// The outermost entry point wins, so a route that calls another route is
/// recorded once, at the site that started it.
pub struct MarkScope {
    previous: Option<Option<Origin>>,
    // Restoring thread-local state must happen on the marking thread.
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

impl Drop for MarkScope {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            CURRENT.with(|current| current.set(previous));
        }
    }
}

pub fn mark_scope(origin: &'static Location<'static>, route: &'static str) -> MarkScope {
    let previous = (crate::profiling::enabled() && CURRENT.with(Cell::get).is_none())
        .then(|| CURRENT.with(|current| current.replace(Some((origin, route)))));
    MarkScope {
        previous,
        _thread_bound: std::marker::PhantomData,
    }
}

/// A ledger received one execution dependence. `caller` is the ledger's own
/// caller, used when no entry point named the mark (a direct ledger call or a
/// forwarded receipt).
pub fn record_ledger_mark(caller: &'static Location<'static>) {
    if !crate::profiling::enabled() {
        return;
    }
    let origin = CURRENT.with(Cell::get).unwrap_or((caller, "ledger"));
    register_exit_dump_once();
    let mut origins = ORIGINS.lock().expect("execution census poisoned");
    *origins
        .get_or_insert_with(HashMap::default)
        .entry(origin)
        .or_default() += 1;
}

/// A cancellation token reported a stop (cancelled, timed out, or past its
/// soft deadline) to some caller.
pub fn note_stop_observed() {
    if crate::profiling::enabled() {
        register_exit_dump_once();
        STOP_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// The stop counter at the moment a capture opens; zero when profiling is off.
pub fn stop_observations() -> u64 {
    if crate::profiling::enabled() {
        STOP_OBSERVATIONS.load(Ordering::Relaxed)
    } else {
        0
    }
}

/// A capture closed. `kept` is whether today's channels let it be reused
/// (no unattributed read, no reuse refusal, no execution dependence);
/// `execution_dependent` is whether the ambient channel marked it.
pub fn record_capture_closed(opened_at_stops: u64, kept: bool, execution_dependent: bool) {
    if !crate::profiling::enabled() {
        return;
    }
    register_exit_dump_once();
    CAPTURES.fetch_add(1, Ordering::Relaxed);
    if execution_dependent {
        CAPTURES_EXECUTION_DEPENDENT.fetch_add(1, Ordering::Relaxed);
    }
    if kept {
        CAPTURES_KEPT.fetch_add(1, Ordering::Relaxed);
        if STOP_OBSERVATIONS.load(Ordering::Relaxed) != opened_at_stops {
            CAPTURES_LATCH_EXTRA.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// (call site, route, ledger receipts), sorted by call site.
    pub origins: Vec<(String, &'static str, u64)>,
    pub stop_observations: u64,
    pub captures: u64,
    pub captures_kept: u64,
    pub captures_execution_dependent: u64,
    /// Kept captures a process-wide token latch would have refused.
    pub captures_latch_extra: u64,
}

pub fn snapshot() -> Snapshot {
    let mut origins: Vec<_> = ORIGINS
        .lock()
        .expect("execution census poisoned")
        .iter()
        .flatten()
        .map(|((location, route), count)| (location.to_string(), *route, *count))
        .collect();
    origins.sort();
    Snapshot {
        origins,
        stop_observations: STOP_OBSERVATIONS.load(Ordering::Relaxed),
        captures: CAPTURES.load(Ordering::Relaxed),
        captures_kept: CAPTURES_KEPT.load(Ordering::Relaxed),
        captures_execution_dependent: CAPTURES_EXECUTION_DEPENDENT.load(Ordering::Relaxed),
        captures_latch_extra: CAPTURES_LATCH_EXTRA.load(Ordering::Relaxed),
    }
}

// Only the Unix exit handler dumps; on Windows the constant is dead code,
// which CI's -D warnings rejects.
#[cfg(unix)]
const DUMP_DIR: &str = "BIFROST_EXECUTION_CENSUS_DIR";

// Every process that closes a capture or sees a stop dumps, not only those
// that mark: a process with only kept captures still counts toward the total.
fn register_exit_dump_once() {
    static REGISTERED: std::sync::Once = std::sync::Once::new();
    REGISTERED.call_once(register_exit_dump);
}

#[cfg(unix)]
fn register_exit_dump() {
    extern "C" fn dump() {
        let Some(dir) = std::env::var_os(DUMP_DIR) else {
            return;
        };
        let census = snapshot();
        let mut text = format!(
            "captures\t{}\t{}\t{}\t{}\t{}\n",
            census.captures,
            census.captures_kept,
            census.captures_execution_dependent,
            census.captures_latch_extra,
            census.stop_observations
        );
        for (site, route, count) in &census.origins {
            text.push_str(&format!("origin\t{site}\t{route}\t{count}\n"));
        }
        let path = std::path::Path::new(&dir).join(format!("{}.tsv", std::process::id()));
        // An exit handler cannot propagate; a failed write loses only this
        // process's measurement, so say so on stderr.
        if let Err(error) = std::fs::write(&path, text) {
            eprintln!("execution census: writing {}: {error}", path.display());
        }
    }
    if std::env::var_os(DUMP_DIR).is_some() {
        // SAFETY: `dump` is a plain `extern "C" fn` with no arguments, as
        // `atexit` requires; it only reads process statics.
        let status = unsafe { libc::atexit(dump) };
        assert_eq!(status, 0, "execution census: atexit registration failed");
    }
}

#[cfg(not(unix))]
fn register_exit_dump() {}
