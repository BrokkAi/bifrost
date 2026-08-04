//! Coarse, process-global stage timers for profiling the index build pipeline.
//!
//! Measurement-only: accumulate wall-clock nanoseconds per stage so a build can
//! report where its time went (extract / embed / compose / encode / sqlite) and we
//! can target the actual bottleneck instead of guessing. Cheap (one relaxed atomic
//! add per timed section) and safe to leave compiled in.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Whether `BIFROST_TRACE=1` is set: emit per-stage BEGIN/END markers so a hang
/// leaves its stuck stage as the last unmatched BEGIN line. Diagnostic only.
fn trace_on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        matches!(
            std::env::var("BIFROST_TRACE").as_deref(),
            Ok("1") | Ok("true") | Ok("on")
        )
    })
}

/// Emit a flushed, thread-tagged trace line when `BIFROST_TRACE=1`.
pub fn trace(args: std::fmt::Arguments<'_>) {
    if trace_on() {
        use std::io::Write;
        let tid = std::thread::current().id();
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "[trace {tid:?}] {args}");
        let _ = err.flush();
    }
}

/// Run `f`, emitting BEGIN/END trace markers around it (when tracing is on) so an
/// in-flight hang is attributable to this labeled region. Also accumulates time.
pub fn traced<T>(bucket: &AtomicU64, label: std::fmt::Arguments<'_>, f: impl FnOnce() -> T) -> T {
    trace(format_args!("BEGIN {label}"));
    let out = time(bucket, f);
    trace(format_args!("END   {label}"));
    out
}

pub static EXTRACT_NS: AtomicU64 = AtomicU64::new(0);
pub static EMBED_NS: AtomicU64 = AtomicU64::new(0);
pub static COMPOSE_NS: AtomicU64 = AtomicU64::new(0);
pub static ENCODE_NS: AtomicU64 = AtomicU64::new(0);
pub static SQLITE_NS: AtomicU64 = AtomicU64::new(0);

/// Run `f`, adding its wall-clock duration to `bucket`.
pub fn time<T>(bucket: &AtomicU64, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    bucket.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    out
}

fn secs(bucket: &AtomicU64) -> f64 {
    bucket.load(Ordering::Relaxed) as f64 / 1e9
}

/// One-line summary of accumulated stage time (sum of per-thread wall-clock, so
/// stages that ran concurrently overlap — read it as where the work is, not as a
/// timeline).
pub fn report() -> String {
    format!(
        "stage time: extract={:.1}s embed={:.1}s compose={:.1}s encode={:.1}s sqlite={:.1}s",
        secs(&EXTRACT_NS),
        secs(&EMBED_NS),
        secs(&COMPOSE_NS),
        secs(&ENCODE_NS),
        secs(&SQLITE_NS),
    )
}
