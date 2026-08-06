use std::cell::Cell;
use std::env;
use std::time::{Duration, Instant};

thread_local! {
    static DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub struct Scope {
    label: Option<String>,
    start: Option<Instant>,
}

impl Scope {
    pub fn new(label: impl Into<String>) -> Self {
        if enabled() {
            let label = label.into();
            DEPTH.with(|depth| {
                let indent = "  ".repeat(depth.get());
                eprintln!("[bifrost-timing] {indent}BEGIN {label}");
                depth.set(depth.get() + 1);
            });
            Self {
                label: Some(label),
                start: Some(Instant::now()),
            }
        } else {
            Self {
                label: None,
                start: None,
            }
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let (Some(label), Some(start)) = (&self.label, self.start) else {
            return;
        };
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        DEPTH.with(|depth| {
            let next = depth.get().saturating_sub(1);
            depth.set(next);
            let indent = "  ".repeat(next);
            eprintln!(
                "[bifrost-timing] {indent}END {} ({elapsed_ms:.1} ms)",
                label
            );
        });
    }
}

pub fn scope(label: impl Into<String>) -> Scope {
    Scope::new(label)
}

pub fn enabled() -> bool {
    // Read once: the flag is set in the process environment at spawn and
    // never toggled at run time, and `scope` sits on per-candidate hot paths
    // where a per-call `env::var_os` (a global env lock) is measurable.
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| env::var_os("BIFROST_TIMING").is_some())
}

pub fn note(label: impl AsRef<str>) {
    if !enabled() {
        return;
    }
    DEPTH.with(|depth| {
        let indent = "  ".repeat(depth.get());
        eprintln!("[bifrost-timing] {indent}NOTE {}", label.as_ref());
    });
}

pub fn duration(label: impl AsRef<str>, duration: Duration) {
    if !enabled() {
        return;
    }
    let elapsed_ms = duration.as_secs_f64() * 1000.0;
    DEPTH.with(|depth| {
        let indent = "  ".repeat(depth.get());
        eprintln!(
            "[bifrost-timing] {indent}DURATION {} ({elapsed_ms:.1} ms)",
            label.as_ref()
        );
    });
}
