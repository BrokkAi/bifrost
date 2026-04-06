use std::cell::Cell;
use std::env;
use std::time::Instant;

thread_local! {
    static DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub struct Scope {
    label: String,
    enabled: bool,
    start: Instant,
}

impl Scope {
    pub(crate) fn new(label: impl Into<String>) -> Self {
        let label = label.into();
        let enabled = enabled();
        if enabled {
            DEPTH.with(|depth| {
                let indent = "  ".repeat(depth.get());
                eprintln!("[bifrost-timing] {indent}BEGIN {label}");
                depth.set(depth.get() + 1);
            });
        }
        Self {
            label,
            enabled,
            start: Instant::now(),
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let elapsed_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        DEPTH.with(|depth| {
            let next = depth.get().saturating_sub(1);
            depth.set(next);
            let indent = "  ".repeat(next);
            eprintln!(
                "[bifrost-timing] {indent}END {} ({elapsed_ms:.1} ms)",
                self.label
            );
        });
    }
}

pub fn scope(label: impl Into<String>) -> Scope {
    Scope::new(label)
}

pub fn enabled() -> bool {
    static KEY: &str = "BIFROST_TIMING";
    env::var_os(KEY).is_some()
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
