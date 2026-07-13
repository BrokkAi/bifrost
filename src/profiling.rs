use std::cell::Cell;
use std::env;
use std::time::Instant;

thread_local! {
    static DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub struct Scope {
    label: Option<String>,
    start: Option<Instant>,
}

impl Scope {
    pub(crate) fn new(label: impl Into<String>) -> Self {
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
