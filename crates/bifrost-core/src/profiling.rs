use std::cell::Cell;
use std::env;
use std::ffi::OsStr;
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
    static KEY: &str = "BIFROST_TIMING";
    timing_enabled(env::var_os(KEY).as_deref())
}

/// Whether `BIFROST_TIMING` asks for span tracing.
///
/// Presence used to be the whole test, so `BIFROST_TIMING=0` turned tracing
/// *on*. The D4 measurement harness set it to `0` expecting silence and paid
/// 247k span events for the run. An off-switch spelling must switch the
/// feature off; anything else a caller writes is a request to turn it on.
fn timing_enabled(value: Option<&OsStr>) -> bool {
    let Some(value) = value else {
        return false;
    };
    // A non-UTF-8 value is not one of the off spellings, so it reads as on.
    let Some(value) = value.to_str() else {
        return true;
    };
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "off"
    )
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

#[cfg(test)]
mod tests {
    use super::timing_enabled;
    use std::ffi::OsStr;

    #[test]
    fn an_unset_variable_leaves_timing_off() {
        assert!(!timing_enabled(None));
    }

    /// The D4 harness footgun: presence-not-value parsing read `0` as on and
    /// charged the measured run 247k span events.
    #[test]
    fn an_off_spelling_switches_timing_off() {
        for value in ["", "0", "false", "off", " off ", "OFF", "False"] {
            assert!(
                !timing_enabled(Some(OsStr::new(value))),
                "`{value}` must read as off"
            );
        }
    }

    #[test]
    fn any_other_value_switches_timing_on() {
        for value in ["1", "true", "on", "yes", "2", "spans"] {
            assert!(
                timing_enabled(Some(OsStr::new(value))),
                "`{value}` must read as on"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_value_is_not_an_off_spelling() {
        use std::os::unix::ffi::OsStrExt;

        assert!(timing_enabled(Some(OsStr::from_bytes(&[0xff]))));
    }
}
