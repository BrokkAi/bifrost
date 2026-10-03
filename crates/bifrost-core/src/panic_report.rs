//! Turn a panic that crossed a thread or task boundary into a reported error.
//!
//! Analysis runs on threads the caller does not own: one build thread per
//! language, a rayon pool per language adapter, background index warms. A panic
//! on one of those threads is a failure of the request that started the work,
//! and the request must say so. The two ways that goes wrong are both silent:
//! a join whose `Err` payload is dropped ("index build thread panicked" with no
//! message), and a process that unwinds out of `main` with nothing on the
//! contract's own output channel.
//!
//! The helpers here keep the panic's own message. [`reported_panic`] wraps a
//! payload a join already produced; [`report_panics`] runs work that may panic
//! and returns the same report instead of unwinding. Neither hides the panic:
//! the process panic hook has already written the original message and location
//! to stderr, and the returned error names the boundary that observed it.

use std::any::Any;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// A panic observed at a boundary, with the panic's own message preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedPanic {
    context: String,
    message: String,
}

impl ReportedPanic {
    /// What the boundary was doing, for example `index build thread`.
    pub fn context(&self) -> &str {
        &self.context
    }

    /// The panic's own message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ReportedPanic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} panicked: {}", self.context, self.message)
    }
}

impl std::error::Error for ReportedPanic {}

/// The message a panic payload carries.
///
/// `panic!` produces a `&'static str` payload for a literal and a `String` for
/// a formatted message; anything else came from `panic_any` and has no message
/// to show.
pub fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Report the payload a join or a `catch_unwind` produced.
pub fn reported_panic(context: impl Into<String>, payload: Box<dyn Any + Send>) -> ReportedPanic {
    ReportedPanic {
        context: context.into(),
        message: panic_payload_message(payload.as_ref()),
    }
}

/// Run `work`, converting a panic into a [`ReportedPanic`] that names
/// `context` and carries the panic's message.
///
/// For a boundary that must report a failure rather than unwind through its
/// caller: a one-shot CLI that owes its caller an answer on stdout, an MCP
/// request that owes its client a result. Callers that can simply propagate
/// should propagate; `std::panic::resume_unwind` keeps the original payload and
/// is the right tool wherever the panic can continue upward.
pub fn report_panics<T>(
    context: impl Into<String>,
    work: impl FnOnce() -> T,
) -> Result<T, ReportedPanic> {
    catch_unwind(AssertUnwindSafe(work)).map_err(|payload| reported_panic(context, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_task_is_reported_with_its_own_message() {
        let reported = report_panics("analysis worker", || {
            panic!("placement boundary gap must name a root scope: site 1743");
        })
        .expect_err("a panicking task must be reported as a failure");

        assert_eq!(reported.context(), "analysis worker");
        assert_eq!(
            reported.message(),
            "placement boundary gap must name a root scope: site 1743"
        );
        assert_eq!(
            reported.to_string(),
            "analysis worker panicked: placement boundary gap must name a root scope: site 1743"
        );
    }

    #[test]
    fn a_joined_thread_panic_keeps_the_workers_message() {
        let worker = std::thread::spawn(|| panic!("injected worker panic {}", 7));
        let payload = worker.join().expect_err("the worker panics");

        let reported = reported_panic("index build thread", payload);

        assert_eq!(reported.message(), "injected worker panic 7");
        assert_eq!(
            reported.to_string(),
            "index build thread panicked: injected worker panic 7"
        );
    }

    #[test]
    fn work_that_does_not_panic_returns_its_value() {
        assert_eq!(report_panics("analysis worker", || 1 + 1), Ok(2));
    }

    #[test]
    fn a_payload_without_a_message_is_named_as_such() {
        let reported = report_panics("analysis worker", || std::panic::panic_any(7u32))
            .expect_err("a panicking task must be reported as a failure");

        assert_eq!(reported.message(), "non-string panic payload");
    }
}
