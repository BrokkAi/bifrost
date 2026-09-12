#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

/// Cloneable cooperative-cancellation flag for bounded in-process work.
///
/// Cancellation is advisory: callers set the shared flag and long-running
/// loops stop at explicit checkpoints. The token does not forcibly terminate
/// threads or encode a domain-specific error.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
    deadline: Option<Instant>,
    /// What the work under this token is doing right now. See
    /// [`CancellationToken::enter_phase`].
    phase: Arc<Mutex<Option<String>>>,
    #[cfg(any(test, feature = "test-support"))]
    cancel_after_checks: Option<Arc<AtomicUsize>>,
    #[cfg(any(test, feature = "test-support"))]
    timeout_after_checks: Option<Arc<AtomicUsize>>,
}

/// Restores the phase that was current when it was entered.
///
/// Returned by [`CancellationToken::enter_phase`]; see it for what the phase
/// is for.
#[must_use = "the phase ends when this guard is dropped"]
pub struct PhaseGuard {
    phase: Arc<Mutex<Option<String>>>,
    previous: Option<String>,
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        *self.phase.lock().expect("cancellation phase lock poisoned") = self.previous.take();
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Record what this token's work is doing, until the guard is dropped.
    ///
    /// A budgeted host cancels the work it is waiting for and then has to say
    /// why the budget went. Without this it can only name the tool: every wait
    /// inside the request, however specific, was reported as "exhausted its
    /// 60s request budget" with nothing to distinguish a slow analysis from a
    /// thread parked on a file lock (issue #3170). The token is what already
    /// spans both ends -- the host holds it while the synchronous analyzer
    /// polls it -- so a long wait publishes its phase here and the host reads
    /// it back when the deadline fires.
    ///
    /// Phases nest: the guard restores the phase that was current when it was
    /// entered, so a request goes back to describing its tool when a wait
    /// inside it ends. Enter one only for work whose duration a person would
    /// want named; this is a diagnostic channel, not a trace.
    pub fn enter_phase(&self, phase: impl Into<String>) -> PhaseGuard {
        let mut current = self.phase.lock().expect("cancellation phase lock poisoned");
        let previous = current.replace(phase.into());
        PhaseGuard {
            phase: Arc::clone(&self.phase),
            previous,
        }
    }

    /// The phase this token's work last entered, if any.
    pub fn phase(&self) -> Option<String> {
        self.phase
            .lock()
            .expect("cancellation phase lock poisoned")
            .clone()
    }

    /// Return a child token that cancels itself after `duration` while still
    /// sharing explicit cancellation with the original token and its clones.
    #[doc(hidden)]
    pub fn with_timeout(mut self, duration: Duration) -> Self {
        let deadline = Instant::now() + duration;
        self.deadline = Some(
            self.deadline
                .map_or(deadline, |current| current.min(deadline)),
        );
        self
    }

    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(
            self.deadline
                .map_or(deadline, |current| current.min(deadline)),
        );
        self
    }

    /// Whether cancellation was triggered by this token's wall-clock deadline.
    pub fn is_timed_out(&self) -> bool {
        self.timed_out.load(Ordering::Acquire)
    }

    pub fn is_cancelled(&self) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(remaining) = &self.timeout_after_checks {
            let previous = remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_sub(1)
                })
                .unwrap_or(0);
            if previous <= 1 {
                self.timed_out.store(true, Ordering::Release);
                self.cancel();
            }
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(remaining) = &self.cancel_after_checks {
            let previous = remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_sub(1)
                })
                .unwrap_or(0);
            if previous <= 1 {
                self.cancel();
            }
        }
        // Check the deadline before the shared explicit-cancellation flag.
        // An MCP client can send `notifications/cancelled` at the same moment
        // its request-wide deadline expires. If the explicit flag wins this
        // race, the timeout is never recorded and policy evaluation turns a
        // canonical incomplete report into a transport error.
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.timed_out.store(true, Ordering::Release);
            self.cancelled.store(true, Ordering::Release);
            return true;
        }
        // An explicit caller cancellation that arrived before the deadline
        // remains distinguishable from a timeout in the public response.
        if self.cancelled.load(Ordering::Acquire) {
            return true;
        }
        false
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn cancel_after_checks_for_test(checks: usize) -> Self {
        Self {
            cancel_after_checks: Some(Arc::new(AtomicUsize::new(checks))),
            ..Self::default()
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn timeout_after_checks_for_test(checks: usize) -> Self {
        Self {
            timeout_after_checks: Some(Arc::new(AtomicUsize::new(checks))),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_cancellation_state() {
        let token = CancellationToken::default();
        let clone = token.clone();

        assert!(!clone.is_cancelled());
        token.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn issue_1228_timeout_cancels_clones_and_records_its_cause() {
        let token = CancellationToken::default().with_timeout(Duration::ZERO);
        let clone = token.clone();

        assert!(clone.is_cancelled());
        assert!(token.is_timed_out());
    }

    #[test]
    fn issue_1228_explicit_cancellation_is_not_reported_as_timeout() {
        let token = CancellationToken::default().with_timeout(Duration::from_secs(60));

        token.cancel();

        assert!(token.is_cancelled());
        assert!(!token.is_timed_out());
    }

    #[test]
    fn issue_1228_nested_timeouts_preserve_the_earliest_deadline() {
        let token = CancellationToken::default()
            .with_timeout(Duration::ZERO)
            .with_timeout(Duration::from_secs(60));

        assert!(token.is_cancelled());
        assert!(token.is_timed_out());
    }
}
