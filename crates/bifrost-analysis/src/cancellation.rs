use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
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
    #[cfg(any(test, feature = "test-support"))]
    cancel_after_checks: Option<Arc<AtomicUsize>>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
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
            cancelled: Arc::new(AtomicBool::new(false)),
            timed_out: Arc::new(AtomicBool::new(false)),
            deadline: None,
            cancel_after_checks: Some(Arc::new(AtomicUsize::new(checks))),
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
