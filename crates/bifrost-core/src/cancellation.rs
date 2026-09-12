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
    /// Where each phase change is published as it happens, for a host that
    /// reports the request's progress while it runs. See
    /// [`CancellationToken::with_phase_sink`].
    phase_sink: Option<PhaseSink>,
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
    sink: Option<PhaseSink>,
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        let restored = self.previous.take();
        // The outer phase is current again, so a host reporting this request's
        // phases has to hear it. There is nothing to report when the work goes
        // back to having no phase at all: the request is between phases, not in
        // a new one.
        if let (Some(sink), Some(restored)) = (&self.sink, &restored) {
            sink.publish(restored);
        }
        *self.phase.lock().expect("cancellation phase lock poisoned") = restored;
    }
}

/// Delivers each phase a token enters to the host that owns the request.
///
/// A callback rather than a channel, so the core crate stays independent of the
/// host's async runtime: the MCP host installs a sink that hands the phase to
/// its own task, which turns it into a progress notification (issue #3170).
#[derive(Clone)]
struct PhaseSink(Arc<dyn Fn(&str) + Send + Sync>);

impl PhaseSink {
    fn publish(&self, phase: &str) {
        (self.0)(phase);
    }
}

impl std::fmt::Debug for PhaseSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PhaseSink")
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
        let phase = phase.into();
        // Published before it is recorded, so the string can then move into the
        // token instead of being cloned. Nothing observes the gap: the sink and
        // `phase()` are two views of one diagnostic, and publishing outside the
        // lock keeps a host's callback off the token's mutex.
        if let Some(sink) = &self.phase_sink {
            sink.publish(&phase);
        }
        let previous = self
            .phase
            .lock()
            .expect("cancellation phase lock poisoned")
            .replace(phase);
        PhaseGuard {
            phase: Arc::clone(&self.phase),
            previous,
            sink: self.phase_sink.clone(),
        }
    }

    /// Also deliver every phase entered under this token to `sink`, so a host
    /// can report what a request is doing while it runs instead of only when
    /// its budget expires.
    ///
    /// `sink` runs on whatever thread enters the phase, which is a synchronous
    /// analyzer thread, so it must not block: hand the phase to another task
    /// and return. Clones taken after this carry the sink, exactly as they
    /// carry the phase.
    pub fn with_phase_sink(mut self, sink: impl Fn(&str) + Send + Sync + 'static) -> Self {
        debug_assert!(
            self.phase_sink.is_none(),
            "a token reports its phases to one host, so a second sink would silence the first"
        );
        self.phase_sink = Some(PhaseSink(Arc::new(sink)));
        self
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
    fn issue_3170_a_phase_sink_hears_every_entry_and_every_restore() {
        let reported = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&reported);
        let token = CancellationToken::default().with_phase_sink(move |phase| {
            recorder
                .lock()
                .expect("recorded phases lock poisoned")
                .push(phase.to_string())
        });
        // The host installs the sink and the work runs under a clone, exactly
        // as a tool call reaches the analyzer.
        let worker = token.clone();

        let outer = worker.enter_phase("executing a tool");
        {
            let _inner = worker.enter_phase("waiting for a lock");
            assert_eq!(worker.phase().as_deref(), Some("waiting for a lock"));
        }
        assert_eq!(worker.phase().as_deref(), Some("executing a tool"));
        drop(outer);
        assert_eq!(worker.phase(), None);

        assert_eq!(
            *reported.lock().expect("recorded phases lock poisoned"),
            ["executing a tool", "waiting for a lock", "executing a tool"]
        );
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
