use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};

/// Cloneable cooperative-cancellation flag for bounded in-process work.
///
/// Cancellation is advisory: callers set the shared flag and long-running
/// loops stop at explicit checkpoints. The token does not forcibly terminate
/// threads or encode a domain-specific error.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    #[cfg(test)]
    cancel_after_checks: Option<Arc<AtomicUsize>>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        #[cfg(test)]
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
        self.cancelled.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn cancel_after_checks_for_test(checks: usize) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
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
}
