use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Cloneable cooperative-cancellation flag for bounded in-process work.
///
/// Cancellation is advisory: callers set the shared flag and long-running
/// loops stop at explicit checkpoints. The token does not forcibly terminate
/// threads or encode a domain-specific error.
#[derive(Clone, Debug, Default)]
pub(crate) struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
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
