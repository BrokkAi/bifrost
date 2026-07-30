//! Bounded admission for expensive analyzer work.
//!
//! Protocol handling and lightweight tools do not take a permit; only the
//! analyzer execution path does. Concurrency here is a measured product
//! constraint, not a transport detail: the `mcp_fairness` scenario in
//! `benchmark/interactive-latency.toml` overlaps a heavy usage scan with a
//! lightweight source lookup and asserts the light request's p95 stays under
//! five seconds. Change [`ANALYZER_POOL_CAPACITY`] only with evidence from
//! that benchmark.
//!
//! The pool waits rather than rejects. The previous hand-written MCP host
//! refused the fifth concurrent request with a JSON-RPC "server busy" error
//! purely because its single reader thread had nowhere to park a waiter;
//! nothing about the analyzer required that. Waiting is asynchronous and
//! cancellation-aware so a queued request never occupies a runtime worker
//! thread and never outlives its client.

use tokio::sync::{Semaphore, SemaphorePermit};
use tokio_util::sync::CancellationToken;

/// Concurrent analyzer executions allowed across the whole server.
pub const ANALYZER_POOL_CAPACITY: usize = 4;

/// A checked-out slot. Returns to the pool when dropped, whether the request
/// completed, failed, or was cancelled.
///
/// The wrapped permit is never read; holding it *is* the whole contract, and
/// `SemaphorePermit` releases on drop.
pub struct AnalyzerPermit<'pool>(#[allow(dead_code)] SemaphorePermit<'pool>);

pub struct AnalyzerExecutionPool {
    slots: Semaphore,
}

impl AnalyzerExecutionPool {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "analyzer pool needs at least one slot");
        Self {
            slots: Semaphore::new(capacity),
        }
    }

    /// Wait for a slot without blocking a runtime worker thread.
    ///
    /// Returns `None` when `cancelled` fires first, which means the client
    /// gave up before the request ever reached the analyzer.
    pub async fn acquire(&self, cancelled: &CancellationToken) -> Option<AnalyzerPermit<'_>> {
        tokio::select! {
            permit = self.slots.acquire() => Some(AnalyzerPermit(
                permit.expect("the analyzer pool semaphore is never closed"),
            )),
            () = cancelled.cancelled() => None,
        }
    }
}

impl Default for AnalyzerExecutionPool {
    fn default() -> Self {
        Self::new(ANALYZER_POOL_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn waiting_for_a_slot_is_cancellable() {
        let pool = AnalyzerExecutionPool::new(1);
        let held = pool
            .acquire(&CancellationToken::new())
            .await
            .expect("first acquire takes the only slot");

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            pool.acquire(&cancelled).await.is_none(),
            "a cancelled request must stop waiting for analyzer capacity"
        );

        drop(held);
        assert!(
            pool.acquire(&CancellationToken::new()).await.is_some(),
            "dropping a permit returns the slot"
        );
    }

    #[tokio::test]
    async fn a_released_slot_wakes_a_waiter() {
        let pool = Arc::new(AnalyzerExecutionPool::new(1));
        let held = pool
            .acquire(&CancellationToken::new())
            .await
            .expect("take the only slot");

        let waiter_pool = Arc::clone(&pool);
        let waiter = tokio::spawn(async move {
            waiter_pool
                .acquire(&CancellationToken::new())
                .await
                .is_some()
        });

        // On the current-thread test runtime the spawned task only runs when
        // this one yields, so yielding is enough to prove it is still parked.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !waiter.is_finished(),
            "a waiter must not be admitted while the only slot is held"
        );

        drop(held);
        assert!(
            waiter.await.expect("waiter task"),
            "the waiter got the slot"
        );
    }
}
