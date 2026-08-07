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
//! The pool waits rather than rejects, but the queue is bounded. The analyzer
//! can wait safely for a permit. It must also bound unanswered work so a
//! client cannot grow the server without limit. `rmcp` spawns a task per
//! request and imposes no such cap, so the bound lives here as a limit on
//! queued waiters.

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Concurrent analyzer executions allowed across the whole server.
pub const ANALYZER_POOL_CAPACITY: usize = 4;

/// Requests that may wait for a slot before the server starts refusing.
///
/// Generous enough that ordinary overlap never sees it, small enough that a
/// client looping on retries cannot grow the server without bound -- each
/// waiter retains its handler task, its client-supplied arguments, and a
/// cancellation bridge task.
pub const MAX_QUEUED_ANALYZER_REQUESTS: usize = 32;

/// A checked-out slot. Returns to the pool when dropped, whether the request
/// completed, failed, or was cancelled.
///
/// The wrapped permit is never read; holding it *is* the whole contract, and
/// `OwnedSemaphorePermit` releases on drop.
pub struct AnalyzerPermit(#[allow(dead_code)] Option<OwnedSemaphorePermit>);

impl AnalyzerPermit {
    /// A permit for work that is bounded by something other than this pool.
    ///
    /// Workspace-mutating tools hold the connection's workspace lock for their
    /// whole execution, so they are already serialized against everything else;
    /// making them queue here as well would let a trivial call block on four
    /// long scans while holding that lock.
    pub fn exempt() -> Self {
        Self(None)
    }
}

/// The outcome of asking for analyzer capacity.
pub enum Admission {
    Granted(AnalyzerPermit),
    /// The client gave up before a slot became free.
    Cancelled,
    /// Too many requests are already queued; the caller must refuse this one.
    Saturated,
}

pub struct AnalyzerExecutionPool {
    slots: Arc<Semaphore>,
    /// Places in the waiting line, held only while a caller is actually
    /// parked. A caller that gets a slot immediately never occupies one, so
    /// this counts exactly the backlog and nothing else.
    queue: Semaphore,
}

impl AnalyzerExecutionPool {
    pub fn new(capacity: usize, max_queued: usize) -> Self {
        assert!(capacity > 0, "analyzer pool needs at least one slot");
        Self {
            slots: Arc::new(Semaphore::new(capacity)),
            queue: Semaphore::new(max_queued),
        }
    }

    /// Wait for a slot without blocking a runtime worker thread.
    pub async fn acquire(&self, cancelled: &CancellationToken) -> Admission {
        // Free capacity is taken without ever entering the queue, so ordinary
        // traffic cannot exhaust the backlog allowance.
        if let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() {
            return Admission::Granted(AnalyzerPermit(Some(permit)));
        }
        let Ok(_queued) = self.queue.try_acquire() else {
            return Admission::Saturated;
        };
        tokio::select! {
            permit = Arc::clone(&self.slots).acquire_owned() => Admission::Granted(AnalyzerPermit(Some(
                permit.expect("the analyzer pool semaphore is never closed"),
            ))),
            () = cancelled.cancelled() => Admission::Cancelled,
        }
    }
}

impl Default for AnalyzerExecutionPool {
    fn default() -> Self {
        Self::new(ANALYZER_POOL_CAPACITY, MAX_QUEUED_ANALYZER_REQUESTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn granted(admission: Admission) -> AnalyzerPermit {
        match admission {
            Admission::Granted(permit) => permit,
            Admission::Cancelled => panic!("expected admission, got cancelled"),
            Admission::Saturated => panic!("expected admission, got saturated"),
        }
    }

    #[tokio::test]
    async fn waiting_for_a_slot_is_cancellable() {
        let pool = AnalyzerExecutionPool::new(1, 4);
        let held = granted(pool.acquire(&CancellationToken::new()).await);

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            matches!(pool.acquire(&cancelled).await, Admission::Cancelled),
            "a cancelled request must stop waiting for analyzer capacity"
        );

        drop(held);
        assert!(matches!(
            pool.acquire(&CancellationToken::new()).await,
            Admission::Granted(_)
        ));
    }

    #[tokio::test]
    async fn a_released_slot_wakes_a_waiter() {
        let pool = Arc::new(AnalyzerExecutionPool::new(1, 4));
        let held = granted(pool.acquire(&CancellationToken::new()).await);

        let waiter_pool = Arc::clone(&pool);
        let waiter = tokio::spawn(async move {
            matches!(
                waiter_pool.acquire(&CancellationToken::new()).await,
                Admission::Granted(_)
            )
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

    #[tokio::test]
    async fn the_queue_is_bounded() {
        // One executing, two queued, then refuse.
        let pool = AnalyzerExecutionPool::new(1, 2);
        let _running = granted(pool.acquire(&CancellationToken::new()).await);

        let idle = CancellationToken::new();
        let mut queued = Vec::new();
        for _ in 0..2 {
            queued.push(Box::pin(pool.acquire(&idle)));
        }
        for waiter in &mut queued {
            assert!(
                futures_poll_pending(waiter).await,
                "a queued waiter must park, not resolve"
            );
        }

        assert!(
            matches!(pool.acquire(&idle).await, Admission::Saturated),
            "past the queue bound the server must refuse rather than grow"
        );
    }

    /// Poll a future once and report whether it is still pending.
    async fn futures_poll_pending<F: Future>(future: &mut std::pin::Pin<Box<F>>) -> bool {
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_pending()))
            .await
    }
}
