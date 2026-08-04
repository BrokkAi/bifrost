//! Coalescing background warmer for the lazily built per-generation query
//! indexes (#1442, #1582).

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::analyzer::WorkspaceAnalyzer;

/// Coalescing background warmer for the lazily built per-generation query
/// indexes (#1442). The Rust type-hierarchy and usage indexes take double-
/// digit seconds to build on large workspaces, so a budgeted request that
/// triggers the build on demand exhausts its request budget. Every snapshot
/// installed after session start (watcher deltas, refresh, update_paths,
/// workspace activation, LSP `didOpen`) is instead warmed here, off the
/// request path; a request arriving mid-warm blocks on the analyzer's
/// one-time index initialization rather than double-building. At most one
/// warm thread runs per warmer, and snapshots installed while a warm is in
/// flight coalesce into a single trailing warm of the latest snapshot, so
/// continuous editing costs at most one superseded build rather than one per
/// delta. Sessions with deferred initial builds use the same path after the
/// complete base snapshot is published, so unrelated code-intelligence
/// operations do not wait for optional accelerators they never query (#1448).
pub struct IndexWarmer {
    state: Mutex<IndexWarmerState>,
    idle: Condvar,
}

#[derive(Default)]
struct IndexWarmerState {
    running: bool,
    pending: Option<Arc<WorkspaceAnalyzer>>,
}

impl IndexWarmer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(IndexWarmerState::default()),
            idle: Condvar::new(),
        })
    }

    /// Queue a background warm of the snapshot's lazy query indexes. Free
    /// when the snapshot is already warm (incremental updates whose sources
    /// were unchanged share the previous generation's indexes).
    pub fn schedule(self: &Arc<Self>, snapshot: Arc<WorkspaceAnalyzer>) {
        if snapshot.query_indexes_warm() {
            return;
        }
        let mut state = self.state.lock().expect("index warmer lock poisoned");
        if state.running {
            state.pending = Some(snapshot);
            return;
        }
        state.running = true;
        drop(state);
        let warmer = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("bifrost-index-warm".to_string())
            .spawn(move || {
                let mut next = Some(snapshot);
                while let Some(current) = next.take() {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        current.warm_query_indexes();
                    }));
                    let mut state = warmer.state.lock().expect("index warmer lock poisoned");
                    if let Err(panic) = outcome {
                        // A panicking index build installs nothing, so the
                        // same panic resurfaces in whichever request first
                        // demands the index; reset the warmer instead of
                        // wedging it, then let the panic reach the hook.
                        state.pending = None;
                        state.running = false;
                        warmer.idle.notify_all();
                        drop(state);
                        std::panic::resume_unwind(panic);
                    }
                    next = state.pending.take();
                    if next.is_none() {
                        state.running = false;
                        warmer.idle.notify_all();
                    }
                }
            });
        if spawned.is_err() {
            // Thread spawn failure leaves the indexes to demand-build inside
            // requests, exactly the pre-warm behavior.
            let mut state = self.state.lock().expect("index warmer lock poisoned");
            state.running = false;
            self.idle.notify_all();
        }
    }

    /// Test support: block until no warm is running or queued. Panics if the
    /// warmer does not go idle within 30 seconds.
    pub fn wait_until_idle(&self) {
        let state = self.state.lock().expect("index warmer lock poisoned");
        let (state, timeout) = self
            .idle
            .wait_timeout_while(state, Duration::from_secs(30), |state| state.running)
            .expect("index warmer lock poisoned while waiting for idle");
        assert!(
            !timeout.timed_out(),
            "background index warm did not complete"
        );
        assert!(!state.running);
    }
}
