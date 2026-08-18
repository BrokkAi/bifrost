//! Cancellation-aware single-flight caching for complete immutable values.
//!
//! A caller that wins a key's flight builds without holding any cache lock and
//! publishes only after it has a complete, validated value. Dropping a leader
//! permit without publishing wakes followers and lets one of them retry; this
//! is how operational errors, cancellation, and domain-specific incomplete
//! outcomes stay out of the ready cache.
//!
//! Unlike [`super::pool_memo::PoolSafeMemo`], this type deliberately forbids
//! duplicate same-key builds. It must therefore not be used where waiters can
//! occupy every worker needed by the leader, and builders must not recursively
//! acquire the same key or introduce cycles between keys. Pre-materialize such
//! dependencies or run their builders outside the bounded worker pool whose
//! tasks may wait here.

use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use moka::sync::Cache;

use crate::cancellation::CancellationToken;
use crate::hash::HashMap;

const CANCELLATION_POLL: Duration = Duration::from_millis(10);

/// How many keys the live-instance registry tracks before it drops the entries
/// whose value is gone.
///
/// An entry is one key and one `Weak`, so the registry costs a small multiple
/// of the ready cache's key set even at this bound; the sweep is a single
/// retain over a map this size and runs only when a publication crosses it.
const LIVE_REGISTRY_SWEEP_KEYS: usize = 8_192;

/// Time spent following already-running same-key materializations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CompleteValueWait {
    pub(crate) waits: u64,
    pub(crate) wait_ns: u64,
}

impl CompleteValueWait {
    fn record(&mut self, started: Instant) {
        self.waits = self.waits.saturating_add(1);
        self.wait_ns = self.wait_ns.saturating_add(elapsed_ns(started));
    }
}

/// Result of acquiring one exact complete-value key.
pub(crate) enum CompleteValueAcquisition<K, V>
where
    K: Eq + Hash,
{
    Cached {
        value: Arc<V>,
    },
    Leader {
        permit: CompleteValuePermit<K, V>,
    },
    /// The same-key leader proved that this flight cannot produce a complete
    /// value. Callers that retain deterministic rejection state can return it
    /// to every follower without serially rebuilding the same value.
    Rejected,
    Cancelled,
}

/// Byte- or weight-bounded ready values plus strict same-key single-flight.
///
/// `K` is the caller's complete validity identity. A derived-layer owner must
/// bind workspace identity, canonical storage generations, content/overlay
/// state, layer kind, exact projection/filter shape, resolver configuration,
/// and representation version before acquisition. This type deliberately does
/// not infer or partially bind any of those dimensions.
pub(crate) struct CompleteValueCache<K, V>
where
    K: Eq + Hash,
{
    entries: Cache<K, Arc<V>>,
    in_flight: Arc<Mutex<HashMap<K, Arc<InFlightMaterialization<V>>>>>,
    live: Arc<Mutex<HashMap<K, Weak<V>>>>,
    revivals: Arc<AtomicU64>,
}

impl<K, V> Clone for CompleteValueCache<K, V>
where
    K: Eq + Hash,
{
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            in_flight: Arc::clone(&self.in_flight),
            live: Arc::clone(&self.live),
            revivals: Arc::clone(&self.revivals),
        }
    }
}

impl<K, V> CompleteValueCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    pub(crate) fn new(
        max_retained_weight: u64,
        weigher: impl Fn(&K, &Arc<V>) -> u32 + Send + Sync + 'static,
    ) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(max_retained_weight.max(1))
                .weigher(move |key, value| weigher(key, value).max(1))
                .build(),
            in_flight: Arc::new(Mutex::new(HashMap::default())),
            live: Arc::new(Mutex::new(HashMap::default())),
            revivals: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The instance this cache already published for `key`, when the value is
    /// still referenced somewhere and the ready cache has only evicted it.
    ///
    /// A value published here is complete and immutable, and `K` is its whole
    /// validity identity, so the live instance is exactly what a rebuild would
    /// produce -- except that a rebuild would produce a *second* instance.
    /// Consumers that identify a value's parts by allocation identity (a
    /// `ProcedureHandle` compares its owning `Arc<SemanticArtifact>` by
    /// pointer) then hold two identities for one entity, and a lookup keyed on
    /// one misses the other: #2307 measured require-model taint losing real
    /// findings this way, because a region's plan was built from the instance
    /// discovery saw and the solve re-materialized the file the byte-bounded
    /// cache had since evicted. Reusing the live instance keeps one identity
    /// per validity key for as long as anyone holds it, and also skips the
    /// rebuild.
    ///
    /// The registry holds `Weak` references only, so it never extends a
    /// value's lifetime and the weight bound on `entries` still governs
    /// retention.
    fn revive(&self, key: &K) -> Option<Arc<V>> {
        let value = self
            .live
            .lock()
            .expect("complete-value live-instance map mutex poisoned")
            .get(key)
            .and_then(Weak::upgrade)?;
        self.entries.insert(key.clone(), Arc::clone(&value));
        self.revivals.fetch_add(1, Ordering::Relaxed);
        Some(value)
    }

    /// Return a ready value, reserve leadership, or follow the current leader.
    ///
    /// Cancellation wins over both ready and just-completed values. Followers
    /// poll cancellation because `std::sync::Condvar` is not interruptible.
    pub(crate) fn acquire(
        &self,
        key: &K,
        cancellation: &CancellationToken,
    ) -> (CompleteValueAcquisition<K, V>, CompleteValueWait) {
        let mut wait = CompleteValueWait::default();
        loop {
            if cancellation.is_cancelled() {
                return (CompleteValueAcquisition::Cancelled, wait);
            }
            if let Some(value) = self.entries.get(key) {
                return (CompleteValueAcquisition::Cached { value }, wait);
            }
            if let Some(value) = self.revive(key) {
                return (CompleteValueAcquisition::Cached { value }, wait);
            }

            let (ready, flight, is_leader) = {
                let mut in_flight = self
                    .in_flight
                    .lock()
                    .expect("complete-value single-flight map mutex poisoned");

                // Close the race between the optimistic ready lookup above and
                // a previous leader publishing and removing its flight.
                if let Some(value) = self.entries.get(key).or_else(|| self.revive(key)) {
                    (Some(value), None, false)
                } else {
                    match in_flight.get(key) {
                        Some(flight) => (None, Some(Arc::clone(flight)), false),
                        None => {
                            let flight = Arc::new(InFlightMaterialization::new());
                            in_flight.insert(key.clone(), Arc::clone(&flight));
                            (None, Some(flight), true)
                        }
                    }
                }
            };

            if let Some(value) = ready {
                return (CompleteValueAcquisition::Cached { value }, wait);
            }
            let flight = flight.expect("a non-ready acquisition has a flight");
            if is_leader {
                return (
                    CompleteValueAcquisition::Leader {
                        permit: CompleteValuePermit {
                            key: key.clone(),
                            flight,
                            entries: self.entries.clone(),
                            in_flight: Arc::clone(&self.in_flight),
                            live: Arc::clone(&self.live),
                        },
                    },
                    wait,
                );
            }

            let started = Instant::now();
            let followed = flight.wait(cancellation);
            wait.record(started);
            match followed {
                FlightWait::Completed(value) => {
                    return (CompleteValueAcquisition::Cached { value }, wait);
                }
                FlightWait::Retry => {}
                FlightWait::Rejected => {
                    return (CompleteValueAcquisition::Rejected, wait);
                }
                FlightWait::Cancelled => {
                    return (CompleteValueAcquisition::Cancelled, wait);
                }
            }
        }
    }

    /// Return a resident complete value without reserving build leadership.
    /// This supports physical planners that may reuse an index for a narrow
    /// request but must not construct the whole-workspace value for it.
    pub(crate) fn get_ready(&self, key: &K, cancellation: &CancellationToken) -> Option<Arc<V>> {
        if cancellation.is_cancelled() {
            return None;
        }
        self.entries.get(key).or_else(|| self.revive(key))
    }

    /// Ready-cache misses that a still-live instance answered instead of a
    /// rebuild. Non-zero means the weight bound is evicting values the process
    /// is still using.
    #[cfg(test)]
    pub(crate) fn revivals_for_test(&self) -> u64 {
        self.revivals.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn insert_complete_for_test(&self, key: K, value: Arc<V>) {
        self.entries.insert(key, value);
    }

    /// Drop one key from the weight-bounded ready cache, exactly as the bound
    /// does at scale, without depending on the admission policy's choice of
    /// victim.
    #[cfg(test)]
    pub(crate) fn evict_for_test(&self, key: &K) {
        self.entries.invalidate(key);
        self.entries.run_pending_tasks();
    }

    #[cfg(test)]
    pub(crate) fn len_for_test(&self) -> u64 {
        self.entries.run_pending_tasks();
        self.entries.entry_count()
    }

    #[cfg(test)]
    pub(crate) fn waiting_count_for_test(&self) -> usize {
        self.in_flight
            .lock()
            .expect("complete-value single-flight map mutex poisoned")
            .values()
            .map(|flight| {
                flight
                    .state
                    .lock()
                    .expect("complete-value single-flight state mutex poisoned")
                    .waiters
            })
            .sum()
    }
}

struct InFlightMaterialization<V> {
    state: Mutex<InFlightState<V>>,
    wake: Condvar,
}

struct InFlightState<V> {
    running: bool,
    waiters: usize,
    completed: Option<Arc<V>>,
    rejected: bool,
}

impl<V> InFlightMaterialization<V> {
    fn new() -> Self {
        Self {
            state: Mutex::new(InFlightState {
                running: true,
                waiters: 0,
                completed: None,
                rejected: false,
            }),
            wake: Condvar::new(),
        }
    }

    fn wait(&self, cancellation: &CancellationToken) -> FlightWait<V> {
        let mut state = self
            .state
            .lock()
            .expect("complete-value single-flight state mutex poisoned");
        state.waiters = state.waiters.saturating_add(1);
        while state.running && !cancellation.is_cancelled() {
            let (next, _) = self
                .wake
                .wait_timeout(state, CANCELLATION_POLL)
                .expect("complete-value single-flight state mutex poisoned while waiting");
            state = next;
        }
        state.waiters = state.waiters.saturating_sub(1);
        if cancellation.is_cancelled() {
            FlightWait::Cancelled
        } else if let Some(value) = &state.completed {
            FlightWait::Completed(Arc::clone(value))
        } else if state.rejected {
            FlightWait::Rejected
        } else {
            FlightWait::Retry
        }
    }
}

enum FlightWait<V> {
    Completed(Arc<V>),
    Rejected,
    Retry,
    Cancelled,
}

/// Leadership for one exact key. Dropping this without publication is the
/// generic failure/incomplete path: followers wake and retry.
pub(crate) struct CompleteValuePermit<K, V>
where
    K: Eq + Hash,
{
    key: K,
    flight: Arc<InFlightMaterialization<V>>,
    entries: Cache<K, Arc<V>>,
    in_flight: Arc<Mutex<HashMap<K, Arc<InFlightMaterialization<V>>>>>,
    live: Arc<Mutex<HashMap<K, Weak<V>>>>,
}

impl<K, V> CompleteValuePermit<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    /// Retain and hand off one complete immutable value, then wake followers.
    pub(crate) fn publish_complete(self, value: Arc<V>) {
        self.entries.insert(self.key.clone(), Arc::clone(&value));
        {
            let mut live = self
                .live
                .lock()
                .expect("complete-value live-instance map mutex poisoned");
            live.insert(self.key.clone(), Arc::downgrade(&value));
            if live.len() > LIVE_REGISTRY_SWEEP_KEYS {
                live.retain(|_, weak| weak.strong_count() > 0);
            }
        }
        self.flight
            .state
            .lock()
            .expect("complete-value single-flight state mutex poisoned")
            .completed = Some(value);
    }

    /// Hand the current flight's deterministic rejection to its followers
    /// without retaining a value in the ready cache. The owner is responsible
    /// for keeping the exact-key reason available after this permit is dropped.
    pub(crate) fn publish_rejected(self) {
        self.flight
            .state
            .lock()
            .expect("complete-value single-flight state mutex poisoned")
            .rejected = true;
    }
}

impl<K, V> Drop for CompleteValuePermit<K, V>
where
    K: Eq + Hash,
{
    fn drop(&mut self) {
        {
            let mut in_flight = self
                .in_flight
                .lock()
                .expect("complete-value single-flight map mutex poisoned");
            if in_flight
                .get(&self.key)
                .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
            {
                in_flight.remove(&self.key);
            }
        }
        let mut state = self
            .flight
            .state
            .lock()
            .expect("complete-value single-flight state mutex poisoned");
        state.running = false;
        drop(state);
        self.flight.wake.notify_all();
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::analyzer::semantic::ids::{StableDigest, WorkspaceMountId};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum FakeDerivedLayerKind {
        DirectImportTopology,
        OtherRelation,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct FakeDerivedLayerKey {
        workspace_mount: WorkspaceMountId,
        storage_generations: Box<[(Box<str>, u64)]>,
        content_overlay_fingerprint: StableDigest,
        kind: FakeDerivedLayerKind,
        projection_filter_fingerprint: StableDigest,
        configuration_fingerprint: StableDigest,
        representation_version: u32,
    }

    fn digest(label: &str) -> StableDigest {
        StableDigest::sha256(label)
    }

    fn fake_derived_key(generation: u64) -> FakeDerivedLayerKey {
        let mut storage_generations = vec![
            (Box::<str>::from("rust"), generation),
            (Box::<str>::from("java"), 0),
        ];
        storage_generations.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        assert!(
            storage_generations
                .windows(2)
                .all(|pair| pair[0].0 != pair[1].0),
            "fake layer key must reject duplicate storage labels"
        );
        FakeDerivedLayerKey {
            workspace_mount: WorkspaceMountId::from_digest(digest("workspace-a")),
            storage_generations: storage_generations.into_boxed_slice(),
            content_overlay_fingerprint: digest("content-overlay-a"),
            kind: FakeDerivedLayerKind::DirectImportTopology,
            projection_filter_fingerprint: digest("projection-filter-a"),
            configuration_fingerprint: digest("resolver-config-a"),
            representation_version: 1,
        }
    }

    fn cache(capacity: u64, weight: u32) -> CompleteValueCache<String, usize> {
        CompleteValueCache::new(capacity, move |_, _| weight)
    }

    fn wait_for_waiter(cache: &CompleteValueCache<String, usize>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.waiting_count_for_test() == 0 {
            assert!(
                Instant::now() < deadline,
                "same-key request did not enter the single-flight wait"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn same_key_has_one_leader_and_hands_off_the_same_arc() {
        let cache = cache(1024, 1);
        let key = "graph".to_string();
        let cancellation = CancellationToken::default();
        let (CompleteValueAcquisition::Leader { permit }, wait) =
            cache.acquire(&key, &cancellation)
        else {
            panic!("first caller must lead")
        };
        assert_eq!(wait, CompleteValueWait::default());

        let follower_cache = cache.clone();
        let follower_key = key.clone();
        let follower = thread::spawn(move || {
            follower_cache.acquire(&follower_key, &CancellationToken::default())
        });
        wait_for_waiter(&cache);

        let built = Arc::new(7);
        permit.publish_complete(Arc::clone(&built));
        let (CompleteValueAcquisition::Cached { value }, wait) =
            follower.join().expect("follower thread")
        else {
            panic!("follower must receive the completed flight")
        };
        assert!(Arc::ptr_eq(&built, &value));
        assert_eq!(wait.waits, 1);
        assert!(wait.wait_ns > 0);
    }

    #[test]
    fn cancelled_waiter_does_not_cancel_or_publish_for_the_leader() {
        let cache = cache(1024, 1);
        let key = "graph".to_string();
        let (CompleteValueAcquisition::Leader { permit }, _) =
            cache.acquire(&key, &CancellationToken::default())
        else {
            panic!("first caller must lead")
        };

        let cancellation = CancellationToken::default();
        let follower_cancellation = cancellation.clone();
        let follower_cache = cache.clone();
        let follower_key = key.clone();
        let follower =
            thread::spawn(move || follower_cache.acquire(&follower_key, &follower_cancellation));
        wait_for_waiter(&cache);
        cancellation.cancel();

        let (CompleteValueAcquisition::Cancelled, wait) =
            follower.join().expect("cancelled follower thread")
        else {
            panic!("cancelled follower must stop waiting")
        };
        assert_eq!(wait.waits, 1);
        let value = Arc::new(11);
        permit.publish_complete(Arc::clone(&value));
        let (CompleteValueAcquisition::Cached { value: ready }, _) =
            cache.acquire(&key, &CancellationToken::default())
        else {
            panic!("leader publication must remain ready")
        };
        assert!(Arc::ptr_eq(&value, &ready));
    }

    #[test]
    fn unpublished_leader_wakes_a_waiter_to_retry() {
        let cache = cache(1024, 1);
        let key = "graph".to_string();
        let (CompleteValueAcquisition::Leader { permit }, _) =
            cache.acquire(&key, &CancellationToken::default())
        else {
            panic!("first caller must lead")
        };

        let follower_cache = cache.clone();
        let follower_key = key.clone();
        let follower = thread::spawn(move || {
            follower_cache.acquire(&follower_key, &CancellationToken::default())
        });
        wait_for_waiter(&cache);

        // A domain error, cancellation, or incomplete result follows this path.
        drop(permit);
        let (CompleteValueAcquisition::Leader { permit }, wait) =
            follower.join().expect("retrying follower thread")
        else {
            panic!("one follower must retry as the next leader")
        };
        assert_eq!(wait.waits, 1);
        assert_eq!(cache.len_for_test(), 0);

        let retried = Arc::new(13);
        permit.publish_complete(Arc::clone(&retried));
        let (CompleteValueAcquisition::Cached { value }, _) =
            cache.acquire(&key, &CancellationToken::default())
        else {
            panic!("retried complete value must be cached")
        };
        assert!(Arc::ptr_eq(&retried, &value));
    }

    #[test]
    fn rejected_leader_hands_failure_to_current_waiters_without_serial_retry() {
        let cache = cache(1024, 1);
        let key = "graph".to_string();
        let (CompleteValueAcquisition::Leader { permit }, _) =
            cache.acquire(&key, &CancellationToken::default())
        else {
            panic!("first caller must lead")
        };

        let follower_cache = cache.clone();
        let follower_key = key.clone();
        let follower = thread::spawn(move || {
            follower_cache.acquire(&follower_key, &CancellationToken::default())
        });
        wait_for_waiter(&cache);

        permit.publish_rejected();
        let (CompleteValueAcquisition::Rejected, wait) = follower.join().expect("follower thread")
        else {
            panic!("follower must receive the same-flight rejection")
        };
        assert_eq!(wait.waits, 1);
        assert_eq!(cache.len_for_test(), 0);

        assert!(matches!(
            cache.acquire(&key, &CancellationToken::default()).0,
            CompleteValueAcquisition::Leader { .. }
        ));
    }

    #[test]
    fn oversize_value_is_handed_to_current_waiters_without_retention() {
        let cache = cache(1, 2);
        let key = "graph".to_string();
        let (CompleteValueAcquisition::Leader { permit }, _) =
            cache.acquire(&key, &CancellationToken::default())
        else {
            panic!("first caller must lead")
        };

        let follower_cache = cache.clone();
        let follower_key = key.clone();
        let follower = thread::spawn(move || {
            follower_cache.acquire(&follower_key, &CancellationToken::default())
        });
        wait_for_waiter(&cache);

        let built = Arc::new(17);
        permit.publish_complete(Arc::clone(&built));
        let (CompleteValueAcquisition::Cached { value }, _) =
            follower.join().expect("follower thread")
        else {
            panic!("current follower must receive oversize value")
        };
        assert!(Arc::ptr_eq(&built, &value));
        assert_eq!(cache.len_for_test(), 0);
    }

    /// #2307: eviction must not split one validity key into two instances.
    ///
    /// A holder that still references an evicted value and a caller that asks
    /// for the same key must get the same allocation. Consumers identify a
    /// value's parts by allocation identity -- a `ProcedureHandle` compares its
    /// owning artifact `Arc` by pointer -- so a second instance silently breaks
    /// every lookup that crosses the two, which is how require-model taint lost
    /// real findings at corpus scale.
    #[test]
    fn an_evicted_value_that_is_still_referenced_is_reused_rather_than_rebuilt() {
        let cache = cache(1, 1);
        let cancellation = CancellationToken::default();
        let key = "held".to_string();

        let (CompleteValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("a new key must lead")
        };
        let held = Arc::new(11);
        permit.publish_complete(Arc::clone(&held));

        // Evict `key` from the weight-bounded ready cache while the caller
        // above still holds its value.
        cache.evict_for_test(&key);
        assert_eq!(cache.len_for_test(), 0);

        let (acquisition, _) = cache.acquire(&key, &cancellation);
        let CompleteValueAcquisition::Cached { value } = acquisition else {
            panic!("an evicted but still-referenced value must not be rebuilt")
        };
        assert!(
            Arc::ptr_eq(&held, &value),
            "one validity key must denote one live instance"
        );
        assert_eq!(cache.revivals_for_test(), 1);
    }

    /// The registry holds weak references only: once the last holder drops the
    /// value, the key rebuilds exactly as it did before.
    #[test]
    fn a_dropped_value_is_rebuilt_rather_than_revived() {
        let cache = cache(1, 1);
        let cancellation = CancellationToken::default();
        let key = "dropped".to_string();

        let (CompleteValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("a new key must lead")
        };
        permit.publish_complete(Arc::new(33));
        cache.evict_for_test(&key);

        assert!(
            matches!(
                cache.acquire(&key, &cancellation).0,
                CompleteValueAcquisition::Leader { .. }
            ),
            "a value nobody holds must be rebuilt, not resurrected"
        );
        assert_eq!(cache.revivals_for_test(), 0);
    }

    #[test]
    fn zero_reported_weights_cannot_bypass_the_retention_bound() {
        let cache = CompleteValueCache::new(1, |_: &String, _: &Arc<usize>| 0);
        let cancellation = CancellationToken::default();

        for (key, value) in [("first".to_string(), 1), ("second".to_string(), 2)] {
            let (CompleteValueAcquisition::Leader { permit }, _) =
                cache.acquire(&key, &cancellation)
            else {
                panic!("a new key must lead")
            };
            permit.publish_complete(Arc::new(value));
        }

        assert_eq!(cache.len_for_test(), 1);
    }

    #[test]
    fn fake_derived_key_binds_every_required_validity_dimension() {
        let baseline = fake_derived_key(1);
        assert_eq!(
            baseline
                .storage_generations
                .iter()
                .map(|(language, _)| language.as_ref())
                .collect::<Vec<_>>(),
            vec!["java", "rust"]
        );

        let mut changed = baseline.clone();
        changed.workspace_mount = WorkspaceMountId::from_digest(digest("workspace-b"));
        assert_ne!(baseline, changed);

        let mut changed = baseline.clone();
        changed.storage_generations[1].1 = 2;
        assert_ne!(baseline, changed);

        let mut changed = baseline.clone();
        changed.content_overlay_fingerprint = digest("content-overlay-b");
        assert_ne!(baseline, changed);

        let mut changed = baseline.clone();
        changed.kind = FakeDerivedLayerKind::OtherRelation;
        assert_ne!(baseline, changed);

        let mut changed = baseline.clone();
        changed.projection_filter_fingerprint = digest("projection-filter-b");
        assert_ne!(baseline, changed);

        let mut changed = baseline.clone();
        changed.configuration_fingerprint = digest("resolver-config-b");
        assert_ne!(baseline, changed);

        let mut changed = baseline.clone();
        changed.representation_version = 2;
        assert_ne!(baseline, changed);
    }

    #[test]
    fn fake_derived_generation_cutover_cannot_reuse_a_ready_value() {
        let first_key = fake_derived_key(1);
        let second_key = fake_derived_key(2);
        let cache = CompleteValueCache::new(1024, |_, _: &Arc<usize>| 1);
        let cancellation = CancellationToken::default();

        let (CompleteValueAcquisition::Leader { permit }, _) =
            cache.acquire(&first_key, &cancellation)
        else {
            panic!("first exact generation should lead")
        };
        let first = Arc::new(23);
        permit.publish_complete(Arc::clone(&first));
        let (CompleteValueAcquisition::Cached { value }, _) =
            cache.acquire(&first_key, &cancellation)
        else {
            panic!("same exact generation should reuse the ready value")
        };
        assert!(Arc::ptr_eq(&first, &value));

        assert!(matches!(
            cache.acquire(&second_key, &cancellation).0,
            CompleteValueAcquisition::Leader { .. }
        ));
    }
}
