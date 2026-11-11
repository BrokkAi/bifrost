//! Cancellation-aware single-flight caching for complete immutable values.
//!
//! A caller that wins a key's flight builds without holding any cache lock and
//! publishes only after it has a complete, validated value. Dropping a leader
//! permit without publishing wakes followers and lets one of them retry; this
//! is how operational errors, cancellation, and domain-specific incomplete
//! outcomes stay out of the ready cache.
//!
//! Unlike [`crate::analyzer::pool_memo::PoolSafeMemo`], this type deliberately forbids
//! duplicate same-key builds. It must therefore not be used where waiters can
//! occupy every worker needed by the leader, and builders must not recursively
//! acquire the same key or introduce cycles between keys. Pre-materialize such
//! dependencies or run their builders outside the bounded worker pool whose
//! tasks may wait here.

use std::hash::Hash;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use moka::sync::Cache;

use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::util::elapsed_ns;

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
pub struct CompleteValueWait {
    pub waits: u64,
    pub wait_ns: u64,
}

/// Test-only account of successful live-value revivals.
///
/// `operations` counts ready-cache misses served by the live registry.
/// `distinct_values` counts exact `(key, allocation)` pairs, so reinserting
/// the same oversize allocation more than once changes only `operations`.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompleteValueRevivalCensus {
    pub operations: u64,
    pub distinct_values: u64,
}

#[cfg(any(test, feature = "test-support"))]
struct CompleteValueRevivalTracker<K, V> {
    census: CompleteValueRevivalCensus,
    values_by_key: HashMap<K, Vec<Weak<V>>>,
}

#[cfg(any(test, feature = "test-support"))]
impl<K, V> Default for CompleteValueRevivalTracker<K, V> {
    fn default() -> Self {
        Self {
            census: CompleteValueRevivalCensus::default(),
            values_by_key: HashMap::default(),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl<K, V> CompleteValueRevivalTracker<K, V>
where
    K: Eq + Hash,
{
    fn record(&mut self, key: K, value: &Arc<V>) {
        self.census.operations = self.census.operations.saturating_add(1);
        let revived = Arc::downgrade(value);
        let values = self.values_by_key.entry(key).or_default();
        if values.iter().any(|seen| Weak::ptr_eq(seen, &revived)) {
            return;
        }
        values.push(revived);
        self.census.distinct_values = self.census.distinct_values.saturating_add(1);
    }

    fn reset(&mut self) {
        self.census = CompleteValueRevivalCensus::default();
        self.values_by_key.clear();
    }
}

impl CompleteValueWait {
    fn record(&mut self, started: Instant) {
        self.waits = self.waits.saturating_add(1);
        self.wait_ns = self.wait_ns.saturating_add(elapsed_ns(started));
    }
}

/// Result of acquiring one exact complete-value key.
pub enum CompleteValueAcquisition<K, V>
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

// The ready cache owns exactly the retention object. Its weak projection
// preserves the public Arc<V> identity and the live-instance revival contract.
struct ReadyValue<V> {
    value: Weak<V>,
    _retention: Arc<dyn Send + Sync>,
}

impl<V> Clone for ReadyValue<V> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            _retention: Arc::clone(&self._retention),
        }
    }
}

impl<V> ReadyValue<V> {
    fn new(value: Arc<V>, retain: fn(Arc<V>) -> Arc<dyn Send + Sync>) -> Self {
        Self {
            value: Arc::downgrade(&value),
            _retention: retain(value),
        }
    }

    fn get(&self) -> Arc<V> {
        self.value
            .upgrade()
            .expect("ready retention owns its value")
    }
}

/// Byte- or weight-bounded ready values plus strict same-key single-flight.
///
/// `K` is the caller's complete validity identity. A derived-layer owner must
/// bind workspace identity, canonical storage generations, content/overlay
/// state, layer kind, exact projection/filter shape, resolver configuration,
/// and representation version before acquisition. This type deliberately does
/// not infer or partially bind any of those dimensions.
///
/// Moka eviction is logically immediate but physical destruction of its
/// internal `Arc` can wait for an epoch-reclamation grace period. During that
/// interval the live registry below can revive and reinsert the same allocation.
/// The retention bound governs logical ready entries; rebuild after the last
/// consumer drops is guaranteed once that internal grace period also ends.
pub struct CompleteValueCache<K, V>
where
    K: Eq + Hash,
{
    entries: Cache<K, ReadyValue<V>>,
    retain: fn(Arc<V>) -> Arc<dyn Send + Sync>,
    in_flight: FlightMap<K, Arc<V>>,
    live: Arc<Mutex<HashMap<K, Weak<V>>>>,
    #[cfg(any(test, feature = "test-support"))]
    revival_tracker: Arc<Mutex<CompleteValueRevivalTracker<K, V>>>,
}

impl<K, V> Clone for CompleteValueCache<K, V>
where
    K: Eq + Hash,
{
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            retain: self.retain,
            in_flight: Arc::clone(&self.in_flight),
            live: Arc::clone(&self.live),
            #[cfg(any(test, feature = "test-support"))]
            revival_tracker: Arc::clone(&self.revival_tracker),
        }
    }
}

impl<K, V> CompleteValueCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    pub fn new(
        max_retained_weight: u64,
        weigher: impl Fn(&K, &Arc<V>) -> u32 + Send + Sync + 'static,
    ) -> Self {
        Self::with_retention(max_retained_weight, weigher, |value| value)
    }

    /// Retain ready values with an owner that distinguishes cache pins from
    /// consumer pins. `retain` must own the supplied allocation until its
    /// returned object drops; it must not substitute a different allocation.
    /// The live registry and all callers still use the original Arc identity.
    pub fn with_retention(
        max_retained_weight: u64,
        weigher: impl Fn(&K, &Arc<V>) -> u32 + Send + Sync + 'static,
        retain: fn(Arc<V>) -> Arc<dyn Send + Sync>,
    ) -> Self {
        Self {
            retain,
            entries: Cache::builder()
                .max_capacity(max_retained_weight.max(1))
                .weigher(move |key, value: &ReadyValue<V>| weigher(key, &value.get()).max(1))
                .build(),
            in_flight: Arc::new(Mutex::new(HashMap::default())),
            live: Arc::new(Mutex::new(HashMap::default())),
            #[cfg(any(test, feature = "test-support"))]
            revival_tracker: Arc::new(Mutex::new(CompleteValueRevivalTracker::default())),
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
    /// The registry holds `Weak` references only, so the registry itself never
    /// extends a value's lifetime and the weight bound on `entries` still
    /// governs logical retention. Moka can retain an evicted entry internally
    /// until epoch reclamation finishes; a request during that grace period may
    /// upgrade the weak reference and make the same allocation resident again.
    fn revive(&self, key: &K) -> Option<Arc<V>> {
        let live = self
            .live
            .lock()
            .expect("complete-value live-instance map mutex poisoned");
        let value = live.get(key).and_then(Weak::upgrade)?;
        self.entries.insert(
            key.clone(),
            ReadyValue::new(Arc::clone(&value), self.retain),
        );
        #[cfg(any(test, feature = "test-support"))]
        self.revival_tracker
            .lock()
            .expect("complete-value revival tracker mutex poisoned")
            .record(key.clone(), &value);
        Some(value)
    }

    /// Return a ready value, reserve leadership, or follow the current leader.
    ///
    /// Cancellation wins over both ready and just-completed values. Followers
    /// poll cancellation because `std::sync::Condvar` is not interruptible.
    pub fn acquire(
        &self,
        key: &K,
        cancellation: &CancellationToken,
    ) -> (CompleteValueAcquisition<K, V>, CompleteValueWait) {
        let mut wait = CompleteValueWait::default();
        loop {
            if cancellation.is_cancelled() {
                return (CompleteValueAcquisition::Cancelled, wait);
            }
            if let Some(value) = self.entries.get(key).map(|entry| entry.get()) {
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
                if let Some(value) = self
                    .entries
                    .get(key)
                    .map(|entry| entry.get())
                    .or_else(|| self.revive(key))
                {
                    (Some(value), None, false)
                } else {
                    match in_flight.get(key) {
                        Some(flight) => (None, Some(Arc::clone(flight)), false),
                        None => {
                            let flight = Arc::new(Flight::new());
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
                            retain: self.retain,
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
                Follow::Completed(value) => {
                    return (CompleteValueAcquisition::Cached { value }, wait);
                }
                Follow::Retry => {}
                Follow::Rejected => {
                    return (CompleteValueAcquisition::Rejected, wait);
                }
                Follow::Cancelled => {
                    return (CompleteValueAcquisition::Cancelled, wait);
                }
            }
        }
    }

    /// Visit ready entries for a temporary diagnostic census.
    pub fn visit_ready(&self, mut visitor: impl FnMut(&V)) {
        self.entries.run_pending_tasks();
        for (_, value) in self.entries.iter() {
            visitor(&value.get());
        }
    }

    /// Return a resident complete value without reserving build leadership.
    /// This supports physical planners that may reuse an index for a narrow
    /// request but must not construct the whole-workspace value for it.
    pub fn get_ready(&self, key: &K, cancellation: &CancellationToken) -> Option<Arc<V>> {
        if cancellation.is_cancelled() {
            return None;
        }
        self.entries
            .get(key)
            .map(|entry| entry.get())
            .or_else(|| self.revive(key))
    }

    /// Remove one complete value and its live-instance identity.
    ///
    /// This is used when a derived owner discovers after publication that its
    /// authority changed. Removing only the ready entry would let `revive`
    /// resurrect the same invalid allocation on the next lookup.
    ///
    /// This does not cancel an in-flight materialization. An invalidation that
    /// completes before a later publication is superseded by that publication;
    /// an owner that detects stale authority must validate again after publish.
    pub fn invalidate(&self, key: &K) {
        let mut live = self
            .live
            .lock()
            .expect("complete-value live-instance map mutex poisoned");
        live.remove(key);
        self.entries.invalidate(key);
    }

    /// Whether a same-key materialization is already running.
    ///
    /// [`Self::acquire`] follows such a build, which is right for a caller
    /// with nothing else to do. A caller that has a cheaper alternative --
    /// a scan over the same facts the value would accelerate -- asks this
    /// first and takes the alternative, so it pays its own cost instead of
    /// the build's (#2879).
    pub fn build_in_flight(&self, key: &K) -> bool {
        self.in_flight
            .lock()
            .expect("complete-value single-flight map mutex poisoned")
            .contains_key(key)
    }

    /// Ready-cache misses served by still-live instances, split into raw
    /// operations and exact key/allocation identities.
    #[cfg(any(test, feature = "test-support"))]
    pub fn revival_census_for_test(&self) -> CompleteValueRevivalCensus {
        self.revival_tracker
            .lock()
            .expect("complete-value revival tracker mutex poisoned")
            .census
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_revival_census_for_test(&self) {
        self.revival_tracker
            .lock()
            .expect("complete-value revival tracker mutex poisoned")
            .reset();
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_complete_for_test(&self, key: K, value: Arc<V>) {
        self.entries
            .insert(key, ReadyValue::new(value, self.retain));
    }

    /// Drop one key from the weight-bounded ready cache, exactly as the bound
    /// does at scale, without depending on the admission policy's choice of
    /// victim.
    #[cfg(any(test, feature = "test-support"))]
    pub fn evict_for_test(&self, key: &K) {
        self.entries.invalidate(key);
        self.entries.run_pending_tasks();
    }

    /// Logically evict every ready value without disturbing live weak
    /// identities. The next lookup for a still-held value must therefore pass
    /// through `revive`, just as it does after capacity eviction.
    #[cfg(any(test, feature = "test-support"))]
    pub fn invalidate_all_for_test(&self) {
        self.entries.invalidate_all();
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn len_for_test(&self) -> u64 {
        self.entries.run_pending_tasks();
        self.entries.entry_count()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn waiting_count_for_test(&self) -> usize {
        self.in_flight
            .lock()
            .expect("complete-value single-flight map mutex poisoned")
            .values()
            .map(|flight| flight.waiters())
            .sum()
    }
}

/// The running flights of one cache, by key.
pub(crate) type FlightMap<K, V> = Arc<Mutex<HashMap<K, Arc<Flight<V>>>>>;

/// One build of one key, shared by its leader and every follower.
///
/// The leader's permit drives the state from `Running` to exactly one terminal
/// state: it publishes a value or a rejection, or it is dropped without either
/// (`Abandoned`, which makes followers retry). Followers wait until the state
/// leaves `Running`. Shared with [`crate::budgeted_value_cache`].
pub(crate) struct Flight<V> {
    state: Mutex<FlightState<V>>,
    wake: Condvar,
    #[cfg(any(test, feature = "test-support"))]
    waiters: std::sync::atomic::AtomicUsize,
}

enum FlightState<V> {
    /// `fenced`: the key or the whole cache was invalidated while this flight
    /// ran, so its value is for its own callers only and must not be retained.
    Running {
        fenced: bool,
    },
    Completed(V),
    Rejected,
    Abandoned,
}

/// What a follower observed when its flight left `Running`.
pub(crate) enum Follow<V> {
    Completed(V),
    Rejected,
    /// The leader stopped without publishing; take the leadership or join a
    /// newer flight.
    Retry,
    Cancelled,
}

impl<V> Flight<V> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(FlightState::Running { fenced: false }),
            wake: Condvar::new(),
            #[cfg(any(test, feature = "test-support"))]
            waiters: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FlightState<V>> {
        self.state
            .lock()
            .expect("single-flight state mutex poisoned")
    }

    /// Keep a still-running build from retaining its value. A flight that
    /// already finished is left alone: its value was published before the
    /// invalidation, which removes it from the cache.
    pub(crate) fn fence(&self) {
        if let FlightState::Running { fenced } = &mut *self.lock() {
            *fenced = true;
        }
    }

    pub(crate) fn reject(&self) {
        let mut state = self.lock();
        assert!(
            matches!(*state, FlightState::Running { .. }),
            "a flight publishes once, while it runs"
        );
        *state = FlightState::Rejected;
    }

    /// End the flight when its permit is dropped, and wake every follower.
    pub(crate) fn finish(&self) {
        let mut state = self.lock();
        if matches!(*state, FlightState::Running { .. }) {
            *state = FlightState::Abandoned;
        }
        drop(state);
        self.wake.notify_all();
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn waiters(&self) -> usize {
        self.waiters.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl<V: Clone> Flight<V> {
    /// Complete the flight with the value `publish` returns. `publish` runs
    /// under the state lock and receives whether the flight was fenced, so a
    /// concurrent [`Self::fence`] either happens first or after the value is
    /// stored.
    pub(crate) fn complete_with(&self, publish: impl FnOnce(bool) -> V) -> V {
        let mut state = self.lock();
        let FlightState::Running { fenced } = *state else {
            panic!("a flight publishes once, while it runs");
        };
        let value = publish(fenced);
        *state = FlightState::Completed(value.clone());
        value
    }

    pub(crate) fn wait(&self, cancellation: &CancellationToken) -> Follow<V> {
        let mut state = self.lock();
        #[cfg(any(test, feature = "test-support"))]
        self.waiters
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        while matches!(*state, FlightState::Running { .. }) && !cancellation.is_cancelled() {
            (state, _) = self
                .wake
                .wait_timeout(state, CANCELLATION_POLL)
                .expect("single-flight state mutex poisoned while waiting");
        }
        #[cfg(any(test, feature = "test-support"))]
        self.waiters
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if cancellation.is_cancelled() {
            return Follow::Cancelled;
        }
        match &*state {
            FlightState::Completed(value) => Follow::Completed(value.clone()),
            FlightState::Rejected => Follow::Rejected,
            FlightState::Abandoned => Follow::Retry,
            FlightState::Running { .. } => unreachable!("the wait loop exits only after Running"),
        }
    }
}

/// Leadership for one exact key. Dropping this without publication is the
/// generic failure/incomplete path: followers wake and retry.
pub struct CompleteValuePermit<K, V>
where
    K: Eq + Hash,
{
    key: K,
    flight: Arc<Flight<Arc<V>>>,
    entries: Cache<K, ReadyValue<V>>,
    retain: fn(Arc<V>) -> Arc<dyn Send + Sync>,
    in_flight: FlightMap<K, Arc<V>>,
    live: Arc<Mutex<HashMap<K, Weak<V>>>>,
}

impl<K, V> CompleteValuePermit<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    /// Retain and hand off one complete immutable value, then wake followers.
    pub fn publish_complete(self, value: Arc<V>) {
        let mut live = self
            .live
            .lock()
            .expect("complete-value live-instance map mutex poisoned");
        // Keep the live-map lock through both operations. `invalidate` and
        // `revive` use the same order, so an invalidated value cannot be
        // reinserted after its weak identity was removed.
        self.entries.insert(
            self.key.clone(),
            ReadyValue::new(Arc::clone(&value), self.retain),
        );
        live.insert(self.key.clone(), Arc::downgrade(&value));
        if live.len() > LIVE_REGISTRY_SWEEP_KEYS {
            live.retain(|_, weak| weak.strong_count() > 0);
        }
        self.flight.complete_with(|_| value);
    }

    /// Hand the current flight's deterministic rejection to its followers
    /// without retaining a value in the ready cache. The owner is responsible
    /// for keeping the exact-key reason available after this permit is dropped.
    pub fn publish_rejected(self) {
        self.flight.reject();
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
        self.flight.finish();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;
    use std::time::{Duration, Instant};

    use brokk_bifrost_test_macros::hardwon;

    use super::*;

    fn cache(capacity: u64, weight: u32) -> CompleteValueCache<String, usize> {
        CompleteValueCache::new(capacity, move |_, _| weight)
    }

    fn wait_for_waiter(cache: &CompleteValueCache<String, usize>) {
        crate::test_support::wait_for_nonzero_count(
            || cache.waiting_count_for_test(),
            "same-key request did not enter the single-flight wait",
        );
    }

    fn wait_for_physical_reclamation(
        cache: &CompleteValueCache<String, usize>,
        value: &Weak<usize>,
    ) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while value.upgrade().is_some() {
            cache.entries.run_pending_tasks();
            assert!(
                Instant::now() < deadline,
                "logically evicted value was not physically reclaimed"
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
    #[hardwon("#10202: a cache clone must revive a live value after ready eviction")]
    fn clone_revives_the_originals_live_value_after_eviction() {
        let cache = cache(1, 1);
        let clone = cache.clone();
        let key = "shared-live".to_string();
        let cancellation = CancellationToken::default();
        let (CompleteValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("a new key must lead")
        };
        let held = Arc::new(7);
        permit.publish_complete(Arc::clone(&held));

        cache.evict_for_test(&key);
        let (CompleteValueAcquisition::Cached { value: revived }, _) =
            clone.acquire(&key, &cancellation)
        else {
            panic!("the clone must revive the held value")
        };
        assert!(Arc::ptr_eq(&held, &revived));

        cache.evict_for_test(&key);
        let (CompleteValueAcquisition::Cached { value: original }, _) =
            cache.acquire(&key, &cancellation)
        else {
            panic!("the original must also revive the held value")
        };
        assert!(Arc::ptr_eq(&held, &original));
    }

    #[test]
    #[hardwon("#10202: pre-cancelled acquisition must stop before a cold or ready key")]
    fn pre_cancelled_acquisition_precedes_cold_and_ready_keys() {
        let cache = cache(1, 1);
        let key = "cancel-first".to_string();
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let live = CancellationToken::default();

        assert!(matches!(
            cache.acquire(&key, &cancelled).0,
            CompleteValueAcquisition::Cancelled
        ));
        let (CompleteValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &live) else {
            panic!("the live cold request must lead")
        };
        let held = Arc::new(11);
        permit.publish_complete(Arc::clone(&held));

        assert!(matches!(
            cache.acquire(&key, &cancelled).0,
            CompleteValueAcquisition::Cancelled
        ));
        let (CompleteValueAcquisition::Cached { value }, _) = cache.acquire(&key, &live) else {
            panic!("the live request must find the resident value")
        };
        assert!(Arc::ptr_eq(&held, &value));
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
    #[hardwon("#2307: an evicted artifact must keep one allocation identity while callers hold it")]
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
        assert_eq!(cache.revival_census_for_test().operations, 1);
    }

    #[test]
    #[hardwon("#3377: invalidation must remove the live identity so stale values cannot revive")]
    fn exact_invalidation_removes_live_identity_and_prevents_resurrection() {
        let cache = cache(1, 1);
        let cancellation = CancellationToken::default();
        let key = "invalid".to_string();

        let (CompleteValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("a new key must lead")
        };
        let invalid = Arc::new(29);
        permit.publish_complete(Arc::clone(&invalid));
        cache.invalidate(&key);

        let (acquisition, _) = cache.acquire(&key, &cancellation);
        assert!(matches!(
            acquisition,
            CompleteValueAcquisition::Leader { .. }
        ));
    }

    #[test]
    #[hardwon("#3377: publication must serialize live identity and ready-cache insertion")]
    fn publication_holds_the_live_identity_lock_through_ready_insertion() {
        let insertion_reached = Arc::new(Barrier::new(2));
        let insertion_release = Arc::new(Barrier::new(2));
        let weigher_reached = Arc::clone(&insertion_reached);
        let weigher_release = Arc::clone(&insertion_release);
        let cache = CompleteValueCache::new(1, move |_: &String, _: &Arc<usize>| {
            weigher_reached.wait();
            weigher_release.wait();
            1
        });
        let cancellation = CancellationToken::default();
        let key = "publication-order".to_string();
        let (CompleteValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("a new key must lead")
        };

        let publisher = thread::spawn(move || permit.publish_complete(Arc::new(30)));
        insertion_reached.wait();
        let publication_holds_live = cache.live.try_lock().is_err();
        insertion_release.wait();
        publisher.join().unwrap();
        assert!(
            publication_holds_live,
            "publication must acquire the live identity lock before inserting the ready entry"
        );
    }

    #[test]
    #[hardwon("#3377: a flight already running at invalidation may publish its completed value")]
    fn publication_after_invalidation_completes_the_existing_flight() {
        let cache = cache(1, 1);
        let cancellation = CancellationToken::default();
        let key = "in-flight".to_string();

        let (CompleteValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("a new key must lead")
        };

        cache.invalidate(&key);
        let follower_cache = cache.clone();
        let follower_key = key.clone();
        let follower_cancellation = cancellation.clone();
        let follower = thread::spawn(move || {
            follower_cache
                .acquire(&follower_key, &follower_cancellation)
                .0
        });
        wait_for_waiter(&cache);

        let published = Arc::new(31);
        permit.publish_complete(Arc::clone(&published));

        let CompleteValueAcquisition::Cached { value } = follower.join().unwrap() else {
            panic!("the existing flight must complete after an earlier invalidation")
        };
        assert!(Arc::ptr_eq(&published, &value));
        let ready = cache
            .get_ready(&key, &cancellation)
            .expect("the later publication must remain ready");
        assert!(Arc::ptr_eq(&published, &ready));
    }

    /// The registry holds weak references only: after the last holder drops the
    /// value and Moka physically reclaims its logically evicted entry, the key
    /// rebuilds exactly as it did before (#2456).
    #[test]
    #[hardwon(
        "#2456: a weak live identity must expire after physical eviction and the last holder drops"
    )]
    fn a_dropped_value_is_rebuilt_rather_than_revived() {
        let cache = cache(1, 1);
        let cancellation = CancellationToken::default();
        let key = "dropped".to_string();

        let (CompleteValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("a new key must lead")
        };
        let built = Arc::new(33);
        let dropped = Arc::downgrade(&built);
        permit.publish_complete(Arc::clone(&built));
        drop(built);
        cache.evict_for_test(&key);
        wait_for_physical_reclamation(&cache, &dropped);

        assert!(
            matches!(
                cache.acquire(&key, &cancellation).0,
                CompleteValueAcquisition::Leader { .. }
            ),
            "a value nobody holds must be rebuilt, not resurrected"
        );
        assert_eq!(cache.revival_census_for_test().operations, 0);
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
    fn invalidate_all_forces_a_ready_miss_and_reset_counts_the_next_revival() {
        let cache = cache(1, 1);
        let cancellation = CancellationToken::default();
        let key = "held".to_string();

        let (CompleteValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("a new key must lead")
        };
        let held = Arc::new(19);
        permit.publish_complete(Arc::clone(&held));

        cache.evict_for_test(&key);
        let (CompleteValueAcquisition::Cached { value }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("the first logical eviction must revive the held value")
        };
        assert!(Arc::ptr_eq(&held, &value));
        assert_eq!(cache.revival_census_for_test().operations, 1);

        cache.reset_revival_census_for_test();
        cache.invalidate_all_for_test();
        let (CompleteValueAcquisition::Cached { value }, _) = cache.acquire(&key, &cancellation)
        else {
            panic!("bulk invalidation must force a miss that revives the held value")
        };
        assert!(Arc::ptr_eq(&held, &value));
        assert_eq!(cache.revival_census_for_test().operations, 1);
    }

    #[test]
    fn revival_census_distinguishes_operations_from_key_allocation_identity() {
        let cache = cache(1, 1);
        let cancellation = CancellationToken::default();
        let first_key = "first".to_string();

        let (CompleteValueAcquisition::Leader { permit }, _) =
            cache.acquire(&first_key, &cancellation)
        else {
            panic!("a new key must lead")
        };
        let first = Arc::new(23);
        permit.publish_complete(Arc::clone(&first));

        for _ in 0..2 {
            cache.evict_for_test(&first_key);
            let (CompleteValueAcquisition::Cached { value }, _) =
                cache.acquire(&first_key, &cancellation)
            else {
                panic!("the held first value must be revived")
            };
            assert!(Arc::ptr_eq(&first, &value));
        }
        assert_eq!(
            cache.revival_census_for_test(),
            CompleteValueRevivalCensus {
                operations: 2,
                distinct_values: 1,
            }
        );

        let second_key = "second".to_string();
        let (CompleteValueAcquisition::Leader { permit }, _) =
            cache.acquire(&second_key, &cancellation)
        else {
            panic!("a second new key must lead")
        };
        let second = Arc::new(29);
        permit.publish_complete(Arc::clone(&second));
        cache.evict_for_test(&second_key);
        let (CompleteValueAcquisition::Cached { value }, _) =
            cache.acquire(&second_key, &cancellation)
        else {
            panic!("the held second value must be revived")
        };
        assert!(Arc::ptr_eq(&second, &value));
        assert_eq!(
            cache.revival_census_for_test(),
            CompleteValueRevivalCensus {
                operations: 3,
                distinct_values: 2,
            }
        );

        cache.reset_revival_census_for_test();
        assert_eq!(
            cache.revival_census_for_test(),
            CompleteValueRevivalCensus::default()
        );
    }
}
