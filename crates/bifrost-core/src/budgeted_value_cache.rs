//! Single-flight construction on a typed retention-budget region.
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::cancellation::CancellationToken;
use crate::complete_value_cache::{CompleteValueWait, Flight, FlightMap, Follow};
use crate::hash::HashMap;
use crate::retention_budget::{
    BudgetRegion, BudgetedValue, RefusalCause, RequestOwned, RetainedBytes,
};
use crate::util::elapsed_ns;

pub enum BudgetedValueAcquisition<K, V>
where
    K: Eq + Hash,
{
    Cached { value: BudgetedValue<V> },
    Leader { permit: BudgetedValuePermit<K, V> },
    Rejected,
    Cancelled,
}

pub struct BudgetedValueCache<K, V>
where
    K: Eq + Hash,
{
    region: BudgetRegion<K, V>,
    in_flight: FlightMap<K, BudgetedValue<V>>,
}
impl<K, V> std::fmt::Debug for BudgetedValueCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BudgetedValueCache")
            .field("region", &self.region.name())
            .field("namespace", &self.region.namespace())
            .field("stats", &self.region.stats())
            .field(
                "in_flight",
                &self
                    .in_flight
                    .lock()
                    .expect("budgeted flight map poisoned")
                    .len(),
            )
            .finish()
    }
}
impl<K, V> Clone for BudgetedValueCache<K, V>
where
    K: Eq + Hash,
{
    fn clone(&self) -> Self {
        Self {
            region: self.region.clone(),
            in_flight: self.in_flight.clone(),
        }
    }
}
impl<K, V> BudgetedValueCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    pub fn new(region: BudgetRegion<K, V>) -> Self {
        Self {
            region,
            in_flight: Arc::new(Mutex::new(HashMap::default())),
        }
    }
    pub fn region(&self) -> &BudgetRegion<K, V> {
        &self.region
    }
    pub fn get_ready(&self, key: &K, cancellation: &CancellationToken) -> Option<BudgetedValue<V>> {
        if cancellation.is_cancelled() {
            return None;
        }
        self.region
            .get(key)
            .or_else(|| self.region.revive(key))
            .map(BudgetedValue::Retained)
    }
    pub fn build_in_flight(&self, key: &K) -> bool {
        self.in_flight
            .lock()
            .expect("budgeted flight map poisoned")
            .contains_key(key)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn waiters_for_test(&self, key: &K) -> usize {
        self.in_flight
            .lock()
            .expect("budgeted flight map poisoned")
            .get(key)
            .map_or(0, |flight| flight.waiters())
    }
    /// Drop the key's value and fence a build of it that is still running,
    /// so that build cannot publish into the region and new requests start a
    /// fresh flight instead of joining it. Fencing comes first: a publication
    /// that wins the race is then removed by the region invalidation.
    ///
    /// The flight map stays locked until the region is cleared, so no flight
    /// can register in between: a flight registered earlier is fenced, and
    /// one registered later belongs to the state after the invalidation.
    /// Values are valid for their key, so a caller whose requests can outlive
    /// a snapshot keys by snapshot or uses a fresh cache per snapshot; this
    /// cache cannot tell which snapshot an acquiring request computes from.
    pub fn invalidate(&self, key: &K) {
        let mut flights = self.in_flight.lock().expect("budgeted flight map poisoned");
        if let Some(flight) = flights.remove(key) {
            flight.fence();
        }
        self.region.invalidate(key);
    }
    /// Drop every value of this cache instance and fence every running build,
    /// as a cache cleared on a new snapshot must. The same boundary as
    /// [`Self::invalidate`] applies.
    pub fn invalidate_all(&self) {
        let mut flights = self.in_flight.lock().expect("budgeted flight map poisoned");
        for (_, flight) in flights.drain() {
            flight.fence();
        }
        self.region.invalidate_all();
    }
    pub fn acquire(
        &self,
        key: &K,
        cancellation: &CancellationToken,
    ) -> (BudgetedValueAcquisition<K, V>, CompleteValueWait) {
        let mut wait = CompleteValueWait::default();
        loop {
            if cancellation.is_cancelled() {
                return (BudgetedValueAcquisition::Cancelled, wait);
            }
            if let Some(value) = self.get_ready(key, cancellation) {
                return (BudgetedValueAcquisition::Cached { value }, wait);
            }
            let (ready, flight, leader) = {
                let mut flights = self.in_flight.lock().expect("budgeted flight map poisoned");
                if let Some(value) = self.get_ready(key, cancellation) {
                    (Some(value), None, false)
                } else if let Some(flight) = flights.get(key) {
                    (None, Some(flight.clone()), false)
                } else {
                    let flight = Arc::new(Flight::new());
                    flights.insert(key.clone(), flight.clone());
                    (None, Some(flight), true)
                }
            };
            if let Some(value) = ready {
                return (BudgetedValueAcquisition::Cached { value }, wait);
            }
            let flight = flight.expect("non-ready acquisition has flight");
            if leader {
                return (
                    BudgetedValueAcquisition::Leader {
                        permit: BudgetedValuePermit {
                            key: key.clone(),
                            flight,
                            region: self.region.clone(),
                            in_flight: self.in_flight.clone(),
                        },
                    },
                    wait,
                );
            }
            let started = Instant::now();
            let followed = flight.wait(cancellation);
            wait.waits = wait.waits.saturating_add(1);
            wait.wait_ns = wait.wait_ns.saturating_add(elapsed_ns(started));
            match followed {
                Follow::Completed(value) => {
                    return (BudgetedValueAcquisition::Cached { value }, wait);
                }
                Follow::Rejected => return (BudgetedValueAcquisition::Rejected, wait),
                Follow::Cancelled => return (BudgetedValueAcquisition::Cancelled, wait),
                Follow::Retry => {}
            }
        }
    }
}

pub struct BudgetedValuePermit<K, V>
where
    K: Eq + Hash,
{
    key: K,
    flight: Arc<Flight<BudgetedValue<V>>>,
    region: BudgetRegion<K, V>,
    in_flight: FlightMap<K, BudgetedValue<V>>,
}
impl<K, V> BudgetedValuePermit<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    /// The key this permit's flight publishes under.
    pub fn key(&self) -> &K {
        &self.key
    }
    /// Publish a complete value. An admission refusal still completes this
    /// flight, but leaves no cross-request ready value.
    pub fn publish_complete(self, value: V) -> BudgetedValue<V> {
        // Published under the flight lock, so an invalidation either fences
        // this flight first or removes the inserted value after it.
        self.flight.complete_with(|fenced| {
            if fenced {
                BudgetedValue::request_only(value)
            } else {
                self.region.insert(self.key.clone(), value)
            }
        })
    }
    /// Publish a complete shared-allocation value that stays revivable after
    /// eviction while a holder keeps its allocation (`BudgetRegion::insert_shared`).
    pub fn publish_shared(self, value: V) -> BudgetedValue<V>
    where
        V: crate::retention_budget::SharedValue,
    {
        self.flight.complete_with(|fenced| {
            if fenced {
                BudgetedValue::request_only(value)
            } else {
                self.region.insert_shared(self.key.clone(), value)
            }
        })
    }
    /// Complete this flight for current callers without cross-request retention.
    pub fn publish_request_owned(self, value: V) -> BudgetedValue<V> {
        self.flight.complete_with(|_| BudgetedValue::RequestOwned {
            value: RequestOwned::new(value),
            cause: RefusalCause::RequestOnly,
        })
    }
    pub fn publish_rejected(self) {
        self.flight.reject();
    }
}
impl<K, V> Drop for BudgetedValuePermit<K, V>
where
    K: Eq + Hash,
{
    fn drop(&mut self) {
        let mut flights = self.in_flight.lock().expect("budgeted flight map poisoned");
        if flights
            .get(&self.key)
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            flights.remove(&self.key);
        }
        drop(flights);
        self.flight.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention_budget::{
        AllocationCharge, RetentionBudget, SelfCharged, SharedAllocation,
    };
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[derive(Clone, Eq, Hash, PartialEq)]
    struct Key(u64);

    impl RetainedBytes for Key {
        fn retained_bytes(&self) -> usize {
            std::mem::size_of::<Self>()
        }
    }

    struct Shared(AllocationCharge);

    impl SelfCharged for Shared {
        fn allocation_charge(&self) -> &AllocationCharge {
            &self.0
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#10202: cache-level shared publication and ready lookup lacked an eviction revival witness"
    )]
    #[test]
    fn published_shared_allocation_revives_for_ready_lookup_after_eviction() {
        let budget = RetentionBudget::new(10_000);
        let cache = BudgetedValueCache::new(
            budget.region::<Key, SharedAllocation<Shared>>("shared-cache-revival", None),
        );
        let key = Key(1);
        let token = CancellationToken::new();
        let held = Arc::new(Shared(AllocationCharge::acquire(&budget, 1_000)));
        let weak = Arc::downgrade(&held);
        let (BudgetedValueAcquisition::Leader { permit }, _) = cache.acquire(&key, &token) else {
            panic!("first request must lead");
        };
        let published = permit.publish_shared(SharedAllocation::new(Arc::clone(&held)));
        assert!(matches!(published, BudgetedValue::Retained(_)));
        assert!(Arc::ptr_eq(
            cache
                .get_ready(&key, &token)
                .expect("ready before eviction")
                .arc(),
            &held
        ));
        drop(published);

        cache.region().evict_all_for_test();
        // The original charged wrapper is the only other strong holder. Moka
        // can remove it logically before physically reclaiming it.
        let deadline = Instant::now() + Duration::from_secs(2);
        let original_reclaimed = loop {
            if Arc::strong_count(&held) == 1 {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            cache.region().run_pending_tasks();
            thread::yield_now();
        };
        if !original_reclaimed {
            cache.invalidate(&key);
            drop(held);
            panic!("original resident wrapper was not reclaimed");
        }
        let revived = cache
            .get_ready(&key, &token)
            .expect("held allocation revives");
        assert!(Arc::ptr_eq(revived.arc(), &held));
        drop(revived);

        cache.region().evict_all_for_test();
        drop(held);
        let deadline = Instant::now() + Duration::from_secs(2);
        let allocation_reclaimed = loop {
            if weak.strong_count() == 0 {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            cache.region().run_pending_tasks();
            thread::yield_now();
        };
        if !allocation_reclaimed {
            cache.invalidate(&key);
            panic!("last shared allocation was not reclaimed");
        }
        assert!(
            cache.get_ready(&key, &token).is_none(),
            "last holder dropped"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#10202: a registered budgeted-cache follower's cancellation was not covered"
    )]
    #[test]
    fn cancelled_follower_returns_while_leader_remains_live() {
        let budget = RetentionBudget::new(4_000);
        let cache = BudgetedValueCache::new(budget.region::<Key, Key>("cancelled-follower", None));
        let key = Key(1);
        let (BudgetedValueAcquisition::Leader { permit }, _) =
            cache.acquire(&key, &CancellationToken::new())
        else {
            panic!("first request must lead");
        };

        let cancellation = CancellationToken::new();
        let follower_token = cancellation.clone();
        let follower_cache = cache.clone();
        let follower_key = key.clone();
        let (sent, received) = mpsc::channel();
        let follower = thread::spawn(move || {
            let outcome = follower_cache.acquire(&follower_key, &follower_token).0;
            sent.send(matches!(outcome, BudgetedValueAcquisition::Cancelled))
                .expect("parent receives follower outcome");
        });
        let registration_deadline = Instant::now() + Duration::from_secs(2);
        let registered = loop {
            if cache.waiters_for_test(&key) != 0 {
                break true;
            }
            if follower.is_finished() || Instant::now() >= registration_deadline {
                break false;
            }
            thread::yield_now();
        };
        cancellation.cancel();
        let outcome = registered.then(|| received.recv_timeout(Duration::from_secs(2)));
        // Either watchdog must not strand the follower behind a live permit.
        drop(permit);
        follower.join().expect("follower thread");
        assert!(registered, "follower did not register before the watchdog");
        assert!(
            matches!(outcome, Some(Ok(true))),
            "cancelled follower did not return before leader completion: {outcome:?}"
        );

        let already_cancelled = CancellationToken::new();
        already_cancelled.cancel();
        assert!(matches!(
            cache.acquire(&key, &already_cancelled).0,
            BudgetedValueAcquisition::Cancelled
        ));
    }
}
