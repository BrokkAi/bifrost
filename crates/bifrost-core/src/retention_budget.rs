//! One process-wide byte budget for immutable cross-request values.
#[cfg(any(test, feature = "test-support"))]
use std::any::Any;
use std::any::TypeId;
use std::cell::RefCell;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use crate::hash::HashMap;
use moka::policy::EvictionPolicy;
use moka::sync::Cache;

/// Estimated inline and owned storage, excluding any separately leased backing.
pub trait RetainedBytes {
    fn retained_bytes(&self) -> usize;
    /// The bytes evicting this value frees when its entry is the value's last
    /// holder: the eviction weight. It differs from the charge only for a
    /// value whose bytes are charged elsewhere, such as a shared allocation
    /// that owns its own charge.
    fn eviction_bytes(&self) -> usize {
        self.retained_bytes()
    }
}
/// Allowance for cache bookkeeping and one allocation control block.
pub const ENTRY_OVERHEAD_BYTES: usize = 512;
impl RetainedBytes for [u8; 32] {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
    }
}
macro_rules! inline_retained_bytes {
    ($($ty:ty),* $(,)?) => {
        $(impl RetainedBytes for $ty {
            fn retained_bytes(&self) -> usize {
                std::mem::size_of::<Self>()
            }
        })*
    };
}
inline_retained_bytes!(
    bool, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);
inline_retained_bytes!(git2::Oid);
inline_retained_bytes!(std::time::SystemTime);
impl RetainedBytes for crate::gitblob::BlobKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.lang.capacity()
    }
}
impl RetainedBytes for String {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.capacity()
    }
}
impl RetainedBytes for Box<str> {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.len()
    }
}
// No impl for a general `Arc<T>`: a cache that stored one would hand out a
// clonable pointer to the value, and a clone that outlives the entry would
// keep the allocation alive after its charge is released. Store `T` and hand
// out `Retained<T>`. A shared string is immutable and small, so keys may use it.
impl RetainedBytes for Arc<str> {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>() + self.len()
    }
}
impl RetainedBytes for std::path::PathBuf {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.capacity()
    }
}
impl<T: RetainedBytes> RetainedBytes for Option<T> {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.as_ref().map_or(0, |value| {
                value
                    .retained_bytes()
                    .saturating_sub(std::mem::size_of::<T>())
            })
    }
}
impl<A: RetainedBytes, B: RetainedBytes> RetainedBytes for (A, B) {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .0
                .retained_bytes()
                .saturating_sub(std::mem::size_of::<A>())
            + self
                .1
                .retained_bytes()
                .saturating_sub(std::mem::size_of::<B>())
    }
}
impl<A: RetainedBytes, B: RetainedBytes, C: RetainedBytes> RetainedBytes for (A, B, C) {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .0
                .retained_bytes()
                .saturating_sub(std::mem::size_of::<A>())
            + self
                .1
                .retained_bytes()
                .saturating_sub(std::mem::size_of::<B>())
            + self
                .2
                .retained_bytes()
                .saturating_sub(std::mem::size_of::<C>())
    }
}
impl<T: RetainedBytes> RetainedBytes for Vec<T> {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
            + self.capacity() * std::mem::size_of::<T>()
            + self
                .iter()
                .map(|item| {
                    item.retained_bytes()
                        .saturating_sub(std::mem::size_of::<T>())
                })
                .sum::<usize>()
    }
}

type ErasedValue = Arc<dyn std::any::Any + Send + Sync>;
struct DeferredDrop {
    value: Option<ErasedValue>,
    callback: Option<Arc<dyn Fn() + Send + Sync>>,
    evicted: bool,
}
struct Ready {
    // All moka clones share this slot. The listener detaches its value so a
    // later epoch cleanup cannot become the value's final owner under admission.
    value: Option<Arc<Mutex<Option<DeferredDrop>>>>,
    weight: u32,
    evictions: Arc<AtomicU64>,
}
impl Clone for Ready {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            weight: self.weight,
            evictions: self.evictions.clone(),
        }
    }
}
struct BudgetInner {
    capacity: u64,
    // Charges hold this counter, not the budget: the budget's cache holds the
    // charged values, so a strong budget reference in a charge is a cycle.
    accounted: Arc<AtomicU64>,
    next_id: AtomicU64,
    admission: Mutex<()>,
    deferred: Arc<Mutex<Vec<DeferredDrop>>>,
    types: Mutex<HashMap<&'static str, (TypeId, TypeId)>>,
    entries: Cache<u64, Ready>,
}
// Moka can destroy values while processing any cache operation. Its listener
// transfers ownership here; callbacks and final value drops run without admission.
struct Admission<'a> {
    budget: &'a RetentionBudget,
    lock: RefCell<Option<MutexGuard<'a, ()>>>,
    actions: RefCell<Vec<Box<dyn FnOnce()>>>,
}
impl Admission<'_> {
    fn defer(&self, action: impl FnOnce() + 'static) {
        self.actions.borrow_mut().push(Box::new(action));
    }
    /// Run deferred work without admission; false when there was none, so
    /// admission was never released.
    fn drain(&self) -> bool {
        let deferred = std::mem::take(
            &mut *self
                .budget
                .0
                .deferred
                .lock()
                .expect("deferred drops poisoned"),
        );
        let actions = std::mem::take(&mut *self.actions.borrow_mut());
        if deferred.is_empty() && actions.is_empty() {
            return false;
        }
        drop(self.lock.borrow_mut().take());
        for action in actions {
            action();
        }
        for deferred in deferred {
            if deferred.evicted
                && let Some(callback) = &deferred.callback
            {
                callback();
            }
            drop(deferred.value);
        }
        *self.lock.borrow_mut() = Some(
            self.budget
                .0
                .admission
                .lock()
                .expect("budget admission poisoned"),
        );
        true
    }
    /// Apply pending cache writes and destroy evicted values until a pass
    /// finds nothing deferred. Residency and accounting then agree, including
    /// for entries admitted while a drain had released admission.
    fn settle(&self) {
        loop {
            self.budget.0.entries.run_pending_tasks();
            if !self.drain() {
                return;
            }
        }
    }
}
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.drain();
    }
}
/// Shared across all regions owned by one process.
#[derive(Clone)]
pub struct RetentionBudget(Arc<BudgetInner>);
impl RetentionBudget {
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests() -> Self {
        Self::new(crate::analyzer::config::AnalyzerConfig::default().retention_budget_bytes())
    }
    fn admission(&self) -> Admission<'_> {
        Admission {
            budget: self,
            actions: RefCell::new(Vec::new()),
            lock: RefCell::new(Some(
                self.0.admission.lock().expect("budget admission poisoned"),
            )),
        }
    }
    // Called before the candidate is staged. Draining may release admission;
    // always recheck accounting after destructors and concurrent admissions.
    fn reclaim_for(
        &self,
        admission: &Admission<'_>,
        additional: u64,
        evictions: Arc<AtomicU64>,
    ) -> bool {
        loop {
            admission.settle();
            let accounted = self.accounted_bytes();
            let resident = self.0.entries.weighted_size();
            let nonresident = accounted.saturating_sub(resident);
            let Some(required) = nonresident.checked_add(additional) else {
                return false;
            };
            if required > self.0.capacity {
                return false;
            }
            if accounted.saturating_add(additional) <= self.0.capacity {
                return true;
            }
            // One moka weight is a u32, so a budget above 4 GiB may need
            // several probes to reserve `required` bytes at once.
            let mut probes = Vec::new();
            let mut remaining = required;
            while remaining > 0 {
                let weight = remaining.min(u64::from(u32::MAX));
                let probe = self.0.next_id.fetch_add(1, Ordering::Relaxed);
                self.0.entries.insert(
                    probe,
                    Ready {
                        value: None,
                        weight: weight as u32,
                        evictions: evictions.clone(),
                    },
                );
                probes.push(probe);
                remaining -= weight;
            }
            self.0.entries.run_pending_tasks();
            for probe in &probes {
                self.0.entries.invalidate(probe);
            }
            self.0.entries.run_pending_tasks();
            // Judge progress by residency while admission is still held:
            // accounting can rise during the unlocked drain when another
            // admission refills the freed bytes.
            if self.0.entries.weighted_size() >= resident {
                admission.drain();
                return self.accounted_bytes().saturating_add(additional) <= self.0.capacity;
            }
        }
    }
    /// A budget that keeps nothing, for a workspace that has no owner to
    /// charge: every admission is refused, so each request computes and drops
    /// its own values.
    pub fn retain_nothing() -> Self {
        Self::new(0)
    }
    pub fn new(capacity: u64) -> Self {
        let deferred = Arc::new(Mutex::new(Vec::new()));
        Self(Arc::new(BudgetInner {
            capacity,
            accounted: Arc::new(AtomicU64::new(0)),
            next_id: AtomicU64::new(1),
            admission: Mutex::new(()),
            deferred: deferred.clone(),
            types: Mutex::new(HashMap::default()),
            entries: Cache::builder()
                .max_capacity(capacity.max(1))
                .eviction_policy(EvictionPolicy::lru())
                .weigher(|_, ready: &Ready| ready.weight)
                .eviction_listener(move |_, ready: Ready, cause| {
                    if let Some(mut value) = ready
                        .value
                        .as_ref()
                        .and_then(|slot| slot.lock().expect("resident value poisoned").take())
                    {
                        value.evicted = cause.was_evicted();
                        if value.evicted {
                            ready.evictions.fetch_add(1, Ordering::Relaxed);
                        }
                        deferred
                            .lock()
                            .expect("deferred drops poisoned")
                            .push(value);
                    }
                })
                .build(),
        }))
    }
    pub fn capacity_bytes(&self) -> u64 {
        self.0.capacity
    }
    pub fn accounted_bytes(&self) -> u64 {
        self.0.accounted.load(Ordering::Acquire)
    }
    pub fn region<K, V>(&self, name: &'static str, entry_cap: Option<usize>) -> BudgetRegion<K, V>
    where
        K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
        V: Send + Sync + RetainedBytes + 'static,
    {
        let mut types = self.0.types.lock().expect("budget type registry poisoned");
        if let Some(previous) = types.insert(name, (TypeId::of::<K>(), TypeId::of::<V>())) {
            assert_eq!(
                previous,
                (TypeId::of::<K>(), TypeId::of::<V>()),
                "region type changed"
            );
        }
        BudgetRegion {
            inner: Arc::new(RegionInner {
                budget: self.clone(),
                name,
                namespace: self.0.next_id.fetch_add(1, Ordering::Relaxed),
                entry_cap,
                cap_cache: entry_cap.map(|cap| {
                    let entries = self.0.entries.clone();
                    Cache::builder()
                        .max_capacity(cap as u64)
                        .eviction_policy(EvictionPolicy::lru())
                        .eviction_listener(move |id: Arc<u64>, _: (), cause| {
                            if cause.was_evicted() {
                                entries.invalidate(id.as_ref());
                            }
                        })
                        .build()
                }),
                live: Arc::new(Mutex::new(HashMap::default())),
                tracked: Arc::new(Mutex::new(HashMap::default())),
                evictions: Arc::new(AtomicU64::new(0)),
                refused: AtomicU64::new(0),
                revivals: AtomicU64::new(0),
                #[cfg(any(test, feature = "test-support"))]
                revival_tracker: Mutex::new(RevivalTracker {
                    census: RevivalCensus::default(),
                    seen: HashMap::default(),
                }),
            }),
        }
    }
    pub fn run_pending_tasks(&self) {
        self.admission().settle();
    }
    /// Charge one shared allocation once, regardless of the number of leases.
    pub fn shared_backing(&self, bytes: u64) -> Option<SharedBackingLease> {
        let guard = self.admission();
        self.shared_backing_locked(&guard, bytes)
    }
    /// Charge required state; see [`AllocationCharge::acquire_required`].
    fn required_backing(&self, bytes: u64) -> SharedBackingLease {
        let guard = self.admission();
        // Evict as much as eviction can free, up to `bytes`: reclaim_for gives
        // up at once on a request that cannot fit, so ask only for what can.
        // Its drains release admission, and a destructor or another admission
        // can charge non-resident bytes meanwhile, so ask again for the
        // smaller room until one is reclaimed or the room stops shrinking.
        // The charge does not depend on the outcome.
        let mut refused: Option<u64> = None;
        loop {
            // Values evicted but not yet destroyed stay charged without being
            // resident; destroy them first so they do not count as unevictable.
            guard.settle();
            let nonresident = self
                .accounted_bytes()
                .saturating_sub(self.0.entries.weighted_size());
            let room = bytes.min(self.0.capacity.saturating_sub(nonresident));
            if refused.is_some_and(|refused| room >= refused)
                || self.reclaim_for(&guard, room, Arc::new(AtomicU64::new(0)))
            {
                break;
            }
            refused = Some(room);
        }
        self.0.accounted.fetch_add(bytes, Ordering::AcqRel);
        SharedBackingLease(Arc::new(SharedBacking {
            accounted: self.0.accounted.clone(),
            bytes,
        }))
    }
    fn shared_backing_locked(
        &self,
        _admission: &Admission<'_>,
        bytes: u64,
    ) -> Option<SharedBackingLease> {
        self.0.entries.run_pending_tasks();
        if !self.reclaim_for(_admission, bytes, Arc::new(AtomicU64::new(0))) {
            return None;
        }
        self.0.accounted.fetch_add(bytes, Ordering::AcqRel);
        Some(SharedBackingLease(Arc::new(SharedBacking {
            accounted: self.0.accounted.clone(),
            bytes,
        })))
    }
}
struct SharedBacking {
    accounted: Arc<AtomicU64>,
    bytes: u64,
}
impl Drop for SharedBacking {
    fn drop(&mut self) {
        self.accounted.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
#[derive(Clone)]
pub struct SharedBackingLease(Arc<SharedBacking>);
impl SharedBackingLease {
    pub fn bytes(&self) -> u64 {
        self.0.bytes
    }
}
/// The charge of a value that is shared as an `Arc` beyond one cache's
/// callers, for example through identity handles, snapshots or other caches.
/// The value owns its charge, so every clone of the `Arc` keeps the bytes
/// charged and the last drop releases them. Acquire it once the value is
/// complete, before the value is wrapped in an `Arc`, and keep the `Arc` in a
/// region as a [`SharedAllocation`].
///
/// A cloned value is a new allocation, so a clone of the charge is uncharged.
/// The charge takes no part in equality or hashing.
pub struct AllocationCharge {
    lease: Option<SharedBackingLease>,
    /// Whether one region entry currently carries these bytes in its
    /// eviction weight. Only one does, so entries sharing the allocation do
    /// not weigh it more than once.
    weighed: AtomicBool,
    /// Run when the value that owns this charge drops: regions use them to
    /// forget a revivable registration once nothing can revive it.
    drop_hooks: Mutex<Vec<Box<dyn AllocationDropHook>>>,
}
/// A region registration that must be forgotten when its allocation drops.
trait AllocationDropHook: Send + Sync {
    /// Whether the registration is still the current one for its key; a
    /// replaced or invalidated registration needs no hook.
    fn is_current(&self) -> bool;
    fn forget(&self);
}
impl AllocationCharge {
    /// Charge `bytes`, or stay uncharged when the budget cannot make room. An
    /// uncharged value is request-only: no region or other cross-request cache
    /// may keep it.
    pub fn acquire(budget: &RetentionBudget, bytes: usize) -> Self {
        Self {
            lease: budget.shared_backing(bytes as u64),
            weighed: AtomicBool::new(false),
            drop_hooks: Mutex::new(Vec::new()),
        }
    }
    /// Charge `bytes` for state the owner cannot answer correctly without
    /// (an analyzer's active semantic models, say), which no cache may
    /// refuse. Evictable entries are reclaimed first; when the budget still
    /// lacks room it runs over capacity until this value drops, and other
    /// admissions are refused meanwhile.
    pub fn acquire_required(budget: &RetentionBudget, bytes: usize) -> Self {
        Self {
            lease: Some(budget.required_backing(bytes as u64)),
            weighed: AtomicBool::new(false),
            drop_hooks: Mutex::new(Vec::new()),
        }
    }
    pub fn is_charged(&self) -> bool {
        self.lease.is_some()
    }
    pub fn bytes(&self) -> u64 {
        self.lease.as_ref().map_or(0, SharedBackingLease::bytes)
    }
    fn claim_weight(&self) -> bool {
        self.is_charged()
            && self
                .weighed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }
    fn release_weight(&self) {
        self.weighed.store(false, Ordering::Release);
    }
}
impl Default for AllocationCharge {
    fn default() -> Self {
        Self {
            lease: None,
            weighed: AtomicBool::new(false),
            drop_hooks: Mutex::new(Vec::new()),
        }
    }
}
impl AllocationCharge {
    /// Register `hook`, pruning hooks whose registrations are gone, so the
    /// list stays bounded by this allocation's current registrations however
    /// often it is invalidated and kept again. Never call it while holding a
    /// region's live map: pruning takes that lock.
    fn on_drop(&self, hook: Box<dyn AllocationDropHook>) {
        let mut hooks = self
            .drop_hooks
            .lock()
            .expect("allocation drop hooks poisoned");
        hooks.retain(|hook| hook.is_current());
        hooks.push(hook);
    }
    fn prune_hooks(&self) {
        self.drop_hooks
            .lock()
            .expect("allocation drop hooks poisoned")
            .retain(|hook| hook.is_current());
    }
}
impl Drop for AllocationCharge {
    fn drop(&mut self) {
        let hooks = std::mem::take(
            self.drop_hooks
                .get_mut()
                .expect("allocation drop hooks poisoned"),
        );
        for hook in hooks {
            hook.forget();
        }
    }
}
impl Clone for AllocationCharge {
    fn clone(&self) -> Self {
        Self::default()
    }
}
impl PartialEq for AllocationCharge {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for AllocationCharge {}
impl Hash for AllocationCharge {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {}
}
impl std::fmt::Debug for AllocationCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.lease {
            Some(lease) => write!(f, "AllocationCharge({} bytes)", lease.bytes()),
            None => f.write_str("AllocationCharge(uncharged)"),
        }
    }
}
/// A value that owns the charge for its own allocation.
pub trait SelfCharged {
    fn allocation_charge(&self) -> &AllocationCharge;
}
/// A value that owns its retention charge, for a type that cannot hold an
/// [`AllocationCharge`] field itself (a foreign collection, or a core type
/// built in many places). Share it as `Arc<Accounted<T>>`; it derefs to `T`.
pub struct Accounted<T> {
    value: T,
    charge: AllocationCharge,
}
impl<T: RetainedBytes> Accounted<T> {
    /// Charge the value's estimated bytes to `budget`. The result is uncharged,
    /// and so request-only, when the budget cannot make room.
    pub fn charged(budget: &RetentionBudget, value: T) -> Self {
        let charge = AllocationCharge::acquire(budget, value.retained_bytes());
        Self { value, charge }
    }
}
impl<T> Accounted<T> {
    /// Charge a value using an existing cache weight when the value does not
    /// implement `RetainedBytes` itself.
    pub fn charged_with_bytes(budget: &RetentionBudget, value: T, bytes: usize) -> Self {
        Self {
            value,
            charge: AllocationCharge::acquire(budget, bytes),
        }
    }
    /// A value for one request, with no charge; no region keeps it.
    pub fn uncharged(value: T) -> Self {
        Self {
            value,
            charge: AllocationCharge::default(),
        }
    }
    pub fn into_inner(self) -> T {
        self.value
    }
}
impl<T> SelfCharged for Accounted<T> {
    fn allocation_charge(&self) -> &AllocationCharge {
        &self.charge
    }
}
impl<T> Deref for Accounted<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T: std::fmt::Debug> std::fmt::Debug for Accounted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}
impl<T: PartialEq> PartialEq for Accounted<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl<T: Eq> Eq for Accounted<T> {}

/// A region value for a shared allocation. Its own charge covers only the
/// pointer: the allocation's bytes are charged by the `AllocationCharge` it
/// owns, for as long as any clone of the `Arc` lives. An uncharged allocation
/// weighs more than any budget, so a region always refuses it and it stays
/// request-only, for example as the value a single flight hands its waiters.
pub struct SharedAllocation<T: SelfCharged> {
    value: Arc<T>,
    /// This entry carries the allocation's bytes in its eviction weight.
    weighs_allocation: bool,
}
impl<T: SelfCharged> SharedAllocation<T> {
    pub fn new(value: Arc<T>) -> Self {
        let weighs_allocation = value.allocation_charge().claim_weight();
        Self {
            value,
            weighs_allocation,
        }
    }
    pub fn arc(&self) -> &Arc<T> {
        &self.value
    }
}
/// A region value that wraps a self-charged shared allocation. A region that
/// keeps one with [`BudgetRegion::insert_shared`] can rebuild it from the
/// allocation after the entry was evicted, as long as any holder still keeps
/// the allocation alive, instead of making the caller build a second copy.
pub trait SharedValue: Sized + Send + Sync + 'static {
    type Shared: SelfCharged + Send + Sync + 'static;
    fn shared(&self) -> &Arc<Self::Shared>;
    fn rewrap(shared: Arc<Self::Shared>) -> Self;
}
impl<T: SelfCharged + Send + Sync + 'static> SharedValue for SharedAllocation<T> {
    type Shared = T;
    fn shared(&self) -> &Arc<T> {
        &self.value
    }
    fn rewrap(shared: Arc<T>) -> Self {
        Self::new(shared)
    }
}
impl<T: SelfCharged> Drop for SharedAllocation<T> {
    fn drop(&mut self) {
        if self.weighs_allocation {
            self.value.allocation_charge().release_weight();
        }
    }
}
impl<T: SelfCharged> Deref for SharedAllocation<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T: SelfCharged> RetainedBytes for SharedAllocation<T> {
    fn retained_bytes(&self) -> usize {
        if self.value.allocation_charge().is_charged() {
            std::mem::size_of::<Self>()
        } else {
            usize::MAX
        }
    }
    // Evicting the entry frees the allocation when the region holds its last
    // reference, so eviction weighs the allocation even though the entry's
    // own charge is only the pointer, and reclaim counts the bytes as
    // reclaimable instead of pinned. Only one entry weighs a given allocation,
    // so sharing it between entries does not count it twice; the others weigh
    // only their pointer, which errs toward refusing admission.
    fn eviction_bytes(&self) -> usize {
        let allocation = if self.weighs_allocation {
            usize::try_from(self.value.allocation_charge().bytes()).unwrap_or(usize::MAX)
        } else {
            0
        };
        self.retained_bytes().saturating_add(allocation)
    }
}
struct Live<V> {
    id: u64,
    value: Weak<Charged<V>>,
    /// For a value kept with insert_shared: how to re-admit it from its
    /// shared allocation after the entry was evicted.
    revive: Option<Revivable<V>>,
}
struct Revivable<V> {
    /// Rebuilds the region value from the shared allocation while a holder
    /// keeps it. Reclaim can release admission to destroy evictions; publication
    /// rechecks the captured live entry after reclaim to fence invalidation
    /// and replacement while the lock was released.
    rewrap: Rewrap<V>,
    /// Identifies this registration across revivals: a revival re-admits the
    /// value under the same registration, so the allocation keeps one drop
    /// hook and one registration charge however often it is revived.
    registration: u64,
    /// The shared allocation, to prune its drop hook once this registration
    /// is invalidated or replaced.
    allocation: Weak<dyn SelfCharged + Send + Sync>,
    /// The allocation's identity for the revival census.
    #[cfg(any(test, feature = "test-support"))]
    identity: Weak<dyn Any + Send + Sync>,
}
type Rewrap<V> = Arc<dyn Fn() -> Option<V> + Send + Sync>;
impl<V> Clone for Revivable<V> {
    fn clone(&self) -> Self {
        Self {
            rewrap: self.rewrap.clone(),
            registration: self.registration,
            allocation: self.allocation.clone(),
            #[cfg(any(test, feature = "test-support"))]
            identity: self.identity.clone(),
        }
    }
}
impl<V> Revivable<V> {
    /// Drop the allocation's hook for a registration that is no longer
    /// current, releasing its charge. Call it without holding the live map.
    fn prune(&self) {
        if let Some(allocation) = self.allocation.upgrade() {
            allocation.allocation_charge().prune_hooks();
        }
    }
}
/// Forgets one revivable registration when its shared allocation drops. It
/// owns the registration's charge (key bytes plus the entry overhead): the
/// registration outlives its entry's charge while the allocation is held,
/// so the budget bounds how many registrations can wait for revival.
struct RevivalRegistration<K, V> {
    live: Weak<Mutex<HashMap<Arc<K>, Live<V>>>>,
    /// The live map's own key allocation, shared rather than copied, so the
    /// registration charge covers the only copy.
    key: Arc<K>,
    registration: u64,
    _charge: SharedBackingLease,
}
impl<K, V> RevivalRegistration<K, V>
where
    K: Eq + Hash,
{
    fn current_in(&self, live: &HashMap<Arc<K>, Live<V>>) -> bool {
        live.get(&self.key).is_some_and(|entry| {
            entry
                .revive
                .as_ref()
                .is_some_and(|revive| revive.registration == self.registration)
        })
    }
}
impl<K, V> AllocationDropHook for RevivalRegistration<K, V>
where
    K: Eq + Hash + Send + Sync,
    V: Send + Sync,
{
    fn is_current(&self) -> bool {
        self.live
            .upgrade()
            .is_some_and(|live| self.current_in(&live.lock().expect("region live map poisoned")))
    }
    fn forget(&self) {
        if let Some(live) = self.live.upgrade() {
            let mut live = live.lock().expect("region live map poisoned");
            if self.current_in(&live) {
                live.remove(&self.key);
            }
        }
    }
}
/// Test-only account of successful revivals: `operations` counts every
/// revival, `distinct_values` counts exact `(key, allocation)` pairs, so
/// reviving the same allocation again changes only `operations`.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RevivalCensus {
    pub operations: u64,
    pub distinct_values: u64,
}
#[cfg(any(test, feature = "test-support"))]
struct RevivalTracker<K> {
    census: RevivalCensus,
    /// Weak identities keep a revived allocation's address from being reused
    /// by another allocation while the census remembers it.
    seen: HashMap<K, Vec<Weak<dyn Any + Send + Sync>>>,
}
struct RegionInner<K, V> {
    budget: RetentionBudget,
    name: &'static str,
    namespace: u64,
    entry_cap: Option<usize>,
    cap_cache: Option<Cache<u64, ()>>,
    // The live map and each entry's drop cleanup share one allocation of
    // the key, so the key's charge covers the only copy.
    live: Arc<Mutex<HashMap<Arc<K>, Live<V>>>>,
    tracked: Arc<Mutex<HashMap<u64, Weak<Charged<V>>>>>,
    evictions: Arc<AtomicU64>,
    refused: AtomicU64,
    revivals: AtomicU64,
    #[cfg(any(test, feature = "test-support"))]
    revival_tracker: Mutex<RevivalTracker<K>>,
}
impl<K, V> Drop for RegionInner<K, V> {
    /// A dropped region can revive nothing: release the drop hooks, and their
    /// registration charges, that held allocations still carry for it.
    fn drop(&mut self) {
        let entries = std::mem::take(&mut *self.live.lock().expect("region live map poisoned"));
        for entry in entries.into_values() {
            if let Some(revive) = entry.revive {
                revive.prune();
            }
        }
    }
}
/// A typed, cache-instance-scoped view of the process budget.
pub struct BudgetRegion<K, V> {
    inner: Arc<RegionInner<K, V>>,
}
impl<K, V> Clone for BudgetRegion<K, V> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
pub struct Charged<V> {
    value: V,
    charge: AtomicU64,
    external: AtomicU64,
    weight: u32,
    on_drop: Option<Box<dyn Fn() + Send + Sync>>,
    on_evict: Option<Arc<dyn Fn() + Send + Sync>>,
    _backing: Option<SharedBackingLease>,
    _release: ChargeRelease,
}
struct ChargeRelease {
    accounted: Arc<AtomicU64>,
    charge: u64,
}
impl Drop for ChargeRelease {
    fn drop(&mut self) {
        self.accounted.fetch_sub(self.charge, Ordering::AcqRel);
    }
}
impl<V> Drop for Charged<V> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.on_drop.take() {
            cleanup();
        }
    }
}
/// A charged allocation whose final drop releases its charge and its live
/// registration. Values embedded inside it must themselves be retained
/// handles, or be included in this allocation's byte charge.
pub struct Retained<V>(Arc<Charged<V>>);
impl<V> Clone for Retained<V> {
    fn clone(&self) -> Self {
        Self::from_arc(self.0.clone())
    }
}
impl<V> Drop for Retained<V> {
    fn drop(&mut self) {
        self.0.external.fetch_sub(1, Ordering::AcqRel);
    }
}
impl<V> Deref for Retained<V> {
    type Target = V;
    fn deref(&self) -> &V {
        &self.0.value
    }
}
impl<V> AsRef<V> for Retained<V> {
    fn as_ref(&self) -> &V {
        self
    }
}
impl<V> Retained<V> {
    fn from_arc(value: Arc<Charged<V>>) -> Self {
        value.external.fetch_add(1, Ordering::AcqRel);
        Self(value)
    }
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCause {
    RequestOnly,
    NoCapacity,
    EntryCap,
    Oversized,
    WeightOverflow,
}

/// A complete value for one request, with no cache or live registration.
pub struct RequestOwned<V>(Arc<V>);
impl<V> RequestOwned<V> {
    pub fn new(value: V) -> Self {
        Self(Arc::new(value))
    }
}
impl<V> Clone for RequestOwned<V> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<V> Deref for RequestOwned<V> {
    type Target = V;
    fn deref(&self) -> &V {
        &self.0
    }
}
impl<V> AsRef<V> for RequestOwned<V> {
    fn as_ref(&self) -> &V {
        self
    }
}

/// An explicit retained or request-only result of an admission attempt.
pub enum BudgetedValue<V> {
    Retained(Retained<V>),
    RequestOwned {
        value: RequestOwned<V>,
        cause: RefusalCause,
    },
}
impl<V> BudgetedValue<V> {
    /// A value computed for one request where no cache applies.
    pub fn request_only(value: V) -> Self {
        Self::RequestOwned {
            value: RequestOwned::new(value),
            cause: RefusalCause::RequestOnly,
        }
    }
}
impl<V> Clone for BudgetedValue<V> {
    fn clone(&self) -> Self {
        match self {
            Self::Retained(value) => Self::Retained(value.clone()),
            Self::RequestOwned { value, cause } => Self::RequestOwned {
                value: value.clone(),
                cause: *cause,
            },
        }
    }
}
impl<V> Deref for BudgetedValue<V> {
    type Target = V;
    fn deref(&self) -> &V {
        match self {
            Self::Retained(value) => value,
            Self::RequestOwned { value, .. } => value,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RegionStats {
    pub entries: usize,
    pub accounted_bytes: u64,
    pub deferred_bytes: u64,
    pub evictions: u64,
    pub refused_admissions: u64,
    /// Shared allocations re-admitted after their entry was evicted.
    pub revivals: u64,
}
impl<K, V> BudgetRegion<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    pub fn name(&self) -> &'static str {
        self.inner.name
    }
    pub fn namespace(&self) -> u64 {
        self.inner.namespace
    }
    pub fn get(&self, key: &K) -> Option<Retained<V>> {
        let (id, weak) = {
            let live = self.inner.live.lock().expect("region live map poisoned");
            let entry = live.get(key)?;
            (entry.id, entry.value.clone())
        };
        let value = weak.upgrade()?;
        if self.inner.budget.0.entries.get(&id).is_some() {
            if let Some(cap) = &self.inner.cap_cache {
                cap.get(&id);
            }
            Some(Retained::from_arc(value))
        } else {
            None
        }
    }
    pub fn revive(&self, key: &K) -> Option<Retained<V>> {
        let budget = &self.inner.budget;
        let guard = budget.admission();
        let (stored_key, id, weak, revivable) = {
            let live = self.inner.live.lock().expect("region live map poisoned");
            let (stored_key, entry) = live.get_key_value(key)?;
            (
                stored_key.clone(),
                entry.id,
                entry.value.clone(),
                entry.revive.clone(),
            )
        };
        let revived = match weak.upgrade() {
            Some(value) => {
                if budget.0.entries.get(&id).is_some() {
                    return Some(Retained::from_arc(value));
                }
                if let Some(cap) = &self.inner.cap_cache {
                    cap.insert(id, ());
                    cap.run_pending_tasks();
                }
                budget.0.entries.insert(
                    id,
                    Ready {
                        value: Some(Arc::new(Mutex::new(Some(DeferredDrop {
                            value: Some(value.clone()),
                            callback: value.on_evict.clone(),
                            evicted: false,
                        })))),
                        weight: value.weight,
                        evictions: self.inner.evictions.clone(),
                    },
                );
                budget.0.entries.run_pending_tasks();
                Retained::from_arc(value)
            }
            // The entry is gone but its shared allocation may still be held.
            None => {
                let revivable = revivable.clone()?;
                let value = (revivable.rewrap)()?;
                // Re-admit under the map's own key allocation, which the
                // registration's charge and drop hook already cover.
                match self.admit(&guard, stored_key, value, None, Some(revivable), None) {
                    Ok((retained, _)) => retained,
                    Err((value, _)) => {
                        guard.defer(move || drop(value));
                        return None;
                    }
                }
            }
        };
        self.inner.revivals.fetch_add(1, Ordering::Relaxed);
        #[cfg(any(test, feature = "test-support"))]
        {
            let identity: Weak<dyn Any + Send + Sync> = match &revivable {
                Some(revivable) => revivable.identity.clone(),
                None => {
                    let charged: Arc<dyn Any + Send + Sync> = revived.0.clone();
                    Arc::downgrade(&charged)
                }
            };
            let mut tracker = self
                .inner
                .revival_tracker
                .lock()
                .expect("region revival tracker poisoned");
            tracker.census.operations += 1;
            let seen = tracker.seen.entry(key.clone()).or_default();
            if !seen.iter().any(|known| Weak::ptr_eq(known, &identity)) {
                seen.push(identity);
                tracker.census.distinct_values += 1;
            }
        }
        drop(guard);
        Some(revived)
    }
    pub fn insert(&self, key: K, value: V) -> BudgetedValue<V> {
        self.insert_with_backing(key, value, None)
    }
    /// Keep a shared-allocation value so that it stays revivable: after its
    /// entry is evicted, `revive` rebuilds and re-admits it from the shared
    /// allocation for as long as any holder keeps that allocation alive. The
    /// registration is forgotten when the allocation drops.
    pub fn insert_shared(&self, key: K, value: V) -> BudgetedValue<V>
    where
        V: SharedValue,
    {
        let guard = self.inner.budget.admission();
        match self.admit_shared(&guard, key, value) {
            Ok(retained) => BudgetedValue::Retained(retained),
            Err((value, cause)) => Self::refused(value, cause),
        }
    }
    fn admit_shared(
        &self,
        admission: &Admission<'_>,
        key: K,
        value: V,
    ) -> Result<Retained<V>, (V, RefusalCause)>
    where
        V: SharedValue,
    {
        let registration_bytes =
            (key.retained_bytes() as u64).saturating_add(ENTRY_OVERHEAD_BYTES as u64);
        let Some(registration_charge) = self
            .inner
            .budget
            .shared_backing_locked(admission, registration_bytes)
        else {
            // No room for the registration: keep the value without revival.
            return self
                .admit(admission, Arc::new(key), value, None, None, None)
                .map(|(retained, _)| retained);
        };
        let held = value.shared().clone();
        let shared = Arc::downgrade(&held);
        let registration = self.inner.budget.0.next_id.fetch_add(1, Ordering::Relaxed);
        let allocation: Arc<dyn SelfCharged + Send + Sync> = held.clone();
        let revivable = Revivable {
            rewrap: Arc::new(move || shared.upgrade().map(V::rewrap)),
            registration,
            allocation: Arc::downgrade(&allocation),
            #[cfg(any(test, feature = "test-support"))]
            identity: {
                let erased: Arc<dyn Any + Send + Sync> = held.clone();
                Arc::downgrade(&erased)
            },
        };
        drop(allocation);
        let (retained, key) =
            self.admit(admission, Arc::new(key), value, None, Some(revivable), None)?;
        held.allocation_charge()
            .on_drop(Box::new(RevivalRegistration {
                live: Arc::downgrade(&self.inner.live),
                key,
                registration,
                _charge: registration_charge,
            }));
        Ok(retained)
    }
    /// Notify the owner when a resident entry is evicted by capacity pressure.
    pub fn insert_with_eviction_callback(
        &self,
        key: K,
        value: V,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> BudgetedValue<V> {
        let guard = self.inner.budget.admission();
        match self.admit(&guard, Arc::new(key), value, None, None, Some(callback)) {
            Ok((retained, _)) => BudgetedValue::Retained(retained),
            Err((value, cause)) => Self::refused(value, cause),
        }
    }
    pub fn insert_with_backing(
        &self,
        key: K,
        value: V,
        backing: Option<SharedBackingLease>,
    ) -> BudgetedValue<V> {
        let guard = self.inner.budget.admission();
        match self.admit(&guard, Arc::new(key), value, backing, None, None) {
            Ok((retained, _)) => BudgetedValue::Retained(retained),
            Err((value, cause)) => Self::refused(value, cause),
        }
    }
    /// Admit one entry under the admission lock the caller holds, returning
    /// it with its key allocation, or the value with the refusal cause.
    /// Evicted values and callbacks are deferred until admission is unlocked.
    /// Reclaim may unlock to destroy them, then rechecks all byte charges.
    /// The live map stores exactly `key`, replacing any equal key, so the charge
    /// computed from it covers the allocation the map keeps.
    fn admit(
        &self,
        _admission: &Admission<'_>,
        key: Arc<K>,
        value: V,
        backing: Option<SharedBackingLease>,
        revive: Option<Revivable<V>>,
        on_evict: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<(Retained<V>, Arc<K>), (V, RefusalCause)> {
        // A new shared insertion has a fresh registration. A revival carries
        // the live registration it observed before reclaim can unlock admission.
        let expected_entry = revive.as_ref().and_then(|revive| {
            let live = self.inner.live.lock().expect("region live map poisoned");
            live.get(&key)
                .filter(|entry| {
                    entry
                        .revive
                        .as_ref()
                        .is_some_and(|current| current.registration == revive.registration)
                })
                .map(|entry| entry.id)
        });
        let Some(charge) = (K::retained_bytes(&key) as u64)
            .checked_add(value.retained_bytes() as u64)
            .and_then(|sum| sum.checked_add(ENTRY_OVERHEAD_BYTES as u64))
        else {
            self.inner.refused.fetch_add(1, Ordering::Relaxed);
            return Err((value, RefusalCause::WeightOverflow));
        };
        let budget = &self.inner.budget;
        if charge > budget.0.capacity || charge > u32::MAX as u64 {
            self.inner.refused.fetch_add(1, Ordering::Relaxed);
            let cause = if charge > budget.0.capacity {
                RefusalCause::Oversized
            } else {
                RefusalCause::WeightOverflow
            };
            return Err((value, cause));
        }
        // Eviction order weighs what evicting the entry frees, which for a
        // self-charged shared allocation includes bytes charged outside it.
        let weight = (K::retained_bytes(&key) as u64)
            .saturating_add(value.eviction_bytes() as u64)
            .saturating_add(ENTRY_OVERHEAD_BYTES as u64)
            .min(u64::from(u32::MAX)) as u32;
        budget.0.entries.run_pending_tasks();
        if self.inner.entry_cap == Some(0) {
            self.inner.refused.fetch_add(1, Ordering::Relaxed);
            return Err((value, RefusalCause::EntryCap));
        }
        if !budget.reclaim_for(_admission, charge, self.inner.evictions.clone()) {
            self.inner.refused.fetch_add(1, Ordering::Relaxed);
            return Err((value, RefusalCause::NoCapacity));
        }
        if let Some(expected) = expected_entry {
            let current = self
                .inner
                .live
                .lock()
                .expect("region live map poisoned")
                .get(&key)
                .is_some_and(|entry| entry.id == expected);
            if !current {
                // Only a revival can reach this refusal. Its caller drops the
                // stale rewrapped value outside admission and returns no hit.
                return Err((value, RefusalCause::RequestOnly));
            }
        }
        let id = budget.0.next_id.fetch_add(1, Ordering::Relaxed);
        let weak_live = Arc::downgrade(&self.inner.live);
        let weak_tracked = Arc::downgrade(&self.inner.tracked);
        let drop_key = key.clone();
        let revivable = revive.is_some();
        let cleanup = move || {
            if let Some(live) = weak_live.upgrade() {
                let mut live = live.lock().expect("region live map poisoned");
                // A revivable registration outlives its entry while its shared
                // allocation does; the allocation's drop hook removes it.
                if live
                    .get(&drop_key)
                    .is_some_and(|entry| entry.id == id && !revivable)
                {
                    live.remove(&drop_key);
                }
            }
            if let Some(tracked) = weak_tracked.upgrade() {
                tracked
                    .lock()
                    .expect("region tracked map poisoned")
                    .remove(&id);
            }
        };
        let charged = Arc::new(Charged {
            value,
            charge: AtomicU64::new(0),
            external: AtomicU64::new(0),
            weight,
            on_drop: Some(Box::new(cleanup)),
            on_evict: on_evict.clone(),
            _backing: backing,
            _release: ChargeRelease {
                accounted: budget.0.accounted.clone(),
                charge,
            },
        });
        budget.0.entries.insert(
            id,
            Ready {
                value: Some(Arc::new(Mutex::new(Some(DeferredDrop {
                    value: Some(charged.clone()),
                    callback: on_evict,
                    evicted: false,
                })))),
                weight,
                evictions: self.inner.evictions.clone(),
            },
        );
        charged.charge.store(charge, Ordering::Release);
        budget.0.accounted.fetch_add(charge, Ordering::AcqRel);
        if let Some(cap) = &self.inner.cap_cache {
            for (old_id, _) in cap.iter() {
                if budget.0.entries.get(old_id.as_ref()).is_none() {
                    cap.invalidate(old_id.as_ref());
                }
            }
            cap.run_pending_tasks();
            cap.insert(id, ());
            cap.run_pending_tasks();
            budget.0.entries.run_pending_tasks();
        }
        self.inner
            .tracked
            .lock()
            .expect("region tracked map poisoned")
            .insert(id, Arc::downgrade(&charged));
        let replaced = {
            let mut live = self.inner.live.lock().expect("region live map poisoned");
            // HashMap::insert would keep the old key allocation of an equal
            // key; remove first so the map keeps the one this charge covers.
            let replaced = live.remove(&*key);
            live.insert(
                key.clone(),
                Live {
                    id,
                    value: Arc::downgrade(&charged),
                    revive,
                },
            );
            replaced
        };
        if let Some(replaced) = replaced {
            // The replaced entry can no longer be looked up, so it must not
            // stay resident and charged until eviction. Outside the live map
            // lock: dropping it runs its cleanup, which takes that lock.
            if let Some(cap) = &self.inner.cap_cache {
                cap.invalidate(&replaced.id);
            }
            budget.0.entries.invalidate(&replaced.id);
            if let Some(revive) = replaced.revive {
                _admission.defer(move || revive.prune());
            }
        }
        Ok((Retained::from_arc(charged), key))
    }
    fn refused(value: V, cause: RefusalCause) -> BudgetedValue<V> {
        BudgetedValue::RequestOwned {
            value: RequestOwned::new(value),
            cause,
        }
    }
    /// Evict every resident entry of this region, as memory pressure would,
    /// keeping live and revivable registrations: unlike invalidation, an
    /// eviction does not make a still-held value wrong.
    #[cfg(any(test, feature = "test-support"))]
    pub fn evict_all_for_test(&self) {
        let ids = self
            .inner
            .live
            .lock()
            .expect("region live map poisoned")
            .values()
            .map(|entry| entry.id)
            .collect::<Vec<_>>();
        for id in ids {
            self.inner.budget.0.entries.invalidate(&id);
        }
        self.run_pending_tasks();
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn revival_census_for_test(&self) -> RevivalCensus {
        self.inner
            .revival_tracker
            .lock()
            .expect("region revival tracker poisoned")
            .census
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn reset_revival_census_for_test(&self) {
        let mut tracker = self
            .inner
            .revival_tracker
            .lock()
            .expect("region revival tracker poisoned");
        tracker.census = RevivalCensus::default();
        tracker.seen.clear();
    }
    #[cfg(test)]
    pub fn evict_ready_for_test(&self, key: &K) {
        let id = self
            .inner
            .live
            .lock()
            .expect("region live map poisoned")
            .get(key)
            .map(|entry| entry.id);
        if let Some(id) = id {
            self.inner.budget.0.entries.invalidate(&id);
            self.run_pending_tasks();
        }
    }
    /// Remove every entry of this region instance, as a cache that is cleared
    /// on a new snapshot does. Values a caller still holds stay charged until
    /// they drop.
    pub fn invalidate_all(&self) {
        let _guard = self.inner.budget.admission();
        let entries =
            std::mem::take(&mut *self.inner.live.lock().expect("region live map poisoned"));
        for entry in entries.into_values() {
            if let Some(cap) = &self.inner.cap_cache {
                cap.invalidate(&entry.id);
            }
            self.inner.budget.0.entries.invalidate(&entry.id);
            if let Some(revive) = entry.revive {
                _guard.defer(move || revive.prune());
            }
        }
    }
    pub fn invalidate(&self, key: &K) {
        let _guard = self.inner.budget.admission();
        let entry = self
            .inner
            .live
            .lock()
            .expect("region live map poisoned")
            .remove(key);
        if let Some(entry) = entry {
            if let Some(cap) = &self.inner.cap_cache {
                cap.invalidate(&entry.id);
            }
            self.inner.budget.0.entries.invalidate(&entry.id);
            if let Some(revive) = entry.revive {
                _guard.defer(move || revive.prune());
            }
        }
    }
    pub fn run_pending_tasks(&self) {
        self.inner.budget.run_pending_tasks();
        if let Some(cap) = &self.inner.cap_cache {
            cap.run_pending_tasks();
            self.inner.budget.run_pending_tasks();
        }
    }
    pub fn stats(&self) -> RegionStats {
        self.run_pending_tasks();
        let values = self
            .inner
            .tracked
            .lock()
            .expect("region tracked map poisoned")
            .iter()
            .filter_map(|(id, weak)| weak.upgrade().map(|value| (*id, value)))
            .collect::<Vec<_>>();
        let mut stats = RegionStats::default();
        for (id, value) in values {
            let charge = value.charge.load(Ordering::Acquire);
            stats.accounted_bytes += charge;
            if self.inner.budget.0.entries.get(&id).is_some() {
                stats.entries += 1;
            } else if value.external.load(Ordering::Acquire) != 0 {
                stats.deferred_bytes += charge;
            }
        }
        stats.evictions = self.inner.evictions.load(Ordering::Relaxed);
        stats.refused_admissions = self.inner.refused.load(Ordering::Relaxed);
        stats.revivals = self.inner.revivals.load(Ordering::Relaxed);
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CancellationToken;
    use crate::budgeted_value_cache::{BudgetedValueAcquisition, BudgetedValueCache};
    use std::sync::Barrier;
    use std::thread;

    #[brokk_bifrost_test_macros::hardwon(
        "#9559: admission evicted a value whose drop re-entered the same budget and deadlocked"
    )]
    #[test]
    fn eviction_destructor_can_invalidate_the_same_budget() {
        struct Reentrant(BudgetRegion<Key, Value>);
        impl RetainedBytes for Reentrant {
            fn retained_bytes(&self) -> usize {
                600
            }
        }
        impl Drop for Reentrant {
            fn drop(&mut self) {
                self.0.invalidate(&Key(1));
            }
        }
        let (send, recv) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let budget = RetentionBudget::new(2000);
            let target = budget.region::<Key, Value>("reentrant-target", None);
            let victims = budget.region::<Key, Reentrant>("reentrant-victim", None);
            let candidates = budget.region::<Key, Value>("reentrant-candidate", None);
            drop(victims.insert(Key(1), Reentrant(target.clone())));
            budget.run_pending_tasks();
            let old_id = victims.inner.live.lock().unwrap().get(&Key(1)).unwrap().id;
            let stale_moka_clone = budget.0.entries.get(&old_id).unwrap();
            drop(target.insert(Key(1), Value(100)));
            budget.run_pending_tasks();
            let admitted = candidates.insert(Key(1), Value(700));
            budget.run_pending_tasks();
            assert!(matches!(admitted, BudgetedValue::Retained(_)));
            assert!(target.get(&Key(1)).is_none());
            {
                let _guard = budget.admission();
                drop(stale_moka_clone);
            }
            drop(admitted);
            candidates.invalidate_all();
            budget.run_pending_tasks();
            assert_eq!(budget.accounted_bytes(), 0);
            send.send(()).unwrap();
        });
        recv.recv_timeout(std::time::Duration::from_secs(10))
            .expect("admission must finish after reentrant eviction");
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#9559: reclaim unlocked admission and a revival resurrected an invalidated registration"
    )]
    #[test]
    fn revival_rechecks_invalidation_and_replacement_during_deferred_drop() {
        let (send, recv) = std::sync::mpsc::channel();
        thread::spawn(move || {
            struct Shared(AllocationCharge);
            impl SelfCharged for Shared {
                fn allocation_charge(&self) -> &AllocationCharge {
                    &self.0
                }
            }
            struct OnDrop(Option<Box<dyn FnOnce() + Send + Sync>>);
            impl RetainedBytes for OnDrop {
                fn retained_bytes(&self) -> usize {
                    64
                }
            }
            impl Drop for OnDrop {
                fn drop(&mut self) {
                    self.0.take().unwrap()();
                }
            }
            for replacement in [None, Some(())] {
                let budget = RetentionBudget::new(100_000);
                let region = budget.region::<Key, SharedAllocation<Shared>>("revival-fence", None);
                let held = Arc::new(Shared(AllocationCharge::acquire(&budget, 1000)));
                drop(region.insert_shared(Key(1), SharedAllocation::new(held.clone())));
                region.evict_all_for_test();
                let newer = replacement
                    .map(|()| Arc::new(Shared(AllocationCharge::acquire(&budget, 1000))));
                let victim = budget.region::<Key, OnDrop>("revival-drop", None);
                let target = region.clone();
                let replacement_value = newer.clone();
                drop(victim.insert(
                    Key(1),
                    OnDrop(Some(Box::new(move || {
                        target.invalidate_all();
                        if let Some(value) = replacement_value {
                            drop(target.insert_shared(Key(1), SharedAllocation::new(value)));
                        }
                    }))),
                ));
                budget.run_pending_tasks();
                let victim_id = victim.inner.live.lock().unwrap().get(&Key(1)).unwrap().id;
                budget.0.entries.invalidate(&victim_id);
                // Queue the destructor without draining it, so reclaim must
                // release admission after revive has captured the registration.
                budget.0.entries.run_pending_tasks();
                assert!(
                    region
                        .inner
                        .live
                        .lock()
                        .unwrap()
                        .get(&Key(1))
                        .unwrap()
                        .value
                        .upgrade()
                        .is_none()
                );
                assert!(region.revive(&Key(1)).is_none());
                match newer {
                    Some(newer) => assert!(Arc::ptr_eq(region.get(&Key(1)).unwrap().arc(), &newer)),
                    None => assert!(region.get(&Key(1)).is_none()),
                }
            }
            send.send(()).unwrap();
        });
        recv.recv_timeout(std::time::Duration::from_secs(10))
            .expect("revival must finish without resurrecting stale state");
    }

    #[derive(Clone, Eq, PartialEq, Hash)]
    struct Key(u64);
    impl RetainedBytes for Key {
        fn retained_bytes(&self) -> usize {
            8
        }
    }
    struct Value(usize);
    impl RetainedBytes for Value {
        fn retained_bytes(&self) -> usize {
            self.0
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#9737: a charge's strong budget reference made the budget own itself, so dropping it leaked every resident value"
    )]
    #[test]
    fn dropping_the_budget_drops_its_resident_values() {
        struct Tracked(Arc<AtomicU64>);
        impl RetainedBytes for Tracked {
            fn retained_bytes(&self) -> usize {
                64
            }
        }
        impl Drop for Tracked {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicU64::new(0));
        let budget = RetentionBudget::new(1_600);
        let region = budget.region::<Key, Tracked>("resident", None);
        let backing = budget.shared_backing(100).expect("backing fits");
        drop(region.insert_with_backing(Key(1), Tracked(dropped.clone()), Some(backing)));
        budget.run_pending_tasks();
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            0,
            "the entry stays resident"
        );
        drop(region);
        drop(budget);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn shared_allocation_stays_charged_until_its_last_clone_drops() {
        struct Shared(AllocationCharge);
        impl SelfCharged for Shared {
            fn allocation_charge(&self) -> &AllocationCharge {
                &self.0
            }
        }
        let budget = RetentionBudget::new(1_600);
        let region = budget.region::<Key, SharedAllocation<Shared>>("shared-allocation", None);
        let held = Arc::new(Shared(AllocationCharge::acquire(&budget, 300)));
        drop(region.insert(Key(1), SharedAllocation::new(held.clone())));
        budget.run_pending_tasks();
        let resident = budget.accounted_bytes();
        assert!(resident >= 300, "{resident}");
        region.evict_ready_for_test(&Key(1));
        budget.run_pending_tasks();
        assert_eq!(
            budget.accounted_bytes(),
            300,
            "the entry's own charge is released; the allocation stays charged"
        );
        drop(held);
        assert_eq!(budget.accounted_bytes(), 0);
        let accounted = Arc::new(Accounted::charged(&budget, Value(200)));
        assert!(accounted.allocation_charge().is_charged());
        assert_eq!(accounted.0, 200);
        drop(accounted);
        let refused = AllocationCharge::acquire(&budget, 1_601);
        assert!(!refused.is_charged());
        let uncharged = Arc::new(Shared(refused));
        assert!(matches!(
            region.insert(Key(2), SharedAllocation::new(uncharged)),
            BudgetedValue::RequestOwned {
                cause: RefusalCause::WeightOverflow,
                ..
            }
        ));
        assert!(!AllocationCharge::acquire(&budget, 10).clone().is_charged());
    }

    #[test]
    fn invalidate_all_clears_one_instance_and_keeps_held_values_charged() {
        let budget = RetentionBudget::new(10_000);
        let cleared = budget.region::<Key, Value>("snapshot-scoped", None);
        let other = budget.region::<Key, Value>("snapshot-scoped", None);
        let held = cleared.insert(Key(1), Value(100));
        drop(cleared.insert(Key(2), Value(100)));
        drop(other.insert(Key(1), Value(100)));
        cleared.invalidate_all();
        budget.run_pending_tasks();
        assert!(cleared.get(&Key(1)).is_none() && cleared.get(&Key(2)).is_none());
        assert!(
            other.get(&Key(1)).is_some(),
            "another instance keeps its entries"
        );
        let stats = cleared.stats();
        assert_eq!(stats.entries, 0);
        assert!(
            stats.deferred_bytes >= 100,
            "the held value stays charged: {stats:?}"
        );
        drop(held);
        assert_eq!(cleared.stats().accounted_bytes, 0);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#9737: a resident shared allocation counted as pinned, so admission refused instead of evicting it"
    )]
    #[test]
    fn evicting_a_shared_allocation_entry_makes_room() {
        struct Shared(AllocationCharge);
        impl SelfCharged for Shared {
            fn allocation_charge(&self) -> &AllocationCharge {
                &self.0
            }
        }
        let budget = RetentionBudget::new(1_600);
        let region = budget.region::<Key, SharedAllocation<Shared>>("evictable-shared", None);
        let resident = Arc::new(Shared(AllocationCharge::acquire(&budget, 1_000)));
        assert!(resident.allocation_charge().is_charged());
        drop(region.insert(Key(1), SharedAllocation::new(resident)));
        budget.run_pending_tasks();
        let next = AllocationCharge::acquire(&budget, 700);
        assert!(
            next.is_charged(),
            "evicting the sole holder frees the shared allocation"
        );
        assert!(region.get(&Key(1)).is_none());
        assert!(budget.accounted_bytes() <= 1_600);
    }

    #[test]
    fn a_shared_allocation_in_two_entries_weighs_once() {
        struct Shared(AllocationCharge);
        impl SelfCharged for Shared {
            fn allocation_charge(&self) -> &AllocationCharge {
                &self.0
            }
        }
        let budget = RetentionBudget::new(2_500);
        let left = budget.region::<Key, SharedAllocation<Shared>>("shared-left", None);
        let right = budget.region::<Key, SharedAllocation<Shared>>("shared-right", None);
        let shared = Arc::new(Shared(AllocationCharge::acquire(&budget, 1_000)));
        drop(left.insert(Key(1), SharedAllocation::new(shared.clone())));
        drop(right.insert(Key(1), SharedAllocation::new(shared.clone())));
        drop(shared);
        budget.run_pending_tasks();
        assert!(
            left.get(&Key(1)).is_some() && right.get(&Key(1)).is_some(),
            "the allocation's bytes count once, so both entries fit"
        );
    }

    #[test]
    fn a_required_charge_evicts_cached_entries_and_may_run_over_capacity() {
        let budget = RetentionBudget::new(2_000);
        let region = budget.region::<Key, Value>("evictable", None);
        drop(region.insert(Key(1), Value(500)));
        budget.run_pending_tasks();
        let required = AllocationCharge::acquire_required(&budget, 3_000);
        budget.run_pending_tasks();
        assert!(required.is_charged());
        assert_eq!(region.stats().entries, 0, "cached entries made room");
        assert_eq!(budget.accounted_bytes(), 3_000);
        assert!(matches!(
            region.insert(Key(2), Value(10)),
            BudgetedValue::RequestOwned { .. }
        ));
        drop(required);
        assert_eq!(budget.accounted_bytes(), 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11083: a required charge sized its eviction before destroying queued drops, so it ran over capacity with entries still resident"
    )]
    fn a_required_charge_sizes_eviction_after_queued_drops() {
        let budget = RetentionBudget::new(2_000);
        let region = budget.region::<Key, Value>("queued-drop", None);
        drop(region.insert(Key(1), Value(400)));
        drop(region.insert(Key(2), Value(400)));
        budget.run_pending_tasks();
        assert_eq!(region.stats().entries, 2);
        // Leave Key(1)'s value charged in the deferred queue, as an eviction
        // during another cache operation does.
        let queued = region.inner.live.lock().unwrap().get(&Key(1)).unwrap().id;
        budget.0.entries.invalidate(&queued);
        assert_eq!(budget.0.deferred.lock().unwrap().len(), 1);
        let required = AllocationCharge::acquire_required(&budget, 2_000);
        budget.run_pending_tasks();
        assert!(required.is_charged());
        assert!(
            region.get(&Key(2)).is_none(),
            "the queued drop freed only part of the room; Key(2) must be evicted"
        );
        assert_eq!(budget.accounted_bytes(), 2_000);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11083: a destructor's non-resident charge made the required charge's first room impossible, so it stopped evicting"
    )]
    fn a_required_charge_shrinks_its_room_after_a_reentrant_charge() {
        struct Charging {
            budget: RetentionBudget,
            values: BudgetRegion<Key, Value>,
            kept: Arc<Mutex<Vec<AllocationCharge>>>,
        }
        impl RetainedBytes for Charging {
            fn retained_bytes(&self) -> usize {
                400
            }
        }
        impl Drop for Charging {
            fn drop(&mut self) {
                drop(self.values.insert(Key(9), Value(400)));
                let charge = AllocationCharge::acquire(&self.budget, 1_000);
                self.kept.lock().unwrap().push(charge);
            }
        }
        let budget = RetentionBudget::new(3_000);
        let values = budget.region::<Key, Value>("reentrant-charge-values", None);
        let charging = budget.region::<Key, Charging>("reentrant-charge-victim", None);
        let kept = Arc::new(Mutex::new(Vec::new()));
        drop(charging.insert(
            Key(1),
            Charging {
                budget: budget.clone(),
                values: values.clone(),
                kept: kept.clone(),
            },
        ));
        budget.run_pending_tasks();
        // Reclaiming the first room evicts the charging entry; its destructor
        // admits Key(9) and charges 1,000 non-resident bytes.
        let required = AllocationCharge::acquire_required(&budget, 3_000);
        budget.run_pending_tasks();
        assert!(kept.lock().unwrap()[0].is_charged());
        assert!(
            values.get(&Key(9)).is_none(),
            "Key(9) was evictable within the smaller room"
        );
        assert_eq!(budget.accounted_bytes(), 1_000 + 3_000);
        drop(required);
        drop(kept);
        assert_eq!(budget.accounted_bytes(), 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11083: an admission during the unlocked drain refilled the freed bytes, so reclaim gave up with evictable entries resident"
    )]
    fn reclaim_continues_after_an_admission_refills_the_drained_room() {
        struct Refilling(BudgetRegion<Key, Value>);
        impl RetainedBytes for Refilling {
            fn retained_bytes(&self) -> usize {
                400
            }
        }
        impl Drop for Refilling {
            fn drop(&mut self) {
                drop(self.0.insert(Key(9), Value(400)));
            }
        }
        let budget = RetentionBudget::new(3_000);
        let values = budget.region::<Key, Value>("refill-values", None);
        let refilling = budget.region::<Key, Refilling>("refill-victim", None);
        drop(refilling.insert(Key(1), Refilling(values.clone())));
        budget.run_pending_tasks();
        drop(values.insert(Key(2), Value(400)));
        budget.run_pending_tasks();
        let before = budget.accounted_bytes();
        // The first round evicts only the refilling entry; its destructor
        // admits an entry of the same size while admission is unlocked.
        let charge = AllocationCharge::acquire(&budget, 2_000);
        budget.run_pending_tasks();
        assert!(charge.is_charged(), "Key(2) was still evictable");
        assert!(values.get(&Key(2)).is_none());
        assert!(values.get(&Key(9)).is_some());
        assert_eq!(budget.accounted_bytes(), before / 2 + 2_000);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9737: inserting an existing key left the replaced entry resident and charged"
    )]
    fn reinserting_a_key_releases_the_replaced_entry() {
        let budget = RetentionBudget::new(100_000);
        let region = budget.region::<Key, Value>("reinsert", None);
        drop(region.insert(Key(1), Value(100)));
        budget.run_pending_tasks();
        let one = budget.accounted_bytes();
        for _ in 0..5 {
            drop(region.insert(Key(1), Value(100)));
        }
        budget.run_pending_tasks();
        assert_eq!(region.stats().entries, 1);
        assert_eq!(budget.accounted_bytes(), one);
    }

    #[test]
    fn a_held_shared_allocation_revives_after_eviction_and_is_forgotten_after_drop() {
        struct Shared(AllocationCharge);
        impl SelfCharged for Shared {
            fn allocation_charge(&self) -> &AllocationCharge {
                &self.0
            }
        }
        let budget = RetentionBudget::new(10_000);
        let region = budget.region::<Key, SharedAllocation<Shared>>("revivable", None);
        let held = Arc::new(Shared(AllocationCharge::acquire(&budget, 1_000)));
        drop(region.insert_shared(Key(1), SharedAllocation::new(held.clone())));
        region.evict_all_for_test();
        assert!(region.get(&Key(1)).is_none(), "evicted");
        assert_eq!(
            budget.accounted_bytes(),
            1_000 + (Key(1).retained_bytes() + ENTRY_OVERHEAD_BYTES) as u64,
            "an evicted registration keeps its own charge while it waits"
        );
        let revived = region.revive(&Key(1)).expect("a held allocation revives");
        assert!(
            Arc::ptr_eq(revived.arc(), &held),
            "the same allocation, not a copy"
        );
        assert_eq!(region.stats().revivals, 1);
        drop(revived);
        region.evict_all_for_test();
        drop(held);
        assert!(
            region.revive(&Key(1)).is_none(),
            "a dropped allocation cannot revive"
        );
        assert!(
            region.inner.live.lock().unwrap().is_empty(),
            "registration forgotten"
        );
        // Invalidation, unlike eviction, forgets the value even while it is
        // held, and keeping it again does not accumulate drop hooks.
        let held = Arc::new(Shared(AllocationCharge::acquire(&budget, 1_000)));
        for _ in 0..3 {
            drop(region.insert_shared(Key(2), SharedAllocation::new(held.clone())));
            region.invalidate(&Key(2));
            assert!(region.revive(&Key(2)).is_none());
        }
        drop(region.insert_shared(Key(2), SharedAllocation::new(held.clone())));
        assert_eq!(held.0.drop_hooks.lock().unwrap().len(), 1);
        region.invalidate(&Key(2));
        assert!(
            held.0.drop_hooks.lock().unwrap().is_empty(),
            "invalidation releases the registration and its charge"
        );
        budget.run_pending_tasks();
        assert_eq!(budget.accounted_bytes(), 1_000);
        // Revivals keep one registration, so they need no second charge.
        drop(region.insert_shared(Key(2), SharedAllocation::new(held.clone())));
        for _ in 0..3 {
            region.evict_all_for_test();
            drop(region.revive(&Key(2)).expect("revives"));
        }
        assert_eq!(held.0.drop_hooks.lock().unwrap().len(), 1);
        region.invalidate(&Key(2));
        drop(held);
        // Dropping the region releases what held allocations keep for it.
        let held = Arc::new(Shared(AllocationCharge::acquire(&budget, 1_000)));
        {
            let dropped = budget.region::<Key, SharedAllocation<Shared>>("dropped", None);
            drop(dropped.insert_shared(Key(4), SharedAllocation::new(held.clone())));
            dropped.evict_all_for_test();
        }
        assert!(held.0.drop_hooks.lock().unwrap().is_empty());
        budget.run_pending_tasks();
        assert_eq!(budget.accounted_bytes(), 1_000);
        drop(held);
        // A caller-held wrapper revives through the live map and counts too.
        let wrapper = region.insert_shared(
            Key(3),
            SharedAllocation::new(Arc::new(Shared(AllocationCharge::acquire(&budget, 1_000)))),
        );
        region.evict_all_for_test();
        assert!(region.revive(&Key(3)).is_some());
        assert_eq!(region.stats().revivals, 5);
        assert_eq!(
            region.revival_census_for_test(),
            RevivalCensus {
                operations: 5,
                distinct_values: 3
            }
        );
        drop(wrapper);
        region.invalidate(&Key(3));
        budget.run_pending_tasks();
        assert_eq!(budget.accounted_bytes(), 0);
    }

    #[test]
    fn cross_region_charge_and_caller_held_eviction() {
        let budget = RetentionBudget::new(1_600);
        let left = budget.region::<Key, Value>("left", None);
        let right = budget.region::<Key, Value>("right", None);
        let held = left.insert(Key(1), Value(300));
        let other = right.insert(Key(2), Value(300));
        budget.run_pending_tasks();
        assert!(budget.accounted_bytes() <= 1_600);
        left.evict_ready_for_test(&Key(1));
        budget.run_pending_tasks();
        assert!(left.get(&Key(1)).is_none());
        assert!(left.stats().deferred_bytes > 0);
        let before = budget.accounted_bytes();
        drop(held);
        budget.run_pending_tasks();
        assert!(budget.accounted_bytes() < before);
        assert_eq!(left.stats().deferred_bytes, 0);
        drop(other);
        right.invalidate(&Key(2));
        budget.run_pending_tasks();
        drop(left.insert(Key(3), Value(300)));
        for _ in 0..100 {
            drop(right.insert(Key(4), Value(300)));
            budget.run_pending_tasks();
            if left.stats().evictions + right.stats().evictions > 0 {
                break;
            }
        }
        assert!(budget.accounted_bytes() <= 1_600);
        assert!(left.stats().evictions + right.stats().evictions > 0);
    }

    #[test]
    fn lru_trades_regions_and_pinned_charge_refuses() {
        let budget = RetentionBudget::new(1_600);
        let left = budget.region::<Key, Value>("trade-left", None);
        let right = budget.region::<Key, Value>("trade-right", None);
        drop(left.insert(Key(1), Value(300)));
        budget.run_pending_tasks();
        let admitted = right.insert(Key(2), Value(300));
        budget.run_pending_tasks();
        assert!(matches!(admitted, BudgetedValue::Retained(_)));
        assert!(left.get(&Key(1)).is_none());
        assert!(right.get(&Key(2)).is_some());
        assert_eq!(budget.accounted_bytes(), 820);

        right.evict_ready_for_test(&Key(2));
        budget.run_pending_tasks();
        let refused = left.insert(Key(3), Value(300));
        assert!(matches!(
            refused,
            BudgetedValue::RequestOwned {
                cause: RefusalCause::NoCapacity,
                ..
            }
        ));
        assert_eq!(refused.0, 300);
        assert!(left.get(&Key(3)).is_none());
        assert!(left.revive(&Key(3)).is_none());
        drop(admitted);
        budget.run_pending_tasks();
        assert_eq!(budget.accounted_bytes(), 0);
    }

    #[test]
    fn revival_and_shared_backing_charge_once() {
        let budget = RetentionBudget::new(3_000);
        let region = budget.region::<Key, Value>("values", None);
        let lease = budget.shared_backing(400).expect("backing fits");
        let held = region.insert_with_backing(Key(1), Value(100), Some(lease.clone()));
        let charge = budget.accounted_bytes();
        region.evict_ready_for_test(&Key(1));
        budget.run_pending_tasks();
        let revived = region.revive(&Key(1)).expect("caller held live allocation");
        let (BudgetedValue::Retained(held), Some(revived)) = (held, Some(revived)) else {
            panic!("admission did not retain");
        };
        assert!(held.ptr_eq(&revived));
        assert_eq!(budget.accounted_bytes(), charge);
        drop(lease);
        drop(revived);
        drop(held);
        region.invalidate(&Key(1));
        budget.run_pending_tasks();
        assert_eq!(budget.accounted_bytes(), 0);
    }

    #[test]
    fn refusal_and_entry_cap() {
        let budget = RetentionBudget::new(2_000);
        let region = budget.region::<Key, Value>("capped", Some(1));
        let first = region.insert(Key(1), Value(100));
        let second = region.insert(Key(2), Value(100));
        region.run_pending_tasks();
        assert!(region.get(&Key(1)).is_none());
        assert!(region.get(&Key(2)).is_some());
        assert!(matches!(second, BudgetedValue::Retained(_)));
        assert_eq!(region.stats().entries, 1);
        let large = region.insert(Key(3), Value(3_000));
        assert!(matches!(
            large,
            BudgetedValue::RequestOwned {
                cause: RefusalCause::Oversized,
                ..
            }
        ));
        assert_eq!(large.0, 3_000);
        assert!(region.get(&Key(3)).is_none());
        assert!(region.revive(&Key(3)).is_none());
        drop((first, second, large));
        let huge_budget = RetentionBudget::new(u64::MAX);
        let huge = huge_budget.region::<Key, Value>("huge", None);
        let value = huge.insert(Key(4), Value(u32::MAX as usize));
        assert!(matches!(
            value,
            BudgetedValue::RequestOwned {
                cause: RefusalCause::WeightOverflow,
                ..
            }
        ));
        assert!(huge.get(&Key(4)).is_none());
        assert_eq!(huge_budget.accounted_bytes(), 0);
        drop(value);
    }

    #[test]
    fn refused_flight_is_usable_without_retention() {
        let budget = RetentionBudget::new(700);
        let cache = BudgetedValueCache::new(budget.region::<Key, Value>("refused-flight", None));
        let token = CancellationToken::new();
        let (acquired, _) = cache.acquire(&Key(1), &token);
        let BudgetedValueAcquisition::Leader { permit } = acquired else {
            panic!("leader");
        };
        let value = permit.publish_complete(Value(500));
        assert!(matches!(
            value,
            BudgetedValue::RequestOwned {
                cause: RefusalCause::Oversized,
                ..
            }
        ));
        assert_eq!(value.0, 500);
        assert!(cache.get_ready(&Key(1), &token).is_none());
        assert!(cache.region().revive(&Key(1)).is_none());
        assert_eq!(budget.accounted_bytes(), 0);
        let (acquired, _) = cache.acquire(&Key(2), &token);
        let BudgetedValueAcquisition::Leader { permit } = acquired else {
            panic!("leader");
        };
        let value = permit.publish_request_owned(Value(10));
        assert!(matches!(
            value,
            BudgetedValue::RequestOwned {
                cause: RefusalCause::RequestOnly,
                ..
            }
        ));
        assert!(cache.get_ready(&Key(2), &token).is_none());
    }

    #[test]
    fn last_drop_clears_live_and_next_demand_rebuilds() {
        let budget = RetentionBudget::new(2_000);
        let cache = BudgetedValueCache::new(budget.region::<Key, Value>("rebuild", None));
        let token = CancellationToken::new();
        let (acquired, _) = cache.acquire(&Key(1), &token);
        let BudgetedValueAcquisition::Leader { permit } = acquired else {
            panic!("leader");
        };
        permit.publish_complete(Value(100));
        let (acquired, _) = cache.acquire(&Key(1), &token);
        let BudgetedValueAcquisition::Cached { value } = acquired else {
            panic!("cached");
        };
        cache.region().evict_ready_for_test(&Key(1));
        drop(value);
        cache.region().run_pending_tasks();
        assert_eq!(budget.accounted_bytes(), 0);
        assert!(cache.region().revive(&Key(1)).is_none());
        let (acquired, _) = cache.acquire(&Key(1), &token);
        assert!(matches!(acquired, BudgetedValueAcquisition::Leader { .. }));
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#9737: a build running across invalidate_all published its old-snapshot value into the cleared cache"
    )]
    #[test]
    fn invalidation_fences_a_running_build() {
        let budget = RetentionBudget::new(4_000);
        let cache = BudgetedValueCache::new(budget.region::<Key, Value>("fenced", None));
        let token = CancellationToken::new();
        for invalidate_all in [true, false] {
            let (acquired, _) = cache.acquire(&Key(1), &token);
            let BudgetedValueAcquisition::Leader { permit } = acquired else {
                panic!("expected leader");
            };
            if invalidate_all {
                cache.invalidate_all();
            } else {
                cache.invalidate(&Key(1));
            }
            // A request after the invalidation starts its own flight rather
            // than joining the fenced one.
            let (fresh, _) = cache.acquire(&Key(1), &token);
            let BudgetedValueAcquisition::Leader { permit: fresh } = fresh else {
                panic!("a new request must not join a fenced flight");
            };
            assert!(matches!(
                permit.publish_complete(Value(100)),
                BudgetedValue::RequestOwned { .. }
            ));
            assert!(
                cache.get_ready(&Key(1), &token).is_none(),
                "the fenced build's value never enters the region"
            );
            assert!(matches!(
                fresh.publish_complete(Value(200)),
                BudgetedValue::Retained(_)
            ));
            assert_eq!(
                cache.get_ready(&Key(1), &token).expect("fresh value").0,
                200
            );
            cache.invalidate(&Key(1));
        }
    }

    #[test]
    fn single_flight_and_registration_cleanup() {
        let budget = RetentionBudget::new(4_000);
        let cache = BudgetedValueCache::new(budget.region::<Key, Value>("flight", None));
        let token = CancellationToken::new();
        let (acquired, _) = cache.acquire(&Key(1), &token);
        let BudgetedValueAcquisition::Leader { permit } = acquired else {
            panic!("expected leader");
        };
        assert!(cache.build_in_flight(&Key(1)));
        let barrier = Arc::new(Barrier::new(2));
        let follower = cache.clone();
        let follower_barrier = barrier.clone();
        let child = thread::spawn(move || {
            follower_barrier.wait();
            follower.acquire(&Key(1), &CancellationToken::new()).0
        });
        barrier.wait();
        while cache.waiters_for_test(&Key(1)) == 0 {
            thread::yield_now();
        }
        permit.publish_complete(Value(100));
        let BudgetedValueAcquisition::Cached { value } = child.join().expect("follower") else {
            panic!("follower missed value");
        };
        assert_eq!(value.0, 100);
        assert!(!cache.build_in_flight(&Key(1)));
        let (acquired, _) = cache.acquire(&Key(2), &token);
        let BudgetedValueAcquisition::Leader { permit } = acquired else {
            panic!("expected leader");
        };
        permit.publish_rejected();
        assert!(!cache.build_in_flight(&Key(2)));
        let (acquired, _) = cache.acquire(&Key(3), &token);
        let BudgetedValueAcquisition::Leader { permit } = acquired else {
            panic!("expected leader");
        };
        drop(permit);
        assert!(!cache.build_in_flight(&Key(3)));
        let cancelled = CancellationToken::new();
        let (acquired, _) = cache.acquire(&Key(4), &cancelled);
        let BudgetedValueAcquisition::Leader { permit } = acquired else {
            panic!("leader");
        };
        cancelled.cancel();
        drop(permit);
        assert!(!cache.build_in_flight(&Key(4)));
        assert!(matches!(
            cache.acquire(&Key(4), &cancelled).0,
            BudgetedValueAcquisition::Cancelled
        ));
    }
    #[test]
    fn probe_accounts_for_deferred_and_resident() {
        let budget = RetentionBudget::new(3_000);
        let region = budget.region::<Key, Value>("probe-regression", None);
        let held = region.insert(Key(1), Value(980)); // charge 1500
        region.evict_ready_for_test(&Key(1));
        drop(region.insert(Key(2), Value(480))); // charge 1000, resident
        region.run_pending_tasks();
        assert_eq!(budget.accounted_bytes(), 2500);
        let candidate = region.insert(Key(3), Value(480));
        region.run_pending_tasks();
        assert!(matches!(candidate, BudgetedValue::Retained(_)));
        assert!(region.get(&Key(2)).is_none());
        assert_eq!(budget.accounted_bytes(), 2500);
        drop(held);
    }

    #[test]
    fn charge_survives_blocked_value_drop() {
        use std::sync::mpsc;
        struct BlockingValue {
            observed: mpsc::Sender<u64>,
            release: Mutex<mpsc::Receiver<()>>,
            budget: RetentionBudget,
        }
        impl RetainedBytes for BlockingValue {
            fn retained_bytes(&self) -> usize {
                100
            }
        }
        impl Drop for BlockingValue {
            fn drop(&mut self) {
                self.observed.send(self.budget.accounted_bytes()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
            }
        }
        let budget = RetentionBudget::new(2000);
        let region = budget.region::<Key, BlockingValue>("blocked-drop", None);
        let (observed_tx, observed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let handle = region.insert(
            Key(1),
            BlockingValue {
                observed: observed_tx,
                release: Mutex::new(release_rx),
                budget: budget.clone(),
            },
        );
        region.invalidate(&Key(1));
        region.run_pending_tasks();
        let child = thread::spawn(move || drop(handle));
        assert_eq!(observed_rx.recv().unwrap(), 620);
        assert_eq!(budget.accounted_bytes(), 620);
        release_tx.send(()).unwrap();
        child.join().unwrap();
        assert_eq!(budget.accounted_bytes(), 0);
    }

    #[test]
    fn rejected_followers_share_failure_wave() {
        let budget = RetentionBudget::new(2000);
        let cache = BudgetedValueCache::new(budget.region::<Key, Value>("failure-wave", None));
        let (first, _) = cache.acquire(&Key(1), &CancellationToken::new());
        let BudgetedValueAcquisition::Leader { permit } = first else {
            panic!("leader")
        };
        let follower = cache.clone();
        let child = thread::spawn(move || follower.acquire(&Key(1), &CancellationToken::new()).0);
        while cache.waiters_for_test(&Key(1)) == 0 {
            thread::yield_now();
        }
        permit.publish_rejected();
        assert!(matches!(
            child.join().unwrap(),
            BudgetedValueAcquisition::Rejected
        ));
        assert!(matches!(
            cache.acquire(&Key(1), &CancellationToken::new()).0,
            BudgetedValueAcquisition::Leader { .. }
        ));
    }

    #[test]
    fn two_owners_keep_shared_backing() {
        let budget = RetentionBudget::new(3000);
        let region = budget.region::<Key, Value>("two-owner", None);
        let lease = budget.shared_backing(400).unwrap();
        let first = region.insert_with_backing(Key(1), Value(100), Some(lease.clone()));
        let second = region.insert_with_backing(Key(2), Value(100), Some(lease.clone()));
        drop(lease);
        region.invalidate(&Key(1));
        region.invalidate(&Key(2));
        region.run_pending_tasks();
        drop(first);
        assert_eq!(budget.accounted_bytes(), 1020);
        drop(second);
        assert_eq!(budget.accounted_bytes(), 0);
    }

    #[test]
    fn concurrent_admission_drop_stress() {
        let budget = RetentionBudget::new(3000);
        let region = budget.region::<Key, Value>("stress", None);
        thread::scope(|scope| {
            for worker in 0..4 {
                let budget = budget.clone();
                let region = region.clone();
                scope.spawn(move || {
                    for iteration in 0..100 {
                        let key = Key(worker * 100 + iteration);
                        let value = region.insert(key.clone(), Value(100));
                        region.invalidate(&key);
                        drop(value);
                        budget.run_pending_tasks();
                        assert!(budget.accounted_bytes() <= 3000);
                    }
                });
            }
        });
        region.run_pending_tasks();
        assert_eq!(budget.accounted_bytes(), 0);
    }
}
