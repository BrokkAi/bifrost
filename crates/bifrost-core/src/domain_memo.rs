//! Typed request-domain memos with exactly two hit shapes (#12538).
//!
//! A request-cache domain keeps typed memos in a [`DomainMemoRegistry`]. The
//! registry accepts only [`DomainMemo`] types, and `DomainMemo` is sealed: it is
//! implemented here for the two answer shapes below and, through
//! [`domain_memo_set!`], for structs whose every field is itself a `DomainMemo`.
//!
//! * Replaying: an entry carries the reads and completion of the fill that
//!   produced it ([`ReplayEntry`]), and a hit replays them into the hitter's
//!   receipt: [`ReplayingMemo`], [`ReplayingStore`], [`ReplayingRegion`].
//! * Certifying: a hit is legal only because the caller holds a
//!   [`CertificationProof`], which is constructible only from a
//!   [`CertificationWitness`] (a value that exists because the caller recorded
//!   an authority), and whose authority must cover the fill's:
//!   [`CertifyingRegion`], [`CertifyingSlot`], [`CertifiedKeyed`], or a memo
//!   that declares itself [`SelfCertifying`].
//!
//! A value-only `Mutex<HashMap<..>>` is neither, so it cannot be registered:
//!
//! ```compile_fail,E0277
//! use brokk_bifrost_core::domain_memo::DomainMemoRegistry;
//! use brokk_bifrost_core::retention_budget::RetentionBudget;
//! use std::{collections::HashMap, sync::Mutex};
//! let registry = DomainMemoRegistry::new(&RetentionBudget::for_test_capacity(1 << 20));
//! let _ = registry.memo::<Mutex<HashMap<u8, u8>>>();
//! ```
//!
//! A certifying hit without a proof does not compile either:
//!
//! ```compile_fail,E0061
//! use brokk_bifrost_core::domain_memo::{CertifyingRegion, DigestAuthority};
//! use brokk_bifrost_core::retention_budget::RetentionBudget;
//! let region: CertifyingRegion<u8, u8, DigestAuthority> =
//!     CertifyingRegion::new(&RetentionBudget::for_test_capacity(1 << 20));
//! let _ = region.get(&1);
//! ```
//!
//! Budget accounting: [`ReplayingRegion`], [`CertifyingRegion`], and a
//! [`ReplayingStore`] backed by a [`BudgetRegion`] are private children of the
//! analyzer's own owner budget and charge their retained entries to it.
//! [`ReplayingMemo`], non-region [`ReplayingStore`]s (`KeyedPoolSafeMemo`,
//! `PoolSafeMemo`, `Mutex<HashMap<..>>`, `Mutex<Option<..>>`),
//! [`CertifiedKeyed`], [`CertifyingSlot`], and [`SelfCertifying`] wrappers
//! enforce shape and retirement without charging the budget (paying those
//! remaining request-resident stores is follow-up work). For budgeted regions,
//! retirement is admission control, not a refund: it drops the region's own
//! references (refunding what they paid) and closes the region so that no
//! later insertion, even through a detached handle, publishes. A caller that
//! still holds a budgeted value keeps its bytes charged until its final drop.
use crate::analyzer::memo_attribution::ReplayingMemo;
use crate::analyzer::pool_memo::{KeyedPoolSafeMemo, PoolSafeMemo};
use crate::budgeted_value_cache::{BudgetedValueAcquisition, BudgetedValueCache};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::retention_budget::{
    BudgetRegion, BudgetedValue, RefusalCause, RequestOwned, Retained, RetainedBytes,
    RetentionBudget,
};
use std::any::{Any, TypeId};
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[doc(hidden)]
pub mod sealed {
    /// Implemented only in this module and by [`domain_memo_set!`](crate::domain_memo_set).
    pub trait Registrable {}
    pub trait Bookkeeping {}
}

/// A memo the registry can hold. Sealed: see the module comment.
pub trait DomainMemo: sealed::Registrable + Send + Sync + 'static {
    /// A fresh memo bound to `owner` (charged to `owner` for region-backed
    /// shapes; see the module comment for unpaid request-resident shapes).
    fn new(owner: &RetentionBudget) -> Self;
    /// Drop this memo's own references and refuse every later insertion.
    fn retire(&self);
}

/// Clears a store without publishing anything. Implemented for storage that
/// already sits behind a shape wrapper; it grants no registration power.
pub trait Retire {
    fn retire(&self);
}

/// An entry that stores the reads and completion of the fill that built it, so
/// that a hit replays them. Implementors vouch for that; the registry only
/// accepts replaying stores whose entries make the claim.
pub trait ReplayEntry {}

impl<T, K> ReplayEntry for crate::analyzer::memo_attribution::ReplayingMemoEntry<T, K> {}
impl<E: ReplayEntry> ReplayEntry for Arc<E> {}

impl<K: Eq + Hash + Clone, E: ReplayEntry> Retire for KeyedPoolSafeMemo<K, E> {
    fn retire(&self) {
        // In-flight builders hold their own cell and publish into it; the
        // detached cell dies with them, never into a later request.
        drop(self.take_cells());
    }
}
impl<E: ReplayEntry> Retire for PoolSafeMemo<E> {
    fn retire(&self) {
        drop(self.take_value());
    }
}
impl<K, E, S> Retire for Mutex<std::collections::HashMap<K, E, S>>
where
    K: Eq + Hash + Send + 'static,
    E: ReplayEntry + Send + 'static,
    S: std::hash::BuildHasher + Default + Send + 'static,
{
    fn retire(&self) {
        let taken = std::mem::take(&mut *self.lock().expect("replaying store poisoned"));
        drop(taken);
    }
}
impl<E: ReplayEntry + Send + 'static> Retire for Mutex<Option<E>> {
    fn retire(&self) {
        let taken = self.lock().expect("replaying store poisoned").take();
        drop(taken);
    }
}
impl<K, V: ReplayEntry> Retire for BudgetRegion<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    fn retire(&self) {
        self.invalidate_all();
    }
}

// Replaying shape over the existing wrappers.
impl<M: Retire> sealed::Registrable for ReplayingMemo<M> {}
impl<M: Retire + Default + Send + Sync + 'static> DomainMemo for ReplayingMemo<M> {
    fn new(_: &RetentionBudget) -> Self {
        Self::default()
    }
    fn retire(&self) {
        self.retire_with(Retire::retire);
    }
}

/// A store of replaying entries reached directly (single-flight cells, pool
/// memos). The entry type must be a [`ReplayEntry`].
#[derive(Debug, Default)]
pub struct ReplayingStore<M>(M);
impl<M> ReplayingStore<M> {
    pub const fn new(store: M) -> Self {
        Self(store)
    }
}
impl<M> std::ops::Deref for ReplayingStore<M> {
    type Target = M;
    fn deref(&self) -> &M {
        &self.0
    }
}
impl<M: Retire> sealed::Registrable for ReplayingStore<M> {}
impl<M: Retire + Default + Send + Sync + 'static> DomainMemo for ReplayingStore<M> {
    fn new(_: &RetentionBudget) -> Self {
        Self::default()
    }
    fn retire(&self) {
        Retire::retire(&self.0);
    }
}

/// Counters and tokens that are not answers. They have no cache semantics, so
/// they are held by [`DomainMemoRegistry::bookkeeping_slot`], never as a memo.
pub trait BookkeepingValue: sealed::Bookkeeping + Default + Send + Sync + 'static {}
macro_rules! bookkeeping {
    ($($ty:ty),*) => {$(
        impl sealed::Bookkeeping for $ty {}
        impl BookkeepingValue for $ty {}
    )*};
}
bookkeeping!(AtomicUsize, AtomicU64, AtomicBool);

/// A bookkeeping field of a memo set (a counter or token, not an answer).
#[derive(Debug, Default)]
pub struct Counter<T: BookkeepingValue>(pub T);
impl<T: BookkeepingValue> sealed::Registrable for Counter<T> {}
impl<T: BookkeepingValue> DomainMemo for Counter<T> {
    fn new(_: &RetentionBudget) -> Self {
        Self::default()
    }
    fn retire(&self) {}
}

/// Declares a memo struct whose fields must all be [`DomainMemo`]s. A bare
/// `Mutex<HashMap<..>>` field fails with "the trait `DomainMemo` is not
/// implemented". A trailing `; test_only { name: Type, .. }` block adds
/// `Default`-built fields that exist only under `cfg(test)`, for counters.
#[macro_export]
macro_rules! domain_memo_set {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($(#[$fmeta:meta])* $fvis:vis $field:ident : $ty:ty),* $(,)?
            $(; test_only { $($tvis:vis $tfield:ident : $tty:ty),* $(,)? })?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $($(#[$fmeta])* $fvis $field: $ty,)*
            $($(#[cfg(test)] $tvis $tfield: $tty,)*)?
        }
        impl $crate::domain_memo::sealed::Registrable for $name {}
        impl $crate::domain_memo::DomainMemo for $name {
            fn new(owner: &$crate::retention_budget::RetentionBudget) -> Self {
                Self {
                    $($field: <$ty as $crate::domain_memo::DomainMemo>::new(owner),)*
                    $($(#[cfg(test)] $tfield: <$tty as Default>::default(),)*)?
                }
            }
            fn retire(&self) {
                $(<$ty as $crate::domain_memo::DomainMemo>::retire(&self.$field);)*
            }
        }
    };
}

/// A memo that validates every hit against the caller's own current authority,
/// declared by its owner and not constructed from a shape. Implementors vouch
/// for the validation (the type documents it), and give retirement: empty the
/// store and refuse later fills. Register with [`self_certifying_domain_memo!`].
pub trait SelfCertifying: Default + Send + Sync + 'static {
    fn retire(&self);
}
#[macro_export]
macro_rules! self_certifying_domain_memo {
    ($ty:ty) => {
        impl $crate::domain_memo::sealed::Registrable for $ty {}
        impl $crate::domain_memo::DomainMemo for $ty {
            fn new(_: &$crate::retention_budget::RetentionBudget) -> Self {
                <$ty as Default>::default()
            }
            fn retire(&self) {
                <$ty as $crate::domain_memo::SelfCertifying>::retire(self)
            }
        }
    };
}

/// A region that can be closed: after [`Self::retire`] it admits nothing and
/// returns nothing, even through a detached `Arc` of its owner.
pub struct ClosableRegion<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    region: BudgetedValueCache<K, V>,
    closed: AtomicBool,
}
impl<K, V> ClosableRegion<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    fn new(owner: &RetentionBudget) -> Self {
        Self {
            region: BudgetedValueCache::new(owner.region(std::any::type_name::<(K, V)>(), None)),
            closed: AtomicBool::new(false),
        }
    }
    fn get(&self, key: &K) -> Option<Retained<V>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        self.region.region().get(key)
    }
    /// A refusal, including a closed region's, returns the complete value as
    /// request-owned: the caller continues normally and nothing is retained.
    fn insert(&self, key: K, value: V) -> BudgetedValue<V> {
        if self.closed.load(Ordering::Acquire) {
            return BudgetedValue::RequestOwned {
                value: RequestOwned::new(value),
                cause: RefusalCause::Closed,
            };
        }
        let admitted = self.region.region().insert(key, value);
        if self.closed.load(Ordering::Acquire) {
            // Retired while this insert was in flight: drop the entry again.
            // The caller's handle keeps its bytes until its final drop.
            self.region.invalidate_all();
        }
        admitted
    }
    fn retire(&self) {
        self.closed.store(true, Ordering::Release);
        self.region.invalidate_all();
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub fn stats(&self) -> crate::retention_budget::RegionStats {
        self.region.region().run_pending_tasks();
        self.region.region().stats()
    }
}
impl<K, V> Drop for ClosableRegion<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    fn drop(&mut self) {
        self.retire();
    }
}

/// Replaying region: the value is a [`ReplayEntry`], and a hit replays it
/// exactly once, through the caller's closure.
pub struct ReplayingRegion<K, V>(ClosableRegion<K, V>)
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: ReplayEntry + Send + Sync + RetainedBytes + 'static;
impl<K, V> ReplayingRegion<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: ReplayEntry + Send + Sync + RetainedBytes + 'static,
{
    /// Look up `key`. Eligibility is pure: a hit calls `replay` once, and a miss
    /// never calls it, so a side-effecting probe cannot replay twice.
    pub fn get(&self, key: &K, replay: impl FnOnce(&V)) -> Option<Retained<V>> {
        let hit = self.0.get(key)?;
        replay(&hit);
        Some(hit)
    }
    /// A pure lookup for a caller that replays the entry itself, and only when
    /// it actually uses the hit (for example after a restore that may refuse).
    /// Replay at most once per use; never probe with a side-effecting check.
    pub fn peek(&self, key: &K) -> Option<Retained<V>> {
        self.0.get(key)
    }
    pub fn stats(&self) -> crate::retention_budget::RegionStats {
        self.0.stats()
    }
    pub fn insert(&self, key: K, value: V) -> BudgetedValue<V> {
        self.0.insert(key, value)
    }
    /// Build a missing value once per key, replaying it for every follower.
    /// The initializer must not depend on a rayon worker: waiters can include
    /// every worker in that pool. Failures and cancellation are never retained.
    pub fn get_or_try_build<E>(
        &self,
        key: &K,
        cancellation: &CancellationToken,
        build: impl FnOnce() -> Result<V, E>,
        replay: impl FnOnce(&V),
    ) -> Result<Option<BudgetedValue<V>>, E> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if self.0.is_closed() {
            return build().map(BudgetedValue::request_only).map(Some);
        }
        match self.0.region.acquire(key, cancellation).0 {
            BudgetedValueAcquisition::Cached { value } => {
                replay(&value);
                Ok(Some(value))
            }
            BudgetedValueAcquisition::Leader { permit } => {
                let value = build()?;
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let value = permit.publish_complete(value);
                if self.0.is_closed() {
                    self.0.region.invalidate_all();
                }
                Ok(Some(value))
            }
            BudgetedValueAcquisition::Cancelled => Ok(None),
            BudgetedValueAcquisition::Rejected => {
                unreachable!("replaying builders retry failures without publishing rejection")
            }
        }
    }
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}
impl<K, V> sealed::Registrable for ReplayingRegion<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: ReplayEntry + Send + Sync + RetainedBytes + 'static,
{
}
impl<K, V> DomainMemo for ReplayingRegion<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: ReplayEntry + Send + Sync + RetainedBytes + 'static,
{
    fn new(owner: &RetentionBudget) -> Self {
        Self(ClosableRegion::new(owner))
    }
    fn retire(&self) {
        self.0.retire();
    }
}

/// What a certifying hit must be covered by.
pub trait CertifiedAuthority: Clone + Send + Sync + 'static {
    /// Whether holding `self` justifies a value filled under `fill`.
    fn covers(&self, fill: &Self) -> bool;
}
/// An authority that is exactly one content digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DigestAuthority(pub [u8; 32]);
impl RetainedBytes for DigestAuthority {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}
impl CertifiedAuthority for DigestAuthority {
    fn covers(&self, fill: &Self) -> bool {
        self == fill
    }
}

/// A value that exists only because its holder recorded an authority, for
/// example a prepared syntax tree obtained through a recorded source read.
pub trait CertificationWitness {
    type Authority: CertifiedAuthority;
    fn authority(&self) -> Self::Authority;
}

/// A prepared syntax tree exists only because its source was read through a
/// recorded read, and its bytes determine the answer: the exact source digest
/// is its authority.
impl CertificationWitness for crate::analyzer::prepared_syntax::PreparedSyntaxTree {
    type Authority = DigestAuthority;
    fn authority(&self) -> DigestAuthority {
        DigestAuthority(self.source_sha256())
    }
}

/// The caller's recorded authority. Its only constructor takes a witness.
pub struct CertificationProof<'w, A: CertifiedAuthority> {
    authority: A,
    witness: PhantomData<&'w ()>,
}
impl<'w, A: CertifiedAuthority> CertificationProof<'w, A> {
    pub fn from_witness<W: CertificationWitness<Authority = A>>(witness: &'w W) -> Self {
        Self {
            authority: witness.authority(),
            witness: PhantomData,
        }
    }
    pub fn authority(&self) -> &A {
        &self.authority
    }
}

/// A value together with the authority under which it was filled.
pub struct Certified<V, A> {
    value: V,
    fill_authority: A,
}
impl<V, A> Certified<V, A> {
    pub fn value(&self) -> &V {
        &self.value
    }
}
impl<V, A> std::ops::Deref for Certified<V, A> {
    type Target = V;
    fn deref(&self) -> &V {
        &self.value
    }
}
impl<V: RetainedBytes, A: RetainedBytes> RetainedBytes for Certified<V, A> {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .value
                .retained_bytes()
                .saturating_sub(std::mem::size_of::<V>())
            + self
                .fill_authority
                .retained_bytes()
                .saturating_sub(std::mem::size_of::<A>())
    }
    fn eviction_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .value
                .eviction_bytes()
                .saturating_sub(std::mem::size_of::<V>())
            + self
                .fill_authority
                .eviction_bytes()
                .saturating_sub(std::mem::size_of::<A>())
    }
}

/// Certifying region: a hit needs a [`CertificationProof`] whose authority
/// covers the fill's. A refused insertion returns the complete request-owned
/// value and is never a later hit.
pub struct CertifyingRegion<K, V, A>(ClosableRegion<K, Certified<V, A>>)
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
    A: CertifiedAuthority + RetainedBytes;
impl<K, V, A> CertifyingRegion<K, V, A>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
    A: CertifiedAuthority + RetainedBytes,
{
    pub fn new(owner: &RetentionBudget) -> Self {
        Self(ClosableRegion::new(owner))
    }
    pub fn get(
        &self,
        key: &K,
        proof: &CertificationProof<'_, A>,
    ) -> Option<Retained<Certified<V, A>>> {
        let hit = self.0.get(key)?;
        proof.authority().covers(&hit.fill_authority).then_some(hit)
    }
    pub fn insert(
        &self,
        key: K,
        value: V,
        proof: &CertificationProof<'_, A>,
    ) -> BudgetedValue<Certified<V, A>> {
        self.0.insert(
            key,
            Certified {
                value,
                fill_authority: proof.authority().clone(),
            },
        )
    }
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
    pub fn stats(&self) -> crate::retention_budget::RegionStats {
        self.0.stats()
    }
}
impl<K, V, A> sealed::Registrable for CertifyingRegion<K, V, A>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
    A: CertifiedAuthority + RetainedBytes,
{
}
impl<K, V, A> DomainMemo for CertifyingRegion<K, V, A>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
    A: CertifiedAuthority + RetainedBytes,
{
    fn new(owner: &RetentionBudget) -> Self {
        Self::new(owner)
    }
    fn retire(&self) {
        self.0.retire();
    }
}

/// A key that embeds the authority a hit is checked against: two callers whose
/// authorities differ never produce equal keys. Implementors vouch for that.
pub trait CertifyingKey: Eq + Hash + Clone + Send + Sync + 'static {}

/// Single-flight cells keyed by a [`CertifyingKey`]: certifying by construction,
/// since the key is the authority.
#[derive(Debug)]
pub struct CertifiedKeyed<K: CertifyingKey, V>(KeyedPoolSafeMemo<K, V>);
impl<K: CertifyingKey, V> Default for CertifiedKeyed<K, V> {
    fn default() -> Self {
        Self(KeyedPoolSafeMemo::new())
    }
}
impl<K: CertifyingKey, V> std::ops::Deref for CertifiedKeyed<K, V> {
    type Target = KeyedPoolSafeMemo<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<K: CertifyingKey, V> sealed::Registrable for CertifiedKeyed<K, V> {}
impl<K: CertifyingKey, V: Send + Sync + 'static> DomainMemo for CertifiedKeyed<K, V> {
    fn new(_: &RetentionBudget) -> Self {
        Self::default()
    }
    fn retire(&self) {
        // In-flight builders hold their own cell; see `Retire` for the cells.
        drop(self.0.take_cells());
    }
}

/// One value filled under an authority, for state that is small, request-local
/// and not charged to a budget (for example one selected snapshot's rows). A
/// covering proof reads or updates it; a proof that does not cover the fill
/// gets `None` and must compute without the slot. Retirement empties and
/// closes it.
pub struct CertifyingSlot<A: CertifiedAuthority, V> {
    state: std::sync::RwLock<Option<(A, V)>>,
    closed: AtomicBool,
}
impl<A: CertifiedAuthority, V> CertifyingSlot<A, V> {
    /// Run `f` on the slot's value, creating it with `init` under the caller's
    /// authority when empty. `None`: closed, or the fill authority is not covered.
    pub fn with<R>(
        &self,
        proof: &CertificationProof<'_, A>,
        init: impl FnOnce() -> V,
        f: impl FnOnce(&mut V) -> R,
    ) -> Option<R> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.state.write().expect("certifying slot poisoned");
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let (fill, value) = state.get_or_insert_with(|| (proof.authority().clone(), init()));
        proof.authority().covers(fill).then(|| f(value))
    }
    /// The value if present and covered; never fills.
    pub fn read<R>(&self, proof: &CertificationProof<'_, A>, f: impl FnOnce(&V) -> R) -> Option<R> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let state = self.state.read().expect("certifying slot poisoned");
        let (fill, value) = state.as_ref()?;
        proof.authority().covers(fill).then(|| f(value))
    }
    /// Replace the value under the caller's authority, unless closed.
    pub fn replace(&self, proof: &CertificationProof<'_, A>, value: V) {
        let old = {
            let mut state = self.state.write().expect("certifying slot poisoned");
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            state.replace((proof.authority().clone(), value))
        };
        drop(old);
    }
}
impl<A: CertifiedAuthority, V> Default for CertifyingSlot<A, V> {
    fn default() -> Self {
        Self {
            state: std::sync::RwLock::new(None),
            closed: AtomicBool::new(false),
        }
    }
}
impl<A: CertifiedAuthority, V: Send + Sync + 'static> sealed::Registrable for CertifyingSlot<A, V> {}
impl<A: CertifiedAuthority, V: Send + Sync + 'static> DomainMemo for CertifyingSlot<A, V> {
    fn new(_: &RetentionBudget) -> Self {
        Self::default()
    }
    fn retire(&self) {
        self.closed.store(true, Ordering::Release);
        let old = self.state.write().expect("certifying slot poisoned").take();
        drop(old);
    }
}

/// Physical bytes of a hash map's table allocation for `capacity` entries of
/// `entry_size` bytes: buckets plus one control byte per bucket and a group.
pub fn hash_table_allocation_bytes(capacity: usize, entry_size: usize) -> usize {
    if capacity == 0 {
        return 0;
    }
    let buckets = (capacity.saturating_mul(8) / 7).next_power_of_two().max(4);
    crate::allocation_size::allocation_size(
        buckets
            .saturating_mul(entry_size)
            .saturating_add(buckets)
            .saturating_add(16),
    )
}

struct Slot {
    memo: Arc<dyn Any + Send + Sync>,
    retire: fn(&(dyn Any + Send + Sync)),
}

/// The typed memos of one (domain, analyzer), bound to that analyzer's own
/// retention owner (charging region-backed shapes to it and retiring every
/// shape together; see the module comment).
pub struct DomainMemoRegistry {
    owner: RetentionBudget,
    slots: Mutex<HashMap<TypeId, Slot>>,
    bookkeeping: Mutex<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>,
    retired: AtomicBool,
}
impl std::fmt::Debug for DomainMemoRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainMemoRegistry")
            .field("retired", &self.is_retired())
            .finish_non_exhaustive()
    }
}
impl DomainMemoRegistry {
    pub fn new(owner: &RetentionBudget) -> Self {
        Self {
            owner: owner.clone(),
            slots: Mutex::new(HashMap::default()),
            bookkeeping: Mutex::new(HashMap::default()),
            retired: AtomicBool::new(false),
        }
    }
    pub fn owner(&self) -> &RetentionBudget {
        &self.owner
    }
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }
    pub fn memo<M: DomainMemo>(&self) -> Option<Arc<M>> {
        self.try_get_or_insert_with(|owner| Some(M::new(owner)))
    }
    /// The memo of type `M`, constructing it with `build` on first use.
    ///
    /// `build` runs outside the registry lock. `None` from `build` (a refused
    /// payment) is a miss and is never cached. A racing loser, and a memo built
    /// for a registry that retired meanwhile, are dropped outside the lock.
    /// `None` is also returned once the registry is retired.
    pub fn try_get_or_insert_with<M: DomainMemo>(
        &self,
        build: impl FnOnce(&RetentionBudget) -> Option<M>,
    ) -> Option<Arc<M>> {
        if self.is_retired() {
            return None;
        }
        if let Some(existing) = self.lookup::<M>() {
            return Some(existing);
        }
        let built = Arc::new(build(&self.owner)?);
        let mut slots = self.slots.lock().expect("domain memo registry poisoned");
        if self.is_retired() {
            drop(slots);
            DomainMemo::retire(&*built);
            return None;
        }
        let winner = slots.entry(TypeId::of::<M>()).or_insert_with(|| Slot {
            memo: built.clone(),
            retire: |any| {
                DomainMemo::retire(any.downcast_ref::<M>().expect("slot type matches key"))
            },
        });
        let winner = Arc::clone(&winner.memo)
            .downcast::<M>()
            .unwrap_or_else(|_| panic!("domain memo registry key and value type disagree"));
        drop(slots);
        if !Arc::ptr_eq(&winner, &built) {
            DomainMemo::retire(&*built);
        }
        drop(built);
        Some(winner)
    }
    fn lookup<M: DomainMemo>(&self) -> Option<Arc<M>> {
        let memo = Arc::clone(
            &self
                .slots
                .lock()
                .expect("domain memo registry poisoned")
                .get(&TypeId::of::<M>())?
                .memo,
        );
        Some(
            memo.downcast::<M>()
                .unwrap_or_else(|_| panic!("domain memo registry key and value type disagree")),
        )
    }
    /// A counter or token that is not an answer. `None` once retired.
    pub fn bookkeeping_slot<T: BookkeepingValue>(&self) -> Option<Arc<T>> {
        if self.is_retired() {
            return None;
        }
        let mut slots = self.bookkeeping.lock().expect("bookkeeping poisoned");
        let slot = slots
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Arc::new(T::default()));
        Some(
            Arc::clone(slot)
                .downcast::<T>()
                .unwrap_or_else(|_| panic!("bookkeeping key and value type disagree")),
        )
    }
    /// Close every memo and drop the registry's own references. Idempotent.
    /// A value a caller still holds stays charged until its final drop.
    pub fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        let slots = std::mem::take(&mut *self.slots.lock().expect("domain memo registry poisoned"));
        let bookkeeping =
            std::mem::take(&mut *self.bookkeeping.lock().expect("bookkeeping poisoned"));
        for slot in slots.values() {
            (slot.retire)(&*slot.memo);
        }
        drop(slots);
        drop(bookkeeping);
    }
}
impl Drop for DomainMemoRegistry {
    fn drop(&mut self) {
        self.retire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention_budget::{Accounted, SharedAllocation};

    struct Unit(&'static str, [u8; 32]);
    impl CertificationWitness for Unit {
        type Authority = DigestAuthority;
        fn authority(&self) -> DigestAuthority {
            DigestAuthority(self.1)
        }
    }

    struct Entry(String);
    impl ReplayEntry for Entry {}
    impl RetainedBytes for Entry {
        fn retained_bytes(&self) -> usize {
            self.0.retained_bytes()
        }
    }

    domain_memo_set! {
        struct Set {
            answers: CertifyingRegion<u64, String, DigestAuthority>,
            replays: ReplayingRegion<u64, Entry>,
            ; test_only { walks: AtomicUsize }
        }
    }

    fn owner() -> RetentionBudget {
        RetentionBudget::for_test_capacity(1 << 24)
    }

    #[test]
    fn replaying_build_shares_one_flight_and_retirement_fences_publication() {
        let owner = owner();
        let region = ReplayingRegion::<u64, Entry>::new(&owner);
        let cancellation = CancellationToken::default();
        let replays = AtomicUsize::new(0);
        let (started, wait_started) = std::sync::mpsc::channel();
        let (release, wait_release) = std::sync::mpsc::channel();
        std::thread::scope(|threads| {
            let source_region = &region;
            let token = &cancellation;
            let first = threads.spawn(move || {
                source_region.get_or_try_build(
                    &1,
                    token,
                    || {
                        started.send(()).unwrap();
                        wait_release.recv().unwrap();
                        Ok::<_, ()>(Entry("one build".into()))
                    },
                    |_| panic!("the builder must not replay its own fill"),
                )
            });
            wait_started.recv().unwrap();
            let follower = threads.spawn(|| {
                region.get_or_try_build(
                    &1,
                    &cancellation,
                    || -> Result<Entry, ()> { panic!("the follower must share the first build") },
                    |_| {
                        replays.fetch_add(1, Ordering::Relaxed);
                    },
                )
            });
            while region.0.region.waiters_for_test(&1) == 0 {
                std::thread::yield_now();
            }
            // A flight on one file must not serialize another file's build.
            assert!(
                region
                    .get_or_try_build(
                        &2,
                        &cancellation,
                        || Ok::<_, ()>(Entry("other file".into())),
                        |_| panic!("cold key")
                    )
                    .unwrap()
                    .is_some()
            );
            region.retire();
            release.send(()).unwrap();
            assert_eq!(first.join().unwrap().unwrap().unwrap().0, "one build");
            assert_eq!(follower.join().unwrap().unwrap().unwrap().0, "one build");
        });
        assert_eq!(replays.load(Ordering::Relaxed), 1);
        assert!(region.peek(&1).is_none());
        assert!(region.peek(&2).is_none());
        owner.run_pending_tasks();
        assert_eq!(owner.accounted_bytes(), 0);
    }

    #[test]
    fn certifying_hit_needs_a_covering_authority_in_either_unit_order() {
        for swap in [false, true] {
            let owner = owner();
            let region = CertifyingRegion::<u64, String, DigestAuthority>::new(&owner);
            let (a, b) = (Unit("a", [1; 32]), Unit("b", [2; 32]));
            let (first, second) = if swap { (&b, &a) } else { (&a, &b) };
            let (pa, pb) = (
                CertificationProof::from_witness(first),
                CertificationProof::from_witness(second),
            );
            assert!(region.get(&7, &pa).is_none());
            let _fill = region.insert(7, "answer".to_owned(), &pa);
            assert_eq!(
                region.get(&7, &pa).as_deref().map(|c| c.value().as_str()),
                Some("answer")
            );
            assert!(
                region.get(&7, &pb).is_none(),
                "a unit whose authority does not cover the fill must not hit ({})",
                second.0
            );
        }
    }

    #[test]
    fn region_bytes_follow_the_final_holder_through_retire_and_unwind() {
        let owner = owner();
        let region = ReplayingRegion::<u64, Entry>::new(&owner);
        let held = region.insert(1, Entry("x".repeat(4096)));
        assert!(matches!(held, BudgetedValue::Retained(_)));
        let charged = owner.accounted_bytes();
        assert!(charged > 4096);
        // A hit replays exactly once.
        let mut replays = 0;
        assert!(region.get(&1, |_| replays += 1).is_some());
        assert!(region.get(&2, |_| replays += 1).is_none());
        assert_eq!(replays, 1);
        // Retirement drops the region's reference but not the caller's.
        DomainMemo::retire(&region);
        assert_eq!(
            owner.accounted_bytes(),
            charged,
            "a held value stays charged"
        );
        assert!(
            region.get(&1, |_| unreachable!()).is_none(),
            "closed regions miss"
        );
        let late = region.insert(2, Entry("late".into()));
        assert!(matches!(
            late,
            BudgetedValue::RequestOwned {
                cause: RefusalCause::Closed,
                ..
            }
        ));
        drop(held);
        drop(late);
        assert_eq!(
            owner.accounted_bytes(),
            0,
            "bytes end with the final holder"
        );

        let owner = self::owner();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let region = ReplayingRegion::<u64, Entry>::new(&owner);
            drop(region.insert(1, Entry("y".repeat(4096))));
            assert!(owner.accounted_bytes() > 0);
            panic!("fill failed");
        }));
        assert!(result.is_err());
        assert_eq!(owner.accounted_bytes(), 0);
    }

    #[test]
    fn shared_allocation_is_not_charged_twice_and_uncharged_is_never_a_hit() {
        let owner = owner();
        let region = ClosableRegion::<u64, SharedAllocation<Accounted<Vec<u8>>>>::new(&owner);
        let payload = Arc::new(Accounted::charged(&owner, vec![0_u8; 100_000]));
        let paid = owner.accounted_bytes();
        assert!(paid >= 100_000);
        let entry = region.insert(1, SharedAllocation::new(Arc::clone(&payload)));
        assert!(matches!(entry, BudgetedValue::Retained(_)));
        assert!(
            owner.accounted_bytes() < paid + 100_000,
            "the entry weighs a pointer"
        );
        drop(entry);
        region.retire();
        assert_eq!(
            owner.accounted_bytes(),
            paid,
            "the holder keeps its own charge"
        );
        drop(payload);
        assert_eq!(owner.accounted_bytes(), 0);

        let region = ClosableRegion::<u64, SharedAllocation<Accounted<Vec<u8>>>>::new(&owner);
        let sentinel = Arc::new(Accounted::uncharged(vec![1_u8; 16]));
        let refused = region.insert(1, SharedAllocation::new(sentinel));
        assert!(matches!(refused, BudgetedValue::RequestOwned { .. }));
        assert!(
            region.get(&1).is_none(),
            "an uncharged sentinel never becomes a hit"
        );
    }

    #[test]
    fn registry_construction_is_lock_free_refusal_is_a_miss_and_losers_drop_outside() {
        use std::sync::Weak;
        struct Probe(Weak<DomainMemoRegistry>);
        impl sealed::Registrable for Probe {}
        impl DomainMemo for Probe {
            fn new(_: &RetentionBudget) -> Self {
                Self(Weak::new())
            }
            fn retire(&self) {}
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                if let Some(registry) = self.0.upgrade() {
                    // Takes the registry lock: deadlocks if dropped under it.
                    assert!(registry.memo::<ReplayingRegion<u64, Entry>>().is_some());
                }
            }
        }
        let registry = Arc::new(DomainMemoRegistry::new(&owner()));
        assert!(registry.try_get_or_insert_with::<Probe>(|_| None).is_none());
        assert!(
            registry.lookup::<Probe>().is_none(),
            "a refusal is never cached"
        );
        let weak = Arc::downgrade(&registry);
        let winner = registry
            .try_get_or_insert_with::<Probe>(|_| {
                // Re-entrancy proves the constructor runs outside the lock.
                let inner = registry.try_get_or_insert_with::<Probe>(|_| Some(Probe(Weak::new())));
                assert!(inner.is_some());
                Some(Probe(weak.clone()))
            })
            .expect("winner");
        assert!(
            winner.0.upgrade().is_none(),
            "the racing loser was dropped, not the winner"
        );
        registry.retire();
        assert!(registry.memo::<ReplayingRegion<u64, Entry>>().is_none());
        assert!(registry.bookkeeping_slot::<AtomicUsize>().is_none());
    }

    #[test]
    fn registries_keep_the_identity_of_their_own_owner() {
        let (one, two) = (owner(), owner());
        let (a, b) = (DomainMemoRegistry::new(&one), DomainMemoRegistry::new(&two));
        assert!(a.owner().ptr_eq(&one) && !a.owner().ptr_eq(&two));
        let set_a = a.memo::<Set>().expect("set");
        let _ = b.memo::<Set>().expect("set");
        assert_eq!(set_a.walks.load(Ordering::Relaxed), 0);
        let proof_unit = Unit("a", [3; 32]);
        let proof = CertificationProof::from_witness(&proof_unit);
        drop(set_a.answers.insert(1, "z".repeat(1024), &proof));
        assert!(one.accounted_bytes() > 0);
        assert_eq!(
            two.accounted_bytes(),
            0,
            "the other analyzer's owner is untouched"
        );
        drop(set_a);
        a.retire();
        assert_eq!(one.accounted_bytes(), 0);
    }
}
