//! The store's cross-request relation caches, as regions of the owner's retention budget.

use super::python_binding_rows::PythonBindingRows;
use super::resolution_operation::PreparedMacroIncludeOverlay;
use super::resolution_operation::go_named::{
    GoPreparedContextCacheKey, GoPreparedImportContextSnapshot,
};
use super::schema_lease::{LastTemp, LastTempKey};
use super::semantic_composition::{
    ComposedGroup, ComposedGroupCacheKey, CompositionDiscoveryCacheKey, CompositionGroupKey,
    RequestSourceAnchorsKey, SearchCandidateKey, SearchCandidateStream, SourceAnchors,
};
use crate::analyzer::resolution::SharedNameId;
use brokk_bifrost_core::retention_budget::{
    BudgetRegion, BudgetedValue, RegionStats, Retained, RetentionBudget,
};
use std::sync::Arc;

pub use brokk_bifrost_core::retention_budget::{ENTRY_OVERHEAD_BYTES, RetainedBytes};

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
struct PythonBindingRowsKey {
    blob_oid: [u8; 20],
    format: i64,
}
impl RetainedBytes for PythonBindingRowsKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}
impl RetainedBytes for SharedNameId {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
    }
}

/// The store's cross-request relation caches, one region of the owner's
/// retention budget per kind, so they trade space with each other and with
/// every other cache of the same owner. Every clone shares the same regions;
/// a request's name table carries a handle so interning participates in the
/// same eviction order.
#[derive(Clone)]
pub struct StoreCacheBudget {
    pub pinned_readers: BudgetRegion<u64, super::model_catalog::PreparedPinnedReader>,
    search_candidates: BudgetRegion<SearchCandidateKey, SearchCandidateStream>,
    composed_groups: BudgetRegion<ComposedGroupCacheKey, ComposedGroup>,
    composition_discovery: BudgetRegion<CompositionDiscoveryCacheKey, Vec<CompositionGroupKey>>,
    request_source_anchors: BudgetRegion<RequestSourceAnchorsKey, SourceAnchors>,
    shared_names: BudgetRegion<[u8; 32], SharedNameId>,
    go_prepared_contexts: BudgetRegion<GoPreparedContextCacheKey, GoPreparedImportContextSnapshot>,
    rust_macro_include_overlays: BudgetRegion<[u8; 32], PreparedMacroIncludeOverlay>,
    python_binding_rows: BudgetRegion<PythonBindingRowsKey, PythonBindingRows>,
    last_temp_schemas: BudgetRegion<LastTempKey, LastTemp>,
    composition_stats: Arc<CompositionCacheCounters>,
    #[cfg(any(test, feature = "test-support"))]
    allocated: Arc<std::sync::atomic::AtomicI64>,
    #[cfg(any(test, feature = "test-support"))]
    overlay_hits: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    overlay_inserts: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    go_prepared_context_hits: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::fmt::Debug for StoreCacheBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreCacheBudget")
            .field("regions", &self.region_stats())
            .finish_non_exhaustive()
    }
}
impl StoreCacheBudget {
    pub fn new(budget: &RetentionBudget) -> Self {
        Self {
            pinned_readers: budget.region("store.pinned-readers", Some(8)),
            search_candidates: budget.region("store.search-candidates", None),
            composed_groups: budget.region("store.composed-groups", None),
            composition_discovery: budget.region("store.composition-discovery", None),
            request_source_anchors: budget.region("store.request-source-anchors", None),
            shared_names: budget.region("store.shared-names", None),
            go_prepared_contexts: budget.region("store.go-prepared-contexts", None),
            rust_macro_include_overlays: budget.region("store.rust-macro-include-overlays", None),
            python_binding_rows: budget.region("store.python-binding-rows", None),
            last_temp_schemas: budget.region("store.last-temp-schemas", None),
            composition_stats: Arc::default(),
            #[cfg(any(test, feature = "test-support"))]
            allocated: Arc::default(),
            #[cfg(any(test, feature = "test-support"))]
            overlay_hits: Arc::default(),
            #[cfg(any(test, feature = "test-support"))]
            overlay_inserts: Arc::default(),
            #[cfg(any(test, feature = "test-support"))]
            go_prepared_context_hits: Arc::default(),
        }
    }

    /// Every region's statistics, in a fixed order.
    pub fn region_stats(&self) -> Vec<(&'static str, RegionStats)> {
        vec![
            (self.pinned_readers.name(), self.pinned_readers.stats()),
            (
                self.search_candidates.name(),
                self.search_candidates.stats(),
            ),
            (self.composed_groups.name(), self.composed_groups.stats()),
            (
                self.request_source_anchors.name(),
                self.request_source_anchors.stats(),
            ),
            (
                self.composition_discovery.name(),
                self.composition_discovery.stats(),
            ),
            (self.shared_names.name(), self.shared_names.stats()),
            (
                self.go_prepared_contexts.name(),
                self.go_prepared_contexts.stats(),
            ),
            (
                self.rust_macro_include_overlays.name(),
                self.rust_macro_include_overlays.stats(),
            ),
            (
                self.python_binding_rows.name(),
                self.python_binding_rows.stats(),
            ),
            (
                self.last_temp_schemas.name(),
                self.last_temp_schemas.stats(),
            ),
        ]
    }

    pub fn search_candidates(
        &self,
        key: SearchCandidateKey,
    ) -> Option<Retained<SearchCandidateStream>> {
        let result = self.search_candidates.get(&key);
        self.composition_stats.search[result.is_some() as usize]
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        result
    }

    pub fn request_source_anchors(
        &self,
        key: &RequestSourceAnchorsKey,
    ) -> Option<Retained<SourceAnchors>> {
        self.request_source_anchors.get(key)
    }

    pub fn insert_request_source_anchors(
        &self,
        key: RequestSourceAnchorsKey,
        value: SourceAnchors,
    ) -> BudgetedValue<SourceAnchors> {
        self.request_source_anchors.insert(key, value)
    }
    pub fn insert_search_candidates(
        &self,
        key: SearchCandidateKey,
        value: SearchCandidateStream,
    ) -> BudgetedValue<SearchCandidateStream> {
        self.search_candidates.insert(key, value)
    }
    pub fn composed_group(&self, key: &ComposedGroupCacheKey) -> Option<Retained<ComposedGroup>> {
        let result = self.composed_groups.get(key);
        self.composition_stats.group[result.is_some() as usize]
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        result
    }
    pub fn insert_composed_group(
        &self,
        key: ComposedGroupCacheKey,
        value: ComposedGroup,
    ) -> BudgetedValue<ComposedGroup> {
        self.composed_groups.insert(key, value)
    }
    pub fn composition_discovery(
        &self,
        key: &CompositionDiscoveryCacheKey,
    ) -> Option<Retained<Vec<CompositionGroupKey>>> {
        let result = self.composition_discovery.get(key);
        self.composition_stats.discovery[result.is_some() as usize]
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        result
    }
    pub fn insert_composition_discovery(
        &self,
        key: CompositionDiscoveryCacheKey,
        value: Vec<CompositionGroupKey>,
    ) -> BudgetedValue<Vec<CompositionGroupKey>> {
        self.composition_discovery.insert(key, value)
    }
    #[doc(hidden)]
    pub fn composition_cache_stats(&self) -> CompositionCacheStats {
        use std::sync::atomic::Ordering::Relaxed;
        let resident = |stats: RegionStats| stats.accounted_bytes - stats.deferred_bytes;
        CompositionCacheStats {
            group_hits: self.composition_stats.group[1].load(Relaxed),
            group_misses: self.composition_stats.group[0].load(Relaxed),
            discovery_hits: self.composition_stats.discovery[1].load(Relaxed),
            discovery_misses: self.composition_stats.discovery[0].load(Relaxed),
            search_hits: self.composition_stats.search[1].load(Relaxed),
            search_misses: self.composition_stats.search[0].load(Relaxed),
            search_retained_bytes: resident(self.search_candidates.stats()),
            retained_bytes: self
                .region_stats()
                .into_iter()
                .map(|(_, stats)| resident(stats))
                .sum(),
        }
    }

    pub(crate) fn python_binding_rows(
        &self,
        blob_oid: [u8; 20],
        format: i64,
    ) -> Option<Retained<PythonBindingRows>> {
        self.python_binding_rows
            .get(&PythonBindingRowsKey { blob_oid, format })
    }
    pub(crate) fn insert_python_binding_rows(
        &self,
        blob_oid: [u8; 20],
        format: i64,
        value: PythonBindingRows,
    ) -> BudgetedValue<PythonBindingRows> {
        self.python_binding_rows
            .insert(PythonBindingRowsKey { blob_oid, format }, value)
    }

    pub(super) fn last_temp_schema(&self, key: &LastTempKey) -> Option<Retained<LastTemp>> {
        self.last_temp_schemas.get(key)
    }
    pub(super) fn insert_last_temp_schema(&self, key: LastTempKey, value: LastTemp) {
        drop(self.last_temp_schemas.insert(key, value));
    }

    /// Evict the TEMP schema region, as memory pressure would.
    #[cfg(test)]
    pub(super) fn evict_classifier_regions_for_test(&self) {
        self.last_temp_schemas.evict_all_for_test();
    }

    pub(crate) fn shared_name(&self, digest: [u8; 32]) -> Option<SharedNameId> {
        self.charged(|| self.shared_names.get(&digest).map(|id| *id))
    }
    pub(crate) fn insert_shared_name(&self, digest: [u8; 32], value: SharedNameId) {
        self.charged(|| drop(self.shared_names.insert(digest, value)));
    }
    pub(crate) fn go_prepared_context(
        &self,
        key: &GoPreparedContextCacheKey,
    ) -> Option<Retained<GoPreparedImportContextSnapshot>> {
        let value = self.go_prepared_contexts.get(key);
        #[cfg(any(test, feature = "test-support"))]
        if value.is_some() {
            self.go_prepared_context_hits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        value
    }
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn go_prepared_context_hits_for_test(&self) -> usize {
        self.go_prepared_context_hits
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    pub(crate) fn insert_go_prepared_context(
        &self,
        key: GoPreparedContextCacheKey,
        value: GoPreparedImportContextSnapshot,
    ) {
        drop(self.go_prepared_contexts.insert(key, value));
    }
    pub(super) fn rust_macro_include_overlay(
        &self,
        key: &[u8; 32],
    ) -> Option<Retained<PreparedMacroIncludeOverlay>> {
        let result = self.rust_macro_include_overlays.get(key);
        #[cfg(any(test, feature = "test-support"))]
        if result.is_some() {
            self.overlay_hits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }
    pub(super) fn insert_rust_macro_include_overlay(
        &self,
        key: [u8; 32],
        value: PreparedMacroIncludeOverlay,
    ) {
        drop(self.rust_macro_include_overlays.insert(key, value));
        #[cfg(any(test, feature = "test-support"))]
        self.overlay_inserts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    /// The resident bytes of every region, excluding evicted values that a
    /// caller still holds.
    #[cfg(any(test, feature = "test-support"))]
    pub fn weighted_bytes(&self) -> u64 {
        self.region_stats()
            .into_iter()
            .map(|(_, stats)| stats.accounted_bytes - stats.deferred_bytes)
            .sum()
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn allocated_bytes(&self) -> i64 {
        self.allocated.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn hit_count_for_test(&self) -> usize {
        self.overlay_hits.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn insert_count_for_test(&self) -> usize {
        self.overlay_inserts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn charged<T>(&self, operation: impl FnOnce() -> T) -> T {
        #[cfg(any(test, feature = "test-support"))]
        let before = super::resolution_operation::heap_pin_bytes();
        let result = operation();
        #[cfg(any(test, feature = "test-support"))]
        self.allocated.fetch_add(
            super::resolution_operation::heap_pin_bytes() - before,
            std::sync::atomic::Ordering::Relaxed,
        );
        result
    }
}

#[derive(Clone, Copy, Default)]
struct OwnerSlot {
    identity: usize,
    bytes: usize,
    expanded: bool,
}

#[derive(Default)]
struct OwnerRegistry {
    slots: Box<[OwnerSlot]>,
    len: usize,
}

impl OwnerRegistry {
    fn index(&self, identity: usize) -> usize {
        // Mix allocation alignment bits before probing the power-of-two table.
        let mut hash = identity as u64;
        hash ^= hash >> 30;
        hash = hash.wrapping_mul(0xbf58476d1ce4e5b9);
        hash ^= hash >> 27;
        hash = hash.wrapping_mul(0x94d049bb133111eb);
        hash ^= hash >> 31;
        let mut index = hash as usize & (self.slots.len() - 1);
        while self.slots[index].identity != 0 && self.slots[index].identity != identity {
            index = (index + 1) & (self.slots.len() - 1);
        }
        index
    }

    fn get(&self, identity: usize) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let slot = self.slots[self.index(identity)];
        (slot.identity != 0).then_some(slot.bytes)
    }
}

/// Temporary census for a single value. Aliases of shared immutable backing
/// allocations are charged once, not once per Arc handle. This set dies at the
/// end of weighing and is never retained by the store. Collection elements and
/// distinct Arc allocations contribute entries; other visits use `add_entries`.
#[derive(Default)]
pub struct RetainedHeap {
    allocation_estimator: Option<fn(usize) -> usize>,
    bytes: usize,
    entries: usize,
    shared: OwnerRegistry,
    owner: Option<usize>,
    exclusive_bytes: usize,
    limit: Option<usize>,
    scratch_bytes: usize,
    refused: bool,
    #[cfg(test)]
    registry_allocations: usize,
}
impl RetainedHeap {
    /// Census allocated storage for a pure evictable cache. The default and
    /// bounded constructors keep the unrounded refusing-admission computation.
    pub fn allocated() -> Self {
        Self {
            allocation_estimator: Some(brokk_bifrost_core::allocation_size::allocation_size),
            ..Self::default()
        }
    }
    pub fn allocation_bytes(&self, bytes: usize) -> usize {
        self.allocation_estimator
            .map_or(bytes, |estimate| estimate(bytes))
    }
    pub fn add_allocation(&mut self, bytes: usize) {
        self.add(self.allocation_bytes(bytes));
    }
    /// One allowance covers retained payload and live census scratch together.
    /// A refusal is terminal; callers must keep all recorded owners alive until
    /// this census is dropped, including when visiting another result.
    pub fn bounded(limit: usize) -> Self {
        Self {
            limit: Some(limit),
            ..Self::default()
        }
    }

    pub const fn is_refused(&self) -> bool {
        self.refused
    }
    pub fn refuse(&mut self) {
        self.refused = true;
    }
    pub const fn scratch_bytes(&self) -> usize {
        self.scratch_bytes
    }
    pub fn owner_count(&self) -> usize {
        self.shared.len
    }

    /// The live joint charge, or refusal. Ordinary byte getters remain payload
    /// censuses and exclude this temporary registry's storage.
    pub fn retained_total(&self) -> Option<usize> {
        if self.refused {
            None
        } else {
            self.bytes.checked_add(self.scratch_bytes)
        }
    }

    pub fn remaining_bytes(&self) -> usize {
        if self.refused {
            return 0;
        }
        self.limit.map_or(usize::MAX, |limit| {
            limit.saturating_sub(self.bytes.saturating_add(self.scratch_bytes))
        })
    }

    fn fits(&mut self, additional: usize) -> bool {
        if self.refused {
            return false;
        }
        if self.limit.is_some_and(|limit| {
            self.bytes
                .checked_add(self.scratch_bytes)
                .and_then(|bytes| bytes.checked_add(additional))
                .is_none_or(|bytes| bytes > limit)
        }) {
            self.refused = true;
            return false;
        }
        true
    }

    /// Admit scratch BEFORE allocation. Release only after its allocation drops.
    pub fn reserve_scratch(&mut self, bytes: usize) -> bool {
        if !self.fits(bytes) {
            return false;
        }
        let Some(total) = self.scratch_bytes.checked_add(bytes) else {
            self.refused = true;
            return false;
        };
        self.scratch_bytes = total;
        true
    }

    pub fn release_scratch(&mut self, bytes: usize) {
        self.scratch_bytes = self
            .scratch_bytes
            .checked_sub(bytes)
            .expect("only live funded scratch can be released");
    }

    fn register(&mut self, identity: usize, bytes: usize, prepaid: usize, expanded: bool) -> bool {
        let bytes = self.allocation_bytes(bytes);
        assert_ne!(identity, 0, "allocation identities are non-null");
        assert!(
            prepaid <= self.scratch_bytes,
            "prepaid storage must remain funded"
        );
        assert!(
            bytes <= prepaid || prepaid == 0,
            "allocation cannot exceed its preflighted storage"
        );
        if self.refused {
            return false;
        }
        if let Some(previous) = self.shared.get(identity) {
            let additional = bytes.saturating_sub(previous).saturating_sub(prepaid);
            if !self.fits(additional) {
                return false;
            }
            let index = self.shared.index(identity);
            let first_expansion = expanded && !self.shared.slots[index].expanded;
            self.shared.slots[index].expanded |= expanded;
            let additional = bytes.saturating_sub(previous);
            self.shared.slots[index].bytes = previous.saturating_add(additional);
            self.bytes = self.bytes.saturating_add(additional);
            self.release_scratch(prepaid);
            return first_expansion;
        }
        let additional = bytes.saturating_sub(prepaid);
        if !self.fits(additional) {
            return false;
        }
        if self.shared.len >= self.shared.slots.len() / 2 {
            let Some(capacity) = self.shared.slots.len().max(2).checked_mul(2) else {
                self.refused = true;
                return false;
            };
            let Some(storage) = capacity.checked_mul(std::mem::size_of::<OwnerSlot>()) else {
                self.refused = true;
                return false;
            };
            // Both tables coexist while rehashing. Include the new payload in
            // this peak check before allocating even the census replacement.
            let Some(peak) = storage.checked_add(additional) else {
                self.refused = true;
                return false;
            };
            if !self.fits(peak) || !self.reserve_scratch(storage) {
                return false;
            }
            #[cfg(test)]
            {
                self.registry_allocations += 1;
            }
            let mut slots = Box::<[OwnerSlot]>::new_uninit_slice(capacity);
            for slot in &mut slots {
                slot.write(OwnerSlot::default());
            }
            // SAFETY: every slot was initialized above; initialization cannot panic.
            let slots = unsafe { slots.assume_init() };
            let mut replacement = OwnerRegistry {
                slots,
                len: self.shared.len,
            };
            for slot in self.shared.slots.iter().filter(|slot| slot.identity != 0) {
                let index = replacement.index(slot.identity);
                replacement.slots[index] = *slot;
            }
            let old = std::mem::replace(&mut self.shared, replacement);
            let old_bytes = std::mem::size_of_val(old.slots.as_ref());
            drop(old);
            self.release_scratch(old_bytes);
        }
        let index = self.shared.index(identity);
        self.shared.slots[index] = OwnerSlot {
            identity,
            bytes,
            expanded,
        };
        self.shared.len += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        self.release_scratch(prepaid);
        true
    }

    /// Visit one actual allocation, whose byte weight already includes its
    /// inline storage. Child owners must be visited independently.
    pub fn allocation(&mut self, identity: usize, bytes: usize) -> bool {
        bytes != 0 && self.register(identity, bytes, 0, true)
    }

    /// Transfer already-funded allocation storage from scratch to its actual
    /// owner record. `actual_bytes` must not exceed the PREALLOCATION grant.
    /// Use exact boxed storage, or validate the allocator's capacity against
    /// that grant; this method never admits an excess after allocation.
    /// On refusal the prepaid charge remains until the caller drops storage
    /// and releases it. Rehashing is itself prepaid while this storage lives.
    pub fn adopt_allocation(
        &mut self,
        identity: usize,
        actual_bytes: usize,
        prepaid: usize,
    ) -> bool {
        assert!(
            actual_bytes <= prepaid,
            "adoption requires its preallocation grant"
        );
        if actual_bytes == 0 {
            self.release_scratch(prepaid);
            return false;
        }
        // Funding storage is not a visit of its children. The later ordinary
        // owner walk must still descend once, including into borrowed semantic
        // owners that were not copied by the metadata allocation.
        self.register(identity, actual_bytes, prepaid, false)
    }

    /// A Weak pins the control allocation but not the value's owned children.
    /// A later Arc visit expands this SAME record instead of hiding its heap.
    pub fn weak_allocation(&mut self, identity: usize, bytes: usize) {
        if identity != usize::MAX {
            self.register(identity, bytes, 0, false);
        }
    }

    pub fn add(&mut self, bytes: usize) {
        if !self.fits(bytes) {
            return;
        }
        self.bytes = self.bytes.saturating_add(bytes);
        if let Some(owner) = self.owner {
            let index = self.shared.index(owner);
            let retained = &mut self.shared.slots[index].bytes;
            *retained = retained.saturating_add(bytes);
        } else {
            self.exclusive_bytes = self.exclusive_bytes.saturating_add(bytes);
        }
    }
    pub fn exclusive_bytes(&self) -> usize {
        self.exclusive_bytes
    }
    /// Owner identities remain valid only while the measured owners are live.
    pub fn shared_allocations(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.shared
            .slots
            .iter()
            .filter(|slot| slot.identity != 0)
            .map(|slot| (slot.identity, slot.bytes))
    }
    pub fn add_entries(&mut self, entries: usize) {
        if !self.refused {
            self.entries = self.entries.saturating_add(entries);
        }
    }
    pub fn totals(self) -> (usize, usize) {
        (self.bytes, self.entries)
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn total(self) -> usize {
        self.bytes
    }
    pub fn slice<T>(&mut self, slice: &[T]) {
        self.add_allocation(std::mem::size_of_val(slice));
        self.add_entries(slice.len());
    }
    /// Census a borrowed view of one independently owned Box allocation.
    /// The caller keeps its owner alive until the pointer record is removed.
    /// Empty slices have no allocation identity.
    pub fn owned_slice<T>(&mut self, slice: &[T]) {
        let bytes = std::mem::size_of_val(slice);
        if bytes == 0 {
            return;
        }
        let identity = slice.as_ptr().cast::<()>() as usize;
        if self.register(identity, bytes, 0, true) {
            self.add_entries(slice.len());
        }
    }

    pub fn vec<T>(&mut self, values: &Vec<T>) {
        self.add_allocation(values.capacity().saturating_mul(std::mem::size_of::<T>()));
        self.add_entries(values.len());
    }
    pub fn map<K, V, S>(&mut self, values: &std::collections::HashMap<K, V, S>) {
        self.add_entries(values.len());
        self.add_allocation(brokk_bifrost_semantic::analyzer::semantic::service::retained_hash_table_bytes::<(K, V)>(values.capacity()));
    }
    pub fn hash_set<T, S>(&mut self, values: &std::collections::HashSet<T, S>) {
        self.add_entries(values.len());
        self.add_allocation(
            brokk_bifrost_semantic::analyzer::semantic::service::retained_hash_table_bytes::<T>(
                values.capacity(),
            ),
        );
    }
    pub fn arc<T: ?Sized>(&mut self, value: &Arc<T>, charge: impl FnOnce(&T, &mut Self)) {
        let identity = Arc::as_ptr(value).cast::<()>() as usize;
        let bytes =
            std::mem::size_of_val(&**value).saturating_add(2 * std::mem::size_of::<usize>());
        if self.register(identity, bytes, 0, true) {
            let previous_owner = self.owner.replace(identity);
            self.add_entries(1);
            charge(value, self);
            self.owner = previous_owner;
        }
    }
    fn btree_nodes<T>(&mut self, entries: usize) {
        self.add_entries(entries);
        // Existing conservative node model: eleven key slots, twelve child
        // pointers and header, allowing one node per five retained entries.
        self.add(entries.div_ceil(5).saturating_mul(
            self.allocation_bytes(
                11 * std::mem::size_of::<T>() + 14 * std::mem::size_of::<usize>(),
            ),
        ));
    }
    pub fn btree_set<T>(&mut self, values: &std::collections::BTreeSet<T>) {
        self.btree_nodes::<T>(values.len());
    }
    pub fn btree_map<K, V>(&mut self, values: &std::collections::BTreeMap<K, V>) {
        self.btree_nodes::<(K, V)>(values.len());
    }
}

impl brokk_bifrost_semantic::analyzer::semantic::service::RetentionCensusSink for RetainedHeap {
    fn allocation(&mut self, identity: usize, bytes: usize) -> bool {
        RetainedHeap::allocation(self, identity, bytes)
    }
    fn exclusive(&mut self, bytes: usize) {
        RetainedHeap::add(self, bytes);
    }
    fn reserve_scratch(&mut self, bytes: usize) -> bool {
        RetainedHeap::reserve_scratch(self, bytes)
    }
    fn release_scratch(&mut self, bytes: usize) {
        RetainedHeap::release_scratch(self, bytes);
    }
    fn is_refused(&self) -> bool {
        RetainedHeap::is_refused(self)
    }
    fn refuse(&mut self) {
        RetainedHeap::refuse(self);
    }
    fn weak_allocation(&mut self, identity: usize, bytes: usize) {
        RetainedHeap::weak_allocation(self, identity, bytes);
    }
}

/// Census one read key's owned allocations. The enclosing collection charges
/// the key's inline storage and the collection's own capacity separately.
pub fn retained_read_key(heap: &mut RetainedHeap, key: &crate::analyzer::read_ledger::ReadKey) {
    use crate::analyzer::read_ledger::{FactSubject, LookupQuestion, ReadKey};
    match key {
        ReadKey::File { rel_path, .. } | ReadKey::PathAbsent { rel_path, .. } => {
            heap.add(heap.allocation_bytes(rel_path.len()));
            heap.add_entries(1);
        }
        ReadKey::Index { key, .. } => {
            heap.add(heap.allocation_bytes(key.len()));
            heap.add_entries(1);
        }
        ReadKey::Lookup { question, .. } => match question {
            LookupQuestion::CertifiedDefinition {
                name, delegates, ..
            } => {
                heap.add(
                    heap.allocation_bytes(name.len())
                        .saturating_add(heap.allocation_bytes(
                            delegates.capacity() * std::mem::size_of::<crate::analyzer::Language>(),
                        )),
                );
                heap.add_entries(2);
            }
            LookupQuestion::StoredSemanticIrPublication(question) => {
                heap.add(
                    heap.allocation_bytes(question.rel_path.len())
                        .saturating_add(heap.allocation_bytes(question.storage_language.len())),
                );
                heap.add_entries(2);
            }
            // #9737 M3: persisted derivation replay is not available yet.
            LookupQuestion::Derivation(question) => {
                if let Some(path) = &question.rel_path {
                    heap.add(heap.allocation_bytes(path.len()));
                    heap.add_entries(1);
                }
                if let Some(name) = &question.name {
                    heap.add(heap.allocation_bytes(name.len()));
                    heap.add_entries(1);
                }
            }
            LookupQuestion::StructuralName { name, .. }
            | LookupQuestion::StructuralRoleName { name, .. } => {
                heap.add(heap.allocation_bytes(name.len()));
                heap.add_entries(1);
            }
            LookupQuestion::StructuralRecovered { .. }
            | LookupQuestion::ExternalSelection { .. } => {}
            LookupQuestion::RustDropSubject { rel_path, .. } => {
                heap.add(heap.allocation_bytes(rel_path.len()));
                heap.add_entries(1);
            }
            LookupQuestion::RustDropInventory {
                module_path,
                rel_path,
                ..
            } => {
                heap.add(
                    heap.allocation_bytes(module_path.len())
                        + heap.allocation_bytes(rel_path.len()),
                );
                heap.add_entries(1);
            }
            LookupQuestion::RustMacroInvocations {
                module_path,
                macro_name,
                ..
            } => {
                heap.add(
                    heap.allocation_bytes(module_path.len())
                        + heap.allocation_bytes(macro_name.len()),
                );
                heap.add_entries(2);
            }
            LookupQuestion::RustCopyAbsence { module_path, .. } => {
                heap.add(heap.allocation_bytes(module_path.len()));
                heap.add_entries(1);
            }
            LookupQuestion::Name { name, .. } => {
                heap.add(heap.allocation_bytes(name.len()));
                heap.add_entries(1);
            }
            LookupQuestion::Declaration {
                rel_path,
                fq_name,
                signature,
                ..
            } => {
                heap.add(
                    heap.allocation_bytes(rel_path.len())
                        .saturating_add(heap.allocation_bytes(fq_name.len())),
                );
                heap.add_entries(2);
                if let Some(signature) = signature {
                    heap.add(heap.allocation_bytes(signature.capacity()));
                    heap.add_entries(1);
                }
            }
            LookupQuestion::RustPlacedDeclaration { rel_path, .. }
            | LookupQuestion::File { rel_path }
            | LookupQuestion::CallSite { rel_path, .. } => {
                heap.add(heap.allocation_bytes(rel_path.len()));
                heap.add_entries(1);
            }
            LookupQuestion::ReceiverCallSite {
                rel_path,
                receiver_class,
                ..
            } => {
                heap.add(
                    heap.allocation_bytes(rel_path.len())
                        .saturating_add(heap.allocation_bytes(receiver_class.len())),
                );
                heap.add_entries(2);
            }
            LookupQuestion::Summary { .. } => {}
            LookupQuestion::WorkspaceFact { subject, .. } => {
                let mut string = |value: &str| {
                    heap.add(heap.allocation_bytes(value.len()));
                    heap.add_entries(1);
                };
                match subject {
                    FactSubject::Whole | FactSubject::Class { .. } => {}
                    FactSubject::File { rel_path } => string(rel_path),
                    FactSubject::Named { name } => string(name),
                    FactSubject::NamedMember { owner, member } => {
                        string(owner);
                        string(member);
                    }
                    FactSubject::ClassMember { member, .. } => string(member),
                    FactSubject::NameGroupMember { names, member } => {
                        string(member);
                        for name in names {
                            string(name);
                        }
                        heap.vec(names);
                    }
                    FactSubject::FileNamedMember {
                        rel_path,
                        owner,
                        member,
                        ..
                    } => {
                        string(rel_path);
                        string(owner);
                        string(member);
                    }
                }
            }
        },
        ReadKey::Artifact { rel_path, .. } => {
            if let Some(path) = rel_path {
                heap.add(heap.allocation_bytes(path.len()));
                heap.add_entries(1);
            }
        }
        ReadKey::Scope { languages, .. } => {
            heap.slice(languages);
        }
        ReadKey::Models(_)
        | ReadKey::Policy { .. }
        | ReadKey::Configuration(_)
        | ReadKey::Epoch(_) => {}
    }
}

#[derive(Default)]
struct CompositionCacheCounters {
    search: [std::sync::atomic::AtomicU64; 2],
    group: [std::sync::atomic::AtomicU64; 2],
    discovery: [std::sync::atomic::AtomicU64; 2],
}
#[doc(hidden)]
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct CompositionCacheStats {
    pub group_hits: u64,
    pub group_misses: u64,
    pub discovery_hits: u64,
    pub discovery_misses: u64,
    pub search_hits: u64,
    pub search_misses: u64,
    pub search_retained_bytes: u64,
    pub retained_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::RetainedHeap;
    use std::sync::Arc;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: joined input census allocated replacement owner tables before admitting their live peak"
    )]
    fn bounded_owner_registry_preflights_replacement_and_stops_after_refusal() {
        let owners = [Arc::new(1u64), Arc::new(2u64), Arc::new(3u64)];
        let mut reference = RetainedHeap::bounded(usize::MAX);
        for owner in &owners {
            reference.arc(owner, |_, _| {});
        }
        let final_bytes = reference.retained_total().expect("unlimited census");
        // Final storage fits, but the previous table must remain live during
        // replacement. Refusing that peak must happen BEFORE allocation.
        let mut tight = RetainedHeap::bounded(final_bytes);
        tight.arc(&owners[0], |_, _| {});
        tight.arc(&owners[1], |_, _| {});
        let allocations_before = tight.registry_allocations;
        let scratch_before = tight.scratch_bytes();
        tight.arc(&owners[2], |_, _| {
            panic!("refused owner must not be visited")
        });
        assert!(tight.is_refused());
        assert_eq!(tight.retained_total(), None);
        assert_eq!(tight.remaining_bytes(), 0);
        assert_eq!(tight.registry_allocations, allocations_before);
        assert_eq!(tight.scratch_bytes(), scratch_before);
        tight.arc(&owners[0], |_, _| panic!("terminal census must not resume"));
        let extra = vec![4u64, 5].into_boxed_slice();
        tight.owned_slice(&extra);
        assert_eq!(tight.registry_allocations, allocations_before);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: a weak control record must not hide a later strong owner's heap or charge aliases twice"
    )]
    fn bounded_census_expands_weak_controls_and_adopts_prepaid_storage() {
        let owner = Arc::new(vec![1u64, 2].into_boxed_slice());
        let weak = Arc::downgrade(&owner);
        let mut joined = RetainedHeap::bounded(usize::MAX);
        joined.weak_allocation(
            weak.as_ptr() as usize,
            std::mem::size_of_val(owner.as_ref()) + 2 * std::mem::size_of::<usize>(),
        );
        let mut visits = 0;
        let alias = Arc::clone(&owner);
        for alias in [&owner, &alias] {
            joined.arc(alias, |values, heap| {
                visits += 1;
                heap.owned_slice(values);
            });
        }
        assert_eq!(visits, 1);
        let mut direct = RetainedHeap::default();
        direct.arc(&owner, |values, heap| heap.owned_slice(values));
        assert_eq!(joined.bytes(), direct.bytes());
        assert_eq!(joined.owner_count(), direct.owner_count());

        let bytes = 7;
        assert!(joined.reserve_scratch(bytes));
        let allocation = vec![0u8; bytes].into_boxed_slice();
        let payload_before = joined.bytes();
        assert!(joined.adopt_allocation(allocation.as_ptr() as usize, allocation.len(), bytes));
        assert_eq!(joined.bytes(), payload_before + bytes);
        // Prepaying an allocation must not hide its as-yet-unvisited children.
        assert!(joined.allocation(allocation.as_ptr() as usize, bytes));
        assert!(!joined.allocation(allocation.as_ptr() as usize, bytes));
        let retained = joined.retained_total();
        joined.owned_slice(&allocation);
        assert_eq!(joined.retained_total(), retained);

        let mut refused = RetainedHeap::bounded(bytes);
        assert!(refused.reserve_scratch(bytes));
        let allocation = vec![0u8; bytes].into_boxed_slice();
        assert!(!refused.adopt_allocation(allocation.as_ptr() as usize, bytes, bytes));
        assert!(refused.is_refused());
        assert_eq!(refused.registry_allocations, 0);
        assert_eq!(refused.scratch_bytes(), bytes);
        drop(allocation);
        refused.release_scratch(bytes);
        assert_eq!(refused.scratch_bytes(), 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: context Box allocation ownership must agree across joined retained censuses"
    )]
    fn owned_slice_records_preserve_parent_owner_charge() {
        let owner: Arc<Box<[u64]>> = Arc::new(vec![1, 2].into_boxed_slice());
        let mut heap = RetainedHeap::default();
        heap.arc(&owner, |values, heap| {
            heap.add(1);
            heap.owned_slice(values);
            heap.add(2);
            heap.owned_slice(values);
            heap.owned_slice::<u64>(&[]);
        });
        let records: Vec<_> = heap.shared_allocations().collect();
        assert_eq!(records.len(), 2);
        let parent = std::mem::size_of_val(owner.as_ref()) + 2 * std::mem::size_of::<usize>() + 3;
        let child = std::mem::size_of_val(owner.as_ref().as_ref());
        assert!(records.contains(&(Arc::as_ptr(&owner) as usize, parent)));
        assert!(records.contains(&(owner.as_ref().as_ptr() as usize, child)));
        assert_eq!(heap.bytes(), parent + child);
        assert_eq!(heap.exclusive_bytes(), 0);
    }

    #[test]
    fn retained_heap_counts_aliased_allocations_and_entries_once() {
        let values = Arc::new(vec![1u64, 2]);
        let alias = Arc::clone(&values);
        let mut heap = RetainedHeap::default();
        let mut visits = 0;
        for value in [&values, &alias] {
            heap.arc(value, |values, heap| {
                visits += 1;
                heap.vec(values);
                heap.add_entries(3);
            });
        }
        let (bytes, entries) = heap.totals();
        let mut single = RetainedHeap::default();
        single.arc(&values, |values, heap| heap.vec(values));
        assert_eq!(bytes, single.total());
        assert_eq!(entries, 6); // One Arc, two elements, three explicit visits.
        assert_eq!(visits, 1);
    }
}

#[cfg(all(feature = "test-support", target_os = "linux"))]
#[doc(hidden)]
pub mod allocation_tests;
