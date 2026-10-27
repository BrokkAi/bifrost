//! One weighted retention budget for the store's cross-request relation caches.

#[cfg(any(test, feature = "test-support"))]
use super::python_binding_rows::PythonBindingRows;
use super::resolution_operation::PreparedMacroIncludeOverlay;
use super::resolution_operation::go_named::{
    GoPreparedContextCacheKey, GoPreparedImportContextSnapshot,
};
use super::semantic_composition::{
    ComposedGroup, ComposedGroupCacheKey, CompositionDiscoveryCacheKey, CompositionGroupKey,
    SearchCandidateStream, SemanticOverlayBuildIdentity,
};
use crate::analyzer::resolution::SharedNameId;
use moka::sync::Cache;
use std::sync::Arc;

/// Estimated retained storage, including inline payload and owned allocations.
/// This is an allocation census, not RSS; callers may pin evicted values.
pub trait RetainedBytes {
    fn retained_bytes(&self) -> usize;
}

/// Moka entry bookkeeping, enum tags/padding, and one Arc control block.
/// Payloads charge their own inline storage; this deliberately conservative
/// allowance is an estimate, independent of allocator and Moka internals.
const ENTRY_OVERHEAD_BYTES: usize = 512;

#[derive(Clone, Eq, PartialEq, Hash)]
enum StoreCacheKey {
    SearchCandidates(SemanticOverlayBuildIdentity),
    ComposedGroup(ComposedGroupCacheKey),
    CompositionDiscovery(CompositionDiscoveryCacheKey),
    SharedName([u8; 32]),
    GoPreparedContext(GoPreparedContextCacheKey),
    RustMacroIncludeOverlay([u8; 32]),
    #[cfg(any(test, feature = "test-support"))]
    PythonBindingRows {
        blob_oid: [u8; 20],
        format: i64,
    },
}

#[derive(Clone)]
enum StoreCacheValue {
    SearchCandidates(Arc<SearchCandidateStream>),
    ComposedGroup(Arc<ComposedGroup>),
    CompositionDiscovery(Arc<Vec<CompositionGroupKey>>),
    SharedName(SharedNameId),
    GoPreparedContext(Arc<GoPreparedImportContextSnapshot>),
    RustMacroIncludeOverlay(Arc<PreparedMacroIncludeOverlay>),
    #[cfg(any(test, feature = "test-support"))]
    PythonBindingRows(Arc<PythonBindingRows>),
}

impl RetainedBytes for [u8; 32] {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
    }
}
impl RetainedBytes for SharedNameId {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of_val(self)
    }
}
impl RetainedBytes for StoreCacheKey {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::SharedName(key) | Self::RustMacroIncludeOverlay(key) => key.retained_bytes(),
            Self::GoPreparedContext(key) => key.retained_bytes(),
            Self::SearchCandidates(key) => key.retained_bytes(),
            Self::ComposedGroup(key) => key.retained_bytes(),
            Self::CompositionDiscovery(key) => key.retained_bytes(),
            #[cfg(any(test, feature = "test-support"))]
            Self::PythonBindingRows { blob_oid, format } => {
                std::mem::size_of_val(blob_oid) + std::mem::size_of_val(format)
            }
        }
    }
}
impl RetainedBytes for StoreCacheValue {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::SharedName(value) => value.retained_bytes(),
            Self::SearchCandidates(value) => value.retained_bytes(),
            Self::ComposedGroup(value) => value.retained_bytes(),
            Self::CompositionDiscovery(value) => value.retained_bytes(),
            Self::GoPreparedContext(value) => value.retained_bytes(),
            Self::RustMacroIncludeOverlay(value) => value.retained_bytes(),
            #[cfg(any(test, feature = "test-support"))]
            Self::PythonBindingRows(value) => value.retained_bytes(),
        }
    }
}

/// Every clone shares the same cache and accounting; a request's name table
/// carries a handle so interning participates in the store's eviction order.
#[derive(Clone)]
pub struct StoreCacheBudget {
    entries: Cache<StoreCacheKey, StoreCacheValue>,
    budget_bytes: u64,
    composition_stats: Arc<CompositionCacheCounters>,
    #[cfg(any(test, feature = "test-support"))]
    allocated: Arc<std::sync::atomic::AtomicI64>,
    #[cfg(any(test, feature = "test-support"))]
    overlay_hits: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    overlay_inserts: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::fmt::Debug for StoreCacheBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreCacheBudget")
            .field("budget_bytes", &self.budget_bytes)
            .finish_non_exhaustive()
    }
}
impl Default for StoreCacheBudget {
    fn default() -> Self {
        Self::new(
            brokk_bifrost_core::analyzer::config::AnalyzerConfig::default()
                .store_cache_budget_bytes(),
        )
    }
}
impl StoreCacheBudget {
    pub fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            composition_stats: Arc::default(),
            entries: Cache::builder()
                .max_capacity(budget_bytes)
                .weigher(entry_weight)
                .build(),
            #[cfg(any(test, feature = "test-support"))]
            allocated: Arc::default(),
            #[cfg(any(test, feature = "test-support"))]
            overlay_hits: Arc::default(),
            #[cfg(any(test, feature = "test-support"))]
            overlay_inserts: Arc::default(),
        }
    }

    pub fn search_candidates(
        &self,
        build: SemanticOverlayBuildIdentity,
    ) -> Option<Arc<SearchCandidateStream>> {
        let result = match self.entries.get(&StoreCacheKey::SearchCandidates(build)) {
            Some(StoreCacheValue::SearchCandidates(value)) => Some(value),
            None => None,
            _ => unreachable!("search candidate key has a scalar stream value"),
        };
        self.composition_stats.search[result.is_some() as usize]
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        result
    }
    pub fn insert_search_candidates(
        &self,
        build: SemanticOverlayBuildIdentity,
        value: Arc<SearchCandidateStream>,
    ) {
        self.admit(
            StoreCacheKey::SearchCandidates(build),
            StoreCacheValue::SearchCandidates(value),
        );
    }
    pub fn composed_group(&self, key: &ComposedGroupCacheKey) -> Option<Arc<ComposedGroup>> {
        let result = match self.entries.get(&StoreCacheKey::ComposedGroup(key.clone())) {
            Some(StoreCacheValue::ComposedGroup(value)) => Some(value),
            None => None,
            _ => unreachable!("composition key has a composition value"),
        };
        self.composition_stats.group[result.is_some() as usize]
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        result
    }
    pub fn insert_composed_group(&self, key: ComposedGroupCacheKey, value: Arc<ComposedGroup>) {
        self.admit(
            StoreCacheKey::ComposedGroup(key),
            StoreCacheValue::ComposedGroup(value),
        );
    }
    pub fn composition_discovery(
        &self,
        key: &CompositionDiscoveryCacheKey,
    ) -> Option<Arc<Vec<CompositionGroupKey>>> {
        let result = match self
            .entries
            .get(&StoreCacheKey::CompositionDiscovery(key.clone()))
        {
            Some(StoreCacheValue::CompositionDiscovery(value)) => Some(value),
            None => None,
            _ => unreachable!("discovery key has a discovery value"),
        };
        self.composition_stats.discovery[result.is_some() as usize]
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        result
    }
    pub fn insert_composition_discovery(
        &self,
        key: CompositionDiscoveryCacheKey,
        value: Arc<Vec<CompositionGroupKey>>,
    ) {
        self.admit(
            StoreCacheKey::CompositionDiscovery(key),
            StoreCacheValue::CompositionDiscovery(value),
        );
    }
    #[doc(hidden)]
    pub fn composition_cache_stats(&self) -> CompositionCacheStats {
        use std::sync::atomic::Ordering::Relaxed;
        self.entries.run_pending_tasks();
        CompositionCacheStats {
            group_hits: self.composition_stats.group[1].load(Relaxed),
            group_misses: self.composition_stats.group[0].load(Relaxed),
            discovery_hits: self.composition_stats.discovery[1].load(Relaxed),
            discovery_misses: self.composition_stats.discovery[0].load(Relaxed),
            search_hits: self.composition_stats.search[1].load(Relaxed),
            search_misses: self.composition_stats.search[0].load(Relaxed),
            search_retained_bytes: self
                .entries
                .iter()
                .filter(|(key, _)| matches!(key.as_ref(), StoreCacheKey::SearchCandidates(_)))
                .map(|(key, value)| entry_weight(&key, &value) as u64)
                .sum(),
            retained_bytes: self.entries.weighted_size(),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn python_binding_rows(
        &self,
        blob_oid: [u8; 20],
        format: i64,
    ) -> Option<Arc<PythonBindingRows>> {
        match self
            .entries
            .get(&StoreCacheKey::PythonBindingRows { blob_oid, format })
        {
            Some(StoreCacheValue::PythonBindingRows(value)) => Some(value),
            None => None,
            _ => unreachable!("a Python binding key has a Python binding value"),
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn insert_python_binding_rows(
        &self,
        blob_oid: [u8; 20],
        format: i64,
        value: Arc<PythonBindingRows>,
    ) {
        self.admit(
            StoreCacheKey::PythonBindingRows { blob_oid, format },
            StoreCacheValue::PythonBindingRows(value),
        );
    }

    pub(crate) fn shared_name(&self, digest: [u8; 32]) -> Option<SharedNameId> {
        self.charged(
            || match self.entries.get(&StoreCacheKey::SharedName(digest)) {
                Some(StoreCacheValue::SharedName(value)) => Some(value),
                None => None,
                _ => unreachable!("a shared-name key has a shared-name value"),
            },
        )
    }
    pub(crate) fn insert_shared_name(&self, digest: [u8; 32], value: SharedNameId) {
        self.charged(|| {
            self.admit(
                StoreCacheKey::SharedName(digest),
                StoreCacheValue::SharedName(value),
            )
        });
    }
    pub(crate) fn go_prepared_context(
        &self,
        key: &GoPreparedContextCacheKey,
    ) -> Option<Arc<GoPreparedImportContextSnapshot>> {
        match self
            .entries
            .get(&StoreCacheKey::GoPreparedContext(key.clone()))
        {
            Some(StoreCacheValue::GoPreparedContext(value)) => Some(value),
            None => None,
            _ => unreachable!("a Go context key has a Go context value"),
        }
    }
    pub(crate) fn insert_go_prepared_context(
        &self,
        key: GoPreparedContextCacheKey,
        value: Arc<GoPreparedImportContextSnapshot>,
    ) {
        self.admit(
            StoreCacheKey::GoPreparedContext(key),
            StoreCacheValue::GoPreparedContext(value),
        );
    }
    pub(super) fn rust_macro_include_overlay(
        &self,
        key: &[u8; 32],
    ) -> Option<Arc<PreparedMacroIncludeOverlay>> {
        let result = match self
            .entries
            .get(&StoreCacheKey::RustMacroIncludeOverlay(*key))
        {
            Some(StoreCacheValue::RustMacroIncludeOverlay(value)) => Some(value),
            None => None,
            _ => unreachable!("an overlay key has an overlay value"),
        };
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
        value: Arc<PreparedMacroIncludeOverlay>,
    ) {
        self.admit(
            StoreCacheKey::RustMacroIncludeOverlay(key),
            StoreCacheValue::RustMacroIncludeOverlay(value),
        );
        #[cfg(any(test, feature = "test-support"))]
        self.overlay_inserts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn weighted_bytes(&self) -> u64 {
        self.entries.run_pending_tasks();
        self.entries.weighted_size()
    }
    /// Per-entry weights for manual corpus measurements, in stable order.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn entry_weights_for_test(&self) -> Vec<(&'static str, u32)> {
        self.entries.run_pending_tasks();
        let mut weights = self
            .entries
            .iter()
            .map(|(key, value)| {
                let kind = match &*key {
                    StoreCacheKey::SharedName(_) => "shared-name",
                    StoreCacheKey::ComposedGroup(_) => "composed-group",
                    StoreCacheKey::CompositionDiscovery(_) => "composition-discovery",
                    StoreCacheKey::SearchCandidates(_) => "search-candidates",
                    StoreCacheKey::GoPreparedContext(_) => "go-context",
                    StoreCacheKey::RustMacroIncludeOverlay(_) => "rust-overlay",
                    StoreCacheKey::PythonBindingRows { .. } => "python-binding-rows",
                };
                (kind, entry_weight(&key, &value))
            })
            .collect::<Vec<_>>();
        weights.sort_unstable();
        weights
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

    /// Every consumer inserts through here. Moka applies capacity maintenance
    /// asynchronously, so an entry heavier than the whole budget would stay
    /// visible to the next reader; refuse it instead and let it be reread.
    fn admit(&self, key: StoreCacheKey, value: StoreCacheValue) {
        if entry_bytes(&key, &value) as u64 > self.budget_bytes {
            return;
        }
        self.entries.insert(key, value);
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

fn entry_bytes(key: &StoreCacheKey, value: &StoreCacheValue) -> usize {
    key.retained_bytes()
        .saturating_add(value.retained_bytes())
        .saturating_add(ENTRY_OVERHEAD_BYTES)
}

fn entry_weight(key: &StoreCacheKey, value: &StoreCacheValue) -> u32 {
    entry_bytes(key, value).min(u32::MAX as usize) as u32
}

/// Temporary census for a single value. Aliases of shared immutable backing
/// allocations are charged once, not once per Arc handle. This set dies at the
/// end of weighing and is never retained by the store.
#[derive(Default)]
pub(crate) struct RetainedHeap {
    bytes: usize,
    shared: crate::hash::HashSet<usize>,
}
impl RetainedHeap {
    pub(crate) fn add(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
    pub(crate) fn total(self) -> usize {
        self.bytes
    }
    pub(crate) fn slice<T>(&mut self, slice: &[T]) {
        self.add(std::mem::size_of_val(slice));
    }
    pub(crate) fn vec<T>(&mut self, values: &Vec<T>) {
        self.add(values.capacity().saturating_mul(std::mem::size_of::<T>()));
    }
    pub(crate) fn map<K, V, S>(&mut self, values: &std::collections::HashMap<K, V, S>) {
        // Hashbrown's load factor reserves 1/8 of the buckets; each bucket
        // owns one control byte. Capacity excludes those reserved buckets.
        if values.capacity() != 0 {
            let buckets = values
                .capacity()
                .saturating_mul(8)
                .div_ceil(7)
                .next_power_of_two();
            self.add(
                buckets
                    .saturating_mul(std::mem::size_of::<(K, V)>() + 1)
                    .saturating_add(16),
            );
        }
    }
    pub(crate) fn hash_set<T, S>(&mut self, values: &std::collections::HashSet<T, S>) {
        if values.capacity() != 0 {
            let buckets = values
                .capacity()
                .saturating_mul(8)
                .div_ceil(7)
                .next_power_of_two();
            self.add(
                buckets
                    .saturating_mul(std::mem::size_of::<T>() + 1)
                    .saturating_add(16),
            );
        }
    }
    pub(crate) fn arc<T: ?Sized>(&mut self, value: &Arc<T>, charge: impl FnOnce(&T, &mut Self)) {
        if self.shared.insert(Arc::as_ptr(value).cast::<()>() as usize) {
            self.add(std::mem::size_of_val(&**value) + 2 * std::mem::size_of::<usize>());
            charge(value, self);
        }
    }
    pub(crate) fn btree_set<T>(&mut self, values: &std::collections::BTreeSet<T>) {
        // A non-root B-tree node holds at least five keys; allow one node
        // per five keys (including the root), with eleven key slots,
        // twelve child pointers and its header, even for a leaf.
        self.add(
            values
                .len()
                .div_ceil(5)
                .saturating_mul(11 * std::mem::size_of::<T>() + 14 * std::mem::size_of::<usize>()),
        );
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
