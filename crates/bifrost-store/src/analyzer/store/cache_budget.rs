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
        self.go_prepared_contexts.get(key)
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

/// Temporary census for a single value. Aliases of shared immutable backing
/// allocations are charged once, not once per Arc handle. This set dies at the
/// end of weighing and is never retained by the store. Collection elements and
/// distinct Arc allocations contribute entries; other visits use `add_entries`.
#[derive(Default)]
pub struct RetainedHeap {
    bytes: usize,
    entries: usize,
    shared: crate::hash::HashSet<usize>,
}
impl RetainedHeap {
    pub fn add(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
    /// Add visited entries independently of their retained byte charge.
    pub fn add_entries(&mut self, entries: usize) {
        self.entries = self.entries.saturating_add(entries);
    }
    /// Return retained bytes and visited entries from this census.
    pub fn totals(self) -> (usize, usize) {
        (self.bytes, self.entries)
    }
    pub fn total(self) -> usize {
        self.bytes
    }
    pub fn slice<T>(&mut self, slice: &[T]) {
        self.add(std::mem::size_of_val(slice));
        self.add_entries(slice.len());
    }
    pub fn vec<T>(&mut self, values: &Vec<T>) {
        self.add(values.capacity().saturating_mul(std::mem::size_of::<T>()));
        self.add_entries(values.len());
    }
    pub fn map<K, V, S>(&mut self, values: &std::collections::HashMap<K, V, S>) {
        self.add_entries(values.len());
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
    pub fn hash_set<T, S>(&mut self, values: &std::collections::HashSet<T, S>) {
        self.add_entries(values.len());
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
    pub fn arc<T: ?Sized>(&mut self, value: &Arc<T>, charge: impl FnOnce(&T, &mut Self)) {
        if self.shared.insert(Arc::as_ptr(value).cast::<()>() as usize) {
            self.add(std::mem::size_of_val(&**value) + 2 * std::mem::size_of::<usize>());
            self.add_entries(1);
            charge(value, self);
        }
    }
    pub fn btree_set<T>(&mut self, values: &std::collections::BTreeSet<T>) {
        self.add_entries(values.len());
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

/// Census one read key's owned allocations. The enclosing collection charges
/// the key's inline storage and the collection's own capacity separately.
pub fn retained_read_key(heap: &mut RetainedHeap, key: &crate::analyzer::read_ledger::ReadKey) {
    use crate::analyzer::read_ledger::{FactSubject, LookupQuestion, ReadKey};
    match key {
        ReadKey::File { rel_path, .. } | ReadKey::PathAbsent { rel_path, .. } => {
            heap.add(rel_path.len());
            heap.add_entries(1);
        }
        ReadKey::Index { key, .. } => {
            heap.add(key.len());
            heap.add_entries(1);
        }
        ReadKey::Lookup { question, .. } => match question {
            LookupQuestion::CertifiedDefinition {
                name, delegates, ..
            } => {
                heap.add(name.len().saturating_add(
                    delegates.capacity() * std::mem::size_of::<crate::analyzer::Language>(),
                ));
                heap.add_entries(2);
            }
            LookupQuestion::StoredSemanticIrPublication(question) => {
                heap.add(
                    question
                        .rel_path
                        .len()
                        .saturating_add(question.storage_language.len()),
                );
                heap.add_entries(2);
            }
            // #9737 M3: persisted derivation replay is not available yet.
            LookupQuestion::Derivation(question) => {
                if let Some(path) = &question.rel_path {
                    heap.add(path.len());
                    heap.add_entries(1);
                }
                if let Some(name) = &question.name {
                    heap.add(name.len());
                    heap.add_entries(1);
                }
            }
            LookupQuestion::StructuralName { name, .. }
            | LookupQuestion::StructuralRoleName { name, .. } => {
                heap.add(name.len());
                heap.add_entries(1);
            }
            LookupQuestion::StructuralRecovered { .. }
            | LookupQuestion::ExternalSelection { .. } => {}
            LookupQuestion::RustCopyAbsence { module_path, .. } => {
                heap.add(module_path.len());
                heap.add_entries(1);
            }
            LookupQuestion::Name { name, .. } => {
                heap.add(name.len());
                heap.add_entries(1);
            }
            LookupQuestion::Declaration {
                rel_path,
                fq_name,
                signature,
                ..
            } => {
                heap.add(rel_path.len().saturating_add(fq_name.len()));
                heap.add_entries(2);
                if let Some(signature) = signature {
                    heap.add(signature.capacity());
                    heap.add_entries(1);
                }
            }
            LookupQuestion::RustPlacedDeclaration { rel_path, .. }
            | LookupQuestion::File { rel_path }
            | LookupQuestion::CallSite { rel_path, .. } => {
                heap.add(rel_path.len());
                heap.add_entries(1);
            }
            LookupQuestion::Summary { .. } => {}
            LookupQuestion::WorkspaceFact { subject, .. } => {
                let mut string = |value: &str| {
                    heap.add(value.len());
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
                heap.add(path.len());
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
