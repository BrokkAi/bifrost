//! The capability surface a language analyzer exposes to structural search,
//! plus the content-keyed facts cache behind it.
//!
//! Follows the `import_analysis_provider()` idiom: `IAnalyzer` has a default
//! `structural_fact_providers()` returning nothing; each language analyzer
//! whose adapter supplies a [`super::spec::StructuralSpec`] exposes its inner
//! `TreeSitterAnalyzer` as a provider, and `MultiAnalyzer` concatenates its
//! delegates'. Each provider covers exactly one language.

use super::edges::EdgeAxis;
use super::extract::{LimitedFileFacts, extract_file_facts, extract_file_facts_limited};
use super::facts::{FileFacts, STRUCTURAL_FACTS_VERSION};
use super::kinds::{NormalizedKind, Role};
use super::materialization::MaterializationAxis;
use super::occurrences::OccurrenceRole;
use super::resolution::EnvironmentAxis;
use super::routes::{IdentityAxis, RouteHopKind};
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::store::StoreError;
use crate::analyzer::tree_sitter_analyzer::{
    LanguageAdapter, PreparedSourceFailure, PreparedSyntaxLimitedOutcome, PreparedSyntaxTree,
    StructuralSnapshotKey, TreeSitterAnalyzer,
};
use crate::analyzer::{CodeUnit, Language, ProjectFile, Range};
use crate::analyzer::{IAnalyzer, QueryScope};
use crate::cancellation::CancellationToken;
use moka::sync::Cache;
use rayon::prelude::*;
use std::cell::Cell;
use std::collections::HashMap;
use std::hash::Hasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::{self, ThreadId};
use std::time::Duration;

/// Opaque snapshot-local acceleration capability for built-in structural
/// providers. This type is public only so external implementations of
/// [`StructuralFactProvider`] can name the defaulted method's return type;
/// concrete cache representation and lifecycle remain crate-private.
#[doc(hidden)]
pub struct StructuralFactSnapshotCache {
    inner: super::index::SnapshotStructuralIndexCache,
}

impl StructuralFactSnapshotCache {
    pub(crate) fn new(memo_budget_bytes: u64) -> Self {
        Self {
            inner: super::index::SnapshotStructuralIndexCache::new(memo_budget_bytes),
        }
    }

    pub fn inner(&self) -> &super::index::SnapshotStructuralIndexCache {
        &self.inner
    }
}

/// What one provider's posting index would cover, measured before any fact is
/// acquired.
///
/// The posting index is roughly proportional to the source it indexes, so this
/// census is what lets the cache predict a build's retained size and its share
/// of the shared memo budget before spending the build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuralIndexCensus {
    /// Files this provider would index.
    pub files: u64,
    /// Their total source bytes.
    pub source_bytes: u64,
    /// Source bytes of every analyzable file in the workspace, across every
    /// analyzer language. A provider's share of this total is its share of the
    /// memo budget the providers apportion between them, so the apportioned
    /// parts sum to one budget however many providers there are.
    pub workspace_source_bytes: u64,
}

/// One file's length on disk, or zero when it cannot be measured.
fn source_bytes(file: &ProjectFile) -> u64 {
    std::fs::metadata(file.abs_path())
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

pub trait StructuralFactProvider: Send + Sync {
    fn structural_language(&self) -> Language;

    /// Every analyzed file of this provider's language, unsorted; callers
    /// order for determinism.
    fn structural_files(&self) -> Vec<ProjectFile>;

    /// Measure `files` without hydrating any source or acquiring any fact.
    ///
    /// `None` means this provider cannot answer, which leaves the build
    /// governed by its own construction limits exactly as before. Third-party
    /// providers keep that default; a provider that answers lets the index
    /// cache reject a build it could never retain before paying for it.
    fn structural_index_census(&self, _files: &[ProjectFile]) -> Option<StructuralIndexCensus> {
        None
    }

    /// Source for an analyzed file. Store-backed analyzers may hydrate this on
    /// demand instead of retaining every file's source in aggregate state.
    fn structural_source(&self, file: &ProjectFile) -> Option<String>;

    /// Capture one source snapshot without hydrating more than
    /// `max_source_bytes`. The default is deliberately unavailable so an
    /// external provider cannot accidentally satisfy a bounded request by
    /// calling the unbounded [`Self::structural_source`] method.
    fn structural_source_limited(
        &self,
        _file: &ProjectFile,
        _max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralSourceLimitedOutcome {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            StructuralSourceLimitedOutcome::Cancelled
        } else {
            StructuralSourceLimitedOutcome::Unavailable
        }
    }

    /// Prepare syntax from the already-admitted source snapshot with
    /// cooperative parse cancellation. The default is unavailable so bounded
    /// receiver analysis cannot silently fall back to an uncancellable parse
    /// through a third-party provider.
    fn structural_syntax_limited(
        &self,
        _file: &ProjectFile,
        _max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralSyntaxLimitedOutcome {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            StructuralSyntaxLimitedOutcome::Cancelled
        } else {
            StructuralSyntaxLimitedOutcome::Unavailable
        }
    }

    /// Normalized facts for one file, served from the facts cache and
    /// extracted from the in-memory source on miss. `None` when the file is
    /// not held by this analyzer, is empty, or the adapter has no structural
    /// spec.
    fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>>;

    /// Normalized facts plus the exact analyzer-generation cache outcome when
    /// the provider can report it. Third-party providers may retain the
    /// default `Unknown` outcome while still supplying facts normally.
    fn structural_facts_with_outcome(
        &self,
        file: &ProjectFile,
    ) -> (Option<Arc<FileFacts>>, StructuralFactsCacheOutcome) {
        (
            self.structural_facts(file),
            StructuralFactsCacheOutcome::Unknown,
        )
    }

    /// Enclose several ranges in one file using a provider-owned index when
    /// available. `None` means that the provider does not implement the batch
    /// capability, so callers must preserve the single-range fallback.
    ///
    /// The returned vector has one entry for every input range, in the same
    /// order. A `None` entry is a valid negative answer, not an unavailable
    /// capability.
    fn structural_enclosing_code_units(
        &self,
        _file: &ProjectFile,
        _ranges: &[Range],
    ) -> Option<Vec<Option<CodeUnit>>> {
        None
    }

    /// Materialize one complete facts snapshot without crossing
    /// `max_fact_nodes` total normalized nodes and semantic role edges, and
    /// stop cooperatively when `cancellation` fires.
    ///
    /// The exact source is supplied by the request so the source-byte
    /// admission and the normalized facts remain generation-coherent. The
    /// default is deliberately unavailable: third-party providers must opt
    /// into a genuinely bounded implementation rather than wrapping an
    /// unbounded [`Self::structural_facts`] call.
    fn structural_facts_limited(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _max_fact_nodes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralFactsLimitedOutcome {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            StructuralFactsLimitedOutcome::Cancelled
        } else {
            StructuralFactsLimitedOutcome::Unavailable
        }
    }

    /// How many extraction (parse + normalize) runs this provider has
    /// performed — i.e. facts-cache misses. Lets planner tests assert that
    /// pruning skipped a file and that repeated queries hit the cache.
    fn structural_extraction_count(&self) -> u64;

    /// How many facts-cache misses were satisfied by persisted relational rows
    /// rather than a tree-sitter parse and normalization pass.
    fn structural_hydration_count(&self) -> u64;

    fn structural_supports_kind(&self, kind: NormalizedKind) -> bool;

    fn structural_supports_role(&self, role: Role) -> bool;

    /// Whether exact normalized boolean-literal values are available. The
    /// default is unsupported for external providers so exact-value queries
    /// become incomplete instead of silently empty.
    fn structural_supports_boolean_literal_value(&self) -> bool {
        false
    }

    /// Whether AST-backed callable asyncness is available. External providers
    /// default to unsupported so missing facts are diagnosed.
    fn structural_supports_unsafe_context(&self) -> bool {
        false
    }

    fn structural_supports_async_callable_value(&self) -> bool {
        false
    }

    /// Whether decoded values of normalized string literals are available.
    /// The default is unsupported for external providers so exact-value
    /// queries become incomplete instead of silently empty.
    fn structural_supports_string_literal_value(&self) -> bool {
        false
    }

    /// Whether exact direct tuple/list assignment-shape facts are available.
    fn structural_supports_assignment_shape(&self) -> bool {
        false
    }

    /// Whether exact canonical values for integer literals are available.
    fn structural_supports_integer_literal_value(&self) -> bool {
        false
    }

    /// Whether the adapter can compare Python dictionary keys by decoded
    /// literal value and report unsupported forms as incomplete.
    fn structural_supports_duplicate_dictionary_keys(&self) -> bool {
        false
    }

    /// Whether the adapter classifies `role` during fact extraction. Total by
    /// construction: an adapter that declares nothing supports nothing.
    fn structural_supports_occurrence_role(&self, role: OccurrenceRole) -> bool;

    /// Whether the adapter answers `axis` of a file's lexical environment.
    /// Total by construction, exactly like the occurrence-role table above.
    fn structural_supports_environment_axis(&self, axis: EnvironmentAxis) -> bool;

    /// Whether the adapter answers `axis` of a file's declaration
    /// materialization. Total by construction, exactly like the two tables
    /// above.
    fn structural_supports_materialization_axis(&self, axis: MaterializationAxis) -> bool;
    /// Whether the adapter answers `axis` of the reference-edge domain.
    /// Total by construction, exactly like the two tables above.
    fn structural_supports_edge_axis(&self, axis: EdgeAxis) -> bool;
    /// Whether the adapter answers `axis` of the identity/route surface.
    fn structural_supports_identity_axis(&self, axis: IdentityAxis) -> bool;

    /// Whether the adapter supplies route edges for the `relation` kind of
    /// indirection. Total by construction.
    fn structural_supports_route_relation(&self, relation: RouteHopKind) -> bool;

    /// The content identity of this provider's analyzed file set (#2449).
    ///
    /// The posting index is keyed by it, so a provider that cannot answer gets
    /// no index reuse at all rather than reuse it cannot prove. That is the
    /// default for a third-party provider, which previously reported a
    /// constant zero generation and could therefore serve postings built from
    /// content it had since replaced.
    fn structural_content_identity(&self) -> Option<WorkspaceContentIdentity> {
        None
    }

    /// Snapshot-owned immutable posting cache. Third-party providers may keep
    /// the default and use scan-only execution.
    fn snapshot_structural_index_cache(&self) -> Option<&StructuralFactSnapshotCache> {
        None
    }
}

/// Where one structural-facts lookup was satisfied. This distinguishes the
/// analyzer-generation cache from request-local CodeQuery caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralFactsCacheOutcome {
    MemoryHit,
    PersistedHydration,
    Extracted,
    Unavailable,
    Unknown,
}

/// Result of bounded syntax preparation for receiver analysis.
#[doc(hidden)]
#[derive(Debug)]
pub enum StructuralSyntaxLimitedOutcome {
    Available(StructuralPreparedSyntax),
    Exceeded { minimum_source_bytes: usize },
    Cancelled,
    Unavailable,
}

/// Opaque prepared syntax returned by a structural provider. Its concrete
/// tree and declaration state remain internal to the analyzer.
#[doc(hidden)]
#[derive(Debug)]
pub struct StructuralPreparedSyntax {
    inner: Arc<PreparedSyntaxTree>,
}

impl StructuralPreparedSyntax {
    /// Exact prepared tree retained by this bounded syntax acquisition.
    pub fn prepared(&self) -> &PreparedSyntaxTree {
        &self.inner
    }

    /// Share this exact source snapshot with a semantic derivation without
    /// parsing or cloning its tree again.
    pub fn clone_prepared(&self) -> Arc<PreparedSyntaxTree> {
        Arc::clone(&self.inner)
    }

    #[doc(hidden)]
    pub fn into_inner(self) -> Arc<PreparedSyntaxTree> {
        self.inner
    }
}

#[derive(Debug)]
pub enum StructuralFactsLimitedOutcome {
    Available {
        facts: Arc<FileFacts>,
        cache_outcome: StructuralFactsCacheOutcome,
    },
    Exceeded {
        minimum_fact_nodes: usize,
    },
    Cancelled,
    Unavailable,
}

#[derive(Debug)]
pub enum StructuralSourceLimitedOutcome {
    Available(Arc<str>),
    Exceeded { minimum_source_bytes: usize },
    Cancelled,
    Unavailable,
}

/// Byte-budgeted facts cache keyed by the content its entries describe.
///
/// The key is the [`StructuralSnapshotKey`] the store persists the same facts
/// under: the blob oid of the source, the storage language key that fixes the
/// grammar, and that language's epoch generation. Keying by content rather
/// than by path is what lets a caller consult this cache *before* it fetches
/// the file's source (#3065). The workspace already knows a file's reusable
/// content identity, so a hit is one map lookup, where a path key made every
/// call -- hit or miss -- pay the source read the entry was then validated
/// against by hashing and comparing those same bytes twice more.
///
/// An entry is therefore exact by construction and nothing validates it. An
/// entry nothing asks for again -- an edited file's previous content, a
/// rotated epoch -- is retired by the byte budget rather than by a generation
/// rotation, which is the rule `SnapshotStructuralIndexCache` adopted in
/// #2449: a key that is still exact keeps answering across an `update()`.
///
/// The entries and the budget are shared by every language delegate of one
/// workspace (see `AnalyzerStoreContext::structural_facts`); the counters are
/// each delegate's own, so a provider still reports the work it did.
/// Follows the moka weigher idiom of the per-language memo caches
/// (`src/analyzer/java/cache.rs`).
pub struct StructuralFactsCache {
    cache: Cache<StructuralSnapshotKey, Arc<FileFacts>>,
    live: Arc<Mutex<LiveFacts>>,
    extractions: AtomicU64,
    hydrations: AtomicU64,
}

// In-flight queries can keep facts alive after the byte-capped cache evicts
// them. Share those allocations instead of hydrating another copy per query.
// Last-drop registrations release weak entries with their live holders: the
// heap-residency rule forbids dead entries outliving the queries holding them.
#[derive(Debug, Default)]
struct LiveFacts {
    entries: HashMap<StructuralSnapshotKey, Weak<FileFacts>>,
    building: HashMap<StructuralSnapshotKey, Arc<BuildSlot>>,
}

#[derive(Debug)]
struct BuildSlot {
    leader: ThreadId,
    done: Mutex<bool>,
    completed: Condvar,
}

// Dropping registered facts takes the live lock. Never drop a registered
// Arc<FileFacts> or insert into moka (which can evict facts) under that lock.
#[derive(Debug)]
pub(crate) struct LiveRegistration {
    registry: Weak<Mutex<LiveFacts>>,
    key: StructuralSnapshotKey,
}

impl Drop for LiveRegistration {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        // A panic here during unwinding would abort the process; removing a
        // dead entry is safe whatever left the lock poisoned.
        let mut live = registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if live
            .entries
            .get(&self.key)
            .is_some_and(|facts| facts.strong_count() == 0)
        {
            live.entries.remove(&self.key);
        }
        if live.entries.capacity() > 64 && live.entries.len() * 4 < live.entries.capacity() {
            live.entries.shrink_to_fit();
        }
    }
}

thread_local! {
    // Build slots this thread currently leads. A leader must never wait for
    // another key's build: two leaders waiting on each other's keys would
    // deadlock. Building one file's facts never requests another file's
    // facts, so this holds by construction; the wait path asserts it.
    static HELD_BUILD_SLOTS: Cell<usize> = const { Cell::new(0) };
}

/// The cheap identity of one in-memory source string, which the analyzer's
/// blob-oid memo (`TreeSitterAnalyzer::content_oid_of`) recognizes repeat bytes by.
pub(crate) fn hash_source(source: &str) -> u64 {
    let mut hasher = rustc_hash::FxHasher::default();
    hasher.write(source.as_bytes());
    hasher.finish()
}

fn weigh_entry(_key: &StructuralSnapshotKey, value: &Arc<FileFacts>) -> u32 {
    let bytes = std::mem::size_of::<StructuralSnapshotKey>() as u64 + value.estimated_bytes();
    bytes.clamp(1, u32::MAX as u64) as u32
}

impl StructuralFactsCache {
    pub(crate) fn new(budget_bytes: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(budget_bytes.max(1))
                .weigher(weigh_entry)
                .build(),
            live: Arc::new(Mutex::new(LiveFacts::default())),
            extractions: AtomicU64::new(0),
            hydrations: AtomicU64::new(0),
        }
    }

    /// Another view of the same entries under the same budget, counting its
    /// own work. This is how the language delegates of one workspace share one
    /// pool: a moka cache clone shares the store it was cloned from.
    pub(crate) fn sharing_entries(&self) -> Self {
        Self {
            cache: self.cache.clone(),
            live: Arc::clone(&self.live),
            extractions: AtomicU64::new(0),
            hydrations: AtomicU64::new(0),
        }
    }

    /// Hydrate this content's facts from the store, or extract them, and
    /// memoize the result.
    ///
    /// The caller has already asked [`Self::get`] for this key and been told
    /// no. Asking again here would cost more than the lookup: a cache read is
    /// also a vote in moka's admission policy, and voting twice for content
    /// this pass has not seen before makes it look twice as popular as the
    /// entry it would displace, which turns a warm working set into a cache
    /// that evicts what it is about to be asked for (measured on django and
    /// shardingsphere for #3065: a second forward pass fell from 688-1115
    /// memory hits to none).
    fn materialize(
        &self,
        key: StructuralSnapshotKey,
        load: impl FnOnce() -> Option<FileFacts>,
        extract: impl FnOnce() -> Option<FileFacts>,
    ) -> (Option<Arc<FileFacts>>, StructuralFactsCacheOutcome) {
        match self.reuse_or_build(
            Some(key),
            || false,
            || {
                if let Some(facts) = load() {
                    self.record_hydration();
                    Ok((
                        Arc::new(facts),
                        StructuralFactsCacheOutcome::PersistedHydration,
                    ))
                } else {
                    self.record_extraction();
                    let facts = extract().ok_or(StructuralFactsCacheOutcome::Unavailable)?;
                    Ok((Arc::new(facts), StructuralFactsCacheOutcome::Extracted))
                }
            },
        ) {
            Ok((facts, outcome)) => (Some(facts), outcome),
            Err(outcome) => (None, outcome),
        }
    }

    // The caller already missed in moka. Do not cast a second admission vote.
    // Waiters retry with their own build after failure or cancellation: a
    // leader's error belongs to its request, not to requests waiting for facts.
    fn reuse_or_build<E>(
        &self,
        key: Option<StructuralSnapshotKey>,
        cancelled: impl Fn() -> bool,
        build: impl FnOnce() -> Result<(Arc<FileFacts>, StructuralFactsCacheOutcome), E>,
    ) -> Result<(Arc<FileFacts>, StructuralFactsCacheOutcome), E> {
        let Some(key) = key else {
            return build();
        };
        struct Building<'a> {
            live: &'a Mutex<LiveFacts>,
            key: StructuralSnapshotKey,
            slot: Arc<BuildSlot>,
        }

        impl Drop for Building<'_> {
            fn drop(&mut self) {
                HELD_BUILD_SLOTS.with(|held| held.set(held.get() - 1));
                self.live
                    .lock()
                    .expect("live facts lock poisoned")
                    .building
                    .remove(&self.key);
                *self.slot.done.lock().expect("build slot lock poisoned") = true;
                self.slot.completed.notify_all();
            }
        }

        let _building = 'choose: loop {
            let mut live = self.live.lock().expect("live facts lock poisoned");
            if let Some(facts) = live.entries.get(&key).and_then(Weak::upgrade) {
                drop(live);
                self.cache.insert(key, Arc::clone(&facts));
                return Ok((facts, StructuralFactsCacheOutcome::MemoryHit));
            }
            if let Some(slot) = live.building.get(&key) {
                // A same-thread recursive request cannot wait for itself.
                // Build without a slot and adopt its result normally below.
                if slot.leader == thread::current().id() {
                    break None;
                }
                let slot = Arc::clone(slot);
                drop(live);
                debug_assert_eq!(
                    HELD_BUILD_SLOTS.with(Cell::get),
                    0,
                    "#7116: a structural facts build leader must not wait for another key's build"
                );
                let mut done = slot.done.lock().expect("build slot lock poisoned");
                while !*done {
                    // A cancelled request must run its own closure promptly,
                    // without waiting for another request's build to finish.
                    if cancelled() {
                        break 'choose None;
                    }
                    done = slot
                        .completed
                        .wait_timeout(done, Duration::from_millis(25))
                        .expect("build slot lock poisoned")
                        .0;
                }
            } else {
                let slot = Arc::new(BuildSlot {
                    leader: thread::current().id(),
                    done: Mutex::new(false),
                    completed: Condvar::new(),
                });
                live.building.insert(key, Arc::clone(&slot));
                HELD_BUILD_SLOTS.with(|held| held.set(held.get() + 1));
                break Some(Building {
                    live: &self.live,
                    key,
                    slot,
                });
            }
        };
        let (facts, outcome) = build()?;
        let existing = {
            let mut live = self.live.lock().expect("live facts lock poisoned");
            // Re-entrant and cancelled no-slot builds can publish first.
            if let Some(existing) = live.entries.get(&key).and_then(Weak::upgrade) {
                Some(existing)
            } else {
                facts
                    .live_registration
                    .set(LiveRegistration {
                        registry: Arc::downgrade(&self.live),
                        key,
                    })
                    .expect("fresh facts must not already be registered");
                live.entries.insert(key, Arc::downgrade(&facts));
                None
            }
        };
        // In particular, drop a losing allocation only after unlocking.
        let facts = existing.unwrap_or(facts);
        self.cache.insert(key, Arc::clone(&facts));
        Ok((facts, outcome))
    }

    #[doc(hidden)]
    pub fn get(&self, key: &StructuralSnapshotKey) -> Option<Arc<FileFacts>> {
        self.cache.get(key)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn take_for_heap_test(&self, key: &StructuralSnapshotKey) -> Option<Arc<FileFacts>> {
        let facts = self.cache.get(key)?;
        let capacity = self
            .cache
            .policy()
            .max_capacity()
            .expect("structural facts have an explicit byte cap");
        assert!(u64::from(weigh_entry(key, &facts)) <= capacity);
        // Called only after the original heap measurement. Hand the entry's
        // ownership to the test so its destructor can attribute actual bytes
        // without counting cache maintenance as request-owned releases.
        self.cache.invalidate(key);
        self.cache.run_pending_tasks();
        Some(facts)
    }

    fn record_extraction(&self) {
        self.extractions.fetch_add(1, Ordering::Relaxed);
    }

    fn record_hydration(&self) {
        self.hydrations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn extraction_count(&self) -> u64 {
        self.extractions.load(Ordering::Relaxed)
    }

    pub fn hydration_count(&self) -> u64 {
        self.hydrations.load(Ordering::Relaxed)
    }
}

impl<A: LanguageAdapter> TreeSitterAnalyzer<A> {
    fn canonical_structural_facts_with_outcome(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> (Option<Arc<FileFacts>>, StructuralFactsCacheOutcome) {
        let snapshot_key = self.structural_snapshot_key(file, source);
        if let Some(key) = snapshot_key.as_ref()
            && let Some(facts) = self.structural_cache().get(key)
        {
            return (Some(facts), StructuralFactsCacheOutcome::MemoryHit);
        }

        let build = || {
            let read = if let Some(key) = snapshot_key.as_ref() {
                match self.load_structural_facts_rows_limited(
                    key,
                    STRUCTURAL_FACTS_VERSION,
                    usize::MAX,
                    None,
                ) {
                    Ok(read) => Some(read),
                    Err(error) => {
                        self.record_store_error(
                            error.context("loading canonical structural facts"),
                        );
                        return Err((None, StructuralFactsCacheOutcome::Unavailable));
                    }
                }
            } else {
                None
            };

            match read {
                Some(crate::analyzer::store::StructuralFactRowsRead::Ready(rows)) => {
                    let facts = match FileFacts::from_persisted_rows(source.to_owned(), rows) {
                        Ok(facts) => Arc::new(facts),
                        Err(error) => {
                            self.record_store_error(StoreError::new(format!(
                                "invalid canonical structural facts: {error}"
                            )));
                            return Err((None, StructuralFactsCacheOutcome::Unavailable));
                        }
                    };
                    self.structural_cache().record_hydration();
                    return Ok((facts, StructuralFactsCacheOutcome::PersistedHydration));
                }
                Some(crate::analyzer::store::StructuralFactRowsRead::Exceeded { .. }) => {
                    unreachable!("unbounded canonical structural facts load exceeded")
                }
                Some(crate::analyzer::store::StructuralFactRowsRead::Cancelled) => {
                    return Err((None, StructuralFactsCacheOutcome::Unavailable));
                }
                Some(crate::analyzer::store::StructuralFactRowsRead::Unavailable) | None => {}
            }

            if let Some(state) = self.cached_canonical_source_state(file, source) {
                let source_facts = state.source_facts.as_ref().expect("canonical source state");
                let facts = Arc::new(FileFacts::from_source_and_rows(
                    source.to_owned(),
                    source_facts.occurrences.clone(),
                    source_facts.structural.clone(),
                ));
                return Ok((facts, StructuralFactsCacheOutcome::MemoryHit));
            }

            // New query source can enter ordinary primary analysis, but missing
            // facts for an indexed source must not be repaired by a reader.
            if crate::analyzer::CodeUnitIndex::indexed_source_matches(self, file, source) {
                self.record_store_error(StoreError::new(format!(
                    "required canonical structural source publication unavailable for {file:?}"
                )));
                return Err((None, StructuralFactsCacheOutcome::Unavailable));
            }

            let Some(source_facts) = self.prepare_canonical_source_facts(file, source.to_owned())
            else {
                return Err((None, StructuralFactsCacheOutcome::Unavailable));
            };
            self.structural_cache().record_extraction();
            // Preparation publishes the parse. Read the published rows back so the
            // recovered regions carry the store's containment answer (#3777). When
            // publication failed the store has no rows, and the parse's own rows,
            // whose regions have no answer, are the facts.
            let published = snapshot_key.as_ref().and_then(|key| {
                match self.load_structural_facts_rows_limited(
                    key,
                    STRUCTURAL_FACTS_VERSION,
                    usize::MAX,
                    None,
                ) {
                    Ok(crate::analyzer::store::StructuralFactRowsRead::Ready(rows)) => Some(rows),
                    Ok(crate::analyzer::store::StructuralFactRowsRead::Unavailable) => None,
                    Ok(
                        crate::analyzer::store::StructuralFactRowsRead::Exceeded { .. }
                        | crate::analyzer::store::StructuralFactRowsRead::Cancelled,
                    ) => unreachable!("an unbounded, uncancellable read cannot stop early"),
                    Err(error) => {
                        self.record_store_error(
                            error.context("reading back prepared canonical structural facts"),
                        );
                        self.mark_execution_dependent();
                        None
                    }
                }
            });
            let retainable = published.is_some();
            let facts = match published {
                Some(rows) => match FileFacts::from_persisted_rows(source.to_owned(), rows) {
                    Ok(facts) => facts,
                    Err(error) => {
                        self.record_store_error(StoreError::new(format!(
                            "invalid prepared canonical structural facts: {error}"
                        )));
                        return Err((None, StructuralFactsCacheOutcome::Unavailable));
                    }
                },
                None => FileFacts::from_source_and_rows(
                    source.to_owned(),
                    source_facts.occurrences,
                    source_facts.structural,
                ),
            };
            let facts = Arc::new(facts);
            if retainable {
                Ok((facts, StructuralFactsCacheOutcome::Extracted))
            } else {
                // The fallback lacks store containment answers (#7311). An
                // owned refusal must bypass both moka and live-facts sharing.
                Err((Some(facts), StructuralFactsCacheOutcome::Extracted))
            }
        };
        match self
            .structural_cache()
            .reuse_or_build(snapshot_key, || false, build)
        {
            Ok((facts, outcome)) => (Some(facts), outcome),
            Err(attempt) => attempt,
        }
    }

    fn cached_canonical_facts_limited(
        &self,
        file: &ProjectFile,
        source: &str,
        max_fact_nodes: usize,
    ) -> Option<StructuralFactsLimitedOutcome> {
        let state = self.cached_canonical_source_state(file, source)?;
        let source_facts = state
            .source_facts
            .as_ref()
            .expect("cached canonical source state must carry source facts");
        let work_items = source_facts.structural.work_item_count();
        if work_items > max_fact_nodes {
            return Some(StructuralFactsLimitedOutcome::Exceeded {
                minimum_fact_nodes: work_items,
            });
        }
        let facts = Arc::new(FileFacts::from_source_and_rows(
            source.to_owned(),
            source_facts.occurrences.clone(),
            source_facts.structural.clone(),
        ));
        Some(StructuralFactsLimitedOutcome::Available {
            facts,
            cache_outcome: StructuralFactsCacheOutcome::MemoryHit,
        })
    }

    /// Whether a structural question about `file` is this provider's to
    /// answer. Every caller asks all providers and takes the first answer, so
    /// a provider that read a foreign file would parse it with the wrong
    /// grammar and publish facts for a file it never indexed: a Python
    /// provider handed bcc's 4.8 MB `vmlinux.h` spent minutes extracting
    /// facts from a flat error tree on every definition lookup. The owner is
    /// decided the way indexing decides it (`adapter_owns_file`), including
    /// include-claimed files (#1837).
    fn owns_structural_file(&self, file: &ProjectFile) -> bool {
        self.adapter_owns_file(file, &self.live_path_snapshot())
    }
}

impl<A: LanguageAdapter> StructuralFactProvider for TreeSitterAnalyzer<A> {
    fn structural_language(&self) -> Language {
        self.adapter().language()
    }

    fn structural_files(&self) -> Vec<ProjectFile> {
        self.all_files()
    }

    /// Measure the files from their own on-disk lengths, and the workspace
    /// they share with the other providers the same way.
    ///
    /// This is a prediction, not the analyzed text: hydrating every source to
    /// measure it exactly would cost as much as the build the prediction
    /// exists to avoid. A file whose length cannot be read (an overlay-only
    /// buffer, a race with a delete) contributes nothing, which can only
    /// shrink the estimate and therefore can only admit a build, never reject
    /// one that would have fitted.
    ///
    /// The workspace total walks the project's own shared listing, so it costs
    /// one `stat` per analyzable file and no source read. Without a listing
    /// there is no denominator to apportion the shared memo budget with, so the
    /// whole census is unavailable and the cache falls back to its fixed share.
    fn structural_index_census(&self, files: &[ProjectFile]) -> Option<StructuralIndexCensus> {
        let listing = self.project().all_files_shared().ok()?;
        let analyzer_languages = self.project().analyzer_languages();
        let analyzable: Vec<&ProjectFile> = listing
            .iter()
            .filter(|file| analyzer_languages.contains(&file.language()))
            .collect();
        let workspace_source_bytes = analyzable.par_iter().map(|file| source_bytes(file)).sum();
        let source_bytes = files.par_iter().map(source_bytes).sum();
        Some(StructuralIndexCensus {
            files: files.len() as u64,
            source_bytes,
            workspace_source_bytes,
        })
    }

    fn structural_source(&self, file: &ProjectFile) -> Option<String> {
        if !self.owns_structural_file(file) {
            return None;
        }
        if self.adapter().produces_canonical_source_facts() {
            self.source_snapshot_for_structural_facts(file)
        } else {
            self.file_source(file)
        }
    }

    fn structural_source_limited(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralSourceLimitedOutcome {
        if !self.owns_structural_file(file) {
            return StructuralSourceLimitedOutcome::Unavailable;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return StructuralSourceLimitedOutcome::Cancelled;
        }
        if !self.owns_file(file) {
            return StructuralSourceLimitedOutcome::Unavailable;
        }
        let snapshot = match self.source_snapshot_limited(file, max_source_bytes) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return StructuralSourceLimitedOutcome::Unavailable,
            Err(PreparedSourceFailure::Refused(_)) => {
                return StructuralSourceLimitedOutcome::Unavailable;
            }
            Err(PreparedSourceFailure::Exceeded(exceeded)) => {
                return StructuralSourceLimitedOutcome::Exceeded {
                    minimum_source_bytes: exceeded.minimum_source_bytes(),
                };
            }
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            StructuralSourceLimitedOutcome::Cancelled
        } else {
            if self.adapter().produces_canonical_source_facts() {
                // This snapshot already passed the bounded source admission
                // check. Keep its raw blob identity for read-ledger
                // invalidation, including when fact materialization hits a
                // persisted or in-memory canonical result.
                self.record_reads(|sink| sink.push(self.file_read_key(file, snapshot.0)));
            }
            StructuralSourceLimitedOutcome::Available(snapshot.1.into_source())
        }
    }

    fn structural_syntax_limited(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralSyntaxLimitedOutcome {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return StructuralSyntaxLimitedOutcome::Cancelled;
        }
        if !self.owns_structural_file(file) {
            return StructuralSyntaxLimitedOutcome::Unavailable;
        }
        let scope = crate::analyzer::AnalyzerQueryScope::new(self);
        match self.prepared_syntax_limited_cancellable(
            scope.token(),
            file,
            max_source_bytes,
            cancellation,
        ) {
            PreparedSyntaxLimitedOutcome::Available(_, inner) => {
                StructuralSyntaxLimitedOutcome::Available(StructuralPreparedSyntax { inner })
            }
            PreparedSyntaxLimitedOutcome::Exceeded(exceeded) => {
                StructuralSyntaxLimitedOutcome::Exceeded {
                    minimum_source_bytes: exceeded.minimum_source_bytes(),
                }
            }
            PreparedSyntaxLimitedOutcome::Cancelled => StructuralSyntaxLimitedOutcome::Cancelled,
            PreparedSyntaxLimitedOutcome::Unavailable
            | PreparedSyntaxLimitedOutcome::Refused(_) => {
                StructuralSyntaxLimitedOutcome::Unavailable
            }
        }
    }

    fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>> {
        self.structural_facts_with_outcome(file).0
    }

    fn structural_facts_with_outcome(
        &self,
        file: &ProjectFile,
    ) -> (Option<Arc<FileFacts>>, StructuralFactsCacheOutcome) {
        let Some(spec) = self.adapter().structural_spec() else {
            return (None, StructuralFactsCacheOutcome::Unavailable);
        };
        if !self.owns_structural_file(file) {
            return (None, StructuralFactsCacheOutcome::Unavailable);
        }
        // Ask the memo for this file's content before reading that content.
        // The workspace's reusable identity for a file is exactly the key its
        // facts are memoized under, and answering it costs a map lookup (one
        // stat where the analyzer does not trust its filesystem generation),
        // against the 0.6-1.5 ms the source read below costs on a real
        // repository (#3065). `reusable_live_oid` answers `None` for every
        // file whose recorded identity is not provably its current content --
        // an overlay above all -- so a hit here is a hit on the same bytes
        // `file_source` would have returned, and a `None` leaves the key to
        // the bytes themselves below.
        let probed = self
            .reusable_live_oid(file)
            .and_then(|oid| Some((oid, self.structural_facts_key(file, oid)?)));
        if let Some((oid, key)) = probed
            && let Some(facts) = self.structural_cache().get(&key)
        {
            self.record_reads(|sink| sink.push(self.file_read_key(file, oid)));
            return (Some(facts), StructuralFactsCacheOutcome::MemoryHit);
        }
        if self.adapter().produces_canonical_source_facts() {
            let Some(source) = self.structural_source(file) else {
                return (None, StructuralFactsCacheOutcome::Unavailable);
            };
            let Some(content_oid) = self.content_oid_of(file, &source) else {
                // The source was available, but its admitted blob identity
                // disappeared between the source and identity observations.
                // There is no attributable file read or sound cache key in
                // that case, so preserve the unavailable result.
                return (None, StructuralFactsCacheOutcome::Unavailable);
            };
            self.record_reads(|sink| sink.push(self.file_read_key(file, content_oid)));
            return self.canonical_structural_facts_with_outcome(file, &source);
        }
        let Some(source) = self.file_source(file) else {
            return (None, StructuralFactsCacheOutcome::Unavailable);
        };
        let Some(content_oid) = self.content_oid_of(file, &source) else {
            // `file_source` answered, so this file had content a moment ago:
            // bytes on disk, an overlay, or an indexed blob the live path map
            // still names. Each of those carries an identity, so the only way
            // to arrive here is a file that vanished between the two reads,
            // and there is then nothing to name the read or key the facts by.
            return (None, StructuralFactsCacheOutcome::Unavailable);
        };
        // The structural facts of one file are a per-file read of exactly these
        // bytes, recorded whether the cache, the store, or a fresh extraction
        // answers: all three are the same input.
        self.record_reads(|sink| sink.push(self.file_read_key(file, content_oid)));
        let key = match probed {
            // The probe and source read are separate observations. An overlay
            // or file replacement between them may change the content; only
            // an unchanged identity has already missed in the memo.
            Some((oid, key)) if oid == content_oid => key,
            _ => {
                let Some(key) = self.structural_facts_key(file, content_oid) else {
                    // This analyzer publishes no epoch for the file's storage
                    // language, so it has no key to memoize or persist under.
                    // Answer from the grammar it does have and keep nothing.
                    let grammar = self.adapter().parser_language_for_file(file);
                    self.structural_cache().record_extraction();
                    return match extract_file_facts(spec, &grammar, &source) {
                        Some(facts) => (
                            Some(Arc::new(facts)),
                            StructuralFactsCacheOutcome::Extracted,
                        ),
                        None => (None, StructuralFactsCacheOutcome::Unavailable),
                    };
                };
                if let Some(facts) = self.structural_cache().get(&key) {
                    return (Some(facts), StructuralFactsCacheOutcome::MemoryHit);
                }
                key
            }
        };
        self.structural_cache().materialize(
            key,
            || None,
            || {
                let grammar = self.adapter().parser_language_for_file(file);
                let facts = extract_file_facts(spec, &grammar, &source)?;
                Some(facts)
            },
        )
    }

    fn structural_enclosing_code_units(
        &self,
        file: &ProjectFile,
        ranges: &[Range],
    ) -> Option<Vec<Option<CodeUnit>>> {
        self.enclosing_code_units_for_ranges(file, ranges)
    }

    fn structural_facts_limited(
        &self,
        file: &ProjectFile,
        source: &str,
        max_fact_nodes: usize,
        cancellation: Option<&CancellationToken>,
    ) -> StructuralFactsLimitedOutcome {
        let Some(spec) = self.adapter().structural_spec() else {
            return StructuralFactsLimitedOutcome::Unavailable;
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return StructuralFactsLimitedOutcome::Cancelled;
        }
        if !self.owns_file(file) {
            return StructuralFactsLimitedOutcome::Unavailable;
        }
        // The caller already holds the admitted snapshot, so this path keys
        // the memo from the content in hand rather than from the workspace's
        // live identity.
        let key = self
            .content_oid_of(file, source)
            .and_then(|oid| self.structural_facts_key(file, oid));
        if let Some(key) = key.as_ref()
            && let Some(facts) = self.structural_cache().get(key)
        {
            let work_items = facts.work_item_count();
            return if work_items > max_fact_nodes {
                StructuralFactsLimitedOutcome::Exceeded {
                    minimum_fact_nodes: work_items,
                }
            } else {
                StructuralFactsLimitedOutcome::Available {
                    facts,
                    cache_outcome: StructuralFactsCacheOutcome::MemoryHit,
                }
            };
        }

        let build = || {
            if self.adapter().produces_canonical_source_facts() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return StructuralFactsLimitedOutcome::Cancelled;
                }
                let Some(key) = self.structural_snapshot_key(file, source) else {
                    return self
                        .cached_canonical_facts_limited(file, source, max_fact_nodes)
                        .unwrap_or(StructuralFactsLimitedOutcome::Unavailable);
                };
                let read = match self.load_structural_facts_rows_limited(
                    &key,
                    STRUCTURAL_FACTS_VERSION,
                    max_fact_nodes,
                    cancellation,
                ) {
                    Ok(read) => read,
                    Err(error) => {
                        self.record_store_error(
                            error.context("loading bounded canonical structural facts"),
                        );
                        if cancellation.is_some_and(CancellationToken::is_cancelled) {
                            return StructuralFactsLimitedOutcome::Cancelled;
                        }
                        return self
                            .cached_canonical_facts_limited(file, source, max_fact_nodes)
                            .unwrap_or(StructuralFactsLimitedOutcome::Unavailable);
                    }
                };
                let rows = match read {
                    crate::analyzer::store::StructuralFactRowsRead::Ready(rows) => rows,
                    crate::analyzer::store::StructuralFactRowsRead::Exceeded {
                        minimum_work_items,
                    } => {
                        return StructuralFactsLimitedOutcome::Exceeded {
                            minimum_fact_nodes: minimum_work_items,
                        };
                    }
                    crate::analyzer::store::StructuralFactRowsRead::Cancelled => {
                        return StructuralFactsLimitedOutcome::Cancelled;
                    }
                    crate::analyzer::store::StructuralFactRowsRead::Unavailable => {
                        if cancellation.is_some_and(CancellationToken::is_cancelled) {
                            return StructuralFactsLimitedOutcome::Cancelled;
                        }
                        return self
                            .cached_canonical_facts_limited(file, source, max_fact_nodes)
                            .unwrap_or(StructuralFactsLimitedOutcome::Unavailable);
                    }
                };
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return StructuralFactsLimitedOutcome::Cancelled;
                }
                let facts = match FileFacts::from_persisted_rows(source.to_owned(), rows) {
                    Ok(facts) => Arc::new(facts),
                    Err(error) => {
                        self.record_store_error(StoreError::new(format!(
                            "invalid canonical structural facts: {error}"
                        )));
                        return StructuralFactsLimitedOutcome::Unavailable;
                    }
                };
                self.structural_cache().record_hydration();
                return StructuralFactsLimitedOutcome::Available {
                    facts,
                    cache_outcome: StructuralFactsCacheOutcome::PersistedHydration,
                };
            }

            self.structural_cache().record_extraction();
            let grammar = self.adapter().parser_language_for_file(file);
            let facts = match extract_file_facts_limited(
                spec,
                &grammar,
                source,
                max_fact_nodes,
                cancellation,
            ) {
                LimitedFileFacts::Complete(facts) => facts,
                LimitedFileFacts::CompleteWithNodeIndex { facts, .. } => facts,
                LimitedFileFacts::Exceeded { minimum_fact_nodes } => {
                    return StructuralFactsLimitedOutcome::Exceeded { minimum_fact_nodes };
                }
                LimitedFileFacts::Cancelled => {
                    return StructuralFactsLimitedOutcome::Cancelled;
                }
                LimitedFileFacts::Unavailable => {
                    return StructuralFactsLimitedOutcome::Unavailable;
                }
            };
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return StructuralFactsLimitedOutcome::Cancelled;
            }

            let facts = Arc::new(facts);
            // The bounded query path must remain promptly cancellable. Durable row conversion
            // clones every normalized node and role edge before insertion, so leave that optional
            // optimization to the ordinary materialization path rather than performing an
            // unmetered post-extraction traversal here.
            StructuralFactsLimitedOutcome::Available {
                facts,
                cache_outcome: StructuralFactsCacheOutcome::Extracted,
            }
        };
        match self.structural_cache().reuse_or_build(
            key,
            || cancellation.is_some_and(CancellationToken::is_cancelled),
            || match build() {
                StructuralFactsLimitedOutcome::Available {
                    facts,
                    cache_outcome,
                } => Ok((facts, cache_outcome)),
                other => Err(other),
            },
        ) {
            Ok((facts, cache_outcome)) => {
                let work_items = facts.work_item_count();
                if work_items > max_fact_nodes {
                    StructuralFactsLimitedOutcome::Exceeded {
                        minimum_fact_nodes: work_items,
                    }
                } else {
                    StructuralFactsLimitedOutcome::Available {
                        facts,
                        cache_outcome,
                    }
                }
            }
            Err(other) => other,
        }
    }

    fn structural_extraction_count(&self) -> u64 {
        self.structural_cache().extraction_count()
    }

    fn structural_hydration_count(&self) -> u64 {
        self.structural_cache().hydration_count()
    }

    fn structural_supports_kind(&self, kind: NormalizedKind) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_kind(kind))
    }

    fn structural_supports_role(&self, role: Role) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_role(role))
    }

    fn structural_supports_boolean_literal_value(&self) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_boolean_literal_value())
    }

    fn structural_supports_unsafe_context(&self) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_unsafe_context())
    }

    fn structural_supports_async_callable_value(&self) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_async_callable_value())
    }

    fn structural_supports_string_literal_value(&self) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_string_literal_value())
    }

    fn structural_supports_assignment_shape(&self) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_assignment_shape())
    }

    fn structural_supports_integer_literal_value(&self) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_integer_literal_value())
    }

    fn structural_supports_duplicate_dictionary_keys(&self) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.supports_duplicate_dictionary_keys())
    }

    fn structural_supports_occurrence_role(&self, role: OccurrenceRole) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.occurrence_role_support().is_supported(role))
    }

    fn structural_supports_environment_axis(&self, axis: EnvironmentAxis) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.lexical_environment_support().is_supported(axis))
    }

    fn structural_supports_materialization_axis(&self, axis: MaterializationAxis) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.materialization_support().is_supported(axis))
    }

    fn structural_supports_edge_axis(&self, axis: EdgeAxis) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.reference_edge_support().is_supported(axis))
    }

    fn structural_supports_identity_axis(&self, axis: IdentityAxis) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.identity_route_support().supports_axis(axis))
    }

    fn structural_supports_route_relation(&self, relation: RouteHopKind) -> bool {
        self.adapter()
            .structural_spec()
            .is_some_and(|spec| spec.identity_route_support().supports_relation(relation))
    }

    fn structural_content_identity(&self) -> Option<WorkspaceContentIdentity> {
        Some(WorkspaceContentIdentity::from_digest(
            self.language_content_identity(),
        ))
    }

    fn snapshot_structural_index_cache(&self) -> Option<&StructuralFactSnapshotCache> {
        Some(self.structural_index_cache())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    use crate::compact_graph::CompactRows;

    fn empty_facts(source: &str) -> FileFacts {
        FileFacts::new(
            source.to_owned(),
            vec![0],
            Vec::new(),
            CompactRows::from_parts(vec![0], Vec::new()),
            CompactRows::from_parts(vec![0], Vec::new()),
            Vec::new(),
        )
    }

    #[test]
    fn source_identity_distinguishes_first_byte_edits() {
        // Equal-length valid strings differ only in their first encoded byte.
        // Blob identity is the independent content identity oracle used by the memo.
        for sources in [["x=1", "y=1", "x=1"], ["\u{e9}=1", "\u{129}=1", "\u{e9}=1"]] {
            let mut previous = None;
            for source in sources {
                let oid =
                    git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
                let hash = hash_source(source);
                if let Some((old_oid, old_hash)) = previous {
                    assert_ne!(oid, old_oid);
                    assert_ne!(
                        hash, old_hash,
                        "different content must invalidate this memo entry"
                    );
                }
                previous = Some((oid, hash));
            }
        }
    }

    #[test]
    fn structural_facts_cache_reuses_live_allocations_after_eviction() {
        let cache = StructuralFactsCache::new(1024 * 1024);
        let shared = cache.sharing_entries();
        let source = "live facts";
        let key = StructuralSnapshotKey::for_test(source, "typescript");
        let hydrate = |cache: &StructuralFactsCache| {
            assert!(cache.get(&key).is_none());
            cache.materialize(
                key,
                || Some(empty_facts(source)),
                || panic!("unexpected extraction"),
            )
        };
        let first = hydrate(&cache).0.unwrap();
        cache.cache.invalidate(&key);
        cache.cache.run_pending_tasks();
        let (second, outcome) = hydrate(&shared);
        let second = second.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(outcome, StructuralFactsCacheOutcome::MemoryHit);
        assert_eq!(cache.hydration_count(), 1);
        assert_eq!(shared.hydration_count(), 0);

        let old = Arc::downgrade(&first);
        drop(first);
        drop(second);
        cache.cache.invalidate(&key);
        cache.cache.run_pending_tasks();
        assert!(old.upgrade().is_none());
        let fresh = hydrate(&cache).0.unwrap();
        assert_eq!(cache.hydration_count(), 2);
        drop(fresh);
        cache.cache.invalidate(&key);
        cache.cache.run_pending_tasks();

        assert!(cache.live.lock().unwrap().entries.is_empty());
    }

    #[test]
    #[hardwon("#7445: dead live-facts registry entries outlived the query that held them")]
    fn structural_facts_cache_releases_registrations_and_capacity() {
        let cache = StructuralFactsCache::new(1024 * 1024);
        let holders: Vec<_> = (0..128)
            .map(|index| {
                let source = format!("live facts {index}");
                let key = StructuralSnapshotKey::for_test(&source, "typescript");
                let facts = cache
                    .materialize(key, || Some(empty_facts(&source)), || None)
                    .0
                    .unwrap();
                cache.cache.invalidate(&key);
                cache.cache.run_pending_tasks();
                facts
            })
            .collect();
        assert_eq!(cache.live.lock().unwrap().entries.len(), holders.len());
        assert!(cache.live.lock().unwrap().entries.capacity() > 64);
        drop(holders);
        assert!(cache.live.lock().unwrap().entries.is_empty());
        assert!(cache.live.lock().unwrap().entries.capacity() <= 64);

        // Simulate an old allocation's delayed registration drop after its
        // dead weak entry has been replaced by a newer live allocation.
        let key = StructuralSnapshotKey::for_test("replacement", "typescript");
        let late_drop = LiveRegistration {
            registry: Arc::downgrade(&cache.live),
            key,
        };
        cache.live.lock().unwrap().entries.insert(key, Weak::new());
        let fresh = cache
            .materialize(key, || Some(empty_facts("replacement")), || None)
            .0
            .unwrap();
        drop(late_drop);
        assert!(
            cache
                .live
                .lock()
                .unwrap()
                .entries
                .get(&key)
                .unwrap()
                .ptr_eq(&Arc::downgrade(&fresh))
        );
        cache.cache.invalidate(&key);
        cache.cache.run_pending_tasks();
        drop(fresh);
        assert!(cache.live.lock().unwrap().entries.is_empty());
    }

    #[test]
    #[hardwon("#7445: a cancelled waiter waited for an unrelated leader's build")]
    fn structural_facts_cache_cancelled_waiter_leaves_blocked_leader() {
        use std::sync::mpsc;

        let cache = StructuralFactsCache::new(1024 * 1024);
        let key = StructuralSnapshotKey::for_test("cancelled waiter", "typescript");
        let cancellation = CancellationToken::new();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (returned_tx, returned_rx) = mpsc::channel();
        thread::scope(|scope| {
            let cache = &cache;
            let leader = scope.spawn(move || {
                cache
                    .reuse_or_build(
                        Some(key),
                        || false,
                        || {
                            started_tx.send(()).unwrap();
                            release_rx.recv_timeout(Duration::from_secs(30)).unwrap();
                            Ok::<_, ()>((
                                Arc::new(empty_facts("cancelled waiter")),
                                StructuralFactsCacheOutcome::Extracted,
                            ))
                        },
                    )
                    .unwrap()
            });
            started_rx.recv_timeout(Duration::from_secs(30)).unwrap();
            let cancellation = &cancellation;
            let waiter = scope.spawn(move || {
                let result = cache.reuse_or_build(
                    Some(key),
                    || {
                        waiting_tx.send(()).unwrap();
                        cancellation.is_cancelled()
                    },
                    || {
                        assert!(cancellation.is_cancelled());
                        Err::<(Arc<FileFacts>, StructuralFactsCacheOutcome), _>(
                            StructuralFactsLimitedOutcome::Cancelled,
                        )
                    },
                );
                returned_tx.send(result).unwrap();
            });
            waiting_rx.recv_timeout(Duration::from_secs(30)).unwrap();
            cancellation.cancel();
            assert!(matches!(
                returned_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                Err(StructuralFactsLimitedOutcome::Cancelled)
            ));
            assert!(!leader.is_finished());
            assert!(cache.live.lock().unwrap().building.contains_key(&key));
            release_tx.send(()).unwrap();
            waiter.join().unwrap();
            let _facts = leader.join().unwrap();
            assert!(cache.live.lock().unwrap().building.is_empty());
        });
    }

    #[test]
    fn structural_facts_cache_waits_for_success_but_retries_failure() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        for fail_leader in [false, true] {
            let cache = StructuralFactsCache::new(1024 * 1024);
            let key = StructuralSnapshotKey::for_test("shared build", "typescript");
            let builds = AtomicU64::new(0);
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            thread::scope(|scope| {
                assert!(cache.get(&key).is_none());
                let cache = &cache;
                let builds = &builds;
                let leader = scope.spawn(move || {
                    cache.reuse_or_build(
                        Some(key),
                        || false,
                        || {
                            builds.fetch_add(1, Ordering::Relaxed);
                            started_tx.send(()).unwrap();
                            release_rx.recv_timeout(Duration::from_secs(30)).unwrap();
                            if fail_leader {
                                Err("leader failed")
                            } else {
                                Ok((
                                    Arc::new(empty_facts("shared build")),
                                    StructuralFactsCacheOutcome::PersistedHydration,
                                ))
                            }
                        },
                    )
                });
                started_rx.recv().unwrap();
                let slot = Arc::clone(cache.live.lock().unwrap().building.get(&key).unwrap());
                let waiter = scope.spawn(move || {
                    assert!(cache.get(&key).is_none());
                    cache.reuse_or_build(
                        Some(key),
                        || false,
                        || {
                            builds.fetch_add(1, Ordering::Relaxed);
                            Ok::<_, &str>((
                                Arc::new(empty_facts("shared build")),
                                StructuralFactsCacheOutcome::PersistedHydration,
                            ))
                        },
                    )
                });
                // Registry, leader guard and this test own three references.
                // A fourth proves the second request reached the wait path
                // before releasing the leader, without timing-based sleeps.
                let deadline = Instant::now() + Duration::from_secs(30);
                while Arc::strong_count(&slot) < 4 {
                    assert!(
                        Instant::now() < deadline,
                        "waiter did not reach the build slot"
                    );
                    thread::yield_now();
                }
                release_tx.send(()).unwrap();
                let leader = leader.join().unwrap();
                let (waiter, outcome) = waiter.join().unwrap().unwrap();
                if fail_leader {
                    assert_eq!(leader.unwrap_err(), "leader failed");
                    assert_eq!(outcome, StructuralFactsCacheOutcome::PersistedHydration);
                    assert_eq!(builds.load(Ordering::Relaxed), 2);
                } else {
                    assert!(Arc::ptr_eq(&leader.unwrap().0, &waiter));
                    assert_eq!(outcome, StructuralFactsCacheOutcome::MemoryHit);
                    assert_eq!(builds.load(Ordering::Relaxed), 1);
                }
                assert!(cache.live.lock().unwrap().building.is_empty());
            });
        }
    }

    #[test]
    fn structural_facts_cache_reentrant_build_adopts_inner_allocation() {
        let cache = StructuralFactsCache::new(1024 * 1024);
        let key = StructuralSnapshotKey::for_test("reentrant", "typescript");
        let mut inner = None;
        let (outer, _) = cache
            .reuse_or_build(
                Some(key),
                || false,
                || {
                    inner = cache
                        .materialize(key, || Some(empty_facts("reentrant")), || None)
                        .0;
                    assert!(cache.live.lock().unwrap().building.contains_key(&key));
                    Ok::<_, ()>((
                        Arc::new(empty_facts("reentrant")),
                        StructuralFactsCacheOutcome::Extracted,
                    ))
                },
            )
            .unwrap();
        assert!(Arc::ptr_eq(&outer, &inner.unwrap()));
        assert!(cache.live.lock().unwrap().building.is_empty());
    }

    #[test]
    fn structural_facts_cache_reports_exact_materialization_outcomes() {
        let source = "export function demo() {}\n";
        let key = StructuralSnapshotKey::for_test(source, "typescript");
        let hydrated = StructuralFactsCache::new(1024 * 1024);

        assert!(hydrated.get(&key).is_none());
        let (facts, outcome) = hydrated.materialize(
            key,
            || Some(empty_facts(source)),
            || panic!("persisted hydration must avoid extraction"),
        );
        assert!(facts.is_some());
        assert_eq!(outcome, StructuralFactsCacheOutcome::PersistedHydration);
        assert_eq!(hydrated.hydration_count(), 1);
        assert_eq!(hydrated.extraction_count(), 0);

        assert!(hydrated.get(&key).is_some());
        assert_eq!(hydrated.hydration_count(), 1);
        assert_eq!(hydrated.extraction_count(), 0);

        // The same bytes under a different grammar are different facts, so
        // they are a different key rather than a hit on this one.
        assert!(
            hydrated
                .get(&StructuralSnapshotKey::for_test(source, "tsx"))
                .is_none()
        );

        let extracted = StructuralFactsCache::new(1024 * 1024);
        let (facts, outcome) = extracted.materialize(key, || None, || Some(empty_facts(source)));
        assert!(facts.is_some());
        assert_eq!(outcome, StructuralFactsCacheOutcome::Extracted);
        assert_eq!(extracted.hydration_count(), 0);
        assert_eq!(extracted.extraction_count(), 1);

        // A second view of the same entries answers from them, and counts its
        // own work rather than the first view's.
        let shared = extracted.sharing_entries();
        assert!(shared.get(&key).is_some());
        assert_eq!(shared.extraction_count(), 0);

        let unavailable = StructuralFactsCache::new(1024 * 1024);
        let (facts, outcome) = unavailable.materialize(
            StructuralSnapshotKey::for_test("other\n", "typescript"),
            || None,
            || None,
        );
        assert!(facts.is_none());
        assert_eq!(outcome, StructuralFactsCacheOutcome::Unavailable);
        assert_eq!(unavailable.hydration_count(), 0);
        assert_eq!(unavailable.extraction_count(), 1);
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "provider/js_ts_tests_support.rs"]
pub mod js_ts_tests_support;
