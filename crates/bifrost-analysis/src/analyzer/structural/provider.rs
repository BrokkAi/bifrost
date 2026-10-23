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
use crate::analyzer::QueryScope;
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::store::StoreError;
use crate::analyzer::tree_sitter_analyzer::{
    LanguageAdapter, PreparedSourceFailure, PreparedSyntaxLimitedOutcome, PreparedSyntaxTree,
    StructuralSnapshotKey, TreeSitterAnalyzer,
};
use crate::analyzer::{CodeUnit, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use moka::sync::Cache;
use rayon::prelude::*;
use std::hash::Hasher;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
    extractions: AtomicU64,
    hydrations: AtomicU64,
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
        let (facts, outcome) = if let Some(facts) = load() {
            self.hydrations.fetch_add(1, Ordering::Relaxed);
            (
                Arc::new(facts),
                StructuralFactsCacheOutcome::PersistedHydration,
            )
        } else {
            self.extractions.fetch_add(1, Ordering::Relaxed);
            let Some(facts) = extract() else {
                return (None, StructuralFactsCacheOutcome::Unavailable);
            };
            (Arc::new(facts), StructuralFactsCacheOutcome::Extracted)
        };
        self.insert(key, Arc::clone(&facts));
        (Some(facts), outcome)
    }

    #[doc(hidden)]
    pub fn get(&self, key: &StructuralSnapshotKey) -> Option<Arc<FileFacts>> {
        self.cache.get(key)
    }

    pub(crate) fn insert(&self, key: StructuralSnapshotKey, facts: Arc<FileFacts>) {
        self.cache.insert(key, facts);
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

        let read = if let Some(key) = snapshot_key.as_ref() {
            match self.load_structural_facts_rows_limited(
                key,
                STRUCTURAL_FACTS_VERSION,
                usize::MAX,
                None,
            ) {
                Ok(read) => Some(read),
                Err(error) => {
                    self.record_store_error(error.context("loading canonical structural facts"));
                    return (None, StructuralFactsCacheOutcome::Unavailable);
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
                        return (None, StructuralFactsCacheOutcome::Unavailable);
                    }
                };
                self.structural_cache().record_hydration();
                if let Some(key) = snapshot_key {
                    self.structural_cache().insert(key, Arc::clone(&facts));
                }
                return (Some(facts), StructuralFactsCacheOutcome::PersistedHydration);
            }
            Some(crate::analyzer::store::StructuralFactRowsRead::Exceeded { .. }) => {
                unreachable!("unbounded canonical structural facts load exceeded")
            }
            Some(crate::analyzer::store::StructuralFactRowsRead::Cancelled) => {
                return (None, StructuralFactsCacheOutcome::Unavailable);
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
            if let Some(key) = snapshot_key {
                self.structural_cache().insert(key, Arc::clone(&facts));
            }
            return (Some(facts), StructuralFactsCacheOutcome::MemoryHit);
        }

        // New query source can enter ordinary primary analysis, but missing
        // facts for an indexed source must not be repaired by a reader.
        if crate::analyzer::CodeUnitIndex::indexed_source_matches(self, file, source) {
            self.record_store_error(StoreError::new(format!(
                "required canonical structural source publication unavailable for {file:?}"
            )));
            return (None, StructuralFactsCacheOutcome::Unavailable);
        }

        let Some(source_facts) = self.prepare_canonical_source_facts(file, source.to_owned())
        else {
            return (None, StructuralFactsCacheOutcome::Unavailable);
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
                    None
                }
            }
        });
        let facts = match published {
            Some(rows) => match FileFacts::from_persisted_rows(source.to_owned(), rows) {
                Ok(facts) => facts,
                Err(error) => {
                    self.record_store_error(StoreError::new(format!(
                        "invalid prepared canonical structural facts: {error}"
                    )));
                    return (None, StructuralFactsCacheOutcome::Unavailable);
                }
            },
            None => FileFacts::from_source_and_rows(
                source.to_owned(),
                source_facts.occurrences,
                source_facts.structural,
            ),
        };
        let facts = Arc::new(facts);
        if let Some(key) = snapshot_key {
            self.structural_cache().insert(key, Arc::clone(&facts));
        }
        (Some(facts), StructuralFactsCacheOutcome::Extracted)
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
        if let Some(key) = self.structural_snapshot_key(file, source) {
            self.structural_cache().insert(key, Arc::clone(&facts));
        }
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
                crate::analyzer::store::StructuralFactRowsRead::Exceeded { minimum_work_items } => {
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
            self.structural_cache().insert(key, Arc::clone(&facts));
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
        if let Some(key) = key {
            self.structural_cache().insert(key, Arc::clone(&facts));
        }
        StructuralFactsLimitedOutcome::Available {
            facts,
            cache_outcome: StructuralFactsCacheOutcome::Extracted,
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
