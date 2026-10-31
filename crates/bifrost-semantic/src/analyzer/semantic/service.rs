//! Shared snapshot, publication, and complete-cache mechanics for language lowerers.

#[cfg(any(test, feature = "test-support"))]
use std::collections::HashMap;
use std::mem::size_of;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::Mutex;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::atomic::{AtomicU64, Ordering};

use brokk_bifrost_core::gitblob::BlobKey;
use moka::sync::Cache;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::complete_value_cache::CompleteValueRevivalCensus;

use brokk_bifrost_core::complete_value_cache::CompleteValueAcquisition;

use brokk_bifrost_core::complete_value_cache::CompleteValueCache;

use brokk_bifrost_core::complete_value_cache::CompleteValueWait;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSourceOrigin;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

use brokk_bifrost_core::analyzer::model::LanguageDialect;

use brokk_bifrost_core::analyzer::project::OverlayRevision;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::semantic::AdapterSemanticsVersion;

use crate::analyzer::semantic::AllocationSite;

use crate::analyzer::semantic::BasicBlock;

use crate::analyzer::semantic::CaptureBinding;

use crate::analyzer::semantic::ConfigurationFingerprint;

use super::ContentIdentity;

use crate::analyzer::semantic::ControlEdge;

use crate::analyzer::semantic::DependencyFingerprint;

use crate::analyzer::semantic::Evidence;

use crate::analyzer::semantic::MemoryLocation;

use super::OverlaySnapshotId;

use crate::analyzer::semantic::PointerInvalidation;

use crate::analyzer::semantic::ProcedureId;

use crate::analyzer::semantic::ProcedureSemantics;

use crate::analyzer::semantic::ProcedureSemanticsParts;

use crate::analyzer::semantic::ProgramPoint;

use crate::analyzer::semantic::SemanticArtifact;

use crate::analyzer::semantic::SemanticArtifactBuildError;

use crate::analyzer::semantic::SemanticArtifactKey;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticCapabilities;

use crate::analyzer::semantic::SemanticEvent;

use crate::analyzer::semantic::SemanticGap;

use crate::analyzer::semantic::SemanticIrVersion;

use crate::analyzer::semantic::SemanticLocator;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticRequest;

use crate::analyzer::semantic::SemanticValue;

use crate::analyzer::semantic::SemanticWork;

use crate::analyzer::semantic::SourceMapping;

use crate::analyzer::semantic::SourceRevision;

use crate::analyzer::semantic::WorkspaceMountId;

use crate::analyzer::semantic::WorkspaceRelativePath;

/// Immutable complete-artifact cache shared by one concrete analyzer adapter.
///
/// Moka bounds retained bytes rather than entry count. Incomplete outcomes are
/// never presented to this type, so a lookup can always be treated as a fully
/// validated immutable artifact. The in-flight map serializes construction for
/// one exact artifact key without retaining completed work.
#[derive(Clone)]
#[doc(hidden)]
pub struct CompleteSemanticArtifactCache {
    #[doc(hidden)]
    pub inner: CompleteValueCache<SemanticArtifactKey, SemanticArtifact>,
    /// Independent deterministic typestate-continuation eviction witnesses
    /// shared by analyzer clones. Production builds carry neither the flags
    /// nor the control surface.
    #[cfg(any(test, feature = "test-support"))]
    selector_continuation_invalidation_armed: Arc<AtomicBool>,
    #[cfg(any(test, feature = "test-support"))]
    evaluation_root_continuation_invalidation_armed: Arc<AtomicBool>,
    #[cfg(any(test, feature = "test-support"))]
    active_invalidation_witness: Arc<AtomicU8>,
    #[cfg(any(test, feature = "test-support"))]
    selector_continuation_revival_census: Arc<Mutex<SemanticCacheRevivalCensus>>,
    #[cfg(any(test, feature = "test-support"))]
    evaluation_root_continuation_revival_census: Arc<Mutex<SemanticCacheRevivalCensus>>,
    /// How this analyzer produced each file's semantics, per file. Shared by
    /// analyzer clones for the same reason the cache itself is.
    #[cfg(any(test, feature = "test-support"))]
    materializations: Arc<Mutex<HashMap<WorkspaceRelativePath, SemanticMaterializationCensus>>>,
}

impl Default for CompleteSemanticArtifactCache {
    fn default() -> Self {
        Self::new(SEMANTIC_MATERIALIZATION_CACHE_BYTES)
    }
}

impl CompleteSemanticArtifactCache {
    #[doc(hidden)]
    pub fn new(max_retained_bytes: u64) -> Self {
        Self {
            inner: CompleteValueCache::with_retention(
                max_retained_bytes,
                weigh_complete_artifact,
                |artifact| Arc::new(CachedSemanticArtifact::new(&artifact)),
            ),
            #[cfg(any(test, feature = "test-support"))]
            selector_continuation_invalidation_armed: Arc::new(AtomicBool::new(false)),
            #[cfg(any(test, feature = "test-support"))]
            evaluation_root_continuation_invalidation_armed: Arc::new(AtomicBool::new(false)),
            #[cfg(any(test, feature = "test-support"))]
            active_invalidation_witness: Arc::new(AtomicU8::new(NO_SEMANTIC_INVALIDATION_WITNESS)),
            #[cfg(any(test, feature = "test-support"))]
            selector_continuation_revival_census: Arc::new(Mutex::new(
                SemanticCacheRevivalCensus::default(),
            )),
            #[cfg(any(test, feature = "test-support"))]
            evaluation_root_continuation_revival_census: Arc::new(Mutex::new(
                SemanticCacheRevivalCensus::default(),
            )),
            #[cfg(any(test, feature = "test-support"))]
            materializations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn record_lowering(&self, path: &WorkspaceRelativePath) {
        let mut census = self
            .materializations
            .lock()
            .expect("semantic materialization census mutex poisoned");
        let file = census.entry(path.clone()).or_default();
        file.lowerings = file.lowerings.saturating_add(1);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn record_hit(&self, path: &WorkspaceRelativePath, repeat: bool) {
        let mut census = self
            .materializations
            .lock()
            .expect("semantic materialization census mutex poisoned");
        let file = census.entry(path.clone()).or_default();
        if repeat {
            file.repeat_hits = file.repeat_hits.saturating_add(1);
        } else {
            file.census_hits = file.census_hits.saturating_add(1);
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn materialization_census_for_test(
        &self,
    ) -> Vec<(WorkspaceRelativePath, SemanticMaterializationCensus)> {
        let mut census: Vec<_> = self
            .materializations
            .lock()
            .expect("semantic materialization census mutex poisoned")
            .iter()
            .map(|(path, file)| (path.clone(), *file))
            .collect();
        census.sort_by(|left, right| left.0.cmp(&right.0));
        census
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn arm_selector_continuation_invalidation_for_test(&self) {
        self.arm_continuation_invalidation_for_test(&self.selector_continuation_invalidation_armed);
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn invalidate_selector_continuation_if_armed_for_test(&self) {
        self.invalidate_continuation_if_armed_for_test(
            &self.selector_continuation_invalidation_armed,
            SELECTOR_CONTINUATION_INVALIDATION_WITNESS,
            &self.selector_continuation_revival_census,
        );
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn arm_evaluation_root_continuation_invalidation_for_test(&self) {
        self.arm_continuation_invalidation_for_test(
            &self.evaluation_root_continuation_invalidation_armed,
        );
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn invalidate_evaluation_root_continuation_if_armed_for_test(&self) {
        self.invalidate_continuation_if_armed_for_test(
            &self.evaluation_root_continuation_invalidation_armed,
            EVALUATION_ROOT_CONTINUATION_INVALIDATION_WITNESS,
            &self.evaluation_root_continuation_revival_census,
        );
    }

    #[cfg(any(test, feature = "test-support"))]
    fn arm_continuation_invalidation_for_test(&self, armed: &AtomicBool) {
        armed.store(true, Ordering::Release);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn invalidate_continuation_if_armed_for_test(
        &self,
        armed: &AtomicBool,
        witness: u8,
        census: &Mutex<SemanticCacheRevivalCensus>,
    ) {
        if !armed.swap(false, Ordering::AcqRel) {
            return;
        }
        self.activate_invalidation_witness_for_test(witness, census);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn activate_invalidation_witness_for_test(
        &self,
        witness: u8,
        census: &Mutex<SemanticCacheRevivalCensus>,
    ) {
        self.latch_active_invalidation_revival_census_for_test();
        *census
            .lock()
            .expect("semantic invalidation revival census mutex poisoned") =
            SemanticCacheRevivalCensus::default();
        self.active_invalidation_witness
            .store(witness, Ordering::Release);
        self.inner.reset_revival_census_for_test();
        self.inner.invalidate_all_for_test();
    }

    #[cfg(any(test, feature = "test-support"))]
    fn latch_active_invalidation_revival_census_for_test(&self) {
        let current =
            SemanticCacheRevivalCensus::from_complete_value(self.inner.revival_census_for_test());
        let retained = match self.active_invalidation_witness.load(Ordering::Acquire) {
            SELECTOR_CONTINUATION_INVALIDATION_WITNESS => {
                &self.selector_continuation_revival_census
            }
            EVALUATION_ROOT_CONTINUATION_INVALIDATION_WITNESS => {
                &self.evaluation_root_continuation_revival_census
            }
            NO_SEMANTIC_INVALIDATION_WITNESS => return,
            witness => panic!("unknown semantic invalidation witness {witness}"),
        };
        let mut retained = retained
            .lock()
            .expect("semantic invalidation revival census mutex poisoned");
        *retained = retained.component_max(current);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn invalidation_revival_census_for_test(
        &self,
        witness: u8,
        census: &Mutex<SemanticCacheRevivalCensus>,
    ) -> SemanticCacheRevivalCensus {
        let retained = *census
            .lock()
            .expect("semantic invalidation revival census mutex poisoned");
        if self.active_invalidation_witness.load(Ordering::Acquire) == witness {
            retained.component_max(SemanticCacheRevivalCensus::from_complete_value(
                self.inner.revival_census_for_test(),
            ))
        } else {
            retained
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn selector_continuation_revival_census_for_test(&self) -> SemanticCacheRevivalCensus {
        self.invalidation_revival_census_for_test(
            SELECTOR_CONTINUATION_INVALIDATION_WITNESS,
            &self.selector_continuation_revival_census,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn evaluation_root_continuation_revival_census_for_test(
        &self,
    ) -> SemanticCacheRevivalCensus {
        self.invalidation_revival_census_for_test(
            EVALUATION_ROOT_CONTINUATION_INVALIDATION_WITNESS,
            &self.evaluation_root_continuation_revival_census,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn insert(&self, key: SemanticArtifactKey, artifact: Arc<SemanticArtifact>) {
        self.inner.insert_complete_for_test(key, artifact);
    }

    #[doc(hidden)]
    pub fn acquire(
        &self,
        key: &SemanticArtifactKey,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> (
        CompleteValueAcquisition<SemanticArtifactKey, SemanticArtifact>,
        CompleteValueWait,
    ) {
        self.inner.acquire(key, cancellation)
    }

    /// Look one already-published artifact up without reserving a flight.
    ///
    /// A caller that has not read the file cannot lead a lowering, so it must
    /// not take a permit: it asks only whether the artifact is already there.
    #[doc(hidden)]
    pub fn get_ready(
        &self,
        key: &SemanticArtifactKey,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Option<Arc<SemanticArtifact>> {
        self.inner.get_ready(key, cancellation)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.inner.len_for_test()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn waiting_count(&self) -> usize {
        self.inner.waiting_count_for_test()
    }
}

/// How many derived content digests one analyzer retains.
///
/// One entry is a 20-byte blob identity, a 32-byte digest, and moka's per-entry
/// bookkeeping. Entries are fixed size, so bounding the count bounds the bytes:
/// this cap is on the order of a few megabytes, well under the artifact cache
/// beside it, and it is a bound rather than a target.
const SOURCE_CONTENT_IDENTITY_MEMO_ENTRIES: u64 = 32_768;

/// Content digests already derived from one exact source snapshot, keyed by
/// that snapshot's blob identity.
///
/// The mapping is a pure function of content. Both sides are taken from one
/// atomic snapshot: the key is the git blob identity of exactly the bytes the
/// value digests. An entry therefore cannot become stale, and two files with
/// identical content share one entry. The freshness question lives entirely on
/// the lookup side, in the caller's proof that the analyzer generation still
/// has that blob identity -- see `TreeSitterAnalyzer::reusable_live_oid`.
///
/// Bounded like the artifact cache beside it, and shared by clones of one
/// analyzer for the same reason: the digests are content-addressed, so sharing
/// them across analyzer snapshots is always correct.
#[derive(Clone)]
#[doc(hidden)]
pub struct SourceContentIdentityMemo {
    entries: Cache<BlobKey, ContentIdentity>,
}

impl Default for SourceContentIdentityMemo {
    fn default() -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(SOURCE_CONTENT_IDENTITY_MEMO_ENTRIES)
                .build(),
        }
    }
}

impl SourceContentIdentityMemo {
    #[doc(hidden)]
    pub fn get(&self, source: BlobKey) -> Option<ContentIdentity> {
        self.entries.get(&source)
    }

    #[doc(hidden)]
    pub fn record(&self, source: BlobKey, content: ContentIdentity) {
        self.entries.insert(source, content);
    }
}

/// Convert the artifact's exact retained-work census and fixed cache overhead
/// into the base portion of its conservative byte weight. Source bytes are
/// intentionally absent: the prepared source is not owned by
/// `SemanticArtifact`.
#[doc(hidden)]
pub fn retained_artifact_base_bytes(artifact: &SemanticArtifact) -> u64 {
    fn rows(count: usize, row_size: usize) -> u64 {
        (count as u64).saturating_mul(row_size as u64)
    }

    let work = artifact.work();
    let locator_index_entry = size_of::<SemanticLocator>()
        .saturating_add(size_of::<ProcedureId>())
        .saturating_add(size_of::<usize>() * 2);
    let pointer_invalidation_rows = artifact
        .procedures()
        .iter()
        .fold(0usize, |rows, procedure| {
            rows.saturating_add(procedure.pointer_invalidations().len())
        });
    let nested_entries = work
        .nested_entries
        .saturating_sub(pointer_invalidation_rows);
    let mut bytes = (size_of::<Arc<SemanticArtifact>>()
        + size_of::<SemanticArtifact>()
        + size_of::<SemanticArtifactKey>()) as u64;
    bytes = bytes
        .saturating_add(rows(work.procedures, size_of::<ProcedureSemantics>()))
        .saturating_add(rows(work.procedures, locator_index_entry))
        .saturating_add(rows(work.blocks, size_of::<BasicBlock>()))
        .saturating_add(rows(work.program_points, size_of::<ProgramPoint>()))
        .saturating_add(rows(work.values, size_of::<SemanticValue>()))
        .saturating_add(rows(work.allocations, size_of::<AllocationSite>()))
        .saturating_add(rows(work.call_sites, size_of::<SemanticCallSite>()))
        .saturating_add(rows(work.memory_locations, size_of::<MemoryLocation>()))
        .saturating_add(rows(work.captures, size_of::<CaptureBinding>()))
        .saturating_add(rows(work.source_mappings, size_of::<SourceMapping>()))
        .saturating_add(rows(work.evidence, size_of::<Evidence>()))
        .saturating_add(rows(work.gaps, size_of::<SemanticGap>()))
        .saturating_add(rows(work.events, size_of::<SemanticEvent>()))
        .saturating_add(rows(work.control_edges, size_of::<ControlEdge>()))
        .saturating_add(rows(
            nested_entries,
            size_of::<SemanticLocator>().saturating_mul(2).max(64),
        ))
        // Pointer invalidations are stored as a flat typed slice; charge their
        // concrete row size, including the target enum's value identity.
        .saturating_add(rows(
            pointer_invalidation_rows,
            size_of::<PointerInvalidation>(),
        ))
        .saturating_add((work.owned_text_bytes as u64).saturating_mul(2))
        .saturating_add(work.source_bytes as u64);

    bytes.max(1)
}

/// Convert the artifact's retained rows and derived indexes into a conservative
/// byte weight. Fixed rows use their concrete Rust size; nested entries reserve
/// at least twice a `SemanticLocator`, and owned text is doubled to cover the
/// independently cloned Moka key. Hash-map bucket, boxed payload, allocator,
/// and Arc allocation overhead are included explicitly.
#[doc(hidden)]
pub fn retained_artifact_bytes(key: &SemanticArtifactKey, artifact: &SemanticArtifact) -> u64 {
    // `key` is intentionally used here as an invariant check: the cache must
    // weigh the same immutable identity embedded in the artifact.
    debug_assert_eq!(key, artifact.key());
    artifact
        .procedures()
        .iter()
        .fold(
            retained_artifact_base_bytes(artifact)
                .saturating_add(artifact.lexical_children_index_retained_bytes())
                .saturating_add(artifact.call_source_extents_retained_bytes()),
            |bytes, procedure| {
                bytes
                    .saturating_add(procedure.call_indexes_retained_bytes())
                    .saturating_add(procedure.value_identity_index_retained_bytes())
            },
        )
        .max(1)
}

pub fn semantic_artifact_retained_bytes(artifact: &SemanticArtifact) -> u64 {
    retained_artifact_bytes(artifact.key(), artifact)
}

fn weigh_complete_artifact(key: &SemanticArtifactKey, artifact: &Arc<SemanticArtifact>) -> u32 {
    retained_artifact_bytes(key, artifact).min(u64::from(u32::MAX)) as u32
}

/// Snapshot-stable adapter identity. Only intrafile extraction inputs belong
/// here; workspace dispatch generations are ICFG state and deliberately absent.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct SemanticAdapterIdentity {
    #[doc(hidden)]
    pub adapter: AdapterSemanticsVersion,
    #[doc(hidden)]
    pub configuration: ConfigurationFingerprint,
    #[doc(hidden)]
    pub dependencies: DependencyFingerprint,
}

impl SemanticAdapterIdentity {
    #[doc(hidden)]
    pub fn for_adapter(
        adapter_name: &str,
        adapter_version: &[u8],
        configuration: &[u8],
        dependencies: DependencyFingerprint,
    ) -> Self {
        Self {
            adapter: AdapterSemanticsVersion::hash_bytes(adapter_name, adapter_version)
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(configuration),
            dependencies,
        }
    }
}

/// The private boundary implemented by one real language lowering adapter.
///
/// `work` in the returned outcome is prospective/observed work only. The
/// service merges it with the validated artifact's retained work at
/// publication, and only publication mutates the caller's budget.
#[doc(hidden)]
pub trait ProgramSemanticsLowerer: Send + Sync {
    /// A lowerer that consumes declaration properties opts into the ordinary
    /// primary source producer on the exact prepared tree.
    fn primary_declaration_lowerer(&self) -> Option<&dyn PrimaryDeclarationSemanticsLowerer> {
        None
    }

    fn identity(&self) -> SemanticAdapterIdentity;

    fn capabilities(&self) -> SemanticCapabilities {
        SemanticCapabilities::default()
    }

    /// Enumerate stable procedure addresses without constructing executable IR.
    fn procedure_inventory(
        &self,
        _file: &ProjectFile,
        _prepared: &PreparedSyntaxTree,
        _budget: &crate::analyzer::semantic::SemanticBudget,
        _cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<Option<crate::analyzer::semantic::SemanticProcedureInventory>, SemanticProviderError>
    {
        Ok(None)
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &crate::analyzer::semantic::SemanticBudget,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError>;
}

/// A language's stateless lowerer, handed to blob preparation so a blob's
/// semantic IR is written as rows when the blob is parsed. The field is
/// crate-private on purpose: the lowering contract is not public API.
pub struct ParseTimeSemanticLowerer {
    inner: &'static dyn ProgramSemanticsLowerer,
}

impl ParseTimeSemanticLowerer {
    #[doc(hidden)]
    pub const fn new(inner: &'static dyn ProgramSemanticsLowerer) -> Self {
        Self { inner }
    }

    #[doc(hidden)]
    pub fn lowerer(&self) -> &'static dyn ProgramSemanticsLowerer {
        self.inner
    }
}

/// Executable lowering that also consumes the primary declaration projection.
#[doc(hidden)]
pub trait PrimaryDeclarationSemanticsLowerer: Send + Sync {
    fn lower_with_primary_declarations(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        primary: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
        budget: &crate::analyzer::semantic::SemanticBudget,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError>;
}

#[path = "primary_declarations.rs"]
#[doc(hidden)]
pub mod primary_declarations;

/// Process-wide counts of how complete semantic artifacts were answered. The
/// counts are relaxed atomics read only by the `BIFROST_TIMING` notes, so a
/// note carries the running totals at the moment it is written.
#[doc(hidden)]
pub struct ServeCounts {
    complete_hits: AtomicU64,
    #[doc(hidden)]
    pub rows_hits: AtomicU64,
    #[doc(hidden)]
    pub rows_misses: AtomicU64,
    #[doc(hidden)]
    pub lowerings: AtomicU64,
    #[doc(hidden)]
    pub lowerer_ns: AtomicU64,
    #[doc(hidden)]
    pub repeat_lowerer_ns: AtomicU64,
}

#[doc(hidden)]
pub static SERVE_COUNTS: ServeCounts = ServeCounts {
    complete_hits: AtomicU64::new(0),
    rows_hits: AtomicU64::new(0),
    rows_misses: AtomicU64::new(0),
    lowerings: AtomicU64::new(0),
    lowerer_ns: AtomicU64::new(0),
    repeat_lowerer_ns: AtomicU64::new(0),
};

/// Count one serve of `event` for `path` and note it with the running totals.
#[doc(hidden)]
pub fn note_serve(counter: &AtomicU64, event: &str, path: impl std::fmt::Display) {
    counter.fetch_add(1, Ordering::Relaxed);
    brokk_bifrost_core::profiling::note_with(|| {
        let total = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        format!(
            "semantic.{event} {path} complete_hits={} rows_hits={} rows_misses={} lowerings={} lowerer_seconds={:.9} repeat_lowerer_seconds={:.9}",
            total(&SERVE_COUNTS.complete_hits),
            total(&SERVE_COUNTS.rows_hits),
            total(&SERVE_COUNTS.rows_misses),
            total(&SERVE_COUNTS.lowerings),
            total(&SERVE_COUNTS.lowerer_ns) as f64 / 1e9,
            total(&SERVE_COUNTS.repeat_lowerer_ns) as f64 / 1e9,
        )
    });
}

/// Notify an opted-in caller only after a complete outcome has committed its
/// semantic budget. Incomplete artifacts are deliberately invisible to the
/// collector: retaining one would let a later coordinator mistake partial
/// provider state for a complete cache continuation.
#[doc(hidden)]
pub fn observe_complete_artifact(
    file: &ProjectFile,
    outcome: &Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError>,
    request: &SemanticRequest<'_>,
) {
    if let Ok(SemanticOutcome::Complete { value, .. }) = outcome {
        request.observe_complete_artifact(file, value);
    }
}

/// What one repeat cache hit actually performs: derive the artifact key, look
/// it up, and clone an `Arc`.
///
/// This is what makes semantic work accounting bounded rather than exact
/// across cache states. Within one cache state the charge is exact: a scope
/// pays one artifact's census once and one unit per later hit. Across states
/// the same touch may find the complete cache not ready and lower the file
/// again instead, which charges that whole physical materialization -- the
/// file's source bytes plus the lowering's transient control-flow work, which
/// the retained-row census does not represent. A consumer that compares work
/// across an eviction must therefore bound the difference by the repeated
/// physical materializations rather than require equality (#2926).
///
/// A repeat lookup increments cumulative work only. It admits no additional
/// resident rows, so it cannot exhaust the resident lane. Execution traversal
/// and solver budgets own work bounds; residency bounds allocation lifetime.
#[doc(hidden)]
pub fn publish_cached(
    #[cfg_attr(not(any(test, feature = "test-support")), allow(unused_variables))]
    cache: &CompleteSemanticArtifactCache,
    artifact: Arc<SemanticArtifact>,
    source_work: SemanticWork,
    mut staged_budget: crate::analyzer::semantic::SemanticBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    note_serve(
        &SERVE_COUNTS.complete_hits,
        "complete_hit",
        artifact.key().path().as_str(),
    );
    #[cfg(any(test, feature = "test-support"))]
    cache.record_hit(
        artifact.key().path(),
        staged_budget.has_charged_artifact(artifact.key().fingerprint()),
    );
    if let Err(exceeded) = staged_budget.charge_complete_artifact(&artifact) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: source_work.component_max(artifact.work()),
        });
    }
    let work = source_work.component_max(artifact.work());
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work,
        });
    }
    *request.budget = staged_budget;
    Ok(SemanticOutcome::Complete {
        value: artifact,
        work,
    })
}

#[doc(hidden)]
pub fn semantic_artifact_key_for_prepared(
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    content: ContentIdentity,
    identity: SemanticAdapterIdentity,
) -> Result<SemanticArtifactKey, SemanticProviderError> {
    let overlay_revision = match prepared.origin() {
        PreparedSourceOrigin::Disk => None,
        PreparedSourceOrigin::Overlay => Some(prepared.overlay_revision().ok_or_else(|| {
            SemanticProviderError::internal(
                "prepared overlay source is missing its atomic revision token",
            )
        })?),
    };
    semantic_artifact_key_from_content(
        file,
        prepared.dialect(),
        content,
        overlay_revision,
        identity,
    )
}

#[doc(hidden)]
pub fn semantic_artifact_key_from_content(
    file: &ProjectFile,
    dialect: LanguageDialect,
    content: ContentIdentity,
    overlay_revision: Option<OverlayRevision>,
    identity: SemanticAdapterIdentity,
) -> Result<SemanticArtifactKey, SemanticProviderError> {
    let path = WorkspaceRelativePath::try_from_path(file.rel_path())
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let revision = match overlay_revision {
        None => SourceRevision::Disk { content },
        Some(revision) => SourceRevision::Overlay {
            content,
            snapshot: OverlaySnapshotId::hash_bytes(revision.get().to_le_bytes()),
        },
    };
    Ok(SemanticArtifactKey::new(
        WorkspaceMountId::from_root(file.root()),
        path,
        dialect,
        revision,
        identity.adapter,
        SemanticIrVersion::current(),
        identity.configuration,
        identity.dependencies,
    ))
}

#[doc(hidden)]
pub fn publish_lowered(
    key: SemanticArtifactKey,
    capabilities: SemanticCapabilities,
    lowered: SemanticOutcome<Vec<ProcedureSemanticsParts>>,
    source_work: SemanticWork,
    started_work: SemanticWork,
    mut staged_budget: crate::analyzer::semantic::SemanticBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    macro_rules! publish_parts {
        ($parts:expr, $work:expr) => {{
            let publication = match publish(
                key.clone(),
                capabilities.clone(),
                $parts,
                &mut staged_budget,
            ) {
                Ok(publication) => publication,
                Err(error) => {
                    *request.budget = staged_budget;
                    return Err(error);
                }
            };
            match publication {
                Publication::Artifact(artifact) => artifact,
                Publication::Exceeded(exceeded) => {
                    *request.budget = staged_budget;
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work: source_work.component_max($work),
                    });
                }
            }
        }};
    }

    macro_rules! reconcile_observed {
        ($work:expr) => {
            reconcile_observed_work(&mut staged_budget, started_work, $work);
        };
    }

    macro_rules! commit_non_cancelled {
        ($work:expr, $outcome:expr) => {{
            reconcile_observed!($work);
            if request.cancellation.is_cancelled() {
                *request.budget = staged_budget;
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: $work,
                });
            }
            let outcome: Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> =
                $outcome;
            *request.budget = staged_budget;
            outcome
        }};
    }

    match lowered {
        SemanticOutcome::Complete { value, work } => {
            let artifact = publish_parts!(value, work);
            let total_work = source_work
                .component_max(work)
                .component_max(artifact.work());
            reconcile_observed!(total_work);
            if request.cancellation.is_cancelled() {
                drop(artifact);
                *request.budget = staged_budget;
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                });
            }
            // Only a complete lowering is retained by the artifact cache, so
            // only a complete lowering can be hit later in this scope. A
            // partial one is lowered and charged again on its next touch,
            // which is honest: that work really is performed again (#2295).
            staged_budget.record_charged_artifact(artifact.key().fingerprint());
            staged_budget.track_resident_artifact(&artifact);
            *request.budget = staged_budget;
            Ok(SemanticOutcome::Complete {
                work: total_work,
                value: artifact,
            })
        }
        SemanticOutcome::Ambiguous { candidates, work } => {
            let candidates = publish_parts!(candidates, work);
            let total_work = source_work
                .component_max(work)
                .component_max(candidates.work());
            commit_non_cancelled!(
                total_work,
                Ok(SemanticOutcome::Ambiguous {
                    candidates,
                    work: total_work,
                })
            )
        }
        SemanticOutcome::Unknown { partial, work } => {
            let partial = match partial {
                Some(partial) => Some(publish_parts!(partial, work)),
                None => None,
            };
            let artifact_work = partial
                .as_ref()
                .map_or(SemanticWork::default(), |artifact| artifact.work());
            let total_work = source_work.component_max(work).component_max(artifact_work);
            match partial {
                Some(partial) => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::Unknown {
                        partial: Some(partial),
                        work: total_work,
                    })
                ),
                None => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::Unknown {
                        partial: None,
                        work: total_work,
                    })
                ),
            }
        }
        SemanticOutcome::Unsupported {
            capability,
            partial,
            work,
        } => {
            let partial = match partial {
                Some(partial) => Some(publish_parts!(partial, work)),
                None => None,
            };
            let artifact_work = partial
                .as_ref()
                .map_or(SemanticWork::default(), |artifact| artifact.work());
            let total_work = source_work.component_max(work).component_max(artifact_work);
            match partial {
                Some(partial) => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::Unsupported {
                        capability,
                        partial: Some(partial),
                        work: total_work,
                    })
                ),
                None => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::Unsupported {
                        capability,
                        partial: None,
                        work: total_work,
                    })
                ),
            }
        }
        SemanticOutcome::Unproven { partial, work } => {
            let partial = publish_parts!(partial, work);
            let total_work = source_work
                .component_max(work)
                .component_max(partial.work());
            commit_non_cancelled!(
                total_work,
                Ok(SemanticOutcome::Unproven {
                    partial,
                    work: total_work,
                })
            )
        }
        SemanticOutcome::ExceededBudget {
            partial,
            exceeded,
            work,
        } => {
            let partial = match partial {
                Some(partial) => Some(publish_parts!(partial, work)),
                None => None,
            };
            let artifact_work = partial
                .as_ref()
                .map_or(SemanticWork::default(), |artifact| artifact.work());
            let total_work = source_work.component_max(work).component_max(artifact_work);
            match partial {
                Some(partial) => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::ExceededBudget {
                        partial: Some(partial),
                        exceeded,
                        work: total_work,
                    })
                ),
                None if request.cancellation.is_cancelled() => {
                    *request.budget = staged_budget;
                    Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: total_work,
                    })
                }
                None => {
                    *request.budget = staged_budget;
                    Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work: total_work,
                    })
                }
            }
        }
        SemanticOutcome::Cancelled { partial, work } => {
            let partial = match partial {
                Some(partial) => Some(publish_parts!(partial, work)),
                None => None,
            };
            let artifact_work = partial
                .as_ref()
                .map_or(SemanticWork::default(), |artifact| artifact.work());
            let total_work = source_work.component_max(work).component_max(artifact_work);
            match partial {
                Some(partial) => {
                    reconcile_observed!(total_work);
                    *request.budget = staged_budget;
                    Ok(SemanticOutcome::Cancelled {
                        partial: Some(partial),
                        work: total_work,
                    })
                }
                None => {
                    *request.budget = staged_budget;
                    Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: total_work,
                    })
                }
            }
        }
    }
}

fn reconcile_observed_work(
    staged_budget: &mut crate::analyzer::semantic::SemanticBudget,
    started_work: SemanticWork,
    observed_work: SemanticWork,
) {
    let charged_work = staged_budget.used().saturating_sub(started_work);
    let uncharged_work = observed_work.saturating_sub(charged_work);
    staged_budget.charge_work(uncharged_work);
}

enum Publication {
    Artifact(Arc<SemanticArtifact>),
    Exceeded(crate::analyzer::semantic::SemanticBudgetExceeded),
}

fn publish(
    key: SemanticArtifactKey,
    capabilities: SemanticCapabilities,
    parts: Vec<ProcedureSemanticsParts>,
    budget: &mut crate::analyzer::semantic::SemanticBudget,
) -> Result<Publication, SemanticProviderError> {
    match SemanticArtifact::try_new_with_budget(key, capabilities, parts, budget) {
        Ok(artifact) => {
            let artifact = Arc::new(artifact);
            budget.track_resident_artifact(&artifact);
            Ok(Publication::Artifact(artifact))
        }
        Err(SemanticArtifactBuildError::Invalid(error)) => {
            Err(SemanticProviderError::invalid_artifact(error))
        }
        Err(SemanticArtifactBuildError::ExceededBudget(exceeded)) => {
            Ok(Publication::Exceeded(exceeded))
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
const NO_SEMANTIC_INVALIDATION_WITNESS: u8 = 0;

#[cfg(any(test, feature = "test-support"))]
const SELECTOR_CONTINUATION_INVALIDATION_WITNESS: u8 = 1;

#[cfg(any(test, feature = "test-support"))]
const EVALUATION_ROOT_CONTINUATION_INVALIDATION_WITNESS: u8 = 2;

/// How one file's semantics were produced inside one analyzer, split by the
/// physical work each production actually performed.
///
/// This is the unit behind semantic work accounting across a cache eviction.
/// A lowering reads the source and builds the artifact again, and charges that
/// whole materialization. A complete-artifact cache hit performs none of that:
/// the first hit in a budget scope charges the artifact's retained-row census,
/// and every later hit in the same scope charges exactly one nested-entry
/// lookup unit. Which of the three a touch becomes is what the complete
/// cache's ready state decides.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SemanticMaterializationCensus {
    /// Touches that read the source and lowered the file again.
    pub lowerings: u64,
    /// Cache hits that paid the artifact's whole retained-row census.
    pub census_hits: u64,
    /// Cache hits that paid one `nested_entries` repeat-materialization unit.
    pub repeat_hits: u64,
}

/// Test-only account of semantic artifacts revived after an armed cache
/// invalidation.
///
/// One oversize artifact may be reinserted repeatedly while remaining the
/// same allocation. `operations` retains that cache-pressure diagnostic;
/// `distinct_artifacts` is the exact key/allocation identity contract.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SemanticCacheRevivalCensus {
    pub operations: u64,
    pub distinct_artifacts: u64,
}

#[cfg(any(test, feature = "test-support"))]
impl SemanticCacheRevivalCensus {
    fn from_complete_value(census: CompleteValueRevivalCensus) -> Self {
        Self {
            operations: census.operations,
            distinct_artifacts: census.distinct_values,
        }
    }

    fn component_max(self, other: Self) -> Self {
        Self {
            operations: self.operations.max(other.operations),
            distinct_artifacts: self.distinct_artifacts.max(other.distinct_artifacts),
        }
    }

    #[doc(hidden)]
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            operations: self.operations.saturating_add(other.operations),
            distinct_artifacts: self
                .distinct_artifacts
                .saturating_add(other.distinct_artifacts),
        }
    }
}

// Provisional owner decision for the current Python semantic path (#5113).
// Revisit when Python moves to the native engine. Each cache gets this cap,
// independently of the global memo budget.
#[doc(hidden)]
pub const SEMANTIC_MATERIALIZATION_CACHE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// One cache-owned artifact reference, excluded from a root's resident census.
/// The mutex serializes reference creation/destruction with census reads,
/// including Moka's delayed physical reclamation after logical eviction.
#[doc(hidden)]
pub struct CachedSemanticArtifact(Option<Arc<SemanticArtifact>>);

impl CachedSemanticArtifact {
    #[doc(hidden)]
    pub fn new(artifact: &Arc<SemanticArtifact>) -> Self {
        let mut pins = artifact.cache_pins.lock();
        *pins += 1;
        Self(Some(Arc::clone(artifact)))
    }
}

impl std::ops::Deref for CachedSemanticArtifact {
    type Target = Arc<SemanticArtifact>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("cache artifact is live until drop")
    }
}

impl Drop for CachedSemanticArtifact {
    fn drop(&mut self) {
        let artifact = self.0.take().expect("cache artifact drops once");
        let counter = Arc::clone(&artifact.cache_pins);
        let mut pins = counter.lock();
        *pins -= 1;
        drop(artifact);
    }
}

/// Temporary, allocation-deduplicated census for cache admission and timing.
/// Drop after one entry weight or one diagnostic sample.
#[doc(hidden)]
#[derive(Default)]
pub struct ArtifactRetentionCensus {
    artifacts: brokk_bifrost_core::hash::HashSet<usize>,
    arenas: brokk_bifrost_core::hash::HashSet<usize>,
    artifact_bytes: u64,
    arena_bytes: u64,
    pending_relations: Vec<crate::analyzer::semantic::OracleRelationHandle>,
}

impl ArtifactRetentionCensus {
    pub fn artifact(&mut self, artifact: &Arc<SemanticArtifact>) {
        if self.artifacts.insert(Arc::as_ptr(artifact) as usize) {
            self.artifact_bytes = self
                .artifact_bytes
                .saturating_add(semantic_artifact_retained_bytes(artifact));
        }
    }

    pub fn procedure(&mut self, procedure: &crate::analyzer::semantic::ProcedureHandle) {
        self.artifact(procedure.artifact());
    }

    pub(crate) fn arena(&mut self, identity: usize, bytes: impl FnOnce() -> usize) -> bool {
        if !self.arenas.insert(identity) {
            return false;
        }
        self.arena_bytes = self.arena_bytes.saturating_add(bytes() as u64);
        true
    }

    pub fn context(&mut self, context: &crate::analyzer::semantic::OracleCallContext) {
        for call in context.calls() {
            self.procedure(call.procedure());
        }
    }

    pub(crate) fn relation(&mut self, relation: &crate::analyzer::semantic::OracleRelationHandle) {
        self.pending_relations.push(relation.clone());
    }

    fn drain_relations(&mut self) {
        while let Some(relation) = self.pending_relations.pop() {
            relation.collect_retained_artifacts(self);
        }
    }

    pub fn artifact_bytes(&mut self) -> u64 {
        self.drain_relations();
        self.artifact_bytes
    }
    pub fn retained_bytes(&mut self) -> u64 {
        self.drain_relations();
        self.artifact_bytes.saturating_add(self.arena_bytes)
    }
}
