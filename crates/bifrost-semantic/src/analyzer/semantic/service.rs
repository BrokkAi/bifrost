//! Shared snapshot, publication, and complete-cache mechanics for language lowerers.

use std::collections::HashMap;
use std::mem::size_of;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::atomic::{AtomicU64, Ordering};

use brokk_bifrost_core::budgeted_value_cache::{
    BudgetedValueAcquisition, BudgetedValueCache, BudgetedValuePermit,
};
use brokk_bifrost_core::gitblob::BlobKey;
use brokk_bifrost_core::retention_budget::{
    AllocationCharge, BudgetRegion, BudgetedValue, RetainedBytes, RetentionBudget, SelfCharged,
    SharedAllocation, SharedValue,
};

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProvenancedArtifactKey {
    pub artifact: SemanticArtifactKey,
    pub built_from: crate::analyzer::semantic::StableDigest,
}

impl RetainedBytes for ProvenancedArtifactKey {
    fn retained_bytes(&self) -> usize {
        self.artifact
            .retained_bytes()
            .saturating_add(size_of::<crate::analyzer::semantic::StableDigest>())
    }
}

/// Immutable complete-artifact cache shared by one concrete analyzer adapter.
///
/// The owner's retention budget bounds kept bytes. Incomplete outcomes are
/// never presented to this type, so a lookup can always be treated as a fully
/// validated immutable artifact. The in-flight map serializes construction for
/// one exact artifact key without retaining completed work.
#[derive(Clone)]
#[doc(hidden)]
pub struct CompleteSemanticArtifactCache {
    retention_budget: RetentionBudget,
    #[doc(hidden)]
    pub inner: BudgetedValueCache<ProvenancedArtifactKey, CachedSemanticArtifact>,
    /// The instance this cache published for each key, held weakly. The
    /// region revives a charged artifact after eviction, but it refuses one
    /// the budget could not charge, so a later miss would build a second
    /// instance while the first is still held. `ProcedureHandle` compares its
    /// artifact by pointer, so that second instance splits the handles a
    /// policy plan was compiled against from the ones its solve resolves and
    /// drops real flow (#2307). Reusing the live instance keeps one identity
    /// per key; the map holds no strong reference, so it bounds identity, not
    /// memory. It is keyed like `inner`, by provenance too, so an instance
    /// built from another stored publication is never reused (#9784).
    live: Arc<Mutex<LiveArtifacts>>,
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
    #[cfg(any(test, feature = "test-support"))]
    acquiring: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(any(test, feature = "test-support"))]
impl Default for CompleteSemanticArtifactCache {
    fn default() -> Self {
        Self::new(SEMANTIC_MATERIALIZATION_CACHE_BYTES)
    }
}

impl CompleteSemanticArtifactCache {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(max_retained_bytes: u64) -> Self {
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(
            max_retained_bytes,
        );
        Self::new_with_budget(&budget)
    }

    pub fn new_with_budget(budget: &RetentionBudget) -> Self {
        Self {
            retention_budget: budget.clone(),
            inner: BudgetedValueCache::new(budget.region("semantic.complete_artifact", None)),
            live: Arc::new(Mutex::new(LiveArtifacts::default())),
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
            #[cfg(any(test, feature = "test-support"))]
            acquiring: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub fn retention_budget(&self) -> &RetentionBudget {
        &self.retention_budget
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
        self.inner.region().reset_revival_census_for_test();
        self.inner.region().evict_all_for_test();
    }

    #[cfg(any(test, feature = "test-support"))]
    fn latch_active_invalidation_revival_census_for_test(&self) {
        let current =
            SemanticCacheRevivalCensus::from_region(self.inner.region().revival_census_for_test());
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
            retained.component_max(SemanticCacheRevivalCensus::from_region(
                self.inner.region().revival_census_for_test(),
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
    pub fn insert(&self, key: ProvenancedArtifactKey, artifact: Arc<SemanticArtifact>) {
        if artifact.allocation_charge().is_charged() {
            self.inner
                .region()
                .insert_shared(key, CachedSemanticArtifact::new(&artifact));
        }
    }

    #[doc(hidden)]
    pub fn acquire(
        &self,
        key: &ProvenancedArtifactKey,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> (
        BudgetedValueAcquisition<ProvenancedArtifactKey, CachedSemanticArtifact>,
        CompleteValueWait,
    ) {
        #[cfg(any(test, feature = "test-support"))]
        self.acquiring.fetch_add(1, Ordering::AcqRel);
        let (acquisition, wait) = self.inner.acquire(key, cancellation);
        #[cfg(any(test, feature = "test-support"))]
        self.acquiring.fetch_sub(1, Ordering::AcqRel);
        let acquisition = match acquisition {
            BudgetedValueAcquisition::Leader { permit } => match self.live_instance(key) {
                Some(artifact) => BudgetedValueAcquisition::Cached {
                    value: self.publish(permit, &artifact),
                },
                None => BudgetedValueAcquisition::Leader { permit },
            },
            other => other,
        };
        (acquisition, wait)
    }

    /// Complete a flight with its artifact. The region keeps a charged one;
    /// an uncharged one is request-owned. Either way its identity is recorded
    /// first, so no flight that starts after this one completes can miss it.
    #[doc(hidden)]
    pub fn publish(
        &self,
        permit: BudgetedValuePermit<ProvenancedArtifactKey, CachedSemanticArtifact>,
        artifact: &Arc<SemanticArtifact>,
    ) -> BudgetedValue<CachedSemanticArtifact> {
        self.live
            .lock()
            .expect("semantic live-artifact map poisoned")
            .record(permit.key(), artifact);
        let cached = CachedSemanticArtifact::new(artifact);
        if artifact.allocation_charge().is_charged() {
            permit.publish_shared(cached)
        } else {
            permit.publish_request_owned(cached)
        }
    }

    /// Drop every artifact and fence every running build, forgetting the live
    /// identities too, so an invalidated instance cannot be reused (#3377).
    #[doc(hidden)]
    pub fn invalidate_all(&self) {
        self.inner.invalidate_all();
        self.live
            .lock()
            .expect("semantic live-artifact map poisoned")
            .instances
            .clear();
    }

    fn live_instance(&self, key: &ProvenancedArtifactKey) -> Option<Arc<SemanticArtifact>> {
        let mut live = self
            .live
            .lock()
            .expect("semantic live-artifact map poisoned");
        let artifact = live.instances.get(key)?.upgrade();
        if artifact.is_none() {
            live.instances.remove(key);
        }
        artifact
    }

    /// Look one already-published artifact up without reserving a flight.
    ///
    /// A caller that has not read the file cannot lead a lowering, so it must
    /// not take a permit: it asks only whether the artifact is already there.
    #[doc(hidden)]
    pub fn get_ready(
        &self,
        key: &ProvenancedArtifactKey,
        cancellation: &crate::analyzer::semantic::CancellationToken,
    ) -> Option<Arc<SemanticArtifact>> {
        self.inner
            .get_ready(key, cancellation)
            .map(|value| Arc::clone(value.arc()))
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.inner.region().stats().entries as u64
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn waiting_count(&self) -> usize {
        self.acquiring.load(Ordering::Acquire)
    }
}

/// Weak identities of published artifacts, swept of dropped ones whenever the
/// map doubles past its last sweep, so a sweep costs amortized constant time
/// per publication and dead entries never outnumber live ones by much.
#[derive(Default)]
struct LiveArtifacts {
    instances: HashMap<ProvenancedArtifactKey, Weak<SemanticArtifact>>,
    sweep_at: usize,
}

impl LiveArtifacts {
    const MIN_SWEEP_KEYS: usize = 1024;

    fn record(&mut self, key: &ProvenancedArtifactKey, artifact: &Arc<SemanticArtifact>) {
        debug_assert_eq!(&key.artifact, artifact.key());
        self.instances.insert(key.clone(), Arc::downgrade(artifact));
        if self.instances.len() > self.sweep_at.max(Self::MIN_SWEEP_KEYS) {
            self.instances.retain(|_, weak| weak.strong_count() > 0);
            self.sweep_at = self.instances.len().saturating_mul(2);
        }
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
    entries: BudgetRegion<SourceBlobKey, ContentIdentity>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SourceBlobKey(BlobKey);

impl RetainedBytes for SourceBlobKey {
    fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + brokk_bifrost_core::allocation_size::allocation_size(self.0.lang.capacity())
    }
}

impl RetainedBytes for ContentIdentity {
    fn retained_bytes(&self) -> usize {
        size_of::<Self>()
    }
}

impl SourceContentIdentityMemo {
    pub fn new(budget: &RetentionBudget) -> Self {
        Self {
            entries: budget.region(
                "semantic_source_content_identity",
                Some(SOURCE_CONTENT_IDENTITY_MEMO_ENTRIES as usize),
            ),
        }
    }
    #[doc(hidden)]
    pub fn get(&self, source: BlobKey) -> Option<ContentIdentity> {
        self.entries.get(&SourceBlobKey(source)).map(|value| *value)
    }

    #[doc(hidden)]
    pub fn record(&self, source: BlobKey, content: ContentIdentity) {
        self.entries.insert(SourceBlobKey(source), content);
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

    let locator_index_entry = size_of::<SemanticLocator>()
        .saturating_add(size_of::<ProcedureId>())
        .saturating_add(size_of::<usize>() * 2);
    let pointer_invalidation_rows = artifact
        .procedures()
        .iter()
        .fold(0usize, |rows, procedure| {
            rows.saturating_add(procedure.pointer_invalidations().len())
                .saturating_add(
                    procedure
                        .guarded_alternate()
                        .map_or(0, |alternate| alternate.pointer_invalidations().len()),
                )
        });
    ((size_of::<Arc<SemanticArtifact>>()
        + size_of::<SemanticArtifact>()
        + size_of::<SemanticArtifactKey>()) as u64)
        .saturating_add(retained_work_bytes(
            &artifact.work(),
            pointer_invalidation_rows,
        ))
        .saturating_add(rows(
            artifact.work().procedures,
            size_of::<ProcedureSemantics>(),
        ))
        .saturating_add(rows(artifact.work().procedures, locator_index_entry))
        .max(1)
}

fn retained_work_bytes(work: &SemanticWork, pointer_invalidation_rows: usize) -> u64 {
    fn rows(count: usize, row_size: usize) -> u64 {
        (count as u64).saturating_mul(row_size as u64)
    }
    let nested_entries = work
        .nested_entries
        .saturating_sub(pointer_invalidation_rows);
    0u64.saturating_add(rows(work.blocks, size_of::<BasicBlock>()))
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
        .saturating_add(work.source_bytes as u64)
}

/// Row storage of one frozen native body copied into a demand view.
#[doc(hidden)]
pub fn frozen_procedure_row_bytes(procedure: &ProcedureSemantics, census: SemanticWork) -> u64 {
    retained_work_bytes(&census, procedure.pointer_invalidations().len())
        .saturating_add(size_of::<ProcedureSemantics>() as u64)
}

/// Conservative retained size of a decoded procedure, including nested rows.
pub fn procedure_parts_retained_bytes(parts: &ProcedureSemanticsParts) -> usize {
    let work = crate::analyzer::semantic::measure_procedure_work(parts);
    let (headers, invalidations) = parts.retained_layout();
    let bytes = (headers as u64).saturating_add(retained_work_bytes(&work, invalidations));
    usize::try_from(bytes).unwrap_or(usize::MAX)
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
    if let Some(bytes) = artifact.ownership_projection_retained_bytes() {
        return bytes;
    }
    artifact
        .procedures()
        .iter()
        .fold(
            retained_artifact_base_bytes(artifact)
                .saturating_add(artifact.lexical_children_index_retained_bytes())
                .saturating_add(artifact.call_source_extents_retained_bytes()),
            |bytes, procedure| {
                let alternate_bytes = procedure.guarded_alternate().map_or(0, |alternate| {
                    procedure
                        .guarded_alternate_wrapper_bytes()
                        .saturating_add(alternate.call_indexes_retained_bytes())
                        .saturating_add(alternate.cleanup_chains().index_retained_bytes() as u64)
                        .saturating_add(alternate.callable_selection_dominance_reserved_bytes())
                        .saturating_add(alternate.value_identity_index_retained_bytes())
                });
                bytes
                    .saturating_add(alternate_bytes)
                    .saturating_add(procedure.call_indexes_retained_bytes())
                    .saturating_add(procedure.cleanup_chains().index_retained_bytes() as u64)
                    .saturating_add(procedure.callable_selection_dominance_reserved_bytes())
                    .saturating_add(procedure.call_gap_index_reserved_bytes())
                    .saturating_add(procedure.value_identity_index_retained_bytes())
            },
        )
        .max(1)
}

pub fn semantic_artifact_retained_bytes(artifact: &SemanticArtifact) -> u64 {
    retained_artifact_bytes(artifact.key(), artifact)
        .saturating_add(artifact.candidate_evidence_retained_bytes() as u64)
        .saturating_add(artifact.candidate_arena_retained_bytes())
}

impl SemanticArtifact {
    #[doc(hidden)]
    pub fn charge_guarded_arena(&mut self, budget: &RetentionBudget) {
        self.charge =
            AllocationCharge::acquire(budget, semantic_artifact_retained_bytes(self) as usize);
    }
}

#[cfg(feature = "test-support")]
impl SemanticArtifact {
    /// Record this canonical artifact allocation and its existing budget
    /// ownership for an explicit test-support census.
    #[doc(hidden)]
    pub fn retention_census_for_test(
        self: &Arc<Self>,
        census: &mut brokk_bifrost_core::retention_census::RetentionCensus<'_>,
        family: &'static str,
    ) {
        use brokk_bifrost_core::retention_census::{
            AllocationAccounting, FamilyLifetime, UnknownKind,
        };

        let mut pending = vec![Arc::clone(self)];
        let mut visited = std::collections::HashSet::new();
        while let Some(artifact) = pending.pop() {
            if !visited.insert(Arc::as_ptr(&artifact) as usize) {
                continue;
            }

            if let Some(base) = artifact.shared_ownership_base() {
                pending.push(Arc::clone(base));
            }
            let accounting = if artifact.charge.is_charged() {
                AllocationAccounting::AlreadyBudgeted
            } else {
                AllocationAccounting::OutsideBudget
            };
            let estimated_bytes = retained_artifact_bytes(artifact.key(), &artifact)
                .saturating_add(artifact.candidate_evidence_retained_bytes() as u64);
            let retained_candidate = artifact.retained_candidate_arena_for_test();
            census.record_arc_allocation(
                Arc::clone(&artifact),
                family,
                FamilyLifetime::Persistent,
                "semantic-artifact",
                estimated_bytes,
                accounting,
            );
            census.record_unknown(
                family,
                FamilyLifetime::Persistent,
                UnknownKind::Coverage,
                "semantic_artifact_estimate_omits_shared_cache_pin_and_opaque_evidence_allocations",
            );
            if let Some(retained_candidate) = retained_candidate {
                pending.push(retained_candidate);
            }
        }
    }
}

impl SelfCharged for SemanticArtifact {
    fn allocation_charge(&self) -> &AllocationCharge {
        &self.charge
    }
}

impl RetainedBytes for SemanticArtifactKey {
    fn retained_bytes(&self) -> usize {
        size_of::<Self>().saturating_add(brokk_bifrost_core::allocation_size::allocation_size(
            self.path().as_str().len(),
        ))
    }
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
#[allow(clippy::too_many_arguments)]
pub fn publish_lowered(
    retention_budget: &RetentionBudget,
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
                retention_budget,
                key.clone(),
                capabilities.clone(),
                $parts,
                &mut staged_budget,
                request.cancellation,
            ) {
                Ok(publication) => publication,
                Err(error) => {
                    *request.budget = staged_budget;
                    return Err(error);
                }
            };
            match publication {
                Publication::Artifact(artifact) => artifact,
                Publication::Cancelled => {
                    reconcile_observed_work(
                        &mut staged_budget,
                        started_work,
                        source_work.component_max($work),
                    );
                    *request.budget = staged_budget;
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: source_work.component_max($work),
                    });
                }
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
    Cancelled,
}

fn publish(
    retention_budget: &RetentionBudget,
    key: SemanticArtifactKey,
    capabilities: SemanticCapabilities,
    parts: Vec<ProcedureSemanticsParts>,
    budget: &mut crate::analyzer::semantic::SemanticBudget,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<Publication, SemanticProviderError> {
    match SemanticArtifact::try_new_with_budget(key, capabilities, parts, budget, cancellation) {
        Ok(mut artifact) => {
            artifact.charge = AllocationCharge::acquire(
                retention_budget,
                semantic_artifact_retained_bytes(&artifact) as usize,
            );
            let artifact = Arc::new(artifact);
            budget.track_resident_artifact(&artifact);
            Ok(Publication::Artifact(artifact))
        }
        Err(SemanticArtifactBuildError::Cancelled) => Ok(Publication::Cancelled),
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
    fn from_region(census: brokk_bifrost_core::retention_budget::RevivalCensus) -> Self {
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
// Revisit when Python moves to the native engine. The prepared dispatch pool
// still uses this cap; the complete artifact cache uses the owner's budget.
#[doc(hidden)]
pub const SEMANTIC_MATERIALIZATION_CACHE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// One cache-owned artifact reference, excluded from a root's resident census.
/// The mutex serializes reference creation/destruction with census reads,
/// including delayed physical reclamation after logical eviction.
#[doc(hidden)]
pub struct CachedSemanticArtifact(Option<SharedAllocation<SemanticArtifact>>);

impl CachedSemanticArtifact {
    #[doc(hidden)]
    pub fn new(artifact: &Arc<SemanticArtifact>) -> Self {
        let mut pins = artifact.cache_pins.lock();
        *pins += 1;
        Self(Some(SharedAllocation::new(Arc::clone(artifact))))
    }

    pub fn arc(&self) -> &Arc<SemanticArtifact> {
        self.0
            .as_ref()
            .expect("cache artifact is live until drop")
            .arc()
    }
}

impl RetainedBytes for CachedSemanticArtifact {
    fn retained_bytes(&self) -> usize {
        self.0
            .as_ref()
            .expect("cache artifact is live until drop")
            .retained_bytes()
    }

    fn eviction_bytes(&self) -> usize {
        self.0
            .as_ref()
            .expect("cache artifact is live until drop")
            .eviction_bytes()
    }
}

impl SharedValue for CachedSemanticArtifact {
    type Shared = SemanticArtifact;

    fn shared(&self) -> &Arc<SemanticArtifact> {
        self.arc()
    }

    fn rewrap(artifact: Arc<SemanticArtifact>) -> Self {
        Self::new(&artifact)
    }
}

impl std::ops::Deref for CachedSemanticArtifact {
    type Target = Arc<SemanticArtifact>;

    fn deref(&self) -> &Self::Target {
        self.arc()
    }
}

impl Drop for CachedSemanticArtifact {
    fn drop(&mut self) {
        let artifact = self.0.take().expect("cache artifact drops once");
        let counter = Arc::clone(&artifact.arc().cache_pins);
        let mut pins = counter.lock();
        *pins -= 1;
        drop(artifact);
    }
}

/// Shared retained-byte model for a concrete standard-library hash table.
/// Census scratch itself uses exact boxed slots instead of this payload model.
pub fn retained_hash_table_bytes<T>(capacity: usize) -> usize {
    if capacity == 0 {
        return 0;
    }
    let Some(buckets) = capacity
        .saturating_mul(8)
        .div_ceil(7)
        .checked_next_power_of_two()
    else {
        return usize::MAX;
    };
    buckets
        .saturating_mul(size_of::<T>() + 1)
        .saturating_add(16)
}

/// Allocation and temporary traversal storage share the caller's existing
/// retention allowance. Refusal is terminal for the lifetime of this census.
pub trait RetentionCensusSink {
    fn allocation(&mut self, identity: usize, bytes: usize) -> bool;
    fn exclusive(&mut self, bytes: usize);
    fn reserve_scratch(&mut self, bytes: usize) -> bool;
    fn release_scratch(&mut self, bytes: usize);
    fn is_refused(&self) -> bool;
    fn refuse(&mut self);
    fn weak_allocation(&mut self, identity: usize, bytes: usize);
}

/// Exact boxed traversal storage, funded before allocation. The previous box
/// remains charged until the replacement has been populated and installed.
pub struct RetentionScratch<T> {
    slots: Box<[Option<T>]>,
    len: usize,
}
impl<T> Default for RetentionScratch<T> {
    fn default() -> Self {
        Self {
            slots: Box::default(),
            len: 0,
        }
    }
}
impl<T> RetentionScratch<T> {
    pub fn push(&mut self, value: T, sink: &mut (impl RetentionCensusSink + ?Sized)) {
        if sink.is_refused() {
            return;
        }
        if self.len == self.slots.len() {
            let Some(capacity) = self.slots.len().max(1).checked_mul(2) else {
                sink.refuse();
                return;
            };
            let Some(bytes) = capacity.checked_mul(size_of::<Option<T>>()) else {
                sink.refuse();
                return;
            };
            if !sink.reserve_scratch(bytes) {
                return;
            }
            let mut slots = Box::<[Option<T>]>::new_uninit_slice(capacity);
            for slot in &mut slots {
                slot.write(None);
            }
            // SAFETY: every slot contains an initialized None.
            let mut slots = unsafe { slots.assume_init() };
            for (next, previous) in slots.iter_mut().zip(self.slots.iter_mut()) {
                *next = previous.take();
            }
            let old = std::mem::replace(&mut self.slots, slots);
            let old_bytes = std::mem::size_of_val(old.as_ref());
            drop(old);
            sink.release_scratch(old_bytes);
        }
        self.slots[self.len] = Some(value);
        self.len += 1;
    }
    pub fn extend(
        &mut self,
        values: impl IntoIterator<Item = T>,
        sink: &mut (impl RetentionCensusSink + ?Sized),
    ) {
        for value in values {
            if sink.is_refused() {
                break;
            }
            self.push(value, sink);
        }
    }
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        self.slots[self.len].take()
    }
    pub fn release(self, sink: &mut (impl RetentionCensusSink + ?Sized)) {
        let bytes = std::mem::size_of_val(self.slots.as_ref());
        drop(self);
        sink.release_scratch(bytes);
    }
}

/// Existing semantic owner traversal, independent of the store's census type.
pub trait ArtifactRetentionVisitor: RetentionCensusSink {
    fn artifact(&mut self, artifact: &Arc<SemanticArtifact>);
    fn relation(&mut self, relation: &crate::analyzer::semantic::OracleRelationHandle);
    fn shared_allocation(&mut self, identity: usize, bytes: impl FnOnce() -> usize) -> bool {
        if self.is_refused() {
            return false;
        }
        self.allocation(identity, bytes())
    }
    fn map<K, V, S>(&mut self, values: &std::collections::HashMap<K, V, S>) {
        self.exclusive(retained_hash_table_bytes::<(K, V)>(values.capacity()));
    }
    fn hash_set<T, S>(&mut self, values: &std::collections::HashSet<T, S>) {
        self.exclusive(retained_hash_table_bytes::<T>(values.capacity()));
    }
    fn arena(&mut self, identity: usize, bytes: impl FnOnce() -> usize) -> bool {
        self.shared_allocation(identity, bytes)
    }
    fn owned_box<T: ?Sized>(&mut self, value: &T) -> bool {
        let bytes = std::mem::size_of_val(value);
        bytes == 0 || self.allocation(std::ptr::from_ref(value).cast::<()>() as usize, bytes)
    }
    fn owned_slice<T>(&mut self, values: &[T]) -> bool {
        let bytes = std::mem::size_of_val(values);
        bytes != 0 && self.allocation(values.as_ptr().cast::<()>() as usize, bytes)
    }
    fn owned_vec<T>(&mut self, values: &Vec<T>) -> bool {
        let bytes = values.capacity().saturating_mul(size_of::<T>());
        bytes != 0 && self.allocation(values.as_ptr().cast::<()>() as usize, bytes)
    }
    fn owned_string(&mut self, value: &String) {
        if value.capacity() != 0 {
            self.allocation(value.as_ptr() as usize, value.capacity());
        }
    }
    fn locator(&mut self, locator: &crate::analyzer::semantic::SemanticLocator) {
        self.owned_slice(locator.path().as_str().as_bytes());
        self.declaration(locator.declaration());
    }
    fn declaration(&mut self, declaration: &crate::analyzer::semantic::DeclarationLocator) {
        if self.owned_slice(declaration.segments()) {
            for segment in declaration.segments() {
                if let Some(name) = segment.name() {
                    self.owned_slice(name.as_bytes());
                }
            }
        }
    }
    fn artifact_key(&mut self, key: &crate::analyzer::semantic::SemanticArtifactKey) {
        self.owned_slice(key.path().as_str().as_bytes());
        self.owned_slice(key.adapter().name().as_bytes());
    }
    fn project_file(&mut self, file: &brokk_bifrost_core::analyzer::model::ProjectFile) {
        let (owner, root, path_capacity) = file.retained_parts();
        if self.shared_allocation(Arc::as_ptr(owner).cast::<()>() as usize, || {
            std::mem::size_of_val(owner.as_ref()) + 2 * size_of::<usize>() + path_capacity
        }) {
            self.shared_allocation(Arc::as_ptr(root).cast::<()>() as usize, || {
                std::mem::size_of_val(root.as_ref()) + 2 * size_of::<usize>()
            });
        }
    }
    fn code_unit(&mut self, unit: &brokk_bifrost_core::analyzer::model::CodeUnit) {
        let (owner, source, bytes) = unit.retained_parts();
        if self.shared_allocation(Arc::as_ptr(owner).cast::<()>() as usize, || {
            std::mem::size_of_val(owner.as_ref()) + 2 * size_of::<usize>() + bytes
        }) {
            self.project_file(source);
        }
    }
    fn usage(&mut self, usage: &brokk_bifrost_core::analyzer::usages::model::UsageHit) {
        self.project_file(&usage.file);
        self.code_unit(&usage.enclosing);
        self.owned_string(&usage.snippet);
        if let Some(reason) = &usage.reason_kind {
            self.owned_string(reason);
        }
    }
    fn procedure(&mut self, procedure: &crate::analyzer::semantic::ProcedureHandle) {
        self.artifact(procedure.artifact());
    }
    fn context(&mut self, context: &crate::analyzer::semantic::OracleCallContext) {
        self.owned_slice(context.calls());
        for call in context.calls() {
            self.procedure(call.procedure());
        }
    }
}

enum RetainedArtifactTask {
    Artifact(Arc<SemanticArtifact>),
    Relation(crate::analyzer::semantic::OracleRelationHandle),
}

/// Uses the caller's ONE owner registry; allocates no separate visited tables.
/// All pending traversal slots are prepaid through that same sink.
pub struct RetainedArtifactWalker<'a, S: RetentionCensusSink> {
    sink: &'a mut S,
    pending: RetentionScratch<RetainedArtifactTask>,
}
impl<'a, S: RetentionCensusSink> RetainedArtifactWalker<'a, S> {
    pub fn new(sink: &'a mut S) -> Self {
        Self {
            sink,
            pending: RetentionScratch::default(),
        }
    }
    pub fn finish(mut self) {
        while !self.sink.is_refused() {
            let Some(task) = self.pending.pop() else {
                break;
            };
            match task {
                RetainedArtifactTask::Relation(relation) => {
                    relation.collect_retained_artifacts(&mut self)
                }
                RetainedArtifactTask::Artifact(artifact) => {
                    artifact.for_each_retained_candidate_arena(|arena| self.artifact(arena));
                }
            }
        }
        self.pending.release(self.sink);
    }
}
impl<S: RetentionCensusSink> RetentionCensusSink for RetainedArtifactWalker<'_, S> {
    fn allocation(&mut self, identity: usize, bytes: usize) -> bool {
        self.sink.allocation(identity, bytes)
    }
    fn exclusive(&mut self, bytes: usize) {
        self.sink.exclusive(bytes);
    }
    fn reserve_scratch(&mut self, bytes: usize) -> bool {
        self.sink.reserve_scratch(bytes)
    }
    fn release_scratch(&mut self, bytes: usize) {
        self.sink.release_scratch(bytes);
    }
    fn is_refused(&self) -> bool {
        self.sink.is_refused()
    }
    fn refuse(&mut self) {
        self.sink.refuse();
    }
    fn weak_allocation(&mut self, identity: usize, bytes: usize) {
        self.sink.weak_allocation(identity, bytes);
    }
}
impl<S: RetentionCensusSink> ArtifactRetentionVisitor for RetainedArtifactWalker<'_, S> {
    fn artifact(&mut self, artifact: &Arc<SemanticArtifact>) {
        if self.is_refused() {
            return;
        }
        // Preserve the existing semantic artifact owner's byte model, but walk
        // retained candidate arenas independently so aliased arenas count once.
        let bytes = retained_artifact_bytes(artifact.key(), artifact)
            .saturating_add(artifact.candidate_evidence_retained_bytes() as u64);
        if self.allocation(
            Arc::as_ptr(artifact) as usize,
            usize::try_from(bytes).unwrap_or(usize::MAX),
        ) {
            // These concrete control allocations are not part of the stored
            // artifact row-weight estimate. Other receipts can share them.
            self.allocation(
                Arc::as_ptr(&artifact.cache_pins) as usize,
                std::mem::size_of_val(artifact.cache_pins.as_ref()) + 2 * size_of::<usize>(),
            );
            if let Some((identity, bytes)) =
                artifact.allocation_charge().retained_control_allocation()
            {
                self.allocation(identity, bytes);
            }
            self.pending.push(
                RetainedArtifactTask::Artifact(Arc::clone(artifact)),
                self.sink,
            );
        }
    }
    fn relation(&mut self, relation: &crate::analyzer::semantic::OracleRelationHandle) {
        self.pending
            .push(RetainedArtifactTask::Relation(relation.clone()), self.sink);
    }
}

/// Temporary, allocation-deduplicated census for cache admission and timing.
/// Drop after one entry weight or one diagnostic sample.
#[doc(hidden)]
#[derive(Default)]
pub struct ArtifactRetentionCensus {
    artifacts: brokk_bifrost_core::hash::HashMap<usize, (Arc<SemanticArtifact>, u64)>,
    arenas: brokk_bifrost_core::hash::HashMap<usize, usize>,
    shared_allocations: brokk_bifrost_core::hash::HashMap<usize, usize>,
    artifact_bytes: u64,
    arena_bytes: u64,
    shared_bytes: u64,
    pending_relations: Vec<crate::analyzer::semantic::OracleRelationHandle>,
}

impl ArtifactRetentionCensus {
    /// Count an immutable shared allocation once within this census. The
    /// caller must keep its owner alive while the census is being assembled.
    pub fn shared_allocation(&mut self, identity: usize, bytes: impl FnOnce() -> usize) -> bool {
        if self.shared_allocations.contains_key(&identity) {
            return false;
        }
        let bytes = bytes();
        self.shared_allocations.insert(identity, bytes);
        self.shared_bytes = self.shared_bytes.saturating_add(bytes as u64);
        true
    }

    pub(crate) fn owned_slice<T>(&mut self, values: &[T]) -> bool {
        if std::mem::size_of_val(values) == 0 {
            return false;
        }
        self.shared_allocation(values.as_ptr().cast::<()>() as usize, || {
            std::mem::size_of_val(values)
        })
    }

    pub fn artifact(&mut self, artifact: &Arc<SemanticArtifact>) {
        let identity = Arc::as_ptr(artifact) as usize;
        if let std::collections::hash_map::Entry::Vacant(entry) = self.artifacts.entry(identity) {
            let bytes = semantic_artifact_retained_bytes(artifact);
            entry.insert((Arc::clone(artifact), bytes));
            self.artifact_bytes = self.artifact_bytes.saturating_add(bytes);
        }
    }

    pub fn procedure(&mut self, procedure: &crate::analyzer::semantic::ProcedureHandle) {
        self.artifact(procedure.artifact());
    }

    pub(crate) fn arena(&mut self, identity: usize, bytes: impl FnOnce() -> usize) -> bool {
        if self.arenas.contains_key(&identity) {
            return false;
        }
        let bytes = bytes();
        self.arenas.insert(identity, bytes);
        self.arena_bytes = self.arena_bytes.saturating_add(bytes as u64);
        true
    }

    pub fn context(&mut self, context: &crate::analyzer::semantic::OracleCallContext) {
        self.owned_slice(context.calls());
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

    /// Borrow every actual artifact allocation found by the existing provenance
    /// traversal, including artifacts reached only through nested arenas.
    pub fn for_each_artifact(&mut self, mut visit: impl FnMut(&Arc<SemanticArtifact>)) {
        self.drain_relations();
        for (artifact, _) in self.artifacts.values() {
            visit(artifact);
        }
    }

    /// Reuse the first census's artifact weights without walking those artifacts again.
    pub fn artifact_allocation_records(&mut self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.drain_relations();
        self.artifacts
            .iter()
            .map(|(identity, (_, bytes))| (*identity, *bytes))
    }

    /// Non-artifact shared allocations. The caller must retain their owners
    /// until these pointer identities have been removed from its accounting.
    pub fn shared_allocation_records(&mut self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.drain_relations();
        self.shared_allocations
            .iter()
            .chain(&self.arenas)
            .map(|(identity, bytes)| (*identity, *bytes))
    }

    pub fn artifact_bytes(&mut self) -> u64 {
        self.drain_relations();
        self.artifact_bytes
    }
    pub fn retained_bytes(&mut self) -> u64 {
        self.drain_relations();
        self.artifact_bytes
            .saturating_add(self.arena_bytes)
            .saturating_add(self.shared_bytes)
    }
}

impl RetentionCensusSink for ArtifactRetentionCensus {
    fn exclusive(&mut self, bytes: usize) {
        self.shared_bytes = self.shared_bytes.saturating_add(bytes as u64);
    }
    fn allocation(&mut self, identity: usize, bytes: usize) -> bool {
        self.shared_allocation(identity, || bytes)
    }
    fn reserve_scratch(&mut self, _: usize) -> bool {
        true
    }
    fn release_scratch(&mut self, _: usize) {}
    fn is_refused(&self) -> bool {
        false
    }
    fn refuse(&mut self) {
        panic!("semantic census storage overflow");
    }
    fn weak_allocation(&mut self, identity: usize, bytes: usize) {
        if identity != usize::MAX {
            self.allocation(identity, bytes);
        }
    }
}
impl ArtifactRetentionVisitor for ArtifactRetentionCensus {
    fn artifact(&mut self, artifact: &Arc<SemanticArtifact>) {
        ArtifactRetentionCensus::artifact(self, artifact);
    }
    fn relation(&mut self, relation: &crate::analyzer::semantic::OracleRelationHandle) {
        ArtifactRetentionCensus::relation(self, relation);
    }
    fn arena(&mut self, identity: usize, bytes: impl FnOnce() -> usize) -> bool {
        ArtifactRetentionCensus::arena(self, identity, bytes)
    }
}

/// All-or-none selection returned by the language admission owner.
pub enum CandidateProcedureSelection<T> {
    Base(T),
    Alternate(T),
}

#[derive(Clone)]
pub struct SelectedCandidateProcedure<T> {
    pub side: CandidateProcedureSide,
    pub procedure: super::ProcedureHandle,
    pub flows: super::partial_flow::ProcedurePartialFlows,
    pub admissions: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateProcedureSide {
    Base,
    Alternate,
}

/// Stops never carry an executable, partially admitted alternate.
pub enum CandidateProcedureOutcome<T> {
    Selected(SelectedCandidateProcedure<T>),
    Cancelled,
    ExceededBudget(super::SemanticBudgetExceeded),
}

/// Preserve dispatch evidence while binding the selected callee's formal ports.
pub fn reseal_selected_candidate(
    candidate: &super::DispatchCandidate,
    call: &super::CallSiteHandle,
    selected: &super::ProcedureHandle,
    limits: super::OracleLimits,
) -> Result<super::DispatchCandidate, super::OracleContractError> {
    candidate.reseal_selected(call, selected, limits)
}

/// The sole query-time mint for executable guarded procedure handles.
/// The callback owns admission policy; this owner keeps semantics and flows paired.
pub fn select_candidate_procedure<T>(
    prepared: &super::StoredCandidateMacroArtifact<
        impl AsRef<
            [(
                super::ProcedureId,
                super::partial_flow::ProcedurePartialFlows,
            )],
        >,
    >,
    base: &super::ProcedureHandle,
    base_flows: Option<&super::partial_flow::ProcedurePartialFlows>,
    select: impl FnOnce(
        &super::ProcedureSemantics,
        &[super::CandidateRecord],
    ) -> CandidateProcedureSelection<T>,
    request: &mut super::SemanticRequest<'_>,
) -> Result<CandidateProcedureOutcome<T>, super::SemanticProviderError> {
    use super::SemanticWork;
    use super::partial_flow::{
        file_local_procedure_relations, fixpoint::partial_flows_from_projection,
    };
    if request.cancellation.is_cancelled() {
        return Ok(CandidateProcedureOutcome::Cancelled);
    }
    assert_eq!(prepared.artifact.key(), base.artifact().key());
    let procedure = prepared
        .artifact
        .procedure(base.id())
        .expect("validated base procedure");
    let alternate = procedure.candidate_macro_alternate();
    let (semantics, candidates) = alternate.unwrap_or((procedure, &[]));
    // Charge candidate processing before invoking any language proof.
    if let Err(exceeded) = request.budget.admit(SemanticWork {
        call_sites: candidates.len(),
        ..Default::default()
    }) {
        return Ok(CandidateProcedureOutcome::ExceededBudget(exceeded));
    }
    let (mut side, admissions) = match select(semantics, candidates) {
        CandidateProcedureSelection::Base(answers) => (CandidateProcedureSide::Base, answers),
        CandidateProcedureSelection::Alternate(answers) => {
            (CandidateProcedureSide::Alternate, answers)
        }
    };
    if request.cancellation.is_cancelled() {
        return Ok(CandidateProcedureOutcome::Cancelled);
    }
    if alternate.is_none() {
        side = CandidateProcedureSide::Base;
    }
    let (handle, stored) = match side {
        CandidateProcedureSide::Base => (base.base_interpretation(), base_flows),
        CandidateProcedureSide::Alternate => (
            prepared
                .artifact
                .candidate_alternate_handle(base.id())
                .expect("validated alternate"),
            prepared
                .flows
                .as_ref()
                .iter()
                .find(|(id, _)| *id == base.id())
                .map(|(_, flows)| flows),
        ),
    };
    let flows = if let Some(stored) = stored {
        if let Err(exceeded) = request.budget.admit(stored.semantic_work()) {
            return Ok(CandidateProcedureOutcome::ExceededBudget(exceeded));
        }
        stored.clone()
    } else {
        let projected =
            file_local_procedure_relations(&handle, &super::OracleCallContext::empty(), request);
        let Some(flows) = partial_flows_from_projection(&handle, projected, request) else {
            return Ok(CandidateProcedureOutcome::Cancelled);
        };
        flows
    };
    if request.cancellation.is_cancelled() {
        return Ok(CandidateProcedureOutcome::Cancelled);
    }
    debug_assert!(side != CandidateProcedureSide::Base || !handle.is_candidate_alternate());
    // Selection is decided even when the paired flows retain a coarse budget stop.
    Ok(CandidateProcedureOutcome::Selected(
        SelectedCandidateProcedure {
            side,
            procedure: handle,
            flows,
            admissions,
        },
    ))
}

#[derive(Debug, Clone)]
pub enum CandidateMacroRefusal {
    /// `candidate_realization_incomplete`: guarded actuals do not match the proven layout.
    RealizationIncomplete,
    UnsupportedLanguage,
    UnavailableAnalyzer,
    Cancelled,
    Evidence(String),
    Route(String),
}

/// Lightweight executable selection with the refusal evidence from its admission receipt.
#[derive(Debug, Clone)]
pub struct SelectedProcedureHandle {
    pub handle: super::ProcedureHandle,
    pub side: CandidateProcedureSide,
    pub refusals: Vec<CandidateMacroRefusalEvidence>,
}

#[derive(Debug, Clone)]
pub struct CandidateMacroRefusalEvidence {
    pub anchor: super::SourceAnchor,
    pub reason: CandidateMacroRefusal,
}

/// Shared evidence rendering for query and policy coverage diagnostics.
pub fn candidate_macro_refusal_detail(refusals: &[CandidateMacroRefusalEvidence]) -> String {
    refusals
        .iter()
        .map(|evidence| format!("{:?}: {:?}", evidence.anchor, evidence.reason))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod allocated_bytes_refusing_pins {
    use super::*;

    #[test]
    fn resident_work_and_registration_payload_keep_master_bytes() {
        // Resident admission and both protocol/taint artifact registrations use
        // this raw census. Text doubles and source bytes stay unrounded.
        let work = SemanticWork {
            owned_text_bytes: 64,
            source_bytes: 17,
            ..SemanticWork::default()
        };
        assert_eq!(retained_work_bytes(&work, 0), 145);
    }
}
