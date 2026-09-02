//! Shared snapshot, publication, and complete-cache mechanics for language lowerers.

use std::mem::size_of;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use git2::Oid;
use moka::sync::Cache;

use crate::analyzer::QueryScope;
use crate::analyzer::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValueWait,
};
use crate::analyzer::tree_sitter_analyzer::{PreparedSourceOrigin, PreparedSyntaxTree};
use crate::analyzer::{
    LanguageAdapter, LanguageDialect, OverlayRevision, ProjectFile, ProjectSourceOrigin,
    TreeSitterAnalyzer,
};

use super::{
    AdapterSemanticsVersion, AllocationSite, BasicBlock, CaptureBinding, ConfigurationFingerprint,
    ContentIdentity, ControlEdge, DependencyFingerprint, Evidence, MemoryLocation,
    OverlaySnapshotId, ProcedureId, ProcedureSemantics, ProcedureSemanticsParts, ProgramPoint,
    SemanticArtifact, SemanticArtifactBuildError, SemanticArtifactKey, SemanticCallSite,
    SemanticCapabilities, SemanticEvent, SemanticGap, SemanticIrVersion, SemanticLocator,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticValue, SemanticWork,
    SourceMapping, SourceRevision, WorkspaceMountId, WorkspaceRelativePath,
};

const DEFAULT_COMPLETE_CACHE_BYTES: u64 = 256 * 1024 * 1024 / 8;

#[cfg(any(test, feature = "test-support"))]
const NO_SEMANTIC_INVALIDATION_WITNESS: u8 = 0;
#[cfg(any(test, feature = "test-support"))]
const SELECTOR_CONTINUATION_INVALIDATION_WITNESS: u8 = 1;
#[cfg(any(test, feature = "test-support"))]
const EVALUATION_ROOT_CONTINUATION_INVALIDATION_WITNESS: u8 = 2;

/// Immutable complete-artifact cache shared by one concrete analyzer adapter.
///
/// Moka bounds retained bytes rather than entry count. Incomplete outcomes are
/// never presented to this type, so a lookup can always be treated as a fully
/// validated immutable artifact. The in-flight map serializes construction for
/// one exact artifact key without retaining completed work.
#[derive(Clone)]
pub(crate) struct CompleteSemanticArtifactCache {
    inner: CompleteValueCache<SemanticArtifactKey, SemanticArtifact>,
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
    selector_continuation_revivals: Arc<AtomicU64>,
    #[cfg(any(test, feature = "test-support"))]
    evaluation_root_continuation_revivals: Arc<AtomicU64>,
}

impl Default for CompleteSemanticArtifactCache {
    fn default() -> Self {
        Self::new(DEFAULT_COMPLETE_CACHE_BYTES)
    }
}

impl CompleteSemanticArtifactCache {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            inner: CompleteValueCache::new(max_retained_bytes, weigh_complete_artifact),
            #[cfg(any(test, feature = "test-support"))]
            selector_continuation_invalidation_armed: Arc::new(AtomicBool::new(false)),
            #[cfg(any(test, feature = "test-support"))]
            evaluation_root_continuation_invalidation_armed: Arc::new(AtomicBool::new(false)),
            #[cfg(any(test, feature = "test-support"))]
            active_invalidation_witness: Arc::new(AtomicU8::new(NO_SEMANTIC_INVALIDATION_WITNESS)),
            #[cfg(any(test, feature = "test-support"))]
            selector_continuation_revivals: Arc::new(AtomicU64::new(0)),
            #[cfg(any(test, feature = "test-support"))]
            evaluation_root_continuation_revivals: Arc::new(AtomicU64::new(0)),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn arm_selector_continuation_invalidation_for_test(&self) {
        self.selector_continuation_invalidation_armed
            .store(true, Ordering::Release);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn invalidate_selector_continuation_if_armed_for_test(&self) {
        if !self
            .selector_continuation_invalidation_armed
            .swap(false, Ordering::AcqRel)
        {
            return;
        }
        self.activate_invalidation_witness_for_test(
            SELECTOR_CONTINUATION_INVALIDATION_WITNESS,
            &self.selector_continuation_revivals,
        );
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn arm_evaluation_root_continuation_invalidation_for_test(&self) {
        self.evaluation_root_continuation_invalidation_armed
            .store(true, Ordering::Release);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn invalidate_evaluation_root_continuation_if_armed_for_test(&self) {
        if !self
            .evaluation_root_continuation_invalidation_armed
            .swap(false, Ordering::AcqRel)
        {
            return;
        }
        self.activate_invalidation_witness_for_test(
            EVALUATION_ROOT_CONTINUATION_INVALIDATION_WITNESS,
            &self.evaluation_root_continuation_revivals,
        );
    }

    #[cfg(any(test, feature = "test-support"))]
    fn activate_invalidation_witness_for_test(&self, witness: u8, counter: &AtomicU64) {
        self.latch_active_invalidation_revivals_for_test();
        counter.store(0, Ordering::Relaxed);
        self.active_invalidation_witness
            .store(witness, Ordering::Release);
        self.inner.reset_revivals_for_test();
        self.inner.invalidate_all_for_test();
    }

    #[cfg(any(test, feature = "test-support"))]
    fn latch_active_invalidation_revivals_for_test(&self) {
        let revivals = self.inner.revivals_for_test();
        match self.active_invalidation_witness.load(Ordering::Acquire) {
            SELECTOR_CONTINUATION_INVALIDATION_WITNESS => {
                self.selector_continuation_revivals
                    .fetch_max(revivals, Ordering::Relaxed);
            }
            EVALUATION_ROOT_CONTINUATION_INVALIDATION_WITNESS => {
                self.evaluation_root_continuation_revivals
                    .fetch_max(revivals, Ordering::Relaxed);
            }
            NO_SEMANTIC_INVALIDATION_WITNESS => {}
            witness => panic!("unknown semantic invalidation witness {witness}"),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn invalidation_revivals_for_test(&self, witness: u8, counter: &AtomicU64) -> u64 {
        let retained = counter.load(Ordering::Relaxed);
        if self.active_invalidation_witness.load(Ordering::Acquire) == witness {
            retained.max(self.inner.revivals_for_test())
        } else {
            retained
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn selector_continuation_revivals_for_test(&self) -> u64 {
        self.invalidation_revivals_for_test(
            SELECTOR_CONTINUATION_INVALIDATION_WITNESS,
            &self.selector_continuation_revivals,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn evaluation_root_continuation_revivals_for_test(&self) -> u64 {
        self.invalidation_revivals_for_test(
            EVALUATION_ROOT_CONTINUATION_INVALIDATION_WITNESS,
            &self.evaluation_root_continuation_revivals,
        )
    }

    #[cfg(test)]
    fn insert(&self, key: SemanticArtifactKey, artifact: Arc<SemanticArtifact>) {
        self.inner.insert_complete_for_test(key, artifact);
    }

    fn acquire(
        &self,
        key: &SemanticArtifactKey,
        cancellation: &super::CancellationToken,
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
    fn get_ready(
        &self,
        key: &SemanticArtifactKey,
        cancellation: &super::CancellationToken,
    ) -> Option<Arc<SemanticArtifact>> {
        self.inner.get_ready(key, cancellation)
    }

    #[cfg(test)]
    fn len(&self) -> u64 {
        self.inner.len_for_test()
    }

    #[cfg(test)]
    fn waiting_count(&self) -> usize {
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
pub(crate) struct SourceContentIdentityMemo {
    entries: Cache<Oid, ContentIdentity>,
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
    fn get(&self, source: Oid) -> Option<ContentIdentity> {
        self.entries.get(&source)
    }

    fn record(&self, source: Oid, content: ContentIdentity) {
        self.entries.insert(source, content);
    }
}

/// Convert the artifact's exact retained-work census and fixed cache overhead
/// into the base portion of its conservative byte weight. Source bytes are
/// intentionally absent: the prepared source is not owned by
/// `SemanticArtifact`.
fn retained_artifact_base_bytes(artifact: &SemanticArtifact) -> u64 {
    fn rows(count: usize, row_size: usize) -> u64 {
        (count as u64).saturating_mul(row_size as u64)
    }

    let work = artifact.work();
    let locator_index_entry = size_of::<SemanticLocator>()
        .saturating_add(size_of::<ProcedureId>())
        .saturating_add(size_of::<usize>() * 2);
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
            work.nested_entries,
            size_of::<SemanticLocator>().saturating_mul(2).max(64),
        ))
        .saturating_add((work.owned_text_bytes as u64).saturating_mul(2));

    bytes.max(1)
}

/// Convert the artifact's retained rows and derived indexes into a conservative
/// byte weight. Fixed rows use their concrete Rust size; nested entries reserve
/// at least twice a `SemanticLocator`, and owned text is doubled to cover the
/// independently cloned Moka key. Hash-map bucket, boxed payload, allocator,
/// and Arc allocation overhead are included explicitly.
fn retained_artifact_bytes(key: &SemanticArtifactKey, artifact: &SemanticArtifact) -> u64 {
    // `key` is intentionally used here as an invariant check: the cache must
    // weigh the same immutable identity embedded in the artifact.
    debug_assert_eq!(key, artifact.key());
    artifact
        .procedures()
        .iter()
        .fold(
            retained_artifact_base_bytes(artifact),
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
pub(crate) struct SemanticAdapterIdentity {
    pub(crate) adapter: AdapterSemanticsVersion,
    pub(crate) configuration: ConfigurationFingerprint,
    pub(crate) dependencies: DependencyFingerprint,
}

/// The private boundary implemented by one real language lowering adapter.
///
/// `work` in the returned outcome is prospective/observed work only. The
/// service merges it with the validated artifact's retained work at
/// publication, and only publication mutates the caller's budget.
pub(crate) trait ProgramSemanticsLowerer: Send + Sync {
    fn identity(&self) -> SemanticAdapterIdentity;

    fn capabilities(&self) -> SemanticCapabilities;

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &super::SemanticBudget,
        cancellation: &super::CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError>;
}

fn validate_semantic_file<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
) -> Result<(), SemanticProviderError> {
    if file.root() != analyzer.project().root() {
        return Err(SemanticProviderError::invalid_identity(format!(
            "semantic file root `{}` does not match analyzer root `{}`",
            file.root().display(),
            analyzer.project().root().display()
        )));
    }
    let file_language = crate::analyzer::common::language_for_file(file);
    if file_language != analyzer.adapter().language() {
        return Err(SemanticProviderError::invalid_identity(format!(
            "semantic file language {} does not match {} adapter",
            file_language.config_label(),
            analyzer.adapter().language().config_label()
        )));
    }
    Ok(())
}

/// Capture current source and derive its complete artifact identity from the
/// same atomic project snapshot. This deliberately does not parse, consult the
/// artifact cache, lower procedures, or mutate a semantic budget.
pub(crate) fn current_artifact_source_with_lowerer<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    max_source_bytes: usize,
) -> Result<Option<super::SemanticArtifactSourceSnapshot>, SemanticProviderError> {
    validate_semantic_file(analyzer, file)?;
    let (source_identity, snapshot) = match analyzer.source_snapshot_limited(file, max_source_bytes)
    {
        Ok(Some(resolved)) => resolved,
        Ok(None) => {
            return Err(SemanticProviderError::source_access(format!(
                "could not capture the current source snapshot for `{file}`"
            )));
        }
        Err(_) => return Ok(None),
    };
    let overlay_revision = match snapshot.origin() {
        ProjectSourceOrigin::Disk => None,
        ProjectSourceOrigin::Overlay(revision) => Some(revision),
    };
    let source = snapshot.into_source();
    // Identity of exactly these bytes, hashed once per distinct content rather
    // than once per freshness check: this path runs for every call site the
    // dispatch oracle resolves, and re-hashing a file it has already hashed is
    // the residual #2295 named.
    let digests = analyzer.semantic_source_digests();
    let content = match digests.get(source_identity) {
        Some(content) => content,
        None => {
            let content = ContentIdentity::hash_bytes(source.as_bytes());
            digests.record(source_identity, content);
            content
        }
    };
    let key = semantic_artifact_key_from_content(
        file,
        LanguageDialect::for_path(analyzer.adapter().language(), file.rel_path()),
        content,
        overlay_revision,
        lowerer.identity(),
    )?;
    Ok(Some(super::SemanticArtifactSourceSnapshot::new(
        key, source,
    )))
}

/// Materialize against exactly one prepared syntax snapshot.
///
/// The content digest, source origin, dialect, tree, and source mappings all
/// come from `prepared_syntax`; no second source read can race key derivation.
pub(crate) fn materialize_with_lowerer<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    cache: &CompleteSemanticArtifactCache,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    let outcome = materialize_with_lowerer_inner(analyzer, cache, lowerer, file, request)?;
    // The artifact is the unit of consumption, and its public fingerprint is
    // the one identity that names it without the workspace mount. Recorded on
    // the cache-hit path as well as the fresh path: a hit in a later request is
    // still a read of that artifact.
    if let Some(artifact) = outcome.available_value() {
        analyzer.record_reads(|sink| {
            sink.push(crate::analyzer::read_ledger::ReadKey::artifact(
                crate::analyzer::invalidation::DerivedArtifactId::semantic_artifact(
                    artifact.key().public_fingerprint(),
                ),
                Some(artifact.key().path().as_str()),
            ));
        });
    }
    Ok(outcome)
}

fn materialize_with_lowerer_inner<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    cache: &CompleteSemanticArtifactCache,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    let started_work = request.budget.used();
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }

    // Admit the file and its top-level traversal before preparing source or
    // consulting the artifact cache. A cache hit is still a materialized file
    // in this request, and a rejected file must perform no hidden work.
    if !request.charge_execution_traversal(1) || !request.admit_materialization(file) {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work: SemanticWork::default(),
        });
    }

    validate_semantic_file(analyzer, file)?;

    // A repeat touch of an unchanged file must not read and hash it again.
    // This is the only path that can answer before the source is read, so it
    // is also the only one that can charge a lookup rather than a file.
    if let Some(artifact) = served_from_unchanged_source(analyzer, cache, lowerer, file, request)? {
        let staged_budget = request.budget.clone();
        let outcome = publish_cached(artifact, SemanticWork::default(), staged_budget, request);
        observe_complete_artifact(file, &outcome, request);
        return outcome;
    }

    let max_source_bytes = request.budget.remaining().source_bytes;
    let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let (source_identity, prepared) =
        match analyzer.prepared_syntax_limited(scope.token(), file, max_source_bytes) {
            Ok(Some(resolved)) => resolved,
            Ok(None) => {
                return Err(SemanticProviderError::source_access(format!(
                    "could not prepare the current source snapshot for `{file}`"
                )));
            }
            Err(limit) => {
                let work = SemanticWork {
                    source_bytes: limit.minimum_source_bytes(),
                    ..SemanticWork::default()
                };
                let exceeded = request.budget.check(work).map_or_else(
                |exceeded| exceeded,
                |_| {
                    unreachable!(
                        "a source snapshot larger than the remaining source budget must exceed it"
                    )
                },
            );
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
        };
    let source_work = SemanticWork {
        source_bytes: prepared.source().len(),
        ..SemanticWork::default()
    };

    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: source_work,
        });
    }
    let mut staged_budget = request.budget.clone();
    if let Err(exceeded) = staged_budget.charge(source_work) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: source_work,
        });
    }

    let identity = lowerer.identity();
    // The one derivation that hashes the source, and the one place that pays
    // for it. Recording the digest against the blob identity of exactly these
    // bytes is what lets the next touch of this content skip both.
    let content = ContentIdentity::hash_bytes(prepared.source().as_bytes());
    analyzer
        .semantic_source_digests()
        .record(source_identity, content);
    let key = semantic_artifact_key_for_prepared(file, &prepared, content, identity)?;
    let (acquisition, cache_wait) = cache.acquire(&key, request.cancellation);
    if cache_wait.wait_ns > 0 {
        crate::profiling::note_with(|| {
            format!(
                "semantic.complete_cache_wait waits={} wait_ns={}",
                cache_wait.waits, cache_wait.wait_ns
            )
        });
    }
    let permit = match acquisition {
        CompleteValueAcquisition::Cached { value: artifact } => {
            let outcome = publish_cached(artifact, source_work, staged_budget, request);
            observe_complete_artifact(file, &outcome, request);
            return outcome;
        }
        CompleteValueAcquisition::Leader { permit } => permit,
        CompleteValueAcquisition::Rejected => {
            unreachable!("semantic artifact cache never publishes rejected flights")
        }
        CompleteValueAcquisition::Cancelled => {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: source_work,
            });
        }
    };

    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: source_work,
        });
    }

    let lowered = lowerer.lower(file, &prepared, &staged_budget, request.cancellation)?;
    if request.cancellation.is_cancelled() {
        if let SemanticOutcome::Cancelled {
            partial: Some(_), ..
        } = &lowered
        {
            // A lowerer-supplied partial still has to pass ordinary publication
            // below before it can be retained by a cancelled outcome.
        } else {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: source_work.component_max(lowered.work()),
            });
        }
    }

    let outcome = publish_lowered(
        key,
        lowerer.capabilities(),
        lowered,
        source_work,
        started_work,
        staged_budget,
        request,
    );
    if let Ok(SemanticOutcome::Complete { value, .. }) = &outcome {
        permit.publish_complete(Arc::clone(value));
    }
    observe_complete_artifact(file, &outcome, request);
    outcome
}

/// Notify an opted-in caller only after a complete outcome has committed its
/// semantic budget. Incomplete artifacts are deliberately invisible to the
/// collector: retaining one would let a later coordinator mistake partial
/// provider state for a complete cache continuation.
fn observe_complete_artifact(
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
/// It is deliberately non-zero. A budget scope that only ever hits the cache
/// must still run out, and the traversal lane that would otherwise bound such a
/// loop lives on [`super::SemanticExecutionBudget`], which is optional: the
/// taint solve path and the summary foundry pass a request without one. The
/// `nested_entries` lane is the existing home for a bounded traversal step that
/// no retained row represents (see `ProcedureCfgBuilder::descend_nested_entry`).
const fn repeat_materialization_work() -> SemanticWork {
    SemanticWork {
        nested_entries: 1,
        ..SemanticWork::uniform(0)
    }
}

/// Charge one complete-artifact cache hit.
///
/// The first hit in this budget scope pays the artifact's whole retained-row
/// census, because that scope has not yet paid for the material it is about to
/// hold and walk. Every later hit on the same artifact pays
/// [`repeat_materialization_work`], because the lowering it would otherwise be
/// charged for has already been paid for in this scope and is not performed
/// again (#2295).
fn publish_cached(
    artifact: Arc<SemanticArtifact>,
    source_work: SemanticWork,
    mut staged_budget: super::SemanticBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    let fingerprint = artifact.key().fingerprint();
    let repeat = staged_budget.has_charged_artifact(fingerprint);
    let charge = if repeat {
        repeat_materialization_work()
    } else {
        artifact.work()
    };
    if let Err(exceeded) = staged_budget.charge(charge) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: source_work.component_max(artifact.work()),
        });
    }
    if !repeat {
        staged_budget.record_charged_artifact(fingerprint);
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

/// Serve one already-lowered artifact for a file whose content the workspace
/// can identify without reading it.
///
/// Three facts have to line up, and any one of them missing falls through to
/// the ordinary read-and-lower path rather than guessing:
///
/// 1. the workspace has a reusable blob identity for the file, either paired
///    with an unchanged stat or owned by the current explicit-update
///    generation (`reusable_live_oid` refuses overlays);
/// 2. the content digest for that blob identity has already been derived, so
///    the artifact key can be rebuilt without hashing the file;
/// 3. the complete-artifact cache already holds that exact key.
///
/// Everything in the key other than the content digest is derived the same way
/// `current_artifact_source_with_lowerer` derives it, from the path and the
/// lowerer's identity, so a stale adapter, configuration, dependency, or IR
/// version cannot be served: it produces a different key, which misses.
fn served_from_unchanged_source<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    cache: &CompleteSemanticArtifactCache,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    request: &SemanticRequest<'_>,
) -> Result<Option<Arc<SemanticArtifact>>, SemanticProviderError> {
    let Some(source_identity) = analyzer.reusable_live_oid(file) else {
        return Ok(None);
    };
    let Some(content) = analyzer.semantic_source_digests().get(source_identity) else {
        return Ok(None);
    };
    let key = semantic_artifact_key_from_content(
        file,
        LanguageDialect::for_path(analyzer.adapter().language(), file.rel_path()),
        content,
        None,
        lowerer.identity(),
    )?;
    Ok(cache.get_ready(&key, request.cancellation))
}

fn semantic_artifact_key_for_prepared(
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

fn semantic_artifact_key_from_content(
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

fn publish_lowered(
    key: SemanticArtifactKey,
    capabilities: SemanticCapabilities,
    lowered: SemanticOutcome<Vec<ProcedureSemanticsParts>>,
    source_work: SemanticWork,
    started_work: SemanticWork,
    mut staged_budget: super::SemanticBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    macro_rules! publish_parts {
        ($parts:expr, $work:expr) => {{
            match publish(
                key.clone(),
                capabilities.clone(),
                $parts,
                &mut staged_budget,
            )? {
                Publication::Artifact(artifact) => artifact,
                Publication::Exceeded(exceeded) => {
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
            if let Err(exceeded) = reconcile_observed_work(&mut staged_budget, started_work, $work)
            {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: $work,
                });
            }
        };
    }

    macro_rules! commit_non_cancelled {
        ($work:expr, $outcome:expr) => {{
            reconcile_observed!($work);
            if request.cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: $work,
                });
            }
            *request.budget = staged_budget;
            $outcome
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
                None if request.cancellation.is_cancelled() => Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                }),
                None => Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: total_work,
                }),
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
                None => Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                }),
            }
        }
    }
}

fn reconcile_observed_work(
    staged_budget: &mut super::SemanticBudget,
    started_work: SemanticWork,
    observed_work: SemanticWork,
) -> Result<(), super::SemanticBudgetExceeded> {
    let charged_work = staged_budget.used().saturating_sub(started_work);
    let uncharged_work = observed_work.saturating_sub(charged_work);
    staged_budget.charge(uncharged_work)
}

enum Publication {
    Artifact(Arc<SemanticArtifact>),
    Exceeded(super::SemanticBudgetExceeded),
}

fn publish(
    key: SemanticArtifactKey,
    capabilities: SemanticCapabilities,
    parts: Vec<ProcedureSemanticsParts>,
    budget: &mut super::SemanticBudget,
) -> Result<Publication, SemanticProviderError> {
    match SemanticArtifact::try_new_with_budget(key, capabilities, parts, budget) {
        Ok(artifact) => Ok(Publication::Artifact(Arc::new(artifact))),
        Err(SemanticArtifactBuildError::Invalid(error)) => {
            Err(SemanticProviderError::InvalidArtifact(error))
        }
        Err(SemanticArtifactBuildError::ExceededBudget(exceeded)) => {
            Ok(Publication::Exceeded(exceeded))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::{Condvar, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::analyzer::semantic::{SemanticArtifactCollector, SemanticBudget};
    use crate::analyzer::typescript::TypescriptAdapter;
    use crate::analyzer::{
        AnalyzerQueryScope, IAnalyzer, Language, OverlayProject, Project, TestProject,
    };

    #[derive(Clone, Copy)]
    enum FakeMode {
        Complete,
        PartialThenComplete,
        Cancel,
        CancelUnknownPartial,
        CancelWithPartial,
    }

    struct FakeLowerer {
        calls: AtomicUsize,
        mode: FakeMode,
    }

    impl FakeLowerer {
        fn new(mode: FakeMode) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                mode,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ProgramSemanticsLowerer for FakeLowerer {
        fn identity(&self) -> SemanticAdapterIdentity {
            SemanticAdapterIdentity {
                adapter: AdapterSemanticsVersion::hash_bytes("fake-typescript", b"v1")
                    .expect("adapter name"),
                configuration: ConfigurationFingerprint::hash_bytes(b"fake-config"),
                dependencies: DependencyFingerprint::hash_bytes(b"fake-dependencies"),
            }
        }

        fn capabilities(&self) -> SemanticCapabilities {
            SemanticCapabilities::default()
        }

        fn lower(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            _budget: &SemanticBudget,
            cancellation: &super::super::CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            match self.mode {
                FakeMode::Complete => Ok(SemanticOutcome::Complete {
                    value: Vec::new(),
                    work: SemanticWork::default(),
                }),
                FakeMode::PartialThenComplete if call == 0 => Ok(SemanticOutcome::Unknown {
                    partial: Some(Vec::new()),
                    work: SemanticWork::default(),
                }),
                FakeMode::PartialThenComplete => Ok(SemanticOutcome::Complete {
                    value: Vec::new(),
                    work: SemanticWork::default(),
                }),
                FakeMode::Cancel => {
                    cancellation.cancel();
                    Ok(SemanticOutcome::Complete {
                        value: Vec::new(),
                        work: SemanticWork::default(),
                    })
                }
                FakeMode::CancelUnknownPartial => {
                    cancellation.cancel();
                    Ok(SemanticOutcome::Unknown {
                        partial: Some(Vec::new()),
                        work: SemanticWork::default(),
                    })
                }
                FakeMode::CancelWithPartial => Ok(SemanticOutcome::Cancelled {
                    partial: Some(Vec::new()),
                    work: SemanticWork::default(),
                }),
            }
        }
    }

    struct IdentityOnlyLowerer(SemanticAdapterIdentity);

    impl ProgramSemanticsLowerer for IdentityOnlyLowerer {
        fn identity(&self) -> SemanticAdapterIdentity {
            self.0.clone()
        }

        fn capabilities(&self) -> SemanticCapabilities {
            SemanticCapabilities::default()
        }

        fn lower(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            _budget: &SemanticBudget,
            _cancellation: &super::super::CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            panic!("artifact-key lookup must not invoke semantic lowering")
        }
    }

    struct BlockingLowerer {
        calls: AtomicUsize,
        entered: mpsc::Sender<()>,
        released: Mutex<bool>,
        release: Condvar,
    }

    impl BlockingLowerer {
        fn new(entered: mpsc::Sender<()>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                entered,
                released: Mutex::new(false),
                release: Condvar::new(),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }

        fn release(&self) {
            *self
                .released
                .lock()
                .expect("blocking lowerer mutex poisoned") = true;
            self.release.notify_all();
        }
    }

    impl ProgramSemanticsLowerer for BlockingLowerer {
        fn identity(&self) -> SemanticAdapterIdentity {
            SemanticAdapterIdentity {
                adapter: AdapterSemanticsVersion::hash_bytes("blocking-typescript", b"v1")
                    .expect("adapter name"),
                configuration: ConfigurationFingerprint::hash_bytes(b"blocking-config"),
                dependencies: DependencyFingerprint::hash_bytes(b"blocking-dependencies"),
            }
        }

        fn capabilities(&self) -> SemanticCapabilities {
            SemanticCapabilities::default()
        }

        fn lower(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            _budget: &SemanticBudget,
            _cancellation: &super::super::CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.entered
                .send(())
                .expect("blocking lowerer entry receiver");
            let mut released = self
                .released
                .lock()
                .expect("blocking lowerer mutex poisoned");
            while !*released {
                released = self
                    .release
                    .wait(released)
                    .expect("blocking lowerer mutex poisoned while waiting");
            }
            Ok(SemanticOutcome::Complete {
                value: Vec::new(),
                work: SemanticWork::default(),
            })
        }
    }

    fn write_file(root: &std::path::Path, rel: &str, contents: &str) -> ProjectFile {
        let file = ProjectFile::new(root.to_path_buf(), rel);
        file.write(contents).expect("write fixture");
        file
    }

    fn analyzer(root: &std::path::Path) -> TreeSitterAnalyzer<TypescriptAdapter> {
        TreeSitterAnalyzer::new(
            Arc::new(TestProject::new(root.to_path_buf(), Language::TypeScript)),
            TypescriptAdapter,
        )
    }

    fn current_artifact_key_with_lowerer(
        analyzer: &TreeSitterAnalyzer<TypescriptAdapter>,
        lowerer: &dyn ProgramSemanticsLowerer,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<SemanticArtifactKey>, SemanticProviderError> {
        current_artifact_source_with_lowerer(analyzer, lowerer, file, max_source_bytes)
            .map(|snapshot| snapshot.map(|snapshot| snapshot.key().clone()))
    }

    fn materialize(
        analyzer: &TreeSitterAnalyzer<TypescriptAdapter>,
        cache: &CompleteSemanticArtifactCache,
        lowerer: &dyn ProgramSemanticsLowerer,
        file: &ProjectFile,
        budget: &mut SemanticBudget,
        cancellation: &super::super::CancellationToken,
    ) -> SemanticOutcome<Arc<SemanticArtifact>> {
        materialize_with_lowerer(
            analyzer,
            cache,
            lowerer,
            file,
            &mut SemanticRequest::new(budget, cancellation),
        )
        .expect("materialization")
    }

    fn wait_for_waiter(cache: &CompleteSemanticArtifactCache) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.waiting_count() == 0 {
            assert!(
                Instant::now() < deadline,
                "same-key request did not enter the single-flight wait"
            );
            thread::yield_now();
        }
    }

    /// A budget that read the file pays exactly that file once, plus the whole
    /// retained census of the artifact it now holds.
    fn assert_source_and_artifact_charged(
        budget: &SemanticBudget,
        file: &ProjectFile,
        artifact: &SemanticArtifact,
    ) {
        assert_census_charged(
            budget,
            file.read_to_string().expect("fixture source").len(),
            artifact,
        );
    }

    /// A budget served an artifact for a source the workspace already
    /// identified pays the census -- it holds and walks that material -- and no
    /// source bytes at all, because it neither read nor hashed the file.
    fn assert_artifact_charged_without_reading(
        budget: &SemanticBudget,
        artifact: &SemanticArtifact,
    ) {
        assert_census_charged(budget, 0, artifact);
    }

    fn assert_census_charged(
        budget: &SemanticBudget,
        source_bytes: usize,
        artifact: &SemanticArtifact,
    ) {
        let mut retained = budget.used();
        assert_eq!(retained.source_bytes, source_bytes);
        retained.source_bytes = 0;
        assert_eq!(retained, artifact.work());
    }

    #[test]
    fn current_artifact_key_tracks_source_adapter_and_configuration_without_lowering() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let identity = |adapter: &[u8], configuration: &[u8], dependencies: &[u8]| {
            IdentityOnlyLowerer(SemanticAdapterIdentity {
                adapter: AdapterSemanticsVersion::hash_bytes("identity-only", adapter)
                    .expect("adapter name"),
                configuration: ConfigurationFingerprint::hash_bytes(configuration),
                dependencies: DependencyFingerprint::hash_bytes(dependencies),
            })
        };

        let baseline_lowerer = identity(b"adapter-v1", b"config-v1", b"dependencies-v1");
        assert_eq!(
            current_artifact_key_with_lowerer(
                &analyzer,
                &baseline_lowerer,
                &file,
                "export const value = 1;\n".len() - 1,
            )
            .expect("bounded key lookup"),
            None
        );
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 0);

        let baseline =
            current_artifact_key_with_lowerer(&analyzer, &baseline_lowerer, &file, usize::MAX)
                .expect("baseline key lookup")
                .expect("baseline key");
        let adapter_changed = current_artifact_key_with_lowerer(
            &analyzer,
            &identity(b"adapter-v2", b"config-v1", b"dependencies-v1"),
            &file,
            usize::MAX,
        )
        .expect("adapter key lookup")
        .expect("adapter key");
        let configuration_changed = current_artifact_key_with_lowerer(
            &analyzer,
            &identity(b"adapter-v1", b"config-v2", b"dependencies-v1"),
            &file,
            usize::MAX,
        )
        .expect("configuration key lookup")
        .expect("configuration key");
        let dependencies_changed = current_artifact_key_with_lowerer(
            &analyzer,
            &identity(b"adapter-v1", b"config-v1", b"dependencies-v2"),
            &file,
            usize::MAX,
        )
        .expect("dependency key lookup")
        .expect("dependency key");

        assert_ne!(baseline, adapter_changed);
        assert_ne!(baseline, configuration_changed);
        assert_ne!(baseline, dependencies_changed);

        file.write("export const value = 2;\n")
            .expect("rewrite fixture");
        let source_changed =
            current_artifact_key_with_lowerer(&analyzer, &baseline_lowerer, &file, usize::MAX)
                .expect("updated source key lookup")
                .expect("updated source key");
        assert_ne!(baseline, source_changed);
        assert_eq!(
            analyzer.prepared_syntax_parse_count_for_test(&file),
            0,
            "freshness identity must not parse source"
        );
    }

    #[test]
    fn current_artifact_key_matches_materialization_without_running_the_lowerer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let _scope = AnalyzerQueryScope::new(&analyzer);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let current = current_artifact_source_with_lowerer(&analyzer, &lowerer, &file, usize::MAX)
            .expect("current artifact source lookup")
            .expect("current artifact source");
        assert_eq!(current.source(), "export const value = 1;\n");
        let current = current.key().clone();
        assert_eq!(lowerer.calls(), 0);
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 0);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("complete artifact")
        };
        assert_eq!(value.key(), &current);
        assert_eq!(lowerer.calls(), 1);
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    #[test]
    fn current_artifact_source_reuses_atomic_overlay_source_and_revision() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const disk = 0;\n");
        let base: Arc<dyn crate::analyzer::Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        let source = "export const value = 1;\n";
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let project_source = overlay
            .read_source_snapshot(&file)
            .expect("first atomic overlay snapshot")
            .into_source();
        let analyzer = TreeSitterAnalyzer::new(
            Arc::clone(&overlay) as Arc<dyn crate::analyzer::Project>,
            TypescriptAdapter,
        );
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let first = {
            let _scope = AnalyzerQueryScope::new(&analyzer);
            current_artifact_source_with_lowerer(&analyzer, &lowerer, &file, source.len())
                .expect("first artifact source lookup")
                .expect("first artifact source")
        };
        let first_key = first.key().clone();
        let (_, first_source) = first.into_parts();
        assert!(Arc::ptr_eq(&project_source, &first_source));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 0);

        let artifact = {
            let _scope = AnalyzerQueryScope::new(&analyzer);
            let mut budget = SemanticBudget::default();
            materialize(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
            .available_value()
            .cloned()
            .expect("first overlay artifact")
        };
        assert_eq!(artifact.key(), &first_key);

        // A new overlay revision invalidates the old artifact even when its
        // source bytes (and therefore content identity) are unchanged.
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let second = {
            let _scope = AnalyzerQueryScope::new(&analyzer);
            current_artifact_source_with_lowerer(&analyzer, &lowerer, &file, source.len())
                .expect("second artifact source lookup")
                .expect("second artifact source")
        };
        assert_eq!(second.source(), source);
        assert_eq!(
            first_key.revision().content(),
            second.key().revision().content()
        );
        assert_ne!(artifact.key(), second.key());

        let _scope = AnalyzerQueryScope::new(&analyzer);
        assert!(
            current_artifact_source_with_lowerer(&analyzer, &lowerer, &file, source.len() - 1,)
                .expect("bounded overlay lookup")
                .is_none()
        );
    }

    #[test]
    fn complete_cache_reuses_arc_but_charges_each_request() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export function main() {}\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let mut first_budget = SemanticBudget::default();
        let first = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut first_budget,
            &super::super::CancellationToken::default(),
        );
        let SemanticOutcome::Complete { value: first, .. } = first else {
            panic!("first complete artifact")
        };
        assert_source_and_artifact_charged(&first_budget, &file, &first);

        let mut second_budget = SemanticBudget::default();
        let second = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut second_budget,
            &super::super::CancellationToken::default(),
        );
        let SemanticOutcome::Complete { value: second, .. } = second else {
            panic!("cached complete artifact")
        };
        assert!(Arc::ptr_eq(&first, &second));
        // Re-derived: the second request is charged the artifact's census
        // again, because it holds that material too, but not the file's bytes.
        // The first request already derived this content's identity, and the
        // workspace can prove the file has not changed since, so the second
        // request neither reads nor hashes it.
        assert_artifact_charged_without_reading(&second_budget, &second);
        assert_eq!(lowerer.calls(), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn semantic_cache_invalidation_witnesses_are_distinct_clone_shared_and_one_shot() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export function main() {}\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let cancellation = super::super::CancellationToken::default();

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: held, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        ) else {
            panic!("initial complete artifact")
        };

        let cloned_cache = cache.clone();
        cloned_cache.arm_selector_continuation_invalidation_for_test();
        cache.invalidate_evaluation_root_continuation_if_armed_for_test();
        assert_eq!(cache.len(), 1, "the evaluation witness is not armed");
        cache.invalidate_selector_continuation_if_armed_for_test();
        assert_eq!(cache.selector_continuation_revivals_for_test(), 0);
        assert_eq!(cache.evaluation_root_continuation_revivals_for_test(), 0);
        assert_eq!(cache.len(), 0);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: revived, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        ) else {
            panic!("revived complete artifact")
        };
        assert!(Arc::ptr_eq(&held, &revived));
        assert_eq!(cache.selector_continuation_revivals_for_test(), 1);
        assert_eq!(cache.evaluation_root_continuation_revivals_for_test(), 0);

        cloned_cache.arm_evaluation_root_continuation_invalidation_for_test();
        cache.invalidate_selector_continuation_if_armed_for_test();
        assert_eq!(cache.len(), 1, "the selector witness is no longer armed");
        cache.invalidate_evaluation_root_continuation_if_armed_for_test();
        assert_eq!(cache.selector_continuation_revivals_for_test(), 1);
        assert_eq!(cache.evaluation_root_continuation_revivals_for_test(), 0);
        assert_eq!(cache.len(), 0);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: revived, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        ) else {
            panic!("second revived complete artifact")
        };
        assert!(Arc::ptr_eq(&held, &revived));
        assert_eq!(cache.selector_continuation_revivals_for_test(), 1);
        assert_eq!(cache.evaluation_root_continuation_revivals_for_test(), 1);

        cache.invalidate_evaluation_root_continuation_if_armed_for_test();
        assert_eq!(cache.selector_continuation_revivals_for_test(), 1);
        assert_eq!(cache.evaluation_root_continuation_revivals_for_test(), 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(lowerer.calls(), 1);
    }

    /// One artifact's retained census, plus room for `repeats` repeat lookups
    /// and for exactly one read of the source.
    ///
    /// One read's worth of `source_bytes` is deliberate and is what makes the
    /// repeat-charge claim below falsifiable: a second charged read of this
    /// file would exceed the budget rather than pass unnoticed.
    ///
    /// Every limit must be positive, so a census dimension the fixture never
    /// uses still gets one row of headroom; that headroom is far below one
    /// extra census, which is what this test's fail-before depends on.
    fn budget_for_one_census(
        census: SemanticWork,
        source_bytes: usize,
        repeats: usize,
    ) -> SemanticBudget {
        let lane = |value: usize| value.max(1);
        SemanticBudget::new(SemanticWork {
            source_bytes: source_bytes.max(1),
            procedures: lane(census.procedures),
            blocks: lane(census.blocks),
            program_points: lane(census.program_points),
            values: lane(census.values),
            allocations: lane(census.allocations),
            call_sites: lane(census.call_sites),
            memory_locations: lane(census.memory_locations),
            captures: lane(census.captures),
            source_mappings: lane(census.source_mappings),
            evidence: lane(census.evidence),
            gaps: lane(census.gaps),
            events: lane(census.events),
            control_edges: lane(census.control_edges),
            nested_entries: lane(census.nested_entries).saturating_add(repeats),
            owned_text_bytes: lane(census.owned_text_bytes),
        })
        .expect("every limit is positive")
    }

    /// #2295: one budget pays one artifact's retained census once, however many
    /// complete-artifact cache hits it serves.
    ///
    /// `DispatchOracle::resolve_call` materializes a callee's file once for each
    /// declaration group it resolves, so a request that reaches one file from
    /// many call sites used to be charged that file's whole census once per call
    /// site even though the file was lowered once. A budget sized for the
    /// material the request actually holds then aborted a request that had
    /// performed no new work. Each repeat now pays
    /// `repeat_materialization_work`, which is what a repeat performs: derive
    /// the key, look it up, clone an `Arc`.
    #[test]
    fn one_budget_charges_one_artifact_census_once_however_many_cache_hits() {
        const REPEATS: usize = 8;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let source = "function target(value: number): number { return value; }\n\
             export function main(): number { return target(1); }\n";
        let file = write_file(&root, "src/calls.ts", source);
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = crate::analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript();

        // Lower once against its own budget, so every materialization below is
        // a cache hit and the census is known exactly.
        let mut warming_budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut warming_budget,
            &super::super::CancellationToken::default(),
        )
        else {
            panic!("the fixture must lower completely")
        };
        let census = artifact.work();
        assert!(
            census.program_points > 1,
            "the fixture must retain enough rows for one census to be measurable: {census:?}"
        );

        let mut budget = budget_for_one_census(census, source.len(), REPEATS);
        for hit in 0..=REPEATS {
            let outcome = materialize(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut budget,
                &super::super::CancellationToken::default(),
            );
            let SemanticOutcome::Complete { value, .. } = outcome else {
                panic!(
                    "cache hit {hit} must not exhaust a budget sized for one census: {outcome:?}"
                )
            };
            assert!(Arc::ptr_eq(&value, &artifact));
        }

        let used = budget.used();
        assert_eq!(
            used.program_points, census.program_points,
            "the census is charged once, not once per hit"
        );
        assert_eq!(used.values, census.values);
        assert_eq!(
            used.nested_entries,
            census.nested_entries + REPEATS,
            "each repeat hit charges exactly one traversal step"
        );
        assert_eq!(
            used.source_bytes, 0,
            "no call re-read or re-hashed a source whose content the workspace \
             had already identified"
        );
        assert_eq!(
            budget.charged_artifact_count(),
            1,
            "one artifact key was charged in this scope"
        );
    }

    /// An explicitly updated file derives a fresh key and is paid for again.
    ///
    /// This is the soundness half of the derivation memo. The memo is keyed by
    /// the blob identity of exactly the bytes it digested, so an entry cannot
    /// describe any other content. Callers notify the analyzer after mutating
    /// files behind its back; the update then derives the new content's key and
    /// pays for its bytes while existing snapshots remain stable.
    #[test]
    fn an_edited_source_derives_a_fresh_key_and_pays_for_its_bytes_again() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let before = "export function main(): number { return 1; }\n";
        let after = "export function main(): number { return 1; }\n\
             export function second(): number { return 2; }\n";
        let file = write_file(&root, "src/edited.ts", before);
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = crate::analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript();

        let mut first_budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: first, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut first_budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("the fixture must lower completely")
        };
        assert_eq!(
            first_budget.used().source_bytes,
            before.len(),
            "the request that lowered the file pays its bytes once"
        );

        // Unchanged: served without reading, which is the behaviour the edit
        // below has to defeat.
        let mut unchanged_budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: served, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut unchanged_budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("an unchanged source must still serve a complete artifact")
        };
        assert!(Arc::ptr_eq(&first, &served));
        assert_artifact_charged_without_reading(&unchanged_budget, &served);

        file.write(after).expect("rewrite fixture");
        let updated_analyzer = analyzer.update(&BTreeSet::from([file.clone()]));

        let mut edited_budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: edited, .. } = materialize(
            &updated_analyzer,
            &cache,
            &lowerer,
            &file,
            &mut edited_budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("the edited fixture must lower completely")
        };
        assert_ne!(
            first.key(),
            edited.key(),
            "an edited source must derive a fresh artifact key"
        );
        assert!(
            !Arc::ptr_eq(&first, &edited),
            "an edited source must not be served the previous artifact"
        );
        assert_eq!(
            edited.procedures().len(),
            2,
            "the edited artifact must describe the edited file"
        );
        assert_eq!(
            edited_budget.used().source_bytes,
            after.len(),
            "the request that re-read and re-hashed the edited file pays its bytes"
        );
    }

    /// A fresh budget is a fresh scope: it pays the census again.
    ///
    /// This is what keeps the change coherent with the per-region reset in
    /// `PolicySelectorSession::reset_region_semantic_budget` and the per-batch
    /// reset in `TaintExecutionBudget::reset_per_batch_solve_budget`. Both
    /// replace the budget value, so both start a scope that pays again for the
    /// material it newly pulls in.
    #[test]
    fn a_fresh_budget_pays_the_census_again() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(
            &root,
            "src/calls.ts",
            "export function main(): number { return 1; }\n",
        );
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = crate::analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript();

        // The lowering budget is deliberately not compared against the census:
        // lowering also charges bounded traversal steps that no retained row
        // represents, so it costs more than the artifact it produces.
        let mut lowering_budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut lowering_budget,
            &super::super::CancellationToken::default(),
        )
        else {
            panic!("the fixture must lower completely")
        };

        for scope in 0..3 {
            let mut budget = SemanticBudget::default();
            assert!(
                materialize(
                    &analyzer,
                    &cache,
                    &lowerer,
                    &file,
                    &mut budget,
                    &super::super::CancellationToken::default(),
                )
                .is_complete()
            );
            // Re-derived: every fresh scope still pays the census, which is
            // what this test is about. It no longer pays the file's bytes,
            // because the lowering scope above already derived this content's
            // identity and no scope after it reads the file.
            assert_artifact_charged_without_reading(&budget, &artifact);
            assert_eq!(
                budget.charged_artifact_count(),
                1,
                "scope {scope} pays for the artifact it holds"
            );
        }
    }

    #[test]
    fn complete_cache_capacity_is_retained_bytes_not_entry_count() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let first_file = write_file(&root, "src/first.ts", "export const value = 1;\n");
        let second_file = write_file(&root, "src/other.ts", "export const value = 2;\n");
        let analyzer = analyzer(&root);
        let staging_cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: first, .. } = materialize(
            &analyzer,
            &staging_cache,
            &lowerer,
            &first_file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("first artifact")
        };
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: second, .. } = materialize(
            &analyzer,
            &staging_cache,
            &lowerer,
            &second_file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("second artifact")
        };

        let first_weight = retained_artifact_bytes(first.key(), &first);
        let second_weight = retained_artifact_bytes(second.key(), &second);
        assert_eq!(first_weight, second_weight, "equal-sized fixtures");
        assert!(first_weight > 1);
        let cache = CompleteSemanticArtifactCache::new(first_weight);
        cache.insert(first.key().clone(), Arc::clone(&first));
        cache.insert(second.key().clone(), Arc::clone(&second));

        assert_eq!(cache.len(), 1, "two byte-weighted entries exceed capacity");
    }

    #[test]
    fn complete_cache_weight_includes_derived_call_indexes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(
            &root,
            "src/calls.ts",
            "function target(value: number): number { return value; }\n\
             export function main(): number { return target(1); }\n",
        );
        let analyzer = analyzer(&root);
        let staging_cache = CompleteSemanticArtifactCache::default();
        let lowerer = crate::analyzer::js_ts::semantic::JsTsSemanticLowerer::typescript();
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: artifact, ..
        } = materialize(
            &analyzer,
            &staging_cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        )
        else {
            panic!("call-bearing artifact")
        };

        let call_index_bytes = artifact
            .procedures()
            .iter()
            .map(ProcedureSemantics::call_indexes_retained_bytes)
            .sum::<u64>();
        let value_identity_index_bytes = artifact
            .procedures()
            .iter()
            .map(ProcedureSemantics::value_identity_index_retained_bytes)
            .sum::<u64>();
        assert!(
            call_index_bytes > 0,
            "fixture must retain derived call-phase indexes"
        );
        let base_bytes = retained_artifact_base_bytes(&artifact);
        let retained_bytes = retained_artifact_bytes(artifact.key(), &artifact);
        assert_eq!(
            retained_bytes,
            base_bytes
                .saturating_add(call_index_bytes)
                .saturating_add(value_identity_index_bytes),
            "cache weight must include every derived semantic-index allocation"
        );

        let undersized = CompleteSemanticArtifactCache::new(base_bytes);
        undersized.insert(artifact.key().clone(), Arc::clone(&artifact));
        assert_eq!(
            undersized.len(),
            0,
            "the former row-only capacity must not retain the indexed artifact"
        );

        let exact = CompleteSemanticArtifactCache::new(retained_bytes);
        exact.insert(artifact.key().clone(), artifact);
        assert_eq!(exact.len(), 1, "the corrected exact capacity retains it");
    }

    #[test]
    fn analyzer_update_preserves_unchanged_content_keyed_artifacts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let unchanged = write_file(&root, "src/unchanged.ts", "export const stable = 1;\n");
        let changed = write_file(&root, "src/changed.ts", "export const changing = 1;\n");
        let analyzer = analyzer(&root);
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let cancellation = super::super::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: before, .. } = analyzer
            .materialize_semantics_with_lowerer(
                &lowerer,
                &unchanged,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("initial materialization")
        else {
            panic!("initial complete artifact")
        };

        changed
            .write("export const changing = 2;\n")
            .expect("update changed fixture");
        let updated = analyzer.update(&BTreeSet::from([changed]));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: after, .. } = updated
            .materialize_semantics_with_lowerer(
                &lowerer,
                &unchanged,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("post-update materialization")
        else {
            panic!("post-update complete artifact")
        };

        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(lowerer.calls(), 1);
    }

    #[test]
    fn concurrent_same_key_materialization_runs_one_lowerer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::new(1);
        let (entered_tx, entered_rx) = mpsc::channel();
        let lowerer = Arc::new(BlockingLowerer::new(entered_tx));

        let first_analyzer = analyzer.clone();
        let first_cache = cache.clone();
        let first_file = file.clone();
        let first_lowerer = Arc::clone(&lowerer);
        let first = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            materialize(
                &first_analyzer,
                &first_cache,
                first_lowerer.as_ref(),
                &first_file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first lowerer entry");

        let second_analyzer = analyzer.clone();
        let second_cache = cache.clone();
        let second_file = file.clone();
        let second_lowerer = Arc::clone(&lowerer);
        let second = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            materialize(
                &second_analyzer,
                &second_cache,
                second_lowerer.as_ref(),
                &second_file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
        });

        wait_for_waiter(&cache);
        assert_eq!(lowerer.calls(), 1);
        lowerer.release();
        let SemanticOutcome::Complete {
            value: first_value, ..
        } = first.join().expect("first materialization thread")
        else {
            panic!("first complete artifact")
        };
        let SemanticOutcome::Complete {
            value: second_value,
            ..
        } = second.join().expect("second materialization thread")
        else {
            panic!("second complete artifact")
        };
        assert!(Arc::ptr_eq(&first_value, &second_value));
        assert_eq!(lowerer.calls(), 1);
        assert_eq!(
            cache.len(),
            0,
            "an oversize artifact is shared with current waiters but not retained"
        );
    }

    #[test]
    fn cancelled_same_key_waiter_does_not_publish_or_lower() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let (entered_tx, entered_rx) = mpsc::channel();
        let lowerer = Arc::new(BlockingLowerer::new(entered_tx));

        let first_analyzer = analyzer.clone();
        let first_cache = cache.clone();
        let first_file = file.clone();
        let first_lowerer = Arc::clone(&lowerer);
        let first = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            materialize(
                &first_analyzer,
                &first_cache,
                first_lowerer.as_ref(),
                &first_file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first lowerer entry");

        let cancellation = super::super::CancellationToken::default();
        let waiter_cancellation = cancellation.clone();
        let second_analyzer = analyzer.clone();
        let second_cache = cache.clone();
        let second_file = file.clone();
        let second_lowerer = Arc::clone(&lowerer);
        let second = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            let outcome = materialize(
                &second_analyzer,
                &second_cache,
                second_lowerer.as_ref(),
                &second_file,
                &mut budget,
                &waiter_cancellation,
            );
            (outcome, budget.used())
        });

        wait_for_waiter(&cache);
        cancellation.cancel();
        let (outcome, used) = second.join().expect("cancelled waiter thread");
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled { partial: None, .. }
        ));
        assert_eq!(used, SemanticWork::default());
        assert_eq!(lowerer.calls(), 1);

        lowerer.release();
        assert!(
            first
                .join()
                .expect("leader materialization thread")
                .is_complete()
        );
        assert_eq!(lowerer.calls(), 1);
    }

    #[test]
    fn dialect_and_source_origin_are_part_of_snapshot_identity() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let source = "export const value = 1;\n";
        let ts = write_file(&root, "src/same.ts", source);
        let tsx = write_file(&root, "src/same.tsx", source);
        let base: Arc<dyn crate::analyzer::Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer = TreeSitterAnalyzer::new(overlay.clone(), TypescriptAdapter);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: disk, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &ts,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("disk artifact")
        };
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: tsx_artifact,
            ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &tsx,
            &mut budget,
            &super::super::CancellationToken::default(),
        )
        else {
            panic!("tsx artifact")
        };
        assert_ne!(disk.key().language(), tsx_artifact.key().language());

        assert!(overlay.set(ts.abs_path(), source.to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: overlay_artifact,
            ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &ts,
            &mut budget,
            &super::super::CancellationToken::default(),
        )
        else {
            panic!("overlay artifact")
        };
        assert_ne!(disk.key(), overlay_artifact.key());
        assert!(matches!(disk.key().revision(), SourceRevision::Disk { .. }));
        assert!(matches!(
            overlay_artifact.key().revision(),
            SourceRevision::Overlay { .. }
        ));
    }

    #[test]
    fn adjacent_overlay_revisions_do_not_reuse_stale_artifacts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 0;\n");
        let base: Arc<dyn crate::analyzer::Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer = TreeSitterAnalyzer::new(overlay.clone(), TypescriptAdapter);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        assert!(overlay.set(file.abs_path(), "export const value = 1;\n".to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: first, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("first overlay")
        };
        assert!(overlay.set(file.abs_path(), "export const value = 2;\n".to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: second, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("second overlay")
        };

        assert_ne!(first.key().revision(), second.key().revision());
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(overlay.set(file.abs_path(), "export const value = 1;\n".to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: third, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("third overlay")
        };
        assert_ne!(first.key().revision(), third.key().revision());
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(lowerer.calls(), 3);
    }

    #[test]
    fn cancellation_discards_unpublished_construction() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Cancel);
        let cancellation = super::super::CancellationToken::default();
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled { partial: None, .. }
        ));
        assert_eq!(budget.used(), SemanticWork::default());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn independently_validated_cancelled_partial_is_charged_but_not_cached() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::CancelWithPartial);
        let cancellation = super::super::CancellationToken::default();
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("validated lowerer partial should survive cancellation")
        };
        assert_source_and_artifact_charged(&budget, &file, &partial);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cancellation_discards_non_cancelled_partial_outcomes_without_charging() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::CancelUnknownPartial);
        let cancellation = super::super::CancellationToken::default();
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled { partial: None, .. }
        ));
        assert_eq!(budget.used(), SemanticWork::default());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn source_limit_is_enforced_before_parsing_or_lowering() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = 8;
        let mut budget = SemanticBudget::new(limits).expect("positive limits");

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::ExceededBudget { partial: None, work, .. }
                if work.source_bytes > 8
        ));
        assert_eq!(lowerer.calls(), 0);
        assert_eq!(budget.used(), SemanticWork::default());
    }

    #[test]
    fn empty_source_is_a_valid_exact_snapshot() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/empty.ts", "");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        );
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("empty TypeScript source should publish an empty complete artifact")
        };
        assert!(value.procedures().is_empty());
        assert_source_and_artifact_charged(&budget, &file, &value);
    }

    #[test]
    fn concrete_provider_rejects_foreign_roots_and_languages_before_source_access() {
        let first = tempfile::tempdir().expect("first temp dir");
        let second = tempfile::tempdir().expect("second temp dir");
        let root = first.path().canonicalize().expect("first root");
        let foreign_root = second.path().canonicalize().expect("second root");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let cancellation = super::super::CancellationToken::default();

        for file in [
            ProjectFile::new(foreign_root, "src/main.ts"),
            ProjectFile::new(root.clone(), "src/Main.java"),
        ] {
            let mut budget = SemanticBudget::default();
            let error = materialize_with_lowerer(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect_err("foreign file identity should be rejected");
            assert!(matches!(error, SemanticProviderError::InvalidIdentity(_)));
            assert_eq!(budget.used(), SemanticWork::default());
        }
        assert_eq!(lowerer.calls(), 0);
    }

    #[test]
    fn partial_artifacts_are_charged_once_but_never_cached_as_complete() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::PartialThenComplete);
        let collector = SemanticArtifactCollector::new();
        let cancellation = super::super::CancellationToken::default();

        let mut budget = SemanticBudget::default();
        let first = materialize_with_lowerer(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut SemanticRequest::new(&mut budget, &cancellation)
                .with_artifact_collector(&collector),
        )
        .expect("partial materialization");
        assert!(matches!(
            first,
            SemanticOutcome::Unknown {
                partial: Some(_),
                ..
            }
        ));
        assert_eq!(cache.len(), 0);
        assert_eq!(collector.len(), 0);
        assert!(collector.take_complete(&file).is_empty());

        let mut budget = SemanticBudget::default();
        let completed = materialize_with_lowerer(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut SemanticRequest::new(&mut budget, &cancellation)
                .with_artifact_collector(&collector),
        )
        .expect("complete materialization");
        let SemanticOutcome::Complete { value, .. } = completed else {
            panic!("second materialization must complete")
        };
        let observed = collector.take_complete(&file);
        assert_eq!(observed.len(), 1);
        assert!(Arc::ptr_eq(observed[0].artifact(), &value));
        let mut budget = SemanticBudget::default();
        assert!(
            materialize(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
            .is_complete()
        );
        assert_eq!(lowerer.calls(), 2);
    }

    #[test]
    fn complete_artifact_collector_follows_staged_requests_and_drains_atomically() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let first = write_file(&root, "src/first.ts", "export const first = 1;\n");
        let second = write_file(&root, "src/second.ts", "export const second = 2;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let collector = SemanticArtifactCollector::new();
        let cancellation = super::super::CancellationToken::default();
        let mut parent_budget = SemanticBudget::default();
        let parent_request = SemanticRequest::new(&mut parent_budget, &cancellation)
            .with_artifact_collector(&collector);

        let mut staged_budget = SemanticBudget::default();
        let mut staged_request = parent_request.staged(&mut staged_budget);
        let SemanticOutcome::Complete {
            value: first_artifact,
            ..
        } = materialize_with_lowerer(&analyzer, &cache, &lowerer, &first, &mut staged_request)
            .expect("first staged materialization")
        else {
            panic!("first staged materialization must complete")
        };
        let SemanticOutcome::Complete {
            value: second_artifact,
            ..
        } = materialize_with_lowerer(&analyzer, &cache, &lowerer, &second, &mut staged_request)
            .expect("second staged materialization")
        else {
            panic!("second staged materialization must complete")
        };

        drop(staged_request);
        drop(parent_request);
        assert_eq!(
            parent_budget.used(),
            SemanticWork::default(),
            "staging keeps scalar work isolated from its parent request"
        );
        let drained = collector.take_all_complete();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].file(), &first);
        assert!(Arc::ptr_eq(drained[0].artifact(), &first_artifact));
        assert_eq!(drained[1].file(), &second);
        assert!(Arc::ptr_eq(drained[1].artifact(), &second_artifact));
        assert!(collector.take_all_complete().is_empty());
    }

    #[test]
    fn complete_artifact_collector_retains_distinct_same_key_allocations() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/subject.ts", "export const subject = 1;\n");
        let analyzer = analyzer(&root);
        let first_cache = CompleteSemanticArtifactCache::default();
        let second_cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let collector = SemanticArtifactCollector::new();
        let cancellation = super::super::CancellationToken::default();
        let materialize_from = |cache: &CompleteSemanticArtifactCache| {
            let mut budget = SemanticBudget::default();
            let outcome = materialize_with_lowerer(
                &analyzer,
                cache,
                &lowerer,
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation)
                    .with_artifact_collector(&collector),
            )
            .expect("complete materialization");
            let SemanticOutcome::Complete { value, .. } = outcome else {
                panic!("materialization must complete")
            };
            value
        };

        let first = materialize_from(&first_cache);
        let first_repeat = materialize_from(&first_cache);
        let second = materialize_from(&second_cache);
        assert!(Arc::ptr_eq(&first, &first_repeat));
        assert_eq!(first.key(), second.key());
        assert_eq!(first.materialization_id(), second.materialization_id());
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(lowerer.calls(), 2);

        let retained = collector.take_complete(&file);
        assert_eq!(retained.len(), 2);
        assert!(
            retained
                .iter()
                .any(|lease| Arc::ptr_eq(lease.artifact(), &first))
        );
        assert!(
            retained
                .iter()
                .any(|lease| Arc::ptr_eq(lease.artifact(), &second))
        );
    }

    #[test]
    fn retained_payload_budget_failure_is_atomic() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let collector = SemanticArtifactCollector::new();
        let cancellation = super::super::CancellationToken::default();
        let mut limits = SemanticBudget::default().limits();
        limits.owned_text_bytes = 1;
        let mut budget = SemanticBudget::new(limits).expect("positive limits");

        let outcome = materialize_with_lowerer(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut SemanticRequest::new(&mut budget, &cancellation)
                .with_artifact_collector(&collector),
        )
        .expect("budget-limited materialization");
        assert!(matches!(
            outcome,
            SemanticOutcome::ExceededBudget { partial: None, .. }
        ));
        assert_eq!(budget.used(), SemanticWork::default());
        assert_eq!(cache.len(), 0);
        assert!(
            collector.take_all_complete().is_empty(),
            "a complete lowerer result whose budget commit failed is not observable"
        );
    }
}
