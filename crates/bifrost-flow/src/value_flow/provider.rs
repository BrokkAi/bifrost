//! Demand materialization of value-flow snapshots, dispatch, and call bindings.
//!
//! [`ValueFlowProvider`] mirrors [`IcfgProvider`](crate::analyzer::semantic::IcfgProvider):
//! it materializes one procedure's value-flow snapshot on demand and one call's
//! bindings on demand, and it returns the same [`SemanticOutcome`] the oracle
//! returns. [`WorkspaceValueFlowProvider`] delegates to
//! [`WorkspaceSemanticOracle`] and retains each result in a bounded,
//! content-keyed [`CompleteValueCache`]. A second query over an unchanged
//! procedure reuses the answer without recharging the semantic budget, and a
//! source edit yields a different content key so the stale entry falls out of
//! the bounded cache.
//!
//! This is the seam [`discover_closure_with`](super::discover_closure_with)
//! walks the resolved-call closure through: the default
//! [`WorkspaceValueFlowProvider`] serves the type-flow client and the
//! dataflow differential, the policy compiler's materialization cache serves
//! require-model taint discovery (#2289), and the #2945 feedback provider
//! appends hinted dispatch candidates through `resolve_call`'s by-value
//! result.
//!
//! ## Non-complete verdicts are retained too (#2284, #2289)
//!
//! What each cache retains is the oracle's whole published *verdict*, not just
//! a complete value. A procedure or a call that the oracle reports as
//! `Unsupported`, `Unknown`, `Unproven`, or `Ambiguous` is an answer that is
//! finished and reproducible, so it is retained with its typed incompleteness
//! and replayed unchanged. Before this, only `Complete` was retained, so every
//! procedure with an unlowered construct or an unresolved dispatch was
//! re-materialized -- and re-charged against the shared semantic budget -- on
//! every touch. A cached `unsupported` answer stays `unsupported`; honesty is
//! unaffected because the retained outcome is the same value the skipped oracle
//! call would return. #2284 did this for snapshots; #2289 did it for bindings,
//! after establishing that the binding key covers every input (below).
//!
//! ## Cache keys cover every verdict input
//!
//! A snapshot key is
//! `(SemanticArtifactKey.fingerprint(), ProcedureId, selected interpretation, OracleLimits, OracleCallContext)`.
//! The artifact fingerprint is a SHA-256 over every validity input of the
//! artifact -- mount, path, language, exact source revision, adapter semantics
//! version, IR version, configuration fingerprint, and dependency fingerprint --
//! so a source edit produces a different key.
//!
//! That is the complete input set of
//! [`WorkspaceSemanticOracle::procedure_relations`], and it is complete for a
//! reason worth stating: every language adapter declares its semantic artifact
//! with `DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies")`, so
//! one artifact's `ProcedureSemantics`, gaps, and capability table are a pure
//! function of one file's content plus the adapter and configuration identity
//! already in the key. Cross-artifact dispatch resolution is a *different*
//! oracle call (`resolve_call`) and does not feed a snapshot verdict, so no
//! workspace-wide state, activated pack, or class-hierarchy expansion setting
//! can change one. `OracleLimits` can turn a snapshot into `Unproven` by
//! truncating retained relations, so it is part of the key. The
//! [`OracleCallContext`] labels the snapshot's provenance owner, so it is part
//! of the key as well.
//!
//! The two inputs the key does *not* cover are the request's semantic budget
//! and its cancellation token. Neither needs covering, because neither can
//! reach a retained entry: exhausting the budget or cancelling produces
//! `SemanticOutcome::ExceededBudget` or `SemanticOutcome::Cancelled`, and
//! [`SemanticOutcome::completed_replay`] retains neither. Budget-caused
//! incompleteness is therefore excluded from the memo by construction rather
//! than by a key dimension, so a later touch with more budget still runs the
//! oracle and can still reach a better answer.
//!
//! ### The dispatch key (#2943)
//!
//! A dispatch key is `(caller artifact fingerprint, caller ProcedureId,
//! CallSiteId, IcfgProviderBehaviorIdentity, OracleLimits)`. The provider
//! behavior's full half covers the workspace content, hierarchy expansion,
//! active semantic models, external dispatch surface, and receiver-class hint
//! digest. Dispatch is where all of those inputs matter. Budget and
//! cancellation outcomes are excluded from publication by the same rule as
//! snapshots and bindings.
//!
//! ### The binding key (#2289)
//!
//! A bindings key is
//! `(caller artifact fingerprint, caller ProcedureId, CallSiteId, target
//! artifact fingerprint, target ProcedureId, candidate proof, candidate
//! completeness, OracleCallContext, OracleLimits, Java conversion environment)`.
//!
//! Caller and callee artifacts pin their IR rows; context and limits pin the
//! bounded mapping contract. Java conversion typing additionally reads current
//! workspace declarations and activated external type identities (#2850), so
//! Java binding keys include the full provider behavior identity used by dispatch.
//! Budget and cancellation outcomes are excluded from publication.
//!
//! The retained `DispatchCandidate` also contributes to cache identity. The candidate's `proof()` and `completeness()` do **not** feed the
//! verdict: the published outcome is decided from `interrupted`, from
//! `coverage` (which comes from `build.truncated` and `build.open`), from
//! `build.has_unproven_relation`, and from `build.gap_quality`, and the
//! candidate reaches none of them. It is consumed only as
//! `candidate.target()`, and then handed to `materialize_call_bindings`, which
//! stores it whole in the retained `CallBindings`. So those two fields are in
//! the key not because the verdict depends on them but because the retained
//! *value* does, and a memo must replay the value it was asked for.
//!
//! The candidate's `provenance()` is in the retained value too and is not in
//! the key, because it cannot be: an `OracleRelationHandle` compares and hashes
//! its arena `Arc` by pointer, which is query-local by design (see
//! `OracleRelationHandle::arena_identity`). This is the same property the
//! snapshot memo already has -- a `ValueFlowSnapshot` carries its own arena --
//! and it is why relation arenas are documented as query-local rather than
//! durable identities.

use crate::analyzer::semantic::service::ArtifactRetentionCensus;
use crate::analyzer::workspace_authority::{ReplayingMemoEntry, memo_attribution};
use brokk_bifrost_core::analyzer::reuse_verdict::Judged;
use std::fmt;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::analyzer::ReadKey;
use crate::analyzer::WorkspaceAnalyzer;
#[cfg(test)]
use crate::analyzer::capture_query_reads;
use crate::analyzer::semantic::{
    CallBinding, CallBindings, CallSiteHandle, CallSiteId, DispatchBoundary, DispatchCandidate,
    DispatchReadAttribution, DispatchResult, EvidenceCompleteness, IcfgProvider,
    IcfgProviderBehaviorIdentity, OracleCallContext, OracleLimits, PreparedWorkspaceDispatchPool,
    ProcedureHandle, ProcedureId, ProofStatus, SemanticOutcome, SemanticProviderError,
    SemanticRequest, SemanticWork, StableDigest, ValueFlowEndpoint, ValueFlowOracle,
    ValueFlowSnapshot, WorkspaceIcfgProvider, WorkspaceSemanticOracle, dispatch_read_attribution,
};
use crate::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};

fn retained_memo_read_bytes<T>(entry: &ReplayingMemoEntry<T, ReadKey>) -> usize {
    // The former CapturedValue weight counted the Arc receipt, its named keys,
    // and their heap payloads. ReplayingMemoEntry also includes refusal origins.
    let mut heap = RetainedHeap::default();
    let receipt = entry.retained_read_bytes(|key| {
        retained_read_key(&mut heap, key);
        0
    });
    receipt
        .saturating_add(heap.total())
        .saturating_add(if entry.named_read_count() == 0 {
            0
        } else {
            2 * size_of::<usize>()
        })
}

use brokk_bifrost_core::complete_value_cache::{CompleteValueAcquisition, CompleteValueCache};

/// Default bound on the retained bytes of one value-flow sub-cache. This
/// mirrors the semantic artifact cache default (256 MiB divided by eight).
const DEFAULT_VALUE_FLOW_CACHE_BYTES: u64 = 256 * 1024 * 1024 / 8;

/// Demand materialization of one procedure's value-flow snapshot and one call's
/// bindings. This mirrors the shape of
/// [`IcfgProvider`](crate::analyzer::semantic::IcfgProvider) and
/// [`ValueFlowOracle`], and it returns the same [`SemanticOutcome`] the oracle
/// returns.
///
/// The associated `Error` keeps a consumer's abort reasons nameable outside
/// this crate: the closure walk reports a provider `Err` with its `Display`
/// and otherwise treats it as opaque (see `discover_closure_with`).
///
/// The trait stays `&self`; a provider that counts or memoizes uses interior
/// mutability the way [`ValueFlowCache`]'s atomic hit and miss counters do.
pub trait ValueFlowProvider {
    /// The consumer-specific failure one operation can abort with.
    type Error: fmt::Display;

    /// Anchor `procedure` to the provider's canonical artifact instance, so
    /// every handle the walk mints beneath it belongs to one instance. The
    /// default keeps the handle as minted; a provider that memoizes by
    /// durable key across materializations pins one instance (#2289).
    fn canonical_procedure(&self, procedure: &ProcedureHandle) -> ProcedureHandle {
        procedure.clone()
    }

    /// Acquire the owner-selected executable body and replay its complete receipt.
    fn selected_executable_procedure(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ProcedureHandle>, Self::Error>;

    fn payload_projection_identity(
        &self,
        _procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<StableDigest>>, Self::Error> {
        Ok(SemanticOutcome::Complete {
            value: None,
            work: Default::default(),
        })
    }

    fn payload_constructor_output(
        &self,
        _call: &CallSiteHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<ValueFlowEndpoint>>, Self::Error> {
        Ok(SemanticOutcome::Complete {
            value: None,
            work: Default::default(),
        })
    }

    /// Materialize the procedure-local value-flow snapshot on demand.
    fn procedure_snapshot(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, Self::Error>;

    /// Resolve one call site's dispatch on demand. The [`DispatchResult`]
    /// comes back by value (inside its outcome) so a feedback provider can
    /// append candidates before the walk sees them (#2945).
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, Self::Error>;

    /// Resolve dispatch using exact bounded entering-call context. Providers
    /// without contextual support retain their ordinary conservative answer.
    fn resolve_call_in_context(
        &self,
        call: &CallSiteHandle,
        _context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, Self::Error> {
        self.resolve_call(call, request)
    }

    /// Materialize one dispatch candidate's call bindings on demand.
    fn call_bindings(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, Self::Error>;
}

/// One dispatch input observed while discovering `caller`'s outgoing calls.
///
/// The attribution is retained even when no replayable [`ReadKey`](crate::analyzer::read_ledger::ReadKey)
/// can be built. Consumers must treat that typed unattributed status as a
/// fail-closed publication barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcedureDispatchRead {
    caller: ProcedureHandle,
    attribution: DispatchReadAttribution,
}

impl ProcedureDispatchRead {
    pub(crate) fn into_parts(self) -> (ProcedureHandle, DispatchReadAttribution) {
        (self.caller, self.attribution)
    }
}

/// Query-local observer for the exact dispatch inputs discovered by a value
/// flow provider.
///
/// Clones share one synchronized collection so a provider can own one clone
/// while the plan builder retains another. The provider's value cache remains
/// independently shared and unchanged.
#[derive(Debug, Clone, Default)]
pub(crate) struct DispatchReadCollector {
    observations: Arc<Mutex<Vec<ProcedureDispatchRead>>>,
}

impl DispatchReadCollector {
    fn record(&self, call: &CallSiteHandle, attribution: DispatchReadAttribution) {
        self.observations
            .lock()
            .expect("dispatch read collector lock is not poisoned")
            .push(ProcedureDispatchRead {
                caller: call.procedure().clone(),
                attribution,
            });
    }

    /// Snapshot the observations in provider-call order.
    pub(crate) fn observations(&self) -> Vec<ProcedureDispatchRead> {
        self.observations
            .lock()
            .expect("dispatch read collector lock is not poisoned")
            .clone()
    }
}

type ContextCallKey = (
    StableDigest,
    usize,
    ProcedureId,
    crate::analyzer::semantic::ProcedureInterpretation,
    CallSiteId,
);

// Preserve exact context-handle equality without retaining artifacts in keys.
// CompleteValueCache keeps weak-value registry keys after ready eviction.
#[derive(Clone, PartialEq, Eq, Hash)]
struct CallContextCacheKey {
    calls: Box<[ContextCallKey]>,
    truncated: bool,
}

impl CallContextCacheKey {
    fn of(context: &OracleCallContext) -> Self {
        Self {
            calls: context
                .calls()
                .iter()
                .map(|call| {
                    let procedure = call.procedure();
                    (
                        procedure.artifact().key().fingerprint(),
                        Arc::as_ptr(procedure.artifact()) as usize,
                        procedure.id(),
                        procedure.interpretation(),
                        call.id(),
                    )
                })
                .collect(),
            truncated: context.was_truncated(),
        }
    }
}

// Cached answers own oracle arenas tied to one materialization. A weak identity
// prevents the cache's weak-value registry from pinning evicted artifact contents.
#[derive(Clone)]
struct ArtifactInstance(std::sync::Weak<crate::analyzer::semantic::SemanticArtifact>);

impl ArtifactInstance {
    fn of(procedure: &ProcedureHandle) -> Self {
        Self(Arc::downgrade(procedure.artifact()))
    }
}

impl PartialEq for ArtifactInstance {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}
impl Eq for ArtifactInstance {}
impl std::hash::Hash for ArtifactInstance {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.0.as_ptr(), state);
    }
}

/// Content-addressed identity of one procedure-local value-flow snapshot
/// verdict.
///
/// These four dimensions are every input
/// [`WorkspaceSemanticOracle::procedure_relations`] reads apart from the
/// request's budget and cancellation token, and those two can only produce an
/// outcome this cache never retains. See the module documentation for the
/// argument in full.
#[derive(Clone, PartialEq, Eq, Hash)]
struct SnapshotKey {
    owner: ArtifactInstance,
    artifact: StableDigest,
    procedure: ProcedureId,
    interpretation: crate::analyzer::semantic::ProcedureInterpretation,
    projection: Option<StableDigest>,
    limits: OracleLimits,
    context: CallContextCacheKey,
}

impl SnapshotKey {
    fn for_query(
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        limits: OracleLimits,
        projection: Option<StableDigest>,
    ) -> Self {
        Self {
            owner: ArtifactInstance::of(procedure),
            artifact: procedure.artifact().key().fingerprint(),
            procedure: procedure.id(),
            interpretation: procedure.interpretation(),
            projection,
            limits,
            context: CallContextCacheKey::of(context),
        }
    }
}

/// The snapshot verdict this cache retains, with its semantic work zeroed
/// because the flight that built it already charged that work.
///
/// Retaining the whole [`SemanticOutcome`] rather than a bare snapshot is what
/// lets a non-complete answer be replayed without losing the typed
/// incompleteness that makes it honest (#2284).
type MemoizedSnapshot = ReplayingMemoEntry<SemanticOutcome<ValueFlowSnapshot>, ReadKey>;

/// The binding verdict this cache retains, on the same terms as
/// [`MemoizedSnapshot`] (#2289).
type MemoizedBindings = ReplayingMemoEntry<SemanticOutcome<CallBindings>, ReadKey>;

/// The dispatch verdict this cache retains, on the same terms as
/// [`MemoizedSnapshot`].
type MemoizedDispatch = ReplayingMemoEntry<SemanticOutcome<DispatchResult>, ReadKey>;

/// Content-addressed identity of one call-dispatch verdict.
///
/// The provider behavior folds the workspace content, hierarchy mode, active
/// semantic-model set, external dispatch surface, and receiver-class hints.
/// The remaining fields select the exact call and retain `OracleLimits` as an
/// explicit verdict input.
#[derive(Clone, PartialEq, Eq, Hash)]
struct DispatchKey {
    owner: ArtifactInstance,
    caller_artifact: StableDigest,
    caller_procedure: ProcedureId,
    caller_interpretation: crate::analyzer::semantic::ProcedureInterpretation,
    call_site: CallSiteId,
    provider_behavior: IcfgProviderBehaviorIdentity,
    limits: OracleLimits,
}

impl DispatchKey {
    fn for_query(
        call: &CallSiteHandle,
        provider_behavior: IcfgProviderBehaviorIdentity,
        limits: OracleLimits,
    ) -> Self {
        Self {
            owner: ArtifactInstance::of(call.procedure()),
            caller_artifact: call.procedure().artifact().key().fingerprint(),
            caller_procedure: call.procedure().id(),
            caller_interpretation: call.procedure().interpretation(),
            call_site: call.id(),
            provider_behavior,
            limits,
        }
    }
}

/// Content-addressed identity of one `(call, candidate)` binding verdict.
///
/// The caller and the dispatch target are each pinned by their artifact content
/// fingerprint and procedure identity, and the call site is pinned by its
/// caller-local identity. Workspace behavior is also part of the key for Java
/// conversions and Python callee defaults, which can change independently of
/// those artifact identities. The candidate's own `proof` and `completeness`
/// are pinned too, then the call context and the oracle limits.
#[derive(Clone, PartialEq, Eq, Hash)]
struct BindingsKey {
    caller: ArtifactInstance,
    target: ArtifactInstance,
    provider_behavior: Option<IcfgProviderBehaviorIdentity>,
    caller_artifact: StableDigest,
    caller_procedure: ProcedureId,
    caller_interpretation: crate::analyzer::semantic::ProcedureInterpretation,
    call_site: CallSiteId,
    target_artifact: StableDigest,
    target_procedure: ProcedureId,
    target_interpretation: crate::analyzer::semantic::ProcedureInterpretation,
    candidate_proof: ProofStatus,
    candidate_completeness: EvidenceCompleteness,
    excluded_targets: Box<[ProcedureId]>,
    context: CallContextCacheKey,
    limits: OracleLimits,
}

impl BindingsKey {
    fn for_query(
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        limits: OracleLimits,
        provider_behavior: IcfgProviderBehaviorIdentity,
    ) -> Self {
        let caller = call.procedure();
        let target = candidate.target();
        Self {
            caller: ArtifactInstance::of(caller),
            target: ArtifactInstance::of(target),
            provider_behavior: (caller.artifact().key().language()
                == crate::analyzer::semantic::SemanticLanguage::Standard(
                    crate::analyzer::Language::Java,
                )
                || target.artifact().key().language()
                    == crate::analyzer::semantic::SemanticLanguage::Standard(
                        crate::analyzer::Language::Python,
                    ))
            .then_some(provider_behavior),
            caller_artifact: caller.artifact().key().fingerprint(),
            caller_procedure: caller.id(),
            caller_interpretation: caller.interpretation(),
            call_site: call.id(),
            target_artifact: target.artifact().key().fingerprint(),
            target_procedure: target.id(),
            target_interpretation: target.interpretation(),
            candidate_proof: candidate.proof().clone(),
            candidate_completeness: candidate.completeness().clone(),
            excluded_targets: candidate
                .excluded_targets()
                .iter()
                .map(ProcedureHandle::id)
                .collect(),
            context: CallContextCacheKey::of(context),
            limits,
        }
    }
}

/// Conservative structural byte weight of one retained snapshot verdict. The
/// shared provenance arena is `Arc`-shared across relations, so this counts the
/// owned relation rows and the entire retained arena once, including records
/// whose projected rows were filtered out.
fn weigh_snapshot(key: &SnapshotKey, outcome: &Arc<MemoizedSnapshot>) -> u32 {
    let mut census = ArtifactRetentionCensus::default();
    if let Some(snapshot) = outcome.value().available_value() {
        snapshot.retained_artifacts(&mut census);
    }
    size_of::<MemoizedSnapshot>()
        .saturating_add(size_of::<SnapshotKey>())
        .saturating_add(std::mem::size_of_val(key.context.calls.as_ref()))
        .saturating_add(retained_memo_read_bytes(outcome))
        .saturating_add(census.retained_bytes().min(usize::MAX as u64) as usize)
        .min(u32::MAX as usize) as u32
}

/// Conservative structural byte weight of one retained binding verdict.
fn weigh_bindings(key: &BindingsKey, outcome: &Arc<MemoizedBindings>) -> u32 {
    let rows = outcome
        .value()
        .available_value()
        .map_or(0, |bindings| bindings.bindings().len())
        .saturating_mul(size_of::<CallBinding>());
    let excluded_targets = outcome
        .value()
        .available_value()
        .map_or(0, |bindings| bindings.candidate().excluded_targets().len())
        .saturating_mul(size_of::<ProcedureHandle>());
    let mut census = ArtifactRetentionCensus::default();
    if let Some(bindings) = outcome.value().available_value() {
        bindings.retained_artifacts(&mut census);
    }
    size_of::<MemoizedBindings>()
        .saturating_add(size_of::<BindingsKey>())
        .saturating_add(std::mem::size_of_val(key.context.calls.as_ref()))
        .saturating_add(rows)
        .saturating_add(excluded_targets)
        .saturating_add(retained_memo_read_bytes(outcome))
        .saturating_add(census.retained_bytes().min(usize::MAX as u64) as usize)
        .min(u32::MAX as usize) as u32
}

/// Conservative structural byte weight of one retained dispatch verdict.
fn weigh_dispatch(_key: &DispatchKey, outcome: &Arc<MemoizedDispatch>) -> u32 {
    let rows = outcome.value().available_value().map_or(0, |dispatch| {
        let exact_chain_bytes = dispatch
            .boundaries()
            .iter()
            .filter_map(|boundary| boundary.exact_external_target.as_ref())
            .map(|target| {
                std::mem::size_of_val(target.receiver_adjustments())
                    + target
                        .receiver_adjustments()
                        .iter()
                        .map(|step| step.retained_heap_bytes())
                        .sum::<usize>()
            })
            .sum::<usize>();
        exact_chain_bytes.saturating_add(
            dispatch
                .candidates()
                .len()
                .saturating_mul(size_of::<DispatchCandidate>())
                .saturating_add(
                    dispatch
                        .boundaries()
                        .len()
                        .saturating_mul(size_of::<DispatchBoundary>()),
                )
                .saturating_add(
                    dispatch
                        .boundaries()
                        .iter()
                        .filter_map(|boundary| boundary.unmaterialized_external_target.as_ref())
                        .map(|target| target.type_argument_binding_heap_bytes())
                        .fold(0, usize::saturating_add),
                ),
        )
    });
    let mut census = ArtifactRetentionCensus::default();
    if let Some(dispatch) = outcome.value().available_value() {
        dispatch.retained_artifacts(&mut census);
    }
    size_of::<MemoizedDispatch>()
        .saturating_add(size_of::<DispatchKey>())
        .saturating_add(rows)
        .saturating_add(retained_memo_read_bytes(outcome))
        .saturating_add(census.retained_bytes().min(usize::MAX as u64) as usize)
        .min(u32::MAX as usize) as u32
}

#[derive(Debug, Default)]
struct ValueFlowCacheStats {
    snapshot_hits: AtomicU64,
    snapshot_misses: AtomicU64,
    dispatch_hits: AtomicU64,
    dispatch_misses: AtomicU64,
    binding_hits: AtomicU64,
    binding_misses: AtomicU64,
}

/// One atomic snapshot of the acquisition counters shared by a
/// [`ValueFlowCache`] and all of its clones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValueFlowCacheStatsSnapshot {
    pub snapshot_hits: u64,
    pub snapshot_misses: u64,
    pub dispatch_hits: u64,
    pub dispatch_misses: u64,
    pub binding_hits: u64,
    pub binding_misses: u64,
}

impl ValueFlowCacheStatsSnapshot {
    pub const fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            snapshot_hits: self.snapshot_hits.saturating_sub(earlier.snapshot_hits),
            snapshot_misses: self.snapshot_misses.saturating_sub(earlier.snapshot_misses),
            dispatch_hits: self.dispatch_hits.saturating_sub(earlier.dispatch_hits),
            dispatch_misses: self.dispatch_misses.saturating_sub(earlier.dispatch_misses),
            binding_hits: self.binding_hits.saturating_sub(earlier.binding_hits),
            binding_misses: self.binding_misses.saturating_sub(earlier.binding_misses),
        }
    }
}

/// Generation-independent, bounded, content-keyed cache of value-flow
/// snapshot, dispatch, and call-binding verdicts. Cloning shares the
/// underlying entries and counters, so the same cache can back one provider
/// per analyzer generation and reuse unchanged procedures across generations
/// and queries. [`Self::with_fresh_stats`] keeps the shared entries while
/// giving one query an independent attribution scope.
#[derive(Clone)]
pub struct ValueFlowCache {
    snapshots: CompleteValueCache<SnapshotKey, MemoizedSnapshot>,
    dispatch: CompleteValueCache<DispatchKey, MemoizedDispatch>,
    bindings: CompleteValueCache<BindingsKey, MemoizedBindings>,
    stats: Arc<ValueFlowCacheStats>,
}

impl Default for ValueFlowCache {
    fn default() -> Self {
        Self::new(DEFAULT_VALUE_FLOW_CACHE_BYTES)
    }
}

impl ValueFlowCache {
    /// Build a cache that bounds each sub-cache to `max_retained_bytes`.
    pub fn new(max_retained_bytes: u64) -> Self {
        Self {
            snapshots: CompleteValueCache::new(max_retained_bytes, weigh_snapshot),
            dispatch: CompleteValueCache::new(max_retained_bytes, weigh_dispatch),
            bindings: CompleteValueCache::new(max_retained_bytes, weigh_bindings),
            stats: Arc::new(ValueFlowCacheStats::default()),
        }
    }

    /// Share retained entries while starting an independent counter scope.
    ///
    /// A workspace cache can serve concurrent queries. Before/after snapshots
    /// of counters shared by those queries would attribute intervening work
    /// from every query to each one. Query entry points use this fork so cache
    /// reuse remains workspace-wide while hit and miss counters remain exact
    /// for the query that reports them.
    pub fn with_fresh_stats(&self) -> Self {
        Self {
            snapshots: self.snapshots.clone(),
            dispatch: self.dispatch.clone(),
            bindings: self.bindings.clone(),
            stats: Arc::new(ValueFlowCacheStats::default()),
        }
    }

    /// Union of artifacts pinned by ready snapshot, dispatch and binding verdicts.
    pub fn artifact_bytes(&self) -> u64 {
        let mut census = ArtifactRetentionCensus::default();
        self.snapshots.visit_ready(|outcome| {
            if let Some(value) = outcome.value().available_value() {
                value.retained_artifacts(&mut census);
            }
        });
        self.dispatch.visit_ready(|outcome| {
            if let Some(value) = outcome.value().available_value() {
                value.retained_artifacts(&mut census);
            }
        });
        self.bindings.visit_ready(|outcome| {
            if let Some(value) = outcome.value().available_value() {
                value.retained_artifacts(&mut census);
            }
        });
        census.artifact_bytes()
    }

    /// Observe the three workspace-owned value-flow memo roots without
    /// advancing Moka maintenance or changing admission/eviction.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn retention_census_for_test(
        &self,
        census: &mut brokk_bifrost_core::retention_census::RetentionCensus<'_>,
    ) {
        use brokk_bifrost_core::retention_census::{
            AllocationAccounting, FamilyLifetime, ResidentWeightUnit, UnknownKind,
        };

        const LIFETIME: FamilyLifetime = FamilyLifetime::Persistent;
        let (count, weight) = self.snapshots.visit_ready_passively_for_test(|key, value| {
            let mut backing = ArtifactRetentionCensus::default();
            if let Some(snapshot) = value.value().available_value() {
                snapshot.retention_census_for_test(census, "flow.value_flow.snapshots");
                snapshot.retained_artifacts(&mut backing);
            }
            let backing_bytes = backing.retained_bytes();
            let weight = weigh_snapshot(key, value);
            let family = "flow.value_flow.snapshots";
            if weight == u32::MAX || backing_bytes > u64::from(weight) {
                census.record_unknown(
                    family,
                    LIFETIME,
                    UnknownKind::Coverage,
                    "memoized_value_or_backing_estimate_saturated",
                );
            } else {
                census.record_arc_allocation(
                    Arc::clone(value),
                    family,
                    LIFETIME,
                    "memoized-value-owned-estimate",
                    u64::from(weight) - backing_bytes,
                    AllocationAccounting::OutsideBudget,
                );
            }
        });
        census.record_resident_reading(
            "flow.value_flow.snapshots",
            LIFETIME,
            count,
            weight,
            ResidentWeightUnit::BytesEstimate,
        );
        let (count, weight) = self.dispatch.visit_ready_passively_for_test(|key, value| {
            let mut backing = ArtifactRetentionCensus::default();
            if let Some(dispatch) = value.value().available_value() {
                let family = "flow.value_flow.dispatch";
                for candidate in dispatch.candidates() {
                    candidate.retention_census_for_test(census, family);
                }
                for boundary in dispatch.boundaries() {
                    for relation in &boundary.provenance {
                        relation.retention_census_for_test(census, family);
                    }
                }
                if let Some(returned) = dispatch.returned_callable() {
                    returned.retention_census_for_test(census, family);
                }
                if let Some(argument) = dispatch.argument_callable() {
                    argument.retention_census_for_test(census, family);
                }
                for value in dispatch.stable_package_values() {
                    value.retention_census_for_test(census, family);
                }
                dispatch.retained_artifacts(&mut backing);
            }
            let backing_bytes = backing.retained_bytes();
            let weight = weigh_dispatch(key, value);
            let family = "flow.value_flow.dispatch";
            if weight == u32::MAX || backing_bytes > u64::from(weight) {
                census.record_unknown(
                    family,
                    LIFETIME,
                    UnknownKind::Coverage,
                    "memoized_value_or_backing_estimate_saturated",
                );
            } else {
                census.record_arc_allocation(
                    Arc::clone(value),
                    family,
                    LIFETIME,
                    "memoized-value-owned-estimate",
                    u64::from(weight) - backing_bytes,
                    AllocationAccounting::OutsideBudget,
                );
            }
        });
        census.record_resident_reading(
            "flow.value_flow.dispatch",
            LIFETIME,
            count,
            weight,
            ResidentWeightUnit::BytesEstimate,
        );
        let (count, weight) = self.bindings.visit_ready_passively_for_test(|key, value| {
            let mut backing = ArtifactRetentionCensus::default();
            if let Some(bindings) = value.value().available_value() {
                bindings.retention_census_for_test(census, "flow.value_flow.bindings");
                bindings.retained_artifacts(&mut backing);
            }
            let backing_bytes = backing.retained_bytes();
            let weight = weigh_bindings(key, value);
            let family = "flow.value_flow.bindings";
            if weight == u32::MAX || backing_bytes > u64::from(weight) {
                census.record_unknown(
                    family,
                    LIFETIME,
                    UnknownKind::Coverage,
                    "memoized_value_or_backing_estimate_saturated",
                );
            } else {
                census.record_arc_allocation(
                    Arc::clone(value),
                    family,
                    LIFETIME,
                    "memoized-value-owned-estimate",
                    u64::from(weight) - backing_bytes,
                    AllocationAccounting::OutsideBudget,
                );
            }
        });
        census.record_resident_reading(
            "flow.value_flow.bindings",
            LIFETIME,
            count,
            weight,
            ResidentWeightUnit::BytesEstimate,
        );

        for family in [
            "flow.value_flow.snapshots",
            "flow.value_flow.dispatch",
            "flow.value_flow.bindings",
        ] {
            census.record_unknown(
                family,
                LIFETIME,
                UnknownKind::NativeBytes,
                "moka_table_key_and_container_capacity_unavailable",
            );
            census.record_unknown(
                family,
                LIFETIME,
                UnknownKind::ActivePins,
                "evicted_live_value_or_external_provider_pins_not_enumerated",
            );
        }
        for (family, flights) in [
            (
                "flow.value_flow.snapshots",
                self.snapshots.in_flight_count_for_test(),
            ),
            (
                "flow.value_flow.dispatch",
                self.dispatch.in_flight_count_for_test(),
            ),
            (
                "flow.value_flow.bindings",
                self.bindings.in_flight_count_for_test(),
            ),
        ] {
            if flights != 0 {
                census.record_unknown(
                    family,
                    LIFETIME,
                    UnknownKind::ActivePins,
                    "active_value_flow_materialization_flights",
                );
            }
        }
    }

    /// Count of snapshot lookups served from a ready cache entry.
    pub fn snapshot_hits(&self) -> u64 {
        self.stats.snapshot_hits.load(Ordering::Relaxed)
    }

    /// Count of snapshot lookups that had to materialize through the oracle.
    pub fn snapshot_misses(&self) -> u64 {
        self.stats.snapshot_misses.load(Ordering::Relaxed)
    }

    /// Count of dispatch lookups served from a ready cache entry.
    pub fn dispatch_hits(&self) -> u64 {
        self.stats.dispatch_hits.load(Ordering::Relaxed)
    }

    /// Count of dispatch lookups that had to materialize through the oracle.
    pub fn dispatch_misses(&self) -> u64 {
        self.stats.dispatch_misses.load(Ordering::Relaxed)
    }

    /// Count of binding lookups served from a ready cache entry.
    pub fn binding_hits(&self) -> u64 {
        self.stats.binding_hits.load(Ordering::Relaxed)
    }

    /// Count of binding lookups that had to materialize through the oracle.
    pub fn binding_misses(&self) -> u64 {
        self.stats.binding_misses.load(Ordering::Relaxed)
    }

    /// Capture all counters for query-local before/after attribution.
    pub fn stats(&self) -> ValueFlowCacheStatsSnapshot {
        ValueFlowCacheStatsSnapshot {
            snapshot_hits: self.snapshot_hits(),
            snapshot_misses: self.snapshot_misses(),
            dispatch_hits: self.dispatch_hits(),
            dispatch_misses: self.dispatch_misses(),
            binding_hits: self.binding_hits(),
            binding_misses: self.binding_misses(),
        }
    }
}

impl fmt::Debug for ValueFlowCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValueFlowCache")
            .field("snapshot_hits", &self.snapshot_hits())
            .field("snapshot_misses", &self.snapshot_misses())
            .field("dispatch_hits", &self.dispatch_hits())
            .field("dispatch_misses", &self.dispatch_misses())
            .field("binding_hits", &self.binding_hits())
            .field("binding_misses", &self.binding_misses())
            .finish_non_exhaustive()
    }
}

/// Fills whose only shortfall is a reuse refusal (#12820). Such a fill is exact
/// for this request but must never be shared, so it lives in the provider that
/// built it: a provider is created for one request, is not `Clone`, and no
/// workspace-lived owner stores one. Within the request, repeated queries must
/// get the first fill back, because callers compare memoized values by identity
/// (a dispatch candidate's provenance arena). Every hit replays the refusal into
/// the reader's capture. Operational failures are stored nowhere.
#[derive(Default)]
struct RefusedFills {
    snapshots: Mutex<crate::hash::HashMap<SnapshotKey, Arc<MemoizedSnapshot>>>,
    dispatch: Mutex<crate::hash::HashMap<DispatchKey, Arc<MemoizedDispatch>>>,
    bindings: Mutex<crate::hash::HashMap<BindingsKey, Arc<MemoizedBindings>>>,
}

impl RefusedFills {
    fn get<K: Eq + std::hash::Hash, V>(
        memo: &Mutex<crate::hash::HashMap<K, Arc<V>>>,
        key: &K,
    ) -> Option<Arc<V>> {
        memo.lock().expect("refused fills lock").get(key).cloned()
    }

    /// Keep the first fill of a key; a racing second fill adopts it.
    fn keep<K: Eq + std::hash::Hash, V>(
        memo: &Mutex<crate::hash::HashMap<K, Arc<V>>>,
        key: K,
        entry: V,
    ) -> Arc<V> {
        Arc::clone(
            memo.lock()
                .expect("refused fills lock")
                .entry(key)
                .or_insert_with(|| Arc::new(entry)),
        )
    }
}

/// A [`ValueFlowProvider`] bound to one immutable analyzer generation and one
/// shared [`ValueFlowCache`]. It is the request-local tier above that cache.
pub struct WorkspaceValueFlowProvider<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    provider_behavior: IcfgProviderBehaviorIdentity,
    cache: ValueFlowCache,
    dispatch_sessions: Arc<PreparedWorkspaceDispatchPool<'a>>,
    dispatch_reads: Option<DispatchReadCollector>,
    retained_writes: Arc<AtomicBool>,
    refused: Arc<RefusedFills>,
}

impl<'a> WorkspaceValueFlowProvider<'a> {
    /// Ready prepared-source artifacts retained by this provider.
    pub fn prepared_pool_artifact_bytes(&self) -> u64 {
        self.dispatch_sessions.artifact_bytes()
    }

    /// Bind the provider to one analyzer generation and one shared cache.
    pub fn new(workspace: &'a WorkspaceAnalyzer, cache: ValueFlowCache) -> Self {
        let provider = WorkspaceIcfgProvider::new(workspace);
        let oracle = provider.oracle().clone();
        Self::with_oracle(oracle, provider.behavior_identity(), cache)
    }

    /// Bind the provider to an externally built oracle and one shared cache.
    ///
    /// A caller that already holds the oracle it means discovery to use (the
    /// executor's snapshot-bound oracle today, a hinted oracle under #2945)
    /// hands it in here; building a second oracle from the current overlay
    /// would give one walk two oracle identities.
    pub fn with_oracle(
        oracle: WorkspaceSemanticOracle<'a>,
        provider_behavior: IcfgProviderBehaviorIdentity,
        cache: ValueFlowCache,
    ) -> Self {
        let dispatch_sessions = Arc::new(oracle.prepare_workspace_dispatch_pool());
        Self {
            oracle,
            provider_behavior,
            cache,
            dispatch_sessions,
            dispatch_reads: None,
            retained_writes: Arc::new(AtomicBool::new(false)),
            refused: Arc::default(),
        }
    }

    /// Select an executable body, retaining cancellation and budget refusal as outcomes.
    pub fn select_executable_procedure(
        workspace: &crate::analyzer::WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ProcedureHandle>, SemanticProviderError> {
        if procedure.interpretation()
            == crate::analyzer::semantic::ProcedureInterpretation::ExecutableAlternate
        {
            return workspace
                .executable_procedure_handle(procedure, request)
                .map(|outcome| outcome.map(|selected| selected.handle));
        }
        match workspace.replay_ownership_procedure_handle(procedure, request)? {
            SemanticOutcome::Complete {
                value: Some(handle),
                work,
            } => Ok(SemanticOutcome::Complete {
                value: handle,
                work,
            }),
            SemanticOutcome::Complete { value: None, .. } => workspace
                .executable_procedure_handle(procedure, request)
                .map(|outcome| outcome.map(|selected| selected.handle)),
            outcome => Ok(outcome.map(|_| unreachable!("stopped ownership replay has no handle"))),
        }
    }

    /// Derive a provider that reports every dispatch input to `collector`
    /// while sharing this provider's immutable oracle and value cache.
    pub(crate) fn observing_dispatch_reads(&self, collector: DispatchReadCollector) -> Self {
        Self {
            oracle: self.oracle.clone(),
            provider_behavior: self.provider_behavior,
            cache: self.cache.clone(),
            dispatch_sessions: Arc::clone(&self.dispatch_sessions),
            dispatch_reads: Some(collector),
            retained_writes: Arc::clone(&self.retained_writes),
            refused: Arc::clone(&self.refused),
        }
    }

    /// A truncated call context keys the answer, so the answer depends on the
    /// truncation. The answer cannot carry that verdict, so it joins the
    /// current captures, where `was_truncated` marked the ambient one.
    fn join_context_verdict(&self, context: &OracleCallContext) {
        self.oracle.workspace().analyzer().join_reuse_verdict(
            crate::analyzer::reuse_verdict::CarriesReuseVerdict::reuse_verdict(context),
        );
    }

    /// The workspace semantic oracle this provider delegates to.
    pub const fn oracle(&self) -> &WorkspaceSemanticOracle<'a> {
        &self.oracle
    }

    /// Whether this provider or one of its observer clones published a
    /// completed outcome into the externally shared value-flow cache.
    pub(crate) fn take_retained_writes(&self) -> bool {
        self.retained_writes.swap(false, Ordering::AcqRel)
    }

    fn record_dispatch_read(
        &self,
        call: &CallSiteHandle,
        outcome: &SemanticOutcome<DispatchResult>,
    ) {
        let attribution = dispatch_read_attribution(call, outcome);
        crate::analyzer::semantic::record_dispatch_read_attribution(
            self.oracle.workspace(),
            &attribution,
        );
        if let Some(collector) = &self.dispatch_reads {
            collector.record(call, attribution);
        }
    }
}

impl fmt::Debug for WorkspaceValueFlowProvider<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceValueFlowProvider")
            .field("cache", &self.cache)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only refusal source standing in for an unrecorded read inside a fill.
    static REFUSE_PROVIDER_FILLS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// A finished partial outcome can still hide a lower operational stop. The
// flag is true when no operational stop happened: cancellation, budget, a
// generation change, an execution dependence or a content gap. A reuse refusal
// is not one: it denies sharing but leaves the answer exact (#12820), so the
// caller keeps such a fill request-locally.
fn complete_provider_fill<T>(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    request: &mut SemanticRequest<'_>,
    build: impl FnOnce(&mut SemanticRequest<'_>) -> Judged<T>,
) -> Judged<(T, bool)> {
    let fill = brokk_bifrost_analysis::analyzer::common::QueryCacheFill::new(analyzer);
    let Judged { value, reuse } = build(request);
    #[cfg(test)]
    if REFUSE_PROVIDER_FILLS.with(std::cell::Cell::get) {
        analyzer.refuse_read_reuse();
    }
    if !reuse.is_content() {
        analyzer.mark_execution_dependent();
        analyzer.join_reuse_verdict(reuse);
    }
    let operationally_complete = fill.is_operationally_complete();
    drop(fill);
    Judged {
        value: (value, operationally_complete),
        reuse,
    }
}

impl ValueFlowProvider for WorkspaceValueFlowProvider<'_> {
    type Error = SemanticProviderError;
    fn payload_projection_identity(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<StableDigest>>, Self::Error> {
        self.oracle.payload_projection_identity(procedure, request)
    }

    fn payload_constructor_output(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<ValueFlowEndpoint>>, Self::Error> {
        self.oracle.payload_constructor_output(call, request)
    }
    fn selected_executable_procedure(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ProcedureHandle>, Self::Error> {
        Self::select_executable_procedure(self.oracle.workspace(), procedure, request)
    }

    fn procedure_snapshot(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError> {
        let projection = self
            .oracle
            .payload_projection_identity(procedure, request)?;
        if !matches!(projection, SemanticOutcome::Complete { .. }) {
            return self.oracle.procedure_relations(procedure, context, request);
        }
        let identity = projection.available_value().copied().flatten();
        self.join_context_verdict(context);
        let key = SnapshotKey::for_query(procedure, context, *self.oracle.limits(), identity);
        if let Some(value) = RefusedFills::get(&self.refused.snapshots, &key) {
            value.replay(&memo_attribution(self.oracle.workspace().analyzer()));
            return Ok(value.value().clone());
        }
        let (acquisition, _wait) = self.cache.snapshots.acquire(&key, request.cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                self.cache
                    .stats
                    .snapshot_hits
                    .fetch_add(1, Ordering::Relaxed);
                // A ready entry charged its semantic work on the flight that
                // built it, and it already carries the exact verdict that
                // flight published. Replaying it owns no new semantic work.
                value.replay(&memo_attribution(self.oracle.workspace().analyzer()));
                Ok(value.value().clone())
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.cache
                    .stats
                    .snapshot_misses
                    .fetch_add(1, Ordering::Relaxed);
                let ((outcome, operational), reads) = ReplayingMemoEntry::capture_judged(
                    &memo_attribution(self.oracle.workspace().analyzer()),
                    || {
                        complete_provider_fill(
                            self.oracle.workspace().analyzer(),
                            request,
                            |request| {
                                self.oracle
                                    .procedure_relations_judged(procedure, context, request)
                            },
                        )
                    },
                )
                .into_parts();
                let outcome = outcome?;
                // A finished verdict is retained whether or not it is complete
                // (#2284). Dropping the permit on a budget-exhausted or
                // cancelled outcome wakes followers to retry, so a shortfall of
                // this request never enters the ready cache.
                if operational
                    && !outcome
                        .available_value()
                        .is_some_and(|snapshot| snapshot.is_execution_dependent())
                    && let Some(memoized) = outcome.completed_replay()
                {
                    let entry = ReplayingMemoEntry::from_parts(memoized, reads);
                    if entry.reuse_refused() {
                        let kept = RefusedFills::keep(&self.refused.snapshots, key, entry);
                        return Ok(kept.value().clone());
                    }
                    permit.publish_complete(Arc::new(entry));
                    self.retained_writes.store(true, Ordering::Release);
                }
                Ok(outcome)
            }
            CompleteValueAcquisition::Rejected => {
                unreachable!("value-flow snapshot cache never publishes rejected flights")
            }
            CompleteValueAcquisition::Cancelled => Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            }),
        }
    }

    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let key = DispatchKey::for_query(call, self.provider_behavior, *self.oracle.limits());
        if let Some(value) = RefusedFills::get(&self.refused.dispatch, &key) {
            value.replay(&memo_attribution(self.oracle.workspace().analyzer()));
            let outcome = value.value().clone();
            self.record_dispatch_read(call, &outcome);
            return Ok(outcome);
        }
        let (acquisition, _wait) = self.cache.dispatch.acquire(&key, request.cancellation);
        let outcome = match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                self.cache
                    .stats
                    .dispatch_hits
                    .fetch_add(1, Ordering::Relaxed);
                value.replay(&memo_attribution(self.oracle.workspace().analyzer()));
                value.value().clone()
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.cache
                    .stats
                    .dispatch_misses
                    .fetch_add(1, Ordering::Relaxed);
                let ((outcome, operational), reads) = ReplayingMemoEntry::capture_judged(
                    &memo_attribution(self.oracle.workspace().analyzer()),
                    || {
                        complete_provider_fill(
                            self.oracle.workspace().analyzer(),
                            request,
                            |request| self.dispatch_sessions.resolve_call_judged(call, request),
                        )
                    },
                )
                .into_parts();
                let outcome = outcome?;
                match outcome.completed_replay() {
                    Some(memoized) if operational => {
                        let entry = ReplayingMemoEntry::from_parts(memoized, reads);
                        if entry.reuse_refused() {
                            RefusedFills::keep(&self.refused.dispatch, key, entry)
                                .value()
                                .clone()
                        } else {
                            permit.publish_complete(Arc::new(entry));
                            self.retained_writes.store(true, Ordering::Release);
                            outcome
                        }
                    }
                    _ => outcome,
                }
            }
            CompleteValueAcquisition::Rejected => {
                unreachable!("value-flow dispatch cache never publishes rejected flights")
            }
            CompleteValueAcquisition::Cancelled => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
        };
        self.record_dispatch_read(call, &outcome);
        Ok(outcome)
    }

    fn resolve_call_in_context(
        &self,
        call: &CallSiteHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.join_context_verdict(context);
        if context.calls().is_empty() && !context.was_truncated() {
            return self.resolve_call(call, request);
        }
        // Contextual outcomes never enter the shared origin-only cache. Paid
        // source is reused by this query's prepared dispatch sessions; proof
        // and captures are recomputed and charged for each exact context.
        let outcome = self
            .dispatch_sessions
            .resolve_call_in_context(call, context, request)?;
        crate::analyzer::semantic::record_dispatch_read_attribution(
            self.oracle.workspace(),
            &DispatchReadAttribution::Unattributed(
                crate::analyzer::semantic::DispatchReadUnattributedReason::CallContextUnavailable,
            ),
        );
        if let Some(collector) = &self.dispatch_reads {
            collector.record(call, DispatchReadAttribution::Unattributed(
                crate::analyzer::semantic::DispatchReadUnattributedReason::CallContextUnavailable,
            ));
        }
        Ok(outcome)
    }

    fn call_bindings(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError> {
        self.join_context_verdict(context);
        let key = BindingsKey::for_query(
            call,
            candidate,
            context,
            *self.oracle.limits(),
            self.provider_behavior,
        );
        if let Some(value) = RefusedFills::get(&self.refused.bindings, &key) {
            value.replay(&memo_attribution(self.oracle.workspace().analyzer()));
            return Ok(value.value().clone());
        }
        let (acquisition, _wait) = self.cache.bindings.acquire(&key, request.cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                self.cache
                    .stats
                    .binding_hits
                    .fetch_add(1, Ordering::Relaxed);
                // A ready entry charged its semantic work on the flight that
                // built it, and it already carries the exact verdict that
                // flight published. Replaying it owns no new semantic work.
                value.replay(&memo_attribution(self.oracle.workspace().analyzer()));
                Ok(value.value().clone())
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.cache
                    .stats
                    .binding_misses
                    .fetch_add(1, Ordering::Relaxed);
                let ((outcome, operational), reads) = ReplayingMemoEntry::capture_judged(
                    &memo_attribution(self.oracle.workspace().analyzer()),
                    || {
                        complete_provider_fill(
                            self.oracle.workspace().analyzer(),
                            request,
                            |request| {
                                self.oracle
                                    .call_bindings_judged(call, candidate, context, request)
                            },
                        )
                    },
                )
                .into_parts();
                let outcome = outcome?;
                // A finished binding verdict is retained whether or not it is
                // complete, on the same terms as a snapshot (#2289).
                if operational && let Some(memoized) = outcome.completed_replay() {
                    let entry = ReplayingMemoEntry::from_parts(memoized, reads);
                    if entry.reuse_refused() {
                        let kept = RefusedFills::keep(&self.refused.bindings, key, entry);
                        return Ok(kept.value().clone());
                    }
                    permit.publish_complete(Arc::new(entry));
                    self.retained_writes.store(true, Ordering::Release);
                }
                Ok(outcome)
            }
            CompleteValueAcquisition::Rejected => {
                unreachable!("value-flow bindings cache never publishes rejected flights")
            }
            CompleteValueAcquisition::Cancelled => Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticBudgetDimension};
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_test_macros::hardwon;

    const BATCH_CALL_SOURCE: &str = concat!(
        "import { open } from \"third-party\";\n",
        "export function caller() { open(\"a\"); open(\"b\"); }\n",
    );

    fn with_batch_calls(
        body: impl FnOnce(&WorkspaceAnalyzer, Vec<CallSiteHandle>, ValueFlowCache),
    ) {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file("batch.ts", BATCH_CALL_SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("batch.ts"),
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("fixture semantic materialization")
            .available_value()
            .cloned()
            .expect("fixture artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture caller");
        let calls = caller
            .semantics()
            .call_sites()
            .iter()
            .map(|call| {
                caller
                    .call_site_handle(call.id)
                    .expect("fixture call remains live")
            })
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2, "fixture has two calls");
        body(&workspace, calls, ValueFlowCache::default());
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn retention_census_deduplicates_shared_dispatch_arena_and_charged_artifact() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "flow.ts",
                "function leaf(v: number) { return v; }\nexport function caller() { return leaf(1); }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.ts"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantic materialization")
            .available_value()
            .cloned()
            .expect("charged fixture artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture caller");
        let call = caller
            .call_site_handle(caller.semantics().call_sites()[0].id)
            .expect("fixture call");
        let context = OracleCallContext::bounded(vec![call.clone()], OracleLimits::default());
        let cache = ValueFlowCache::default();
        let provider = WorkspaceValueFlowProvider::new(&workspace, cache.clone());

        let snapshot = provider
            .procedure_snapshot(
                &caller,
                &context,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("value-flow snapshot");
        assert!(snapshot.available_value().is_some());
        let dispatch = provider
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("dispatch");
        let candidate = dispatch
            .available_value()
            .and_then(|dispatch| dispatch.candidates().first())
            .expect("local leaf candidate");
        assert!(!candidate.provenance().is_empty());
        let bindings = provider
            .call_bindings(
                &call,
                candidate,
                &context,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("call bindings");
        assert!(bindings.available_value().is_some());

        let mut census = brokk_bifrost_core::retention_census::RetentionCensus::new();
        cache.retention_census_for_test(&mut census);
        let report = census.finish();
        let shared_arena = report.allocation_groups.iter().find(|group| {
            group.kind == Some("oracle-relation-arena")
                && group.families.contains(&"flow.value_flow.dispatch")
                && group.families.contains(&"flow.value_flow.bindings")
        });
        assert!(
            shared_arena.is_some(),
            "dispatch provenance arena is shared with cached call bindings: {report:?}"
        );
        assert_eq!(
            shared_arena.and_then(|group| group.accounting),
            Some(brokk_bifrost_core::retention_census::AllocationAccounting::OutsideBudget)
        );
        assert!(
            report.allocation_groups.iter().any(|group| {
                group.kind == Some("semantic-artifact")
                    && group.accounting
                        == Some(
                            brokk_bifrost_core::retention_census::AllocationAccounting::AlreadyBudgeted,
                        )
                    && group.families.contains(&"flow.value_flow.dispatch")
                    && group.families.contains(&"flow.value_flow.bindings")
            }),
            "the charged caller artifact is shared across the two cached results: {report:?}"
        );
    }

    #[test]
    #[hardwon(
        "#9925: nested base/alternate call contexts collided and returned the cached snapshot's wrong context"
    )]
    fn execution_dependent_snapshot_is_recomputed_but_clear_snapshot_is_retained() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "flow.go",
                "package fixture\nfunc helper(input string) string { return input }\nfunc run(input string) string { return helper(input) }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("fixture semantic materialization")
            .available_value()
            .cloned()
            .expect("fixture artifact");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .expect("fixture declares run");
        let procedure = artifact
            .procedure_handle(procedure.id())
            .expect("fixture procedure remains live");
        let cache = ValueFlowCache::default();
        {
            let cancellation = CancellationToken::default();
            let provider = WorkspaceValueFlowProvider::new(&workspace, cache.clone());
            let context = OracleCallContext::empty();
            let mut limits = SemanticBudget::default().limits();
            limits.nested_entries = 1;
            // Each request gets the same fresh restricted budget, so the two
            // marked answers are comparable.
            let mut budget = SemanticBudget::new(limits).expect("positive fixture budget");
            let marked_first = provider
                .procedure_snapshot(
                    &procedure,
                    &context,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("marked snapshot");
            assert!(
                marked_first
                    .available_value()
                    .expect("snapshot available")
                    .is_execution_dependent()
            );
            let mut budget = SemanticBudget::new(limits).expect("positive fixture budget");
            let marked_second = provider
                .procedure_snapshot(
                    &procedure,
                    &context,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("recomputed marked snapshot");
            // A budget-limited answer depends on the execution: with other
            // caches now warm, the same limits stop at a different point, so
            // the two partial snapshots may differ. Retaining the first would
            // serve it in place of the second request's own answer.
            assert!(
                marked_second
                    .available_value()
                    .expect("snapshot available")
                    .is_execution_dependent()
            );
            assert_eq!(cache.snapshot_misses(), 2);
            assert_eq!(cache.snapshot_hits(), 0);

            let clear_cache = ValueFlowCache::default();
            let clear_provider = WorkspaceValueFlowProvider::new(&workspace, clear_cache.clone());
            let clear_context = OracleCallContext::empty();
            let mut clear_budget = SemanticBudget::default();
            let clear_first = clear_provider
                .procedure_snapshot(
                    &procedure,
                    &clear_context,
                    &mut SemanticRequest::new(&mut clear_budget, &cancellation),
                )
                .expect("clear snapshot");
            assert!(
                !clear_first
                    .available_value()
                    .expect("snapshot available")
                    .is_execution_dependent()
            );
            let mut clear_budget = SemanticBudget::default();
            let clear_second = clear_provider
                .procedure_snapshot(
                    &procedure,
                    &clear_context,
                    &mut SemanticRequest::new(&mut clear_budget, &cancellation),
                )
                .expect("retained clear snapshot");
            // A hit returns the retained snapshot; only its work report differs.
            assert_eq!(
                clear_first.available_value(),
                clear_second.available_value()
            );
            assert_eq!(clear_cache.snapshot_misses(), 1);
            assert_eq!(clear_cache.snapshot_hits(), 1);

            // Both nested calls retain the SAME artifact allocation and dense
            // IDs. Only their executable interpretation differs.
            let base_call = procedure
                .call_site_handle(procedure.semantics().call_sites()[0].id)
                .expect("fixture run calls helper");
            let alternate = artifact
                .candidate_alternate_handle(procedure.id())
                .expect("fixture alternate interpretation");
            let alternate_call = alternate
                .call_site_handle(base_call.id())
                .expect("same dense call in alternate interpretation");
            assert!(Arc::ptr_eq(
                base_call.procedure().artifact(),
                alternate_call.procedure().artifact(),
            ));
            assert_ne!(base_call, alternate_call);
            let contexts = [base_call, alternate_call]
                .map(|call| OracleCallContext::bounded(vec![call], OracleLimits::default()));
            assert_ne!(contexts[0], contexts[1]);
            for (index, context) in contexts.iter().enumerate() {
                let mut budget = SemanticBudget::default();
                let first = clear_provider
                    .procedure_snapshot(
                        &procedure,
                        context,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("distinct nested-context snapshot");
                assert_eq!(
                    first
                        .available_value()
                        .expect("snapshot available")
                        .context(),
                    context,
                );
                assert_eq!(clear_cache.snapshot_misses(), index as u64 + 2);
                let mut budget = SemanticBudget::default();
                let second = clear_provider
                    .procedure_snapshot(
                        &procedure,
                        context,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("retained nested-context snapshot");
                assert_eq!(
                    second
                        .available_value()
                        .expect("snapshot available")
                        .context(),
                    context,
                );
                assert_eq!(first.available_value(), second.available_value());
                assert_eq!(clear_cache.snapshot_misses(), index as u64 + 2);
                assert_eq!(clear_cache.snapshot_hits(), index as u64 + 2);
            }
        }

        let interface_project = InlineTestProject::with_language(Language::Go)
            .file(
                "flow.go",
                "package fixture\ntype Reader interface { Read() string }\nfunc run(input Reader) string { return input.Read() }\n",
            )
            .build();
        let interface_workspace = interface_project.workspace_analyzer(AnalyzerConfig::default());
        let mut materialization_budget = SemanticBudget::default();
        let interface_artifact = interface_workspace
            .materialize_program_semantics(
                &interface_project.file("flow.go"),
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("interface fixture semantic materialization")
            .available_value()
            .cloned()
            .expect("interface fixture artifact");
        let interface_procedure = interface_artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .expect("interface fixture declares run");
        let interface_procedure = interface_artifact
            .procedure_handle(interface_procedure.id())
            .expect("interface fixture procedure remains live");
        let interface_cache = ValueFlowCache::default();
        let interface_provider =
            WorkspaceValueFlowProvider::new(&interface_workspace, interface_cache.clone());
        let interface_context = OracleCallContext::empty();
        let mut first_budget = SemanticBudget::default();
        let interface_first = interface_provider
            .procedure_snapshot(
                &interface_procedure,
                &interface_context,
                &mut SemanticRequest::new(&mut first_budget, &cancellation),
            )
            .expect("interface snapshot");
        assert!(interface_first.completed_replay().is_some());
        let first_snapshot = interface_first
            .available_value()
            .expect("interface snapshot available");
        assert!(first_snapshot.is_execution_dependent());
        let mut second_budget = SemanticBudget::default();
        let interface_second = interface_provider
            .procedure_snapshot(
                &interface_procedure,
                &interface_context,
                &mut SemanticRequest::new(&mut second_budget, &cancellation),
            )
            .expect("recomputed interface snapshot");
        // ProcedureHandle equality includes the artifact Arc's identity, and
        // the recomputation holds its own artifact instance, so compare the
        // rendered content of the two answers.
        assert_eq!(
            format!("{first_snapshot:?}"),
            format!(
                "{:?}",
                interface_second
                    .available_value()
                    .expect("recomputed snapshot available")
            )
        );
        assert_eq!(interface_cache.snapshot_misses(), 2);
        assert_eq!(interface_cache.snapshot_hits(), 0);
    }

    fn fixture_procedure_parts(
        procedure: &crate::analyzer::semantic::ProcedureSemantics,
    ) -> crate::analyzer::semantic::ProcedureSemanticsParts {
        use crate::analyzer::semantic::ProcedureSemanticsParts;
        assert!(procedure.guard_facts().is_empty());
        assert!(procedure.switch_facts().is_empty());
        let mut parts = ProcedureSemanticsParts::new(
            procedure.id(),
            procedure.locator().clone(),
            procedure.kind(),
            procedure.source(),
            procedure.evidence(),
        );
        parts.lexical_parent = procedure.lexical_parent();
        parts.properties = procedure.properties();
        macro_rules! copy_rows {
            ($($field:ident),* $(,)?) => { $(parts.$field = procedure.$field().to_vec();)* };
        }
        copy_rows!(
            values,
            allocations,
            memory_locations,
            captures,
            call_sites,
            source_mappings,
            statement_entries,
            loop_sites,
            evidence_rows,
            gaps,
            blocks,
            points,
            drops,
            move_outs,
            scope_ends,
            pointer_origins,
            pointer_aliases,
            pointer_accesses,
            pointer_invalidations,
            incomplete_facts,
            receiver_type_facts
        );
        parts.control_edges = procedure.cfg().edges().to_vec();
        parts
    }

    #[test]
    fn executable_body_identity_survives_warm_keys_and_output_coordinates() {
        use crate::analyzer::semantic::{ProcedureInterpretation, SemanticArtifact};
        use crate::taint::output_product::OutputCallRow;
        with_batch_calls(|_, calls, _| {
            let original = calls[0].procedure();
            let parts = fixture_procedure_parts(original.semantics());
            let census = crate::analyzer::semantic::ir::measure_procedure_work(&parts);
            let projected = Arc::new(
                SemanticArtifact::try_executable_projection(
                    original.artifact().clone(),
                    parts,
                    census,
                    &mut SemanticBudget::default(),
                    &CancellationToken::default(),
                )
                .expect("validated one-body projection"),
            );
            let base = projected.procedure_handle(original.id()).unwrap();
            let executable = projected
                .executable_alternate_handle(original.id())
                .unwrap();
            assert_ne!(
                projected.materialization_id(),
                original.artifact().materialization_id()
            );
            assert!(Arc::ptr_eq(base.artifact(), executable.artifact()));
            assert_eq!(base.id(), executable.id());
            assert!(
                projected
                    .procedure(base.id())
                    .unwrap()
                    .candidate_macro_alternate()
                    .is_none()
            );
            assert!(projected.candidate_alternate_handle(base.id()).is_none());
            assert!(
                executable
                    .validate_durable_locator(&base.durable_key())
                    .is_err()
            );
            assert!(
                base.validate_durable_locator(&executable.durable_key())
                    .is_err()
            );
            assert_ne!(
                crate::flow_state::procedure_public_digest(&base),
                crate::flow_state::procedure_public_digest(&executable)
            );
            assert_eq!(
                crate::flow_state::procedure_public_digest(&base),
                crate::analyzer::semantic::SemanticProcedureReference::public_digest_for(
                    base.artifact().key(),
                    base.semantics().locator()
                )
            );
            let context = OracleCallContext::empty();
            let limits = OracleLimits::default();
            let behavior = IcfgProviderBehaviorIdentity::hash_bytes(b"executable-key-boundary");
            assert!(
                SnapshotKey::for_query(&base, &context, limits, None)
                    != SnapshotKey::for_query(&executable, &context, limits, None)
            );
            let base_call = base.call_site_handle(calls[0].id()).unwrap();
            let executable_call = executable.call_site_handle(calls[0].id()).unwrap();
            assert!(
                DispatchKey::for_query(&base_call, behavior, limits)
                    != DispatchKey::for_query(&executable_call, behavior, limits)
            );
            let candidate = |target| {
                DispatchCandidate::new(
                    target,
                    ProofStatus::Proven,
                    EvidenceCompleteness::Complete,
                    [],
                    limits,
                )
                .unwrap()
            };
            let base_candidate = candidate(base.clone());
            let executable_candidate = candidate(executable.clone());
            let base_binding =
                BindingsKey::for_query(&base_call, &base_candidate, &context, limits, behavior);
            assert!(
                base_binding
                    != BindingsKey::for_query(
                        &executable_call,
                        &base_candidate,
                        &context,
                        limits,
                        behavior
                    )
            );
            assert!(
                base_binding
                    != BindingsKey::for_query(
                        &base_call,
                        &executable_candidate,
                        &context,
                        limits,
                        behavior
                    )
            );
            let mut rows = Vec::new();
            for interpretation in [
                ProcedureInterpretation::Base,
                ProcedureInterpretation::CandidateAlternate,
                ProcedureInterpretation::ExecutableAlternate,
            ] {
                let key = (
                    (base.artifact().key().clone(), base.id(), interpretation),
                    base_call.id(),
                );
                let row = OutputCallRow::encode(&key);
                let json = serde_json::to_value(&row).unwrap();
                let decoded: OutputCallRow = serde_json::from_value(json.clone()).unwrap();
                assert_eq!(decoded.decode().unwrap(), key);
                assert!(!rows.contains(&json));
                rows.push(json);
            }
            assert_eq!(rows.len(), 3);
        });
    }

    fn rematerialize_fixture_artifact(
        original: &crate::analyzer::semantic::SemanticArtifact,
    ) -> Arc<crate::analyzer::semantic::SemanticArtifact> {
        use crate::analyzer::semantic::SemanticArtifact;
        assert!(original.go_predeclared_builtin_assumptions().is_empty());
        let parts = original
            .procedures()
            .iter()
            .map(fixture_procedure_parts)
            .collect();
        let artifact = Arc::new(
            SemanticArtifact::try_new(
                original.key().clone(),
                original.capabilities().clone(),
                parts,
            )
            .expect("validated fixture rematerialization"),
        );
        assert_eq!(artifact.materialization_id(), original.materialization_id());
        artifact
    }

    #[test]
    #[hardwon(
        "#5113: verdict caches and prepared sessions retained artifacts beyond their byte caps"
    )]
    fn byte_caps_release_caller_artifacts_including_context_keys() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file("flow.ts", "function leaf(v: number) { return v; }\nexport function caller() { return leaf(1); }\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            retention_budget_bytes: Some(4 * (8)),
            ..AnalyzerConfig::default()
        });
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let lowered = workspace
            .materialize_program_semantics(
                &project.file("flow.ts"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture materialization")
            .available_value()
            .cloned()
            .expect("fixture artifact");
        // An independently allocated copy isolates these owners from the
        // analyzer's artifact cache and tests context-key retention too.
        let artifact = rematerialize_fixture_artifact(&lowered);
        let weak = Arc::downgrade(&artifact);
        let cache = ValueFlowCache::new(1);
        {
            let caller = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("caller")
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("caller");
            let call = caller
                .call_site_handle(caller.semantics().call_sites()[0].id)
                .expect("call");
            let context = OracleCallContext::bounded(vec![call.clone()], OracleLimits::default());
            let provider = WorkspaceValueFlowProvider::new(&workspace, cache.clone());
            let snapshot = provider
                .procedure_snapshot(
                    &caller,
                    &context,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("snapshot");
            assert!(snapshot.available_value().is_some());
            let dispatch = provider
                .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .expect("dispatch");
            let target = dispatch
                .available_value()
                .expect("dispatch result")
                .candidates()
                .first()
                .expect("leaf target");
            let bindings = provider
                .call_bindings(
                    &call,
                    target,
                    &context,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("bindings");
            assert!(bindings.available_value().is_some());
            // The fixed materialization pool is independent of the tiny
            // verdict cache. Its pins end when this provider leaves scope;
            // the verdict cache must still release its context-key owners.
            assert!(provider.prepared_pool_artifact_bytes() > 0);
        }
        drop(artifact);
        // Drain logical evictions and allow Moka's epoch grace period to end.
        for _ in 0..100 {
            if cache.artifact_bytes() == 0 && weak.strong_count() == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(cache.artifact_bytes(), 0);
        assert_eq!(
            weak.strong_count(),
            0,
            "weak-value registry keys must not pin caller artifacts"
        );
    }

    #[test]
    fn observer_clones_share_one_prepared_source_charge_for_distinct_calls() {
        with_batch_calls(|workspace, calls, cache| {
            let provider = WorkspaceValueFlowProvider::new(workspace, cache.clone());
            let left = provider.observing_dispatch_reads(DispatchReadCollector::default());
            let right = provider.observing_dispatch_reads(DispatchReadCollector::default());
            let cancellation = CancellationToken::default();
            let mut limits = SemanticBudget::default().limits();
            limits.source_bytes = BATCH_CALL_SOURCE.len();
            let mut budget = SemanticBudget::new(limits).expect("positive source budget");

            let first = left
                .resolve_call(
                    &calls[0],
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("first prepared dispatch");
            let second = right
                .resolve_call(
                    &calls[1],
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("second prepared dispatch");

            assert!(first.available_value().is_some(), "{first:?}");
            assert!(second.available_value().is_some(), "{second:?}");
            assert_eq!(first.work().source_bytes, BATCH_CALL_SOURCE.len());
            assert_eq!(second.work().source_bytes, 0);
            // Parking the first session refunds residency. The second call
            // re-admits that source, but reuses the scan: two admissions and
            // one scan remain in cumulative telemetry.
            assert_eq!(budget.used().source_bytes, 3 * BATCH_CALL_SOURCE.len());
            assert_eq!(budget.resident().source_bytes, 0);
            assert_eq!(cache.dispatch_misses(), 2);
            assert_eq!(cache.dispatch_hits(), 0);
        });
    }

    #[test]
    #[hardwon("#5113: equal-content re-lowerings accumulated prepared source sessions")]
    fn prepared_pool_rebinds_equal_content_without_repaying_source() {
        with_batch_calls(|workspace, calls, cache| {
            let provider = WorkspaceValueFlowProvider::new(workspace, cache);
            let cancellation = CancellationToken::default();
            let mut limits = SemanticBudget::default().limits();
            limits.source_bytes = BATCH_CALL_SOURCE.len();
            let mut budget = SemanticBudget::new(limits).expect("positive source grant");
            let first = provider
                .resolve_call(
                    &calls[0],
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("first call");
            assert!(first.available_value().is_some());
            let artifact = rematerialize_fixture_artifact(calls[1].procedure().artifact());
            let call = artifact
                .procedure_handle(calls[1].procedure().id())
                .and_then(|procedure| procedure.call_site_handle(calls[1].id()))
                .expect("rematerialized call");
            let second = provider
                .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .expect("second allocation call");
            let result = second
                .available_value()
                .expect("equal-content syntax remains reusable");
            result
                .validate_for_call(&call)
                .expect("provenance belongs to the new caller allocation");
            assert_eq!(second.work().source_bytes, 0);
            assert_eq!(
                provider.prepared_pool_artifact_bytes(),
                crate::analyzer::semantic::semantic_artifact_retained_bytes(
                    calls[0].procedure().artifact()
                )
            );
        });
    }

    #[test]
    #[hardwon("#5113: concurrent prepared calls must share one paid source allocation")]
    fn concurrent_dispatch_calls_share_paid_prepared_source() {
        with_batch_calls(|workspace, calls, cache| {
            let provider = WorkspaceValueFlowProvider::new(workspace, cache);
            let barrier = std::sync::Barrier::new(2);
            let cancellation = CancellationToken::default();
            let resolve = |call: &CallSiteHandle| {
                barrier.wait();
                let mut budget = SemanticBudget::default();
                provider
                    .resolve_call(call, &mut SemanticRequest::new(&mut budget, &cancellation))
                    .expect("concurrent dispatch")
            };
            let outcomes = std::thread::scope(|scope| {
                let left = scope.spawn(|| resolve(&calls[0]));
                let right = scope.spawn(|| resolve(&calls[1]));
                [
                    left.join().expect("first dispatch thread"),
                    right.join().expect("second dispatch thread"),
                ]
            });
            assert!(
                outcomes
                    .iter()
                    .all(|outcome| outcome.available_value().is_some())
            );
            assert_eq!(
                outcomes
                    .iter()
                    .map(|outcome| outcome.work().source_bytes)
                    .sum::<usize>(),
                BATCH_CALL_SOURCE.len()
            );
        });
    }

    #[test]
    #[hardwon("#5113: dispatch result refusal rolled back scan telemetry")]
    fn failed_prepared_dispatch_releases_source_but_keeps_scan_work() {
        with_batch_calls(|workspace, calls, cache| {
            let provider = WorkspaceValueFlowProvider::new(workspace, cache.clone());
            let cancellation = CancellationToken::default();
            let mut starved_budget = SemanticBudget::default();
            let nested_limit = starved_budget.limits().nested_entries;
            // Leave one retained entry; the dispatch payload cannot fit,
            // even though the resolver's traversal work always proceeds.
            starved_budget
                .admit(SemanticWork {
                    nested_entries: nested_limit - 1,
                    ..SemanticWork::default()
                })
                .expect("leave one nested entry of headroom");

            let starved = provider
                .resolve_call(
                    &calls[0],
                    &mut SemanticRequest::new(&mut starved_budget, &cancellation),
                )
                .expect("starved dispatch remains typed");
            let SemanticOutcome::ExceededBudget { exceeded, work, .. } = starved else {
                panic!("the resolver must exceed the nested-entry budget: {starved:?}");
            };
            assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
            assert_eq!(work.source_bytes, BATCH_CALL_SOURCE.len());
            assert_eq!(
                starved_budget.used().source_bytes,
                2 * BATCH_CALL_SOURCE.len()
            );
            assert_eq!(
                provider.prepared_pool_artifact_bytes(),
                0,
                "an unpaid empty session must not pin its artifact"
            );

            let mut retry_budget = SemanticBudget::default();
            let retry = provider
                .resolve_call(
                    &calls[0],
                    &mut SemanticRequest::new(&mut retry_budget, &cancellation),
                )
                .expect("funded retry reparses the unpaid source");
            assert!(retry.available_value().is_some(), "{retry:?}");
            assert_eq!(retry.work().source_bytes, BATCH_CALL_SOURCE.len());
            assert_eq!(
                retry_budget.used().source_bytes,
                2 * BATCH_CALL_SOURCE.len()
            );
            assert_eq!(cache.dispatch_misses(), 2);
            assert_eq!(cache.dispatch_hits(), 0);
        });
    }

    #[test]
    fn semantic_artifact_hits_record_the_consumed_content_identity() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file("input.ts", "export function value() { return 1; }\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut read = || {
            workspace
                .materialize_program_semantics(
                    &project.file("input.ts"),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("materialization")
                .available_value()
                .cloned()
                .expect("artifact")
        };
        let (first, first_reads) = capture_query_reads(workspace.analyzer(), &mut read);
        let (later, later_reads) = capture_query_reads(workspace.analyzer(), &mut read);
        let key = ReadKey::semantic_artifact(first.key());
        assert!(first_reads.keys().contains(&key));
        assert!(later_reads.keys().contains(&key));
        assert!(
            Arc::ptr_eq(&first, &later),
            "the later capture must hit the retained artifact"
        );
    }

    #[test]
    fn captured_verdict_hits_replay_into_later_captures() {
        with_batch_calls(|workspace, _, _| {
            // Snapshot and binding verdicts share this capture and replay
            // protocol. Inject a transitive input at fill time so a fixture
            // needing no workspace lookup cannot make this test vacuous.
            let cache = CompleteValueCache::new(
                1_000_000,
                |_: &u8, entry: &Arc<ReplayingMemoEntry<usize, ReadKey>>| {
                    retained_memo_read_bytes(entry) as u32
                },
            );
            let key = ReadKey::Models(StableDigest::sha256(b"verdict input"));
            let cancellation = CancellationToken::default();
            let (_, reads) = capture_query_reads(workspace.analyzer(), || {
                let (acquisition, _) = cache.acquire(&0, &cancellation);
                let CompleteValueAcquisition::Leader { permit } = acquisition else {
                    panic!("the first capture must fill the cache");
                };
                let captured =
                    ReplayingMemoEntry::capture(&memo_attribution(workspace.analyzer()), || {
                        workspace.analyzer().record_read(key.clone());
                        workspace.analyzer().record_unattributed_read();
                        17
                    });
                permit.publish_complete(Arc::new(captured));
            });
            assert_eq!(reads.keys(), vec![key.clone()]);
            assert_eq!(reads.unattributed_reads(), 1);
            let (_, reads) = capture_query_reads(workspace.analyzer(), || {
                let (acquisition, _) = cache.acquire(&0, &cancellation);
                let CompleteValueAcquisition::Cached { value } = acquisition else {
                    panic!("the later capture must hit the retained verdict");
                };
                value.replay(&memo_attribution(workspace.analyzer()));
                assert_eq!(*value.value(), 17);
            });
            assert_eq!(reads.keys(), vec![key]);
            assert_eq!(reads.unattributed_reads(), 1);
        });
    }

    #[test]
    #[hardwon("#12820: a refused dispatch fill was rebuilt in a fresh arena within one request")]
    fn a_refused_dispatch_fill_is_reused_within_its_request_and_never_shared() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "flow.ts",
                concat!(
                    "function leaf(value: number): number { return value; }\n",
                    "export function caller(): number { return leaf(1); }\n",
                ),
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.ts"),
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("fixture semantic materialization")
            .available_value()
            .cloned()
            .expect("fixture artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture caller");
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("fixture call");
        let cache = ValueFlowCache::default();
        let provider = WorkspaceValueFlowProvider::new(&workspace, cache.clone());
        let resolve = || {
            capture_query_reads(workspace.analyzer(), || {
                provider
                    .resolve_call(
                        &call,
                        &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
                    )
                    .expect("dispatch")
            })
        };
        REFUSE_PROVIDER_FILLS.with(|flag| flag.set(true));
        let (first, first_reads) = resolve();
        let (second, second_reads) = resolve();
        REFUSE_PROVIDER_FILLS.with(|flag| flag.set(false));
        assert!(first.available_value().is_some(), "{first:?}");
        assert!(first_reads.reuse_refused());
        assert!(
            second_reads.reuse_refused(),
            "a hit on a refused fill replays the refusal into its reader"
        );
        assert_eq!(
            first.available_value(),
            second.available_value(),
            "the refused fill is kept for the request, so the candidates are identical"
        );
        assert_eq!(cache.dispatch_hits(), 0, "a refused fill is never shared");
        assert!(!provider.take_retained_writes());
        let fresh = WorkspaceValueFlowProvider::new(&workspace, cache.clone());
        let (_, fresh_reads) = capture_query_reads(workspace.analyzer(), || {
            fresh
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
                )
                .expect("dispatch")
        });
        assert!(
            !fresh_reads.reuse_refused(),
            "another request does not see the refused fill"
        );
    }

    #[test]
    fn cold_and_cached_dispatch_observe_the_same_read() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file(
                "flow.ts",
                concat!(
                    "function leaf(value: number): number { return value; }\n",
                    "export function caller(): number { return leaf(1); }\n",
                ),
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.ts"),
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("fixture semantic materialization")
            .available_value()
            .cloned()
            .expect("fixture artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture caller");
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("fixture call");
        let cache = ValueFlowCache::default();
        let provider = WorkspaceValueFlowProvider::new(&workspace, cache.clone());
        assert!(!provider.take_retained_writes());

        let cold_reads = DispatchReadCollector::default();
        let cold_provider = provider.observing_dispatch_reads(cold_reads.clone());
        let mut cold_budget = SemanticBudget::default();
        let (cold, cold_ledger) = capture_query_reads(workspace.analyzer(), || {
            cold_provider
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut cold_budget, &cancellation),
                )
                .expect("cold dispatch")
        });
        assert!(cold.available_value().is_some());
        assert!(provider.take_retained_writes());

        let cached_reads = DispatchReadCollector::default();
        let cached_provider = provider.observing_dispatch_reads(cached_reads.clone());
        let mut cached_budget = SemanticBudget::default();
        let (cached, cached_ledger) = capture_query_reads(workspace.analyzer(), || {
            cached_provider
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut cached_budget, &cancellation),
                )
                .expect("cached dispatch")
        });
        let DispatchReadAttribution::Attributed(key) = dispatch_read_attribution(&call, &cached)
        else {
            panic!("the fixture dispatch must have a named read");
        };
        assert!(cold_ledger.keys().contains(&key));
        assert!(cached_ledger.keys().contains(&key));

        let hit_only_provider = WorkspaceValueFlowProvider::new(&workspace, cache.clone());
        assert!(!hit_only_provider.take_retained_writes());
        let mut hit_only_budget = SemanticBudget::default();
        let hit_only = hit_only_provider
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut hit_only_budget, &cancellation),
            )
            .expect("dispatch cached before this provider was created");

        assert_eq!(cold.available_value(), cached.available_value());
        assert_eq!(cold.available_value(), hit_only.available_value());
        assert!(
            !hit_only_provider.take_retained_writes(),
            "cache hits are not retained writes by the current provider"
        );
        assert_eq!(cache.dispatch_misses(), 1);
        assert_eq!(cache.dispatch_hits(), 2);
        assert_eq!(cold_reads.observations(), cached_reads.observations());
        assert_eq!(cold_reads.observations().len(), 1);
    }
}
