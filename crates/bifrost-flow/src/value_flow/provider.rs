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
//! `(SemanticArtifactKey.fingerprint(), ProcedureId, OracleLimits, OracleCallContext)`.
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

use std::fmt;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CallBinding, CallBindings, CallSiteHandle, CallSiteId, DispatchBoundary, DispatchCandidate,
    DispatchReadAttribution, DispatchResult, EvidenceCompleteness, IcfgProvider,
    IcfgProviderBehaviorIdentity, OracleCallContext, OracleLimits, PreparedWorkspaceDispatchPool,
    ProcedureHandle, ProcedureId, ProofStatus, SemanticOutcome, SemanticProviderError,
    SemanticRequest, SemanticWork, StableDigest, ValueFlowOracle, ValueFlowRelation,
    ValueFlowSnapshot, WorkspaceIcfgProvider, WorkspaceSemanticOracle, dispatch_read_attribution,
};
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
    artifact: StableDigest,
    procedure: ProcedureId,
    limits: OracleLimits,
    context: OracleCallContext,
}

impl SnapshotKey {
    fn for_query(
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        limits: OracleLimits,
    ) -> Self {
        Self {
            artifact: procedure.artifact().key().fingerprint(),
            procedure: procedure.id(),
            limits,
            context: context.clone(),
        }
    }
}

/// The snapshot verdict this cache retains, with its semantic work zeroed
/// because the flight that built it already charged that work.
///
/// Retaining the whole [`SemanticOutcome`] rather than a bare snapshot is what
/// lets a non-complete answer be replayed without losing the typed
/// incompleteness that makes it honest (#2284).
type MemoizedSnapshot = SemanticOutcome<ValueFlowSnapshot>;

/// The binding verdict this cache retains, on the same terms as
/// [`MemoizedSnapshot`] (#2289).
type MemoizedBindings = SemanticOutcome<CallBindings>;

/// The dispatch verdict this cache retains, on the same terms as
/// [`MemoizedSnapshot`].
type MemoizedDispatch = SemanticOutcome<DispatchResult>;

/// Content-addressed identity of one call-dispatch verdict.
///
/// The provider behavior folds the workspace content, hierarchy mode, active
/// semantic-model set, external dispatch surface, and receiver-class hints.
/// The remaining fields select the exact call and retain `OracleLimits` as an
/// explicit verdict input.
#[derive(Clone, PartialEq, Eq, Hash)]
struct DispatchKey {
    caller_artifact: StableDigest,
    caller_procedure: ProcedureId,
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
            caller_artifact: call.procedure().artifact().key().fingerprint(),
            caller_procedure: call.procedure().id(),
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
/// caller-local identity. The candidate's own `proof` and `completeness` are
/// pinned too, then the call context and the oracle limits. See
/// `call_bindings` below for why each of those is here.
#[derive(Clone, PartialEq, Eq, Hash)]
struct BindingsKey {
    conversion_environment: Option<IcfgProviderBehaviorIdentity>,
    caller_artifact: StableDigest,
    caller_procedure: ProcedureId,
    call_site: CallSiteId,
    target_artifact: StableDigest,
    target_procedure: ProcedureId,
    candidate_proof: ProofStatus,
    candidate_completeness: EvidenceCompleteness,
    excluded_targets: Box<[ProcedureId]>,
    context: OracleCallContext,
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
            conversion_environment: (caller.artifact().key().language()
                == crate::analyzer::semantic::SemanticLanguage::Standard(
                    crate::analyzer::Language::Java,
                ))
            .then_some(provider_behavior),
            caller_artifact: caller.artifact().key().fingerprint(),
            caller_procedure: caller.id(),
            call_site: call.id(),
            target_artifact: target.artifact().key().fingerprint(),
            target_procedure: target.id(),
            candidate_proof: candidate.proof().clone(),
            candidate_completeness: candidate.completeness().clone(),
            excluded_targets: candidate
                .excluded_targets()
                .iter()
                .map(ProcedureHandle::id)
                .collect(),
            context: context.clone(),
            limits,
        }
    }
}

/// Conservative structural byte weight of one retained snapshot verdict. The
/// shared provenance arena is `Arc`-shared across relations, so this counts the
/// owned relation rows without double counting the arena.
fn weigh_snapshot(_key: &SnapshotKey, outcome: &Arc<MemoizedSnapshot>) -> u32 {
    let relations = outcome
        .available_value()
        .map_or(0, |snapshot| snapshot.relations().len())
        .saturating_mul(size_of::<ValueFlowRelation>());
    size_of::<MemoizedSnapshot>()
        .saturating_add(relations)
        .min(u32::MAX as usize) as u32
}

/// Conservative structural byte weight of one retained binding verdict.
fn weigh_bindings(_key: &BindingsKey, outcome: &Arc<MemoizedBindings>) -> u32 {
    let rows = outcome
        .available_value()
        .map_or(0, |bindings| bindings.bindings().len())
        .saturating_mul(size_of::<CallBinding>());
    let excluded_targets = outcome
        .available_value()
        .map_or(0, |bindings| bindings.candidate().excluded_targets().len())
        .saturating_mul(size_of::<ProcedureHandle>());
    size_of::<MemoizedBindings>()
        .saturating_add(rows)
        .saturating_add(excluded_targets)
        .min(u32::MAX as usize) as u32
}

/// Conservative structural byte weight of one retained dispatch verdict.
fn weigh_dispatch(_key: &DispatchKey, outcome: &Arc<MemoizedDispatch>) -> u32 {
    let rows = outcome.available_value().map_or(0, |dispatch| {
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
    });
    size_of::<MemoizedDispatch>()
        .saturating_add(rows)
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

/// A [`ValueFlowProvider`] bound to one immutable analyzer generation and one
/// shared [`ValueFlowCache`].
pub struct WorkspaceValueFlowProvider<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    provider_behavior: IcfgProviderBehaviorIdentity,
    cache: ValueFlowCache,
    dispatch_sessions: Arc<PreparedWorkspaceDispatchPool<'a>>,
    dispatch_reads: Option<DispatchReadCollector>,
    retained_writes: Arc<AtomicBool>,
}

impl<'a> WorkspaceValueFlowProvider<'a> {
    /// Bind the provider to one analyzer generation and one shared cache.
    pub fn new(workspace: &'a WorkspaceAnalyzer, cache: ValueFlowCache) -> Self {
        let provider = WorkspaceIcfgProvider::new(workspace);
        let oracle = provider.oracle().clone();
        let dispatch_sessions = Arc::new(oracle.prepare_workspace_dispatch_pool());
        Self {
            oracle,
            provider_behavior: provider.behavior_identity(),
            cache,
            dispatch_sessions,
            dispatch_reads: None,
            retained_writes: Arc::new(AtomicBool::new(false)),
        }
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
        }
    }

    /// The shared cache behind this provider.
    pub fn cache(&self) -> &ValueFlowCache {
        &self.cache
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
        if let Some(collector) = &self.dispatch_reads {
            collector.record(call, dispatch_read_attribution(call, outcome));
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

impl ValueFlowProvider for WorkspaceValueFlowProvider<'_> {
    type Error = SemanticProviderError;

    fn procedure_snapshot(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError> {
        let key = SnapshotKey::for_query(procedure, context, *self.oracle.limits());
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
                Ok((*value).clone())
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.cache
                    .stats
                    .snapshot_misses
                    .fetch_add(1, Ordering::Relaxed);
                let outcome = self
                    .oracle
                    .procedure_relations(procedure, context, request)?;
                // A finished verdict is retained whether or not it is complete
                // (#2284). Dropping the permit on a budget-exhausted or
                // cancelled outcome wakes followers to retry, so a shortfall of
                // this request never enters the ready cache.
                if let Some(memoized) = outcome.completed_replay() {
                    permit.publish_complete(Arc::new(memoized));
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
        let (acquisition, _wait) = self.cache.dispatch.acquire(&key, request.cancellation);
        let outcome = match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                self.cache
                    .stats
                    .dispatch_hits
                    .fetch_add(1, Ordering::Relaxed);
                (*value).clone()
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.cache
                    .stats
                    .dispatch_misses
                    .fetch_add(1, Ordering::Relaxed);
                let outcome = self.dispatch_sessions.resolve_call(call, request)?;
                if let Some(memoized) = outcome.completed_replay() {
                    permit.publish_complete(Arc::new(memoized));
                    self.retained_writes.store(true, Ordering::Release);
                }
                outcome
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

    fn call_bindings(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError> {
        let key = BindingsKey::for_query(
            call,
            candidate,
            context,
            *self.oracle.limits(),
            self.provider_behavior,
        );
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
                Ok((*value).clone())
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.cache
                    .stats
                    .binding_misses
                    .fetch_add(1, Ordering::Relaxed);
                let outcome = self
                    .oracle
                    .call_bindings(call, candidate, context, request)?;
                // A finished binding verdict is retained whether or not it is
                // complete, on the same terms as a snapshot (#2289).
                if let Some(memoized) = outcome.completed_replay() {
                    permit.publish_complete(Arc::new(memoized));
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
            assert_eq!(budget.used().source_bytes, BATCH_CALL_SOURCE.len());
            assert_eq!(cache.dispatch_misses(), 2);
            assert_eq!(cache.dispatch_hits(), 0);
        });
    }

    #[test]
    fn unpaid_prepared_source_is_dropped_before_a_dispatch_retry() {
        with_batch_calls(|workspace, calls, cache| {
            let provider = WorkspaceValueFlowProvider::new(workspace, cache.clone());
            let cancellation = CancellationToken::default();
            let mut starved_budget = SemanticBudget::default();
            let nested_limit = starved_budget.limits().nested_entries;
            starved_budget
                .charge(SemanticWork {
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
            assert_eq!(starved_budget.used().source_bytes, 0);

            let mut retry_budget = SemanticBudget::default();
            let retry = provider
                .resolve_call(
                    &calls[0],
                    &mut SemanticRequest::new(&mut retry_budget, &cancellation),
                )
                .expect("funded retry reparses the unpaid source");
            assert!(retry.available_value().is_some(), "{retry:?}");
            assert_eq!(retry.work().source_bytes, BATCH_CALL_SOURCE.len());
            assert_eq!(retry_budget.used().source_bytes, BATCH_CALL_SOURCE.len());
            assert_eq!(cache.dispatch_misses(), 2);
            assert_eq!(cache.dispatch_hits(), 0);
        });
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
        let cold = cold_provider
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut cold_budget, &cancellation),
            )
            .expect("cold dispatch");
        assert!(cold.available_value().is_some());
        assert!(provider.take_retained_writes());

        let cached_reads = DispatchReadCollector::default();
        let cached_provider = provider.observing_dispatch_reads(cached_reads.clone());
        let mut cached_budget = SemanticBudget::default();
        let cached = cached_provider
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut cached_budget, &cancellation),
            )
            .expect("cached dispatch");

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
