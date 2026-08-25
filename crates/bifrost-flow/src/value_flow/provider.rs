//! Demand materialization of value-flow snapshots and call bindings.
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
//! This is foundation only. Nothing here is wired into `discover_value_flow`,
//! the taint solve, or the compile yet; a later Stage C step routes the solve
//! through this provider.
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
//! `memoizable_outcome` retains neither. Budget-caused incompleteness is
//! therefore excluded from the memo by construction rather than by a key
//! dimension, so a later touch with more budget still runs the oracle and can
//! still reach a better answer.
//!
//! ### The binding key (#2289)
//!
//! A bindings key is
//! `(caller artifact fingerprint, caller ProcedureId, CallSiteId, target
//! artifact fingerprint, target ProcedureId, candidate proof, candidate
//! completeness, OracleCallContext, OracleLimits)`.
//!
//! Read `WorkspaceSemanticOracle::call_bindings`
//! (`analyzer/semantic/workspace_oracle/value_flow.rs`) top to bottom and it
//! reads exactly six things. The caller's `ProcedureSemantics` -- its gaps, its
//! call row at `call.id()`, and its values -- which the first three dimensions
//! pin. The callee's `ProcedureSemantics` -- its gaps, formals, receiver, and
//! exit ports -- which the next two pin. The `OracleCallContext`, which becomes
//! the retained bindings' context and which the argument-location contract
//! checks against. `self.limits()`, which decides through `BindingBuild::
//! can_retain` whether the answer is `Truncated`, and `Truncated` is published
//! as `Unproven`, so limits are a genuine verdict input. And the request's
//! budget and cancellation, excluded by construction as above.
//!
//! The sixth thing is the `DispatchCandidate`, and it is worth being exact
//! about. The candidate's `proof()` and `completeness()` do **not** feed the
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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::semantic::{
    CallBinding, CallBindings, CallSiteHandle, CallSiteId, DispatchCandidate, EvidenceCompleteness,
    OracleCallContext, OracleLimits, ProcedureHandle, ProcedureId, ProofStatus, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork, StableDigest, ValueFlowOracle,
    ValueFlowRelation, ValueFlowSnapshot, WorkspaceSemanticOracle,
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
pub trait ValueFlowProvider {
    /// Materialize the procedure-local value-flow snapshot on demand.
    fn procedure_snapshot(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError>;

    /// Materialize one dispatch candidate's call bindings on demand.
    fn call_bindings(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError>;
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

/// Which published outcomes are safe to retain, and in what form.
///
/// `Complete`, `Ambiguous`, `Unknown`, `Unsupported`, and `Unproven` are
/// finished verdicts: the oracle ran to the end of the procedure or the call
/// and reported what it found, so a later touch with the same key reproduces
/// exactly this answer.
///
/// `ExceededBudget` and `Cancelled` are not verdicts about the procedure or the
/// call at all. They report that *this* request ran out of budget or was
/// interrupted, which is a property of the request rather than of the artifact.
/// Retaining one would freeze a transient shortfall into an authoritative
/// answer and deny a later, better-funded touch the chance to succeed -- with
/// the per-region budget reset in `TaintPolicyCompiler::compile_inner`, a later
/// region really can afford work an earlier region could not. Returning `None`
/// for them keeps them out of the cache and out of every follower's answer.
///
/// A value-less `Unknown` or `Unsupported` carries nothing worth replaying, so
/// it is not retained either.
///
/// One function serves both sub-caches because the rule is a property of
/// [`SemanticOutcome`] rather than of the value inside it.
fn memoizable_outcome<T: Clone>(outcome: &SemanticOutcome<T>) -> Option<SemanticOutcome<T>> {
    let work = SemanticWork::default();
    match outcome {
        SemanticOutcome::Complete { value, .. } => Some(SemanticOutcome::Complete {
            value: value.clone(),
            work,
        }),
        SemanticOutcome::Ambiguous { candidates, .. } => Some(SemanticOutcome::Ambiguous {
            candidates: candidates.clone(),
            work,
        }),
        SemanticOutcome::Unproven { partial, .. } => Some(SemanticOutcome::Unproven {
            partial: partial.clone(),
            work,
        }),
        SemanticOutcome::Unknown {
            partial: Some(partial),
            ..
        } => Some(SemanticOutcome::Unknown {
            partial: Some(partial.clone()),
            work,
        }),
        SemanticOutcome::Unsupported {
            capability,
            partial: Some(partial),
            ..
        } => Some(SemanticOutcome::Unsupported {
            capability: *capability,
            partial: Some(partial.clone()),
            work,
        }),
        SemanticOutcome::Unknown { partial: None, .. }
        | SemanticOutcome::Unsupported { partial: None, .. }
        | SemanticOutcome::ExceededBudget { .. }
        | SemanticOutcome::Cancelled { .. } => None,
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
    caller_artifact: StableDigest,
    caller_procedure: ProcedureId,
    call_site: CallSiteId,
    target_artifact: StableDigest,
    target_procedure: ProcedureId,
    candidate_proof: ProofStatus,
    candidate_completeness: EvidenceCompleteness,
    context: OracleCallContext,
    limits: OracleLimits,
}

impl BindingsKey {
    fn for_query(
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        limits: OracleLimits,
    ) -> Self {
        let caller = call.procedure();
        let target = candidate.target();
        Self {
            caller_artifact: caller.artifact().key().fingerprint(),
            caller_procedure: caller.id(),
            call_site: call.id(),
            target_artifact: target.artifact().key().fingerprint(),
            target_procedure: target.id(),
            candidate_proof: candidate.proof().clone(),
            candidate_completeness: candidate.completeness().clone(),
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
    size_of::<MemoizedBindings>()
        .saturating_add(rows)
        .min(u32::MAX as usize) as u32
}

#[derive(Debug, Default)]
struct ValueFlowCacheStats {
    snapshot_hits: AtomicU64,
    snapshot_misses: AtomicU64,
    binding_hits: AtomicU64,
    binding_misses: AtomicU64,
}

/// Generation-independent, bounded, content-keyed cache of value-flow snapshot
/// verdicts and complete call bindings. Cloning shares the underlying entries
/// and counters, so the same cache can back one provider per analyzer
/// generation and reuse unchanged procedures across generations and queries.
#[derive(Clone)]
pub struct ValueFlowCache {
    snapshots: CompleteValueCache<SnapshotKey, MemoizedSnapshot>,
    bindings: CompleteValueCache<BindingsKey, MemoizedBindings>,
    stats: Arc<ValueFlowCacheStats>,
}

impl Default for ValueFlowCache {
    fn default() -> Self {
        Self::new(DEFAULT_VALUE_FLOW_CACHE_BYTES)
    }
}

impl ValueFlowCache {
    /// Build a cache that bounds each of the snapshot and binding sub-caches to
    /// `max_retained_bytes`.
    pub fn new(max_retained_bytes: u64) -> Self {
        Self {
            snapshots: CompleteValueCache::new(max_retained_bytes, weigh_snapshot),
            bindings: CompleteValueCache::new(max_retained_bytes, weigh_bindings),
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

    /// Count of binding lookups served from a ready cache entry.
    pub fn binding_hits(&self) -> u64 {
        self.stats.binding_hits.load(Ordering::Relaxed)
    }

    /// Count of binding lookups that had to materialize through the oracle.
    pub fn binding_misses(&self) -> u64 {
        self.stats.binding_misses.load(Ordering::Relaxed)
    }
}

impl fmt::Debug for ValueFlowCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValueFlowCache")
            .field("snapshot_hits", &self.snapshot_hits())
            .field("snapshot_misses", &self.snapshot_misses())
            .field("binding_hits", &self.binding_hits())
            .field("binding_misses", &self.binding_misses())
            .finish_non_exhaustive()
    }
}

/// A [`ValueFlowProvider`] bound to one immutable analyzer generation and one
/// shared [`ValueFlowCache`].
pub struct WorkspaceValueFlowProvider<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    cache: ValueFlowCache,
}

impl<'a> WorkspaceValueFlowProvider<'a> {
    /// Bind the provider to one analyzer generation and one shared cache.
    pub fn new(workspace: &'a WorkspaceAnalyzer, cache: ValueFlowCache) -> Self {
        Self {
            oracle: workspace.semantic_oracle_provider(),
            cache,
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
                if let Some(memoized) = memoizable_outcome(&outcome) {
                    permit.publish_complete(Arc::new(memoized));
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

    fn call_bindings(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError> {
        let key = BindingsKey::for_query(call, candidate, context, *self.oracle.limits());
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
                if let Some(memoized) = memoizable_outcome(&outcome) {
                    permit.publish_complete(Arc::new(memoized));
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
