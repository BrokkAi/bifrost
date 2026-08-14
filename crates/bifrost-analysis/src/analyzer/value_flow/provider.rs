//! Demand materialization of value-flow snapshots and call bindings.
//!
//! [`ValueFlowProvider`] mirrors [`IcfgProvider`](crate::analyzer::semantic::IcfgProvider):
//! it materializes one procedure's value-flow snapshot on demand and one call's
//! bindings on demand, and it returns the same [`SemanticOutcome`] the oracle
//! returns. [`WorkspaceValueFlowProvider`] delegates to
//! [`WorkspaceSemanticOracle`] and caches each *complete* result in a bounded,
//! content-keyed [`CompleteValueCache`]. A second query over an unchanged
//! procedure reuses the snapshot without recharging the semantic budget, and a
//! source edit yields a different content key so the stale entry falls out of
//! the bounded cache.
//!
//! This is foundation only. Nothing here is wired into `discover_value_flow`,
//! the taint solve, or the compile yet; a later Stage C step routes the solve
//! through this provider.
//!
//! ## Cache keys are content addressed
//!
//! A snapshot key is `(SemanticArtifactKey.fingerprint(), ProcedureId)`. The
//! fingerprint is a SHA-256 over every validity input of the artifact,
//! including the exact source content, so a source edit produces a different
//! key. A bindings key adds the call-site identity and the dispatch target
//! identity, because bindings are specific to one `(call, candidate)` pair.
//!
//! The oracle's `procedure_relations` computes the retained relations from the
//! procedure's own semantics; the [`OracleCallContext`] only labels the
//! snapshot's provenance owner and does not change the relation content. The
//! demand-taint path always queries with the empty context, so keying on
//! procedure identity alone is exact for that path.

use std::fmt;
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::complete_value_cache::{CompleteValueAcquisition, CompleteValueCache};
use crate::analyzer::semantic::{
    CallBinding, CallBindings, CallSiteHandle, CallSiteId, DispatchCandidate, OracleCallContext,
    ProcedureHandle, ProcedureId, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticWork, StableDigest, ValueFlowOracle, ValueFlowRelation, ValueFlowSnapshot,
    WorkspaceSemanticOracle,
};

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

/// Content-addressed identity of one procedure-local value-flow snapshot.
#[derive(Clone, PartialEq, Eq, Hash)]
struct SnapshotKey {
    artifact: StableDigest,
    procedure: ProcedureId,
}

impl SnapshotKey {
    fn for_procedure(procedure: &ProcedureHandle) -> Self {
        Self {
            artifact: procedure.artifact().key().fingerprint(),
            procedure: procedure.id(),
        }
    }
}

/// Content-addressed identity of one `(call, candidate)` binding set. The
/// caller and the dispatch target are each pinned by their artifact content
/// fingerprint and procedure identity, and the call site is pinned by its
/// caller-local identity.
#[derive(Clone, PartialEq, Eq, Hash)]
struct BindingsKey {
    caller_artifact: StableDigest,
    caller_procedure: ProcedureId,
    call_site: CallSiteId,
    target_artifact: StableDigest,
    target_procedure: ProcedureId,
}

impl BindingsKey {
    fn for_call(call: &CallSiteHandle, candidate: &DispatchCandidate) -> Self {
        let caller = call.procedure();
        let target = candidate.target();
        Self {
            caller_artifact: caller.artifact().key().fingerprint(),
            caller_procedure: caller.id(),
            call_site: call.id(),
            target_artifact: target.artifact().key().fingerprint(),
            target_procedure: target.id(),
        }
    }
}

/// Conservative structural byte weight of one retained snapshot. The shared
/// provenance arena is `Arc`-shared across relations, so this counts the owned
/// relation rows without double counting the arena.
fn weigh_snapshot(_key: &SnapshotKey, snapshot: &Arc<ValueFlowSnapshot>) -> u32 {
    let relations = snapshot
        .relations()
        .len()
        .saturating_mul(size_of::<ValueFlowRelation>());
    size_of::<ValueFlowSnapshot>()
        .saturating_add(relations)
        .min(u32::MAX as usize) as u32
}

/// Conservative structural byte weight of one retained binding set.
fn weigh_bindings(_key: &BindingsKey, bindings: &Arc<CallBindings>) -> u32 {
    let rows = bindings
        .bindings()
        .len()
        .saturating_mul(size_of::<CallBinding>());
    size_of::<CallBindings>()
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

/// Generation-independent, bounded, content-keyed cache of complete value-flow
/// snapshots and call bindings. Cloning shares the underlying entries and
/// counters, so the same cache can back one provider per analyzer generation
/// and reuse unchanged procedures across generations and queries.
#[derive(Clone)]
pub struct ValueFlowCache {
    snapshots: CompleteValueCache<SnapshotKey, ValueFlowSnapshot>,
    bindings: CompleteValueCache<BindingsKey, CallBindings>,
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
        let key = SnapshotKey::for_procedure(procedure);
        let (acquisition, _wait) = self.cache.snapshots.acquire(&key, request.cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                self.cache
                    .stats
                    .snapshot_hits
                    .fetch_add(1, Ordering::Relaxed);
                // A ready entry charged its semantic work on the flight that
                // built it. Reusing it owns no new semantic work.
                Ok(SemanticOutcome::Complete {
                    value: (*value).clone(),
                    work: SemanticWork::default(),
                })
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.cache
                    .stats
                    .snapshot_misses
                    .fetch_add(1, Ordering::Relaxed);
                let outcome = self
                    .oracle
                    .procedure_relations(procedure, context, request)?;
                // Only a complete snapshot is retained. Dropping the permit on
                // any other outcome wakes followers to retry, so incomplete
                // results never enter the ready cache.
                if let SemanticOutcome::Complete { value, .. } = &outcome {
                    permit.publish_complete(Arc::new(value.clone()));
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
        let key = BindingsKey::for_call(call, candidate);
        let (acquisition, _wait) = self.cache.bindings.acquire(&key, request.cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                self.cache
                    .stats
                    .binding_hits
                    .fetch_add(1, Ordering::Relaxed);
                Ok(SemanticOutcome::Complete {
                    value: (*value).clone(),
                    work: SemanticWork::default(),
                })
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.cache
                    .stats
                    .binding_misses
                    .fetch_add(1, Ordering::Relaxed);
                let outcome = self
                    .oracle
                    .call_bindings(call, candidate, context, request)?;
                if let SemanticOutcome::Complete { value, .. } = &outcome {
                    permit.publish_complete(Arc::new(value.clone()));
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
