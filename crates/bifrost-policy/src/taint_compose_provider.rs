//! The production [`CompositionProvider`] of a taint policy compile (spec
//! Every answer comes from the workspace or from the plan:
//!
//! - partial flows are the file's stored rows when its complete publication
//!   carries the artifact, and otherwise the file-local relations projected
//!   at query time;
//! - interior runs are the M2 fixpoint over the workspace oracle's relations;
//! - dispatch and bindings are the compile's discovery provider's answers;
//! - models are answered at each call from the policy's bound external
//!   models, the call's own dispatch answer and its semantics: the external
//!   models bound to the call, a format-result identity its dispatch proves,
//!   a Rust std builtin its structure proves, the authored summaries of the
//!   external targets it names, and whether it is a resolved external call.
//!   The plan holds only the sinks; no region is discovered for it;
//! - openness is the workspace host's gap sweep;
//! - endpoints are the policy's sources, sanitizers and transforms matched on
//!   one blob at a time when the search first enters a procedure of it, with
//!   the compile's own selection and binding code.
//!
//! The memos live in this value, which the compile drops when it finishes,
//! except the frontier's endpoint matches and the call dispatches, which live
//! in a [`CompositionMemo`] the policy run holds across its composed batches.
//! A candidate may consume the provider after projection to keep only its
//! query-local input backing and the admitted shared entries it consulted.

use super::taint_policy::language_intrinsic_call;
use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
use brokk_bifrost_analysis::analyzer::semantic::IntrinsicCall;
use brokk_bifrost_analysis::analyzer::semantic::service::{
    ArtifactRetentionVisitor, RetainedArtifactWalker,
};
use brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator;
use brokk_bifrost_analysis::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    ReplayingMemo, ReplayingMemoEntry, memo_attribution,
};
use brokk_bifrost_core::retention_budget::SelfCharged;
use brokk_bifrost_flow::composition::LocalTransferDiscovery;
use brokk_bifrost_rust_analysis::analyzer::rust::semantic::canonical_returned_field_member;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::languages::language_support_for_hook;
use brokk_bifrost_analysis::analyzer::semantic::partial_flow::ports::call_port_values;
use brokk_bifrost_analysis::analyzer::semantic::partial_flow::rules::{
    GuardEdgeKill, conditional_guard_edge_kills,
};
use brokk_bifrost_analysis::analyzer::semantic::partial_flow::{
    ExtendedPartialFlows, ExtraObservation, ExtraSeed, GuardProjectionMode, ImplicitHeapRead,
    ObservationFilter, PartialFlowPort, ProcedurePartialFlows, compute_partial_flows_filtered,
    compute_partial_flows_in_mode, compute_partial_flows_with_implicit_reads,
    file_local_procedure_relations, observation_value,
};
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::ProcedureOpenness;
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    ProcedureRangeLookupStatus, procedures_for_definition_with_limits,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    BarrierObservation, CallArgumentEndpoint, CallInvocationMode, CallSiteHandle, CallSiteId,
    CallStorageRelationIndex, CandidateCoverage, DispatchBoundary, DispatchBoundaryKind,
    DispatchOracle, DispatchResult, DurableCallContext, EvidenceCompleteness, ExactCallSiteKey,
    ExactProcedureIdentity, LenientValueTypeBarriers, ObservationPhase, OracleCallContext,
    ProcedureHandle, ProgramPointId, ProofStatus, SemanticArtifactKey, SemanticCallSite,
    SemanticCapability, SemanticExecutionBudget, SemanticGapImpact, SemanticGapKind,
    SemanticGapSubject, SemanticOutcome, SemanticRequest, StrictValueTypeBarriers,
    ValueFlowEndpoint, ValueTypeBarrierDecision, ValueTypeBarrierFilter, ValueTypeBarrierReason,
    ValueTypePredicate,
};
use brokk_bifrost_analysis::analyzer::{Language, ProjectFile, WorkspaceAnalyzer};
use brokk_bifrost_flow::composition::CallStructureProvider;
use brokk_bifrost_flow::dataflow::{
    CuratedCallModel, ExternalSemanticSummarySet, SemanticInputStatus, SemanticProcedureSummary,
    SummaryEffect, SummaryEffectKey, SummaryExitKind, SummaryOrigin, SummaryPort, SummaryTransfer,
    UnmodeledCallBehavior,
};
use brokk_bifrost_flow::taint::compose::{
    BoundSource, CallModel, Callers, Completeness, CompositionProvider, Dispatch, ExecutionArm,
    ExecutionCallableInstance, ExecutionDispatch, ExecutionDispatchOutcome,
    ExecutionEndpointStatus, ExecutionEndpoints, ExecutionTarget, FallbackPorts, HopQuality,
    InteriorFlows, InteriorObservation, InteriorSeed, InvocationSite, Invocations, ModelTransfer,
    Openness, ProcedureEndpointAnswer, ProcedureEndpoints, StoreChannelLink, StoreChannelLinks,
    StoreWriteObservation, ValueTypeBarrierCheck, retained_port, taint_model_kill,
};
use brokk_bifrost_flow::taint::{
    SourceEventKey, TaintAnalysisPlan, TaintClassSet, TaintEdgeFunction, TaintUniverse,
};
use brokk_bifrost_flow::value_flow::{
    AuthoredArmClosure, CallSiteCoverage, DurableCallSiteKey, DurableProcedureKey,
    SummaryCallActual, SummaryCallBinding, ValueFlowCarrier, ValueFlowProvider,
    authored_call_closures, closes_as_resolved_constructor,
};

use crate::definition::PolicyId;
use crate::resolved::ResolvedEndpointIdentity;
use crate::taint_policy::{
    BoundExternalModel, CallResolutionDiscoveryEvidence, CompiledStoreEnd, CompiledTaintEndpoint,
    DiscoveryMaterializationCache, ExternalCallSeams, FrontierEndpoint, FrontierEndpointBinder,
    FrontierGap, FrontierSelector, PolicyDiscoveryProvider, RefusalNotice, SanitizerDecline,
    TaintPolicyCompileError, UnjudgedSource, intrinsic_call_model,
    intrinsic_format_result_identity,
};
use crate::units::WidenReason;

impl CallStructureProvider for PolicyDiscoveryProvider<'_, '_> {}

#[derive(Default)]
struct ProjectionCounter {
    calls: Cell<u64>,
    cpu_ns: Cell<u64>,
}

impl ProjectionCounter {
    fn start() -> Option<std::time::Duration> {
        brokk_bifrost_analysis::profiling::enabled()
            .then(brokk_bifrost_analysis::profiling::thread_cpu_time)
    }

    fn record(&self, start: Option<std::time::Duration>) {
        self.calls.set(self.calls.get() + 1);
        if let Some(start) = start {
            let elapsed = brokk_bifrost_analysis::profiling::thread_cpu_time()
                .saturating_sub(start)
                .as_nanos();
            self.cpu_ns.set(
                self.cpu_ns
                    .get()
                    .saturating_add(u64::try_from(elapsed).unwrap_or(u64::MAX)),
            );
        }
    }

    fn totals(&self) -> (u64, u64) {
        (self.calls.get(), self.cpu_ns.get())
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct ConditionalPartitions {
    pub(crate) baseline: Option<TaintEdgeFunction>,
    pub(crate) groups: Vec<(TaintEdgeFunction, Vec<GuardEdgeKill>)>,
    pub(crate) guard_declines: Vec<brokk_bifrost_analysis::analyzer::semantic::partial_flow::guard_bindings::GuardBindingDecline>,
}

type ConditionalPartialFlows = Vec<(Option<TaintEdgeFunction>, Arc<ProcedurePartialFlows>)>;

type ProcedureMemo<T, K = ExactProcedureIdentity> = RefCell<HashMap<K, AdmittedReplayEntry<T>>>;
type ModeProcedureKey = (ExactProcedureIdentity, GuardProjectionMode);
type PayloadProcedureKey = (
    ExactProcedureIdentity,
    Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest>,
    GuardProjectionMode,
);
type PayloadProcedureMemo<T> = ProcedureMemo<T, PayloadProcedureKey>;

/// Existing query-local semantic input caches. The provider reads and fills
/// this same group; extraction moves its admitted owners after report projection.
/// Keys select coordinates, never certify content or admission by themselves.
#[derive(Default)]
pub(crate) struct ProviderInputBacking {
    pub(crate) served: ProcedureMemo<ProcedureHandle>,
    /// Partial flows by procedure: the first read or computation per compile.
    pub(crate) partial_flows: PayloadProcedureMemo<Arc<ProcedurePartialFlows>>,
    pub(crate) conditional_partitions: ProcedureMemo<ConditionalPartitions, ModeProcedureKey>,
    pub(crate) conditional_declines: RefCell<Vec<SanitizerDecline>>,
    pub(crate) conditional_partial: PayloadProcedureMemo<ConditionalPartialFlows>,
    /// Incoming relation indexes for the compile's immutable procedure snapshots.
    pub(crate) call_storage_indexes: PayloadProcedureMemo<Arc<CallStorageRelationIndex>>,
    pub(crate) filtered_flows: PayloadProcedureMemo<Arc<ProcedurePartialFlows>>,
    /// Openness per procedure, decided once per compile.
    pub(crate) openness_memo: ProcedureMemo<Openness, ModeProcedureKey>,
    /// The gap sweep of each procedure whose partial flows the search read.
    /// It runs at that read, before the openness decision needs it, so the
    /// procedure's refinement calls join its file's next dispatch batch.
    pub(crate) sweeps: ProcedureMemo<ProcedureOpenness>,
    /// Query-local certificates emitted only by actual interior requests.
    pub(crate) value_obligation_accounting: RefCell<
        HashMap<ExactProcedureIdentity, Box<[brokk_bifrost_analysis::analyzer::semantic::GapKey]>>,
    >,
    /// Actual admitted dispatch/model answers consulted by this provider.
    pub(crate) models: RefCell<HashMap<ExactCallSiteKey, AdmittedReplayEntry<MemoizedDispatch>>>,
    /// Every dispatched call, recorded in the shape the ICFG engine's
    /// call-resolution diagnostic reads. The first record of a call wins.
    pub(crate) dispatched: RefCell<HashMap<ExactCallSiteKey, RecordedDispatch>>,
    /// The boundaries of every recorded dispatch, for the same diagnostic.
    pub(crate) dispatch_boundaries: RefCell<Vec<DispatchBoundary>>,
    /// Actual admitted frontier matches, never all entries from the run memo.
    pub(crate) consulted_matches:
        RefCell<std::collections::BTreeMap<ConsultedMatch, FrontierMatchEntry>>,
    /// The origin metadata of every source answered, which the projection
    /// reads to attribute a finding's origins to the policy's sources.
    pub(crate) frontier_sources: RefCell<Vec<CompiledTaintEndpoint>>,
    /// The sources answered with unknown evidence, by origin: the row to
    /// judge each from and the endpoint it was bound for.
    pub(crate) unjudged: RefCell<HashMap<SourceEventKey, SourceJudgment>>,
    /// Config-inactive reverse sites excluded during this composition batch.
    /// These are configuration exclusions, never incomplete discovery.
    pub(crate) excluded_callers:
        RefCell<Vec<(ProjectFile, brokk_bifrost_analysis::analyzer::Range)>>,
    pub(crate) store_writes: Vec<StoreWriteObservation>,
    pub(crate) store_links: HashMap<(ExactProcedureIdentity, PartialFlowPort), StoreChannelLinks>,
    pub(crate) store_by_read: HashMap<(ExactProcedureIdentity, PartialFlowPort), HashSet<String>>,
    pub(crate) consulted_stores: RefCell<HashSet<String>>,
    pub(crate) store_calls: HashSet<ExactCallSiteKey>,
    /// Frozen selected source/summary projection capabilities for this query.
    pub(crate) endpoint_projections_enabled: bool,
    pub(crate) barriers: Vec<(Box<str>, ValueTypePredicate)>,
}

impl ProviderInputBacking {
    /// Conservative strict-to-relaxed content correspondence only. The caller
    /// separately proves root/search correspondence, admission, completion and
    /// coverage of every removed frontier sanitizer by its declared kill set.
    /// All domains are checked; unrepresented recipes refuse correspondence.
    pub(crate) fn has_same_nonkill_inputs(&self, other: &Self) -> bool {
        // Store and type-barrier correspondence is not represented here yet.
        if !self.store_writes.is_empty()
            || !other.store_writes.is_empty()
            || !self.store_links.is_empty()
            || !other.store_links.is_empty()
            || !self.store_by_read.is_empty()
            || !other.store_by_read.is_empty()
            || !self.consulted_stores.borrow().is_empty()
            || !other.consulted_stores.borrow().is_empty()
            || !self.store_calls.is_empty()
            || !other.store_calls.is_empty()
            || !self.barriers.is_empty()
            || !other.barriers.is_empty()
        {
            return false;
        }
        if self.endpoint_projections_enabled != other.endpoint_projections_enabled
            || *self.excluded_callers.borrow() != *other.excluded_callers.borrow()
            || *self.dispatch_boundaries.borrow() != *other.dispatch_boundaries.borrow()
        {
            return false;
        }
        let declines = self.conditional_declines.borrow();
        let other_declines = other.conditional_declines.borrow();
        if declines.len() != other_declines.len()
            || !declines
                .iter()
                .zip(other_declines.iter())
                .all(|(left, right)| {
                    left.sanitizer == right.sanitizer
                        && left.point == right.point
                        && left.target == right.target
                        && left.reason == right.reason
                })
        {
            return false;
        }
        // Empty admitted recipes only: the cache lost authored selector IDs.
        if !same_provider_memo(
            &self.conditional_partitions,
            &other.conditional_partitions,
            |left, right| {
                left.guard_declines == right.guard_declines
                    && left.baseline.is_none()
                    && left.groups.is_empty()
                    && right.baseline.is_none()
                    && right.groups.is_empty()
            },
        ) {
            return false;
        }
        // Exact full projected-flow equality is deliberately conservative.
        // Different kill-filtered flows cannot be justified by skipping a map.
        if !same_provider_memo(&self.served, &other.served, |left, right| left == right && Arc::ptr_eq(left.artifact(), right.artifact()))
            || !same_provider_memo(&self.partial_flows, &other.partial_flows, |left, right| left == right)
            || !same_provider_memo(&self.filtered_flows, &other.filtered_flows, |left, right| left == right)
            || !same_provider_memo(&self.conditional_partial, &other.conditional_partial, |left, right| left == right && left.iter().all(|(function, _)| function.is_none()))
            // This private index has no complete typed equality. Only the
            // identical immutable owner establishes its whole contents.
            || !same_provider_memo(&self.call_storage_indexes, &other.call_storage_indexes, Arc::ptr_eq)
            || !same_provider_memo(&self.openness_memo, &other.openness_memo, |left, right| left == right)
            || !same_provider_memo(&self.sweeps, &other.sweeps, |left, right| left == right)
            || !same_provider_map(&self.value_obligation_accounting.borrow(), &other.value_obligation_accounting.borrow(), |left, right| left == right)
            || !same_provider_memo(&self.models, &other.models, |left, right| left == right)
            || !same_provider_map(&self.dispatched.borrow(), &other.dispatched.borrow(), |left, right| left == right)
        {
            return false;
        }
        let sources = self.frontier_sources.borrow();
        let other_sources = other.frontier_sources.borrow();
        if sources.len() != other_sources.len()
            || !sources
                .iter()
                .zip(other_sources.iter())
                .all(|(left, right)| {
                    left.evidence_site == right.evidence_site
                        && left.endpoint == right.endpoint
                        && left.event == right.event
                })
        {
            return false;
        }
        // Source judgment is post-report evidence: a strict missing path need
        // not judge the relaxed positive source. The selected question must
        // still correspond in full, and both answers remain independently owned.
        if !same_provider_map(
            &self.unjudged.borrow(),
            &other.unjudged.borrow(),
            |left, right| {
                left.source.origin == right.source.origin
                    && left.source.identity == right.source.identity
                    && left
                        .source
                        .selection
                        .has_same_inputs(&right.source.selection)
            },
        ) {
            return false;
        }
        let matches = self.consulted_matches.borrow();
        let other_matches = other.consulted_matches.borrow();
        if other_matches.keys().any(|key| !matches.contains_key(key)) {
            return false;
        }
        matches
            .iter()
            .all(|(key, left)| match other_matches.get(key) {
                Some(right) => {
                    left.execution_dependent() == right.execution_dependent()
                        && left.value().has_same_nonkill_inputs(right.value())
                }
                None => {
                    matches!(key.1, FrontierSelector::Sanitizer(_))
                        && !left.execution_dependent()
                        && left.value().only_proven_sanitizers()
                }
            })
    }

    /// Borrow every sanitizer recipe in the actual consulted frontier. No
    /// lookup-key equality, allocation or additional frontier read is involved.
    pub(crate) fn all_sanitizers_match(
        &self,
        mut predicate: impl FnMut(&crate::taint_policy::BoundSanitizer) -> bool,
    ) -> bool {
        self.consulted_matches.borrow().values().all(|entry| {
            entry.value().by_procedure.values().all(|endpoints| {
                endpoints.iter().all(|endpoint| match endpoint {
                    FrontierEndpoint::Sanitizer(sanitizer) => predicate(sanitizer),
                    FrontierEndpoint::Source(_) | FrontierEndpoint::Transform(_) => true,
                })
            })
        })
    }

    /// Owned children only: the enclosing candidate charges this group's inline
    /// storage. Every visitor shares its bounded census; no owner is reacquired.
    pub(crate) fn retained_heap(&self, heap: &mut RetainedHeap) {
        retained_procedure_memo(
            &self.served,
            heap,
            retained_exact_procedure_key,
            |handle, heap| {
                let mut artifacts = RetainedArtifactWalker::new(heap);
                artifacts.procedure(handle);
                artifacts.finish();
            },
        );
        retained_procedure_memo(
            &self.partial_flows,
            heap,
            retained_payload_key,
            retained_partial_flows,
        );
        retained_procedure_memo(
            &self.filtered_flows,
            heap,
            retained_payload_key,
            retained_partial_flows,
        );
        retained_procedure_memo(
            &self.conditional_partitions,
            heap,
            |key, heap| retained_exact_procedure_key(&key.0, heap),
            |parts, heap| {
                if let Some(function) = &parts.baseline {
                    function.retained_heap(heap);
                }
                heap.vec(&parts.guard_declines);
                for decline in &parts.guard_declines {
                    heap.owned_slice(decline.id.as_bytes());
                    let mut artifacts = RetainedArtifactWalker::new(heap);
                    artifacts.procedure(&decline.procedure);
                    artifacts.finish();
                }
                heap.vec(&parts.groups);
                for (function, kills) in &parts.groups {
                    function.retained_heap(heap);
                    heap.vec(kills);
                    let mut artifacts = RetainedArtifactWalker::new(heap);
                    for kill in kills {
                        kill.carrier.retained_artifacts(&mut artifacts);
                    }
                    artifacts.finish();
                }
            },
        );
        retained_procedure_memo(
            &self.conditional_partial,
            heap,
            retained_payload_key,
            |parts, heap| {
                heap.vec(parts);
                for (function, flows) in parts {
                    if let Some(function) = function {
                        function.retained_heap(heap);
                    }
                    retained_partial_flows(flows, heap);
                }
            },
        );
        retained_procedure_memo(
            &self.call_storage_indexes,
            heap,
            retained_payload_key,
            |index, heap| {
                heap.arc(index, |index, heap| {
                    let mut artifacts = RetainedArtifactWalker::new(heap);
                    index.retained_artifacts(&mut artifacts);
                    artifacts.finish();
                });
            },
        );
        retained_procedure_memo(
            &self.openness_memo,
            heap,
            |key, heap| retained_exact_procedure_key(&key.0, heap),
            |openness, heap| openness.retained_heap(heap),
        );
        retained_procedure_memo(
            &self.sweeps,
            heap,
            retained_exact_procedure_key,
            |sweep, heap| heap.vec(&sweep.relevant_gaps),
        );

        let accounting = self.value_obligation_accounting.borrow();
        heap.map(&accounting);
        for (procedure, gaps) in accounting.iter() {
            retained_exact_procedure_key(procedure, heap);
            heap.slice(gaps);
        }
        drop(accounting);

        let declines = self.conditional_declines.borrow();
        heap.vec(&declines);
        for decline in declines.iter() {
            heap.owned_slice(decline.sanitizer.as_bytes());
            retained_string(&decline.reason, heap);
            let mut artifacts = RetainedArtifactWalker::new(heap);
            artifacts.procedure(decline.point.procedure());
            artifacts.finish();
        }
        let models = self.models.borrow();
        heap.map(&models);
        for (call, entry) in models.iter() {
            retained_exact_procedure_key(&call.0, heap);
            retained_admitted_replay_entry(entry, heap, |entry, heap| entry.retained_heap(heap));
        }
        let dispatched = self.dispatched.borrow();
        heap.map(&dispatched);
        for (call, record) in dispatched.iter() {
            retained_exact_procedure_key(&call.0, heap);
            record.retained_heap(heap);
        }
        let boundaries = self.dispatch_boundaries.borrow();
        heap.vec(&boundaries);
        let mut artifacts = RetainedArtifactWalker::new(heap);
        for boundary in boundaries.iter() {
            boundary.retained_artifacts(&mut artifacts);
        }
        artifacts.finish();
        let matches = self.consulted_matches.borrow();
        heap.btree_map(&matches);
        for ((artifact, _), entry) in matches.iter() {
            retained_artifact_key(artifact, heap);
            retained_admitted_replay_entry(entry, heap, |matched, heap| {
                heap.arc(matched, |matched, heap| matched.retained_heap(heap));
            });
        }
        let sources = self.frontier_sources.borrow();
        heap.vec(&sources);
        for source in sources.iter() {
            retained_endpoint_identity(&source.endpoint, heap);
            let mut artifacts = RetainedArtifactWalker::new(heap);
            artifacts.locator(source.event.site());
            if let Some(site) = &source.evidence_site {
                artifacts.locator(site);
            }
            artifacts.finish();
        }
        let judgments = self.unjudged.borrow();
        heap.map(&judgments);
        for (origin, judgment) in judgments.iter() {
            let mut artifacts = RetainedArtifactWalker::new(heap);
            artifacts.locator(origin.value_flow_key().site());
            artifacts.locator(judgment.source.origin.value_flow_key().site());
            artifacts.finish();
            retained_endpoint_identity(&judgment.source.identity, heap);
            heap.arc(&judgment.source.selection, |selection, heap| {
                selection.retained_heap(heap)
            });
            if let Some(answer) = &judgment.answer {
                retained_admitted_replay_entry(answer, heap, |_, _| {});
            }
        }
        let excluded = self.excluded_callers.borrow();
        heap.vec(&excluded);
        for (file, _) in excluded.iter() {
            let (owner, root, path_capacity) = file.retained_parts();
            heap.arc(owner, |_, heap| {
                heap.add(path_capacity);
                heap.arc(root, |_, _| {});
            });
        }
        heap.vec(&self.store_writes);
        for write in &self.store_writes {
            write.retained_heap(heap);
        }
        heap.map(&self.store_links);
        for ((procedure, port), links) in &self.store_links {
            retained_exact_procedure_key(procedure, heap);
            retained_port(heap, port);
            links.retained_heap(heap);
        }
        heap.map(&self.store_by_read);
        for ((procedure, port), channels) in &self.store_by_read {
            retained_exact_procedure_key(procedure, heap);
            retained_port(heap, port);
            heap.hash_set(channels);
            for channel in channels {
                retained_string(channel, heap);
            }
        }
        let consulted_stores = self.consulted_stores.borrow();
        heap.hash_set(&consulted_stores);
        for channel in consulted_stores.iter() {
            retained_string(channel, heap);
        }
        heap.hash_set(&self.store_calls);
        for call in &self.store_calls {
            retained_exact_procedure_key(&call.0, heap);
        }
        heap.vec(&self.barriers);
        for (name, _) in &self.barriers {
            heap.owned_slice(name.as_bytes());
        }
    }
}

/// Equal domains plus every actual value; keys choose coordinates only.
fn same_provider_map<K: Eq + std::hash::Hash, T, U>(
    left: &HashMap<K, T>,
    right: &HashMap<K, U>,
    mut same: impl FnMut(&T, &U) -> bool,
) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|(key, value)| right.get(key).is_some_and(|other| same(value, other)))
}

fn same_provider_memo<K: Eq + std::hash::Hash, T>(
    left: &ProcedureMemo<T, K>,
    right: &ProcedureMemo<T, K>,
    mut same: impl FnMut(&T, &T) -> bool,
) -> bool {
    same_provider_map(&left.borrow(), &right.borrow(), |left, right| {
        same(left.value(), right.value())
    })
}

fn retained_procedure_memo<T, K>(
    memo: &ProcedureMemo<T, K>,
    heap: &mut RetainedHeap,
    key: impl Fn(&K, &mut RetainedHeap),
    payload: impl Fn(&T, &mut RetainedHeap),
) {
    let memo = memo.borrow();
    heap.map(&memo);
    for (coordinate, entry) in memo.iter() {
        key(coordinate, heap);
        retained_admitted_replay_entry(entry, heap, &payload);
    }
}

pub(crate) fn retained_artifact_key(key: &SemanticArtifactKey, heap: &mut RetainedHeap) {
    heap.owned_slice(key.path().as_str().as_bytes());
    heap.owned_slice(key.adapter().name().as_bytes());
}

pub(crate) fn retained_procedure_key(key: &DurableProcedureKey, heap: &mut RetainedHeap) {
    retained_artifact_key(&key.0, heap);
}

// Exact identities are fixed-width values; map storage accounts their bytes.
// Their admitted values retain and visit the actual semantic owners.
fn retained_exact_procedure_key(_key: &ExactProcedureIdentity, _heap: &mut RetainedHeap) {}

pub(crate) fn retained_payload_key(_key: &PayloadProcedureKey, _heap: &mut RetainedHeap) {}

fn retained_partial_flows(flows: &Arc<ProcedurePartialFlows>, heap: &mut RetainedHeap) {
    heap.arc(flows, |flows, heap| {
        if let Some(detail) = &flows.detail {
            retained_string(detail, heap);
        }
        heap.vec(&flows.ports);
        for port in &flows.ports {
            retained_port(heap, port);
        }
        heap.vec(&flows.flows);
        for flow in &flows.flows {
            heap.owned_slice(&flow.crossed);
            for crossed in &flow.crossed {
                heap.owned_slice(crossed);
            }
        }
        heap.vec(&flows.discharged_gaps);
    });
}

fn retained_endpoint_identity(identity: &ResolvedEndpointIdentity, heap: &mut RetainedHeap) {
    match identity {
        ResolvedEndpointIdentity::Local {
            policy_id,
            entry_id,
        } => {
            heap.owned_slice(policy_id.as_str().as_bytes());
            heap.owned_slice(entry_id.as_str().as_bytes());
        }
        ResolvedEndpointIdentity::Catalog { catalog, entry_id } => {
            heap.owned_slice(catalog.name.as_str().as_bytes());
            heap.owned_slice(entry_id.as_str().as_bytes());
        }
        ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => {
            heap.owned_slice(endpoint_id.as_str().as_bytes())
        }
    }
}

/// A selected source question and the exact admitted answer, if it was judged.
pub(crate) struct SourceJudgment {
    pub(crate) source: UnjudgedSource,
    pub(crate) answer: Option<AdmittedReplayEntry<HopQuality>>,
}

/// The composition's provider over one workspace, one compile and one plan.
pub(crate) struct PolicyCompositionProvider<'a> {
    inputs: ProviderInputBacking,
    workspace: &'a WorkspaceAnalyzer,
    discovery: PolicyDiscoveryProvider<'a, 'a>,
    execution_budget: SemanticExecutionBudget,
    plan: &'a TaintAnalysisPlan,
    /// The policy's bound external models, sorted by call.
    external_models: &'a [BoundExternalModel],
    /// Incoming calls kept per procedure, the composition's caller lane.
    max_callers_per_procedure: usize,
    // Open lazily after candidate discovery; drop operations and memos with this query.
    barrier_service: crate::taint_barriers::ValueTypeBarrierService<'a>,
    barrier_fixpoints: Cell<u64>,
    /// Distinct recomputed chop procedures, retained only for this query's metrics.
    barrier_procedures: RefCell<HashSet<DurableProcedureKey>>,
    barrier_filter: RefCell<Box<dyn ValueTypeBarrierFilter>>,
    barrier_chop: RefCell<HashSet<DurableProcedureKey>>,
    lenient_chop: RefCell<HashSet<DurableProcedureKey>>,
    strict_witnesses: RefCell<
        HashSet<(
            SourceEventKey,
            brokk_bifrost_flow::value_flow::ValueFlowSinkId,
        )>,
    >,
    /// Partial-flow answers read from the store.
    stored_reads: Cell<u64>,
    /// Partial-flow answers computed at query time.
    computed: Cell<u64>,
    baseline_reads_cost: ProjectionCounter,
    interior_cost: ProjectionCounter,
    overlay_cost: ProjectionCounter,
    /// Calls this provider dispatched; the run memo answered every other
    /// dispatch request.
    dispatches_made: Cell<usize>,
    /// Selects and binds the policy's sources, sanitizers and transforms.
    binder: RefCell<FrontierEndpointBinder<'a>>,
    /// The policy whose endpoints the binder matches, the memo's key.
    policy: PolicyId,
    /// The run's frontier matches and dispatches, shared with the run's other
    /// batches.
    memo: &'a CompositionMemo,
    /// Sliced selector evaluations this batch ran; the memo answered the
    /// rest.
    endpoint_evaluations: Cell<u64>,
    /// The selectors this batch could not slice, with the reason, in the
    /// order they were first evaluated.
    endpoint_widened: RefCell<Vec<(FrontierSelector, WidenReason)>>,
    /// Points-to evidence runs this batch made; the memo answered the rest.
    source_evidence_resolved: Cell<u64>,
}

/// What the composition learned over one policy run that its batches share.
/// A policy's composed batches each build their own provider, and a
/// procedure or call two batches reach is the same blob under the same
/// selectors and the same dispatch, so the run holds these and every batch
/// reads them. Nothing here outlives the run.
///
/// - The endpoints the frontier matched: what each selector of
///   each policy bound in each blob, and the workspace-wide rows of each
///   selector that could not be sliced.
/// - Each call's dispatch: the search, the openness refinement
///   and the model lookup read one answer, so a call is dispatched once per
///   policy run. A call's models depend on the policy (its bound external
///   models and label universe), so the answer is keyed by policy too.
/// - Each call's Rust std builtin classification, which reads the call's
///   source and the workspace resolution of its method name and so is shared
///   by every policy.
///
/// Every entry carries the reads of its own build. The unit that fills an
/// entry records them as it builds; every later unit that hits the entry
/// replays them, so the read set of a unit does not depend on which unit
/// reached the shared entry first (#7262).
type ExecutionDiscovery = (
    Vec<brokk_bifrost_flow::taint::compose::ExecutionReach>,
    Vec<brokk_bifrost_flow::taint::compose::Incompleteness>,
);
type ExecutionDiscoveryKey = (PolicyId, usize, usize, usize);
type ExecutionDiscoveryEntry =
    Arc<AdmittedMemoEntry<ReplayingMemoEntry<ExecutionDiscovery, ReadKey>>>;

#[derive(Default)]
pub(crate) struct CompositionMemo {
    /// Execution-root discovery depends on the policy's label universe and
    /// the composition limits, not on the anchors a search selects, so every
    /// Output anchor of the policy run reads one answer.
    execution: RefCell<HashMap<ExecutionDiscoveryKey, ExecutionDiscoveryEntry>>,
    matches:
        RefCell<HashMap<(PolicyId, SemanticArtifactKey, FrontierSelector), FrontierMatchEntry>>,
    refusal_history: RefCell<HashMap<PolicyId, Vec<RefusalNotice>>>,
    widened: RefCell<HashMap<(PolicyId, FrontierSelector), WidenedRowsEntry>>,
    dispatches: RefCell<HashMap<(PolicyId, ExactCallSiteKey), Arc<DispatchEntry>>>,
    std_builtins: RefCell<HashMap<ExactCallSiteKey, Arc<StdBuiltinEntry>>>,
    /// The evidence of each frontier matched-value source that reached a
    /// sink, by policy, endpoint and selected site. Judging one is a
    /// points-to question, so the run asks it once for a site however many
    /// batches report a flow from it.
    evidence: RefCell<HashMap<EvidenceKey, Arc<EvidenceEntry>>>,
    /// Reads answered from a kept entry, per map, for the hit-path read
    /// parity test.
    hits: MemoHits,
    /// The order test's handle for this run, if a test asked for one.
    #[cfg(any(test, feature = "test-support"))]
    order_probe: Option<crate::taint_policy::OutputOrderProbe>,
}

#[derive(Default)]
struct MemoHits {
    execution: Cell<u64>,
    matches: Cell<u64>,
    widened: Cell<u64>,
    dispatches: Cell<u64>,
    std_builtins: Cell<u64>,
    evidence: Cell<u64>,
}

type DispatchEntry = AdmittedMemoEntry<ReplayingMemoEntry<MemoizedDispatch, ReadKey>>;
type StdBuiltinEntry = ReplayingMemoEntry<Option<IntrinsicCall>, ReadKey>;
type EvidenceEntry = AdmittedMemoEntry<ReplayingMemoEntry<HopQuality, ReadKey>>;

type AdmittedReplayEntry<T> = Arc<AdmittedMemoEntry<ReplayingMemoEntry<T, ReadKey>>>;

/// A cold fill's admission travels with its value, independently of read replay.
pub(crate) struct AdmittedMemoEntry<T> {
    value: Arc<T>,
    admission: brokk_bifrost_analysis::analyzer::semantic::SemanticMemoAdmission,
}
impl<T> std::ops::Deref for AdmittedMemoEntry<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> AdmittedMemoEntry<T> {
    /// The admission receipt's owned storage, for a store that charges it.
    pub(crate) fn admission_retained_bytes(&self) -> usize {
        self.admission.retained_bytes()
    }
}

/// Where [`read_admitted`] keeps entries. A plain map keeps every entry for
/// its owner's lifetime; a budgeted store may drop entries under memory
/// pressure, which only turns a later hit into a cold fill.
pub(crate) trait AdmittedMemoStore<K, T> {
    type Handle: std::ops::Deref<Target = AdmittedMemoEntry<T>>;
    fn get(&self, key: &K) -> Option<Self::Handle>;
    fn remove(&self, key: &K);
    /// Keep `entry` under `key` when `keep` holds, and return a handle to it.
    fn insert(&self, key: K, entry: AdmittedMemoEntry<T>, keep: bool) -> Self::Handle;
}

impl<K: Eq + std::hash::Hash, T> AdmittedMemoStore<K, T>
    for RefCell<HashMap<K, Arc<AdmittedMemoEntry<T>>>>
{
    type Handle = Arc<AdmittedMemoEntry<T>>;
    fn get(&self, key: &K) -> Option<Self::Handle> {
        self.borrow().get(key).cloned()
    }
    fn remove(&self, key: &K) {
        self.borrow_mut().remove(key);
    }
    fn insert(&self, key: K, entry: AdmittedMemoEntry<T>, keep: bool) -> Self::Handle {
        let entry = Arc::new(entry);
        if keep {
            self.borrow_mut().insert(key, Arc::clone(&entry));
        }
        entry
    }
}

/// Visit the actual admitted owner and its value in the caller's single
/// bounded census. The payload callback counts owned children, not inline T.
/// This neither replays reads nor reacquires semantic capabilities.
pub(crate) fn retained_admitted_entry<T>(
    entry: &Arc<AdmittedMemoEntry<T>>,
    heap: &mut RetainedHeap,
    payload: impl FnOnce(&T, &mut RetainedHeap),
) {
    heap.arc(entry, |entry, heap| {
        let mut artifacts = RetainedArtifactWalker::new(heap);
        entry.admission.retained_allocations(&mut artifacts);
        artifacts.finish();
        heap.arc(&entry.value, payload);
    });
}

/// Captured read receipts and the charge control are owners of the selected
/// replay entry too; visiting its payload alone would omit those allocations.
pub(crate) fn retained_admitted_replay_entry<T>(
    entry: &AdmittedReplayEntry<T>,
    heap: &mut RetainedHeap,
    payload: impl FnOnce(&T, &mut RetainedHeap),
) {
    retained_admitted_entry(entry, heap, |entry, heap| {
        let reads = entry.captured_reads();
        heap.arc(&reads.keys, |keys, heap| {
            for key in keys {
                retained_read_key(heap, key);
            }
        });
        for refusal in [&reads.first_refusal, &reads.first_execution_refusal]
            .into_iter()
            .flatten()
        {
            retained_string(&refusal.reason, heap);
        }
        if let Some((identity, bytes)) = entry.allocation_charge().retained_control_allocation() {
            heap.allocation(identity, bytes);
        }
        payload(entry.value(), heap);
    });
}

fn retained_string(value: &String, heap: &mut RetainedHeap) {
    if value.capacity() != 0 {
        heap.allocation(value.as_ptr() as usize, value.capacity());
    }
}

/// A replayed value that also keeps its actual admission descriptor alive.
struct AdmittedReplayValue<T>(AdmittedReplayEntry<T>);
impl<T> std::ops::Deref for AdmittedReplayValue<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.value.value()
    }
}

/// Borrow the ledger only for capture/probe, never across the cold build.
/// Rejected entries and borrowed handles close before the replacement fill.
pub(crate) fn read_admitted<K, T: Send + Sync + 'static, E, S: AdmittedMemoStore<K, T>>(
    entries: &S,
    key: K,
    reacquirer: Option<&dyn brokk_bifrost_analysis::analyzer::semantic::MemoDependencyReacquirer>,
    with_budget: impl Fn(
        &mut dyn FnMut(&mut brokk_bifrost_analysis::analyzer::semantic::SemanticBudget),
    ),
    build: impl FnOnce() -> Result<T, E>,
    keep: impl FnOnce(&T) -> bool,
    hit: impl FnOnce(),
) -> Result<S::Handle, E> {
    if let Some(entry) = entries.get(&key) {
        let mut accepted = false;
        with_budget(&mut |budget| {
            accepted = budget
                .admit_memo_hit_with(&entry.admission, reacquirer)
                .is_ok()
        });
        if accepted {
            hit();
            return Ok(entry);
        }
        entries.remove(&key);
        drop(entry);
    }
    let mut before = None;
    with_budget(&mut |budget| {
        before = Some(budget.replay_snapshot());
    });
    let value = Arc::new(build()?);
    let mut admission = None;
    with_budget(&mut |budget| {
        admission = Some(budget.memo_admission_since(before.as_ref().unwrap(), &value))
    });
    let keep = keep(&value);
    let entry = AdmittedMemoEntry {
        value,
        admission: admission.unwrap(),
    };
    Ok(entries.insert(key, entry, keep))
}

/// The entry of `entries` under `key`, built by `build` when absent and kept
/// when `keep` accepts the built value. The build records its reads into the
/// entry, and every read replays them into the current capture, whether this
/// read built the entry or found it.
fn read_shared<K: Eq + std::hash::Hash, V: Send + Sync + 'static, E>(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    entries: &RefCell<HashMap<K, AdmittedReplayEntry<V>>>,
    hits: &Cell<u64>,
    key: K,
    with_budget: impl Fn(
        &mut dyn FnMut(&mut brokk_bifrost_analysis::analyzer::semantic::SemanticBudget),
    ),
    build: impl FnOnce() -> Result<V, E>,
    keep: impl FnOnce(&V) -> bool,
) -> Result<AdmittedReplayValue<V>, E> {
    let capability = memo_attribution(analyzer);
    let mut admitted = None;
    let replayed = ReplayingMemo::new(()).read(&capability, |_, capture| {
        let entry = read_admitted(
            entries,
            key,
            None,
            with_budget,
            || capture.try_build(build),
            |entry| keep(entry.value()),
            || hits.set(hits.get() + 1),
        )?;
        let value = Arc::clone(&entry.value);
        admitted = Some(entry);
        Ok::<_, E>(value)
    })?;
    drop(replayed);
    Ok(AdmittedReplayValue(
        admitted.expect("a replayed read selected its admitted entry"),
    ))
}

fn read_shared_unbudgeted<K: Eq + std::hash::Hash, V, E>(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    entries: &RefCell<HashMap<K, Arc<ReplayingMemoEntry<V, ReadKey>>>>,
    hits: &Cell<u64>,
    key: K,
    build: impl FnOnce() -> Result<V, E>,
    keep: impl FnOnce(&V) -> bool,
) -> Result<impl std::ops::Deref<Target = V>, E> {
    let capability = memo_attribution(analyzer);
    ReplayingMemo::new(()).read(&capability, |_, capture| {
        if let Some(entry) = entries.borrow().get(&key) {
            hits.set(hits.get() + 1);
            return Ok(Arc::clone(entry));
        }
        let entry = Arc::new(capture.try_build(build)?);
        if keep(entry.value()) {
            entries.borrow_mut().insert(key, Arc::clone(&entry));
        }
        Ok(entry)
    })
}

/// The refusals of `entries`, preserving each row's distinct typed causes.
/// A verdict from a build
/// that depended on its execution has an additional uncertified contribution.
/// Preserve its known operational inventory before deduplicating retained detail.
fn merged_refusals<'m>(
    entries: impl Iterator<Item = &'m FrontierMatchEntry>,
) -> Vec<RefusalNotice> {
    let mut messages = entries
        .flat_map(|entry| {
            let execution_dependent = entry.execution_dependent();
            entry
                .value()
                .refusals
                .iter()
                .cloned()
                .flat_map(move |refusal| {
                    if execution_dependent {
                        let unknown = refusal.clone().into_operational();
                        [Some(refusal), Some(unknown)]
                    } else {
                        [Some(refusal), None]
                    }
                    .into_iter()
                    .flatten()
                })
        })
        .collect::<Vec<_>>();
    normalize_refusals(&mut messages);
    messages
}

fn normalize_refusals(messages: &mut Vec<RefusalNotice>) {
    use brokk_bifrost_flow::taint::compose::{BudgetLane, IncompleteCause, OperationalCause};
    let cause_order = |cause| match cause {
        IncompleteCause::Operational(OperationalCause::Provider) => 0,
        IncompleteCause::Operational(OperationalCause::Cancelled) => 1,
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Procedures)) => 2,
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Hops)) => 3,
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::CallersPerProcedure)) => {
            4
        }
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)) => 5,
        IncompleteCause::Content => 6,
    };
    messages.sort_by(|left, right| {
        left.message
            .cmp(&right.message)
            .then_with(|| cause_order(left.cause()).cmp(&cause_order(right.cause())))
    });
    messages.dedup_by(|left, right| left.message == right.message && left.cause() == right.cause());
    // A row's content verdict cannot outrank any operational contributor.
    // Distinct operational causes remain separate existing typed notices.
    let operational = messages
        .iter()
        .filter(|notice| notice.cause() != IncompleteCause::Content)
        .map(|notice| notice.message.clone())
        .collect::<HashSet<_>>();
    messages.retain(|notice| {
        notice.cause() != IncompleteCause::Content || !operational.contains(&notice.message)
    });
}

impl CompositionMemo {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_order_probe(
        mut self,
        probe: Option<crate::taint_policy::OutputOrderProbe>,
    ) -> Self {
        self.order_probe = probe;
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn order_probe(&self) -> Option<&crate::taint_policy::OutputOrderProbe> {
        self.order_probe.as_ref()
    }

    /// Report-only history, independent of memo rollback and unit diagnostics.
    pub(crate) fn run_refusal_messages(&self, policy: &PolicyId) -> Vec<RefusalNotice> {
        self.refusal_history
            .borrow()
            .get(policy)
            .cloned()
            .unwrap_or_default()
    }

    fn record_refusals(&self, policy: &PolicyId, entry: &FrontierMatchEntry) {
        let mut history = self.refusal_history.borrow_mut();
        let notices = history.entry(policy.clone()).or_default();
        notices.extend(merged_refusals(std::iter::once(entry)));
        normalize_refusals(notices);
    }

    pub(crate) fn execution_discovery<E>(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
        key: ExecutionDiscoveryKey,
        with_budget: impl Fn(
            &mut dyn FnMut(&mut brokk_bifrost_analysis::analyzer::semantic::SemanticBudget),
        ),
        build: impl FnOnce() -> Result<ExecutionDiscovery, E>,
    ) -> Result<ExecutionDiscovery, E> {
        // A discovery with an operational gap is not kept: another unit
        // repeats it under its own budget and decides its own stop.
        let result = read_shared(
            analyzer,
            &self.execution,
            &self.hits.execution,
            key,
            with_budget,
            build,
            |discovery| {
                !discovery.1.iter().any(|gap| {
                    matches!(
                        gap.cause(),
                        brokk_bifrost_flow::taint::compose::IncompleteCause::Operational(_)
                    )
                })
            },
        )?;
        Ok((*result).clone())
    }

    /// Retry overlays see only the charged entries present at batch entry.
    /// Values are immutable replay receipts; cloning their Arcs preserves reads.
    pub(crate) fn retry_overlay(&self, checkpoint: &ChargedEntriesCheckpoint) -> Self {
        let overlay = Self {
            execution: RefCell::new(self.execution.borrow().clone()),
            matches: RefCell::new(self.matches.borrow().clone()),
            widened: RefCell::new(self.widened.borrow().clone()),
            dispatches: RefCell::new(self.dispatches.borrow().clone()),
            evidence: RefCell::new(self.evidence.borrow().clone()),
            std_builtins: RefCell::new(self.std_builtins.borrow().clone()),
            #[cfg(any(test, feature = "test-support"))]
            order_probe: self.order_probe.clone(),
            ..Self::default()
        };
        overlay.restore_charged_entries(checkpoint);
        overlay
    }

    pub(crate) fn merge_retry_history(&self, overlay: &Self) {
        let mut history = self.refusal_history.borrow_mut();
        for (policy, additions) in overlay.refusal_history.borrow().iter() {
            let notices = history.entry(policy.clone()).or_default();
            notices.extend(additions.iter().cloned());
            normalize_refusals(notices);
        }
    }

    /// Publish charged entries only after their unit completes. A stopped
    /// overlay is dropped together with restoration of its budget checkpoint.
    pub(crate) fn merge_retry_overlay(&self, overlay: Self) {
        self.merge_retry_history(&overlay);
        self.execution
            .borrow_mut()
            .extend(overlay.execution.into_inner());
        self.matches
            .borrow_mut()
            .extend(overlay.matches.into_inner());
        self.widened
            .borrow_mut()
            .extend(overlay.widened.into_inner());
        self.dispatches
            .borrow_mut()
            .extend(overlay.dispatches.into_inner());
        self.evidence
            .borrow_mut()
            .extend(overlay.evidence.into_inner());
    }

    /// The keys of `policy`'s entries whose hit skips a semantic charge. These
    /// are the maps a search fills while it charges the run's budget; a hit
    /// there lets a later search skip a charge a from-scratch run pays.
    /// `std_builtins` is not one: it takes no budget. An earlier batch of the
    /// same policy (its sinks split across root plans) may already hold
    /// entries; a from-scratch run holds them too, so they stay.
    pub(crate) fn charged_entries_checkpoint(&self, policy: &PolicyId) -> ChargedEntriesCheckpoint {
        fn keys<K: Clone + Eq + std::hash::Hash, V>(
            map: &RefCell<HashMap<K, V>>,
            owner: impl Fn(&K) -> bool,
        ) -> HashSet<K> {
            map.borrow()
                .keys()
                .filter(|key| owner(key))
                .cloned()
                .collect()
        }
        ChargedEntriesCheckpoint {
            policy: policy.clone(),
            execution: keys(&self.execution, |key| &key.0 == policy),
            matches: keys(&self.matches, |key| &key.0 == policy),
            widened: keys(&self.widened, |key| &key.0 == policy),
            dispatches: keys(&self.dispatches, |key| &key.0 == policy),
            evidence: keys(&self.evidence, |key| &key.0 == policy),
        }
    }

    /// Drop the entries of the checkpoint's policy that were added after it,
    /// when the budget their charges were made against is restored. Entries
    /// are only ever inserted, so this undoes the abandoned attempt exactly.
    /// Reusing one would let the fallback skip a charge a from-scratch run
    /// pays, and the ledger would then bill a later search for rows the
    /// skipped one had already paid for (#10560).
    pub(crate) fn restore_charged_entries(&self, checkpoint: &ChargedEntriesCheckpoint) {
        let policy = &checkpoint.policy;
        self.execution
            .borrow_mut()
            .retain(|key, _| &key.0 != policy || checkpoint.execution.contains(key));
        self.matches
            .borrow_mut()
            .retain(|key, _| &key.0 != policy || checkpoint.matches.contains(key));
        self.widened
            .borrow_mut()
            .retain(|key, _| &key.0 != policy || checkpoint.widened.contains(key));
        self.dispatches
            .borrow_mut()
            .retain(|key, _| &key.0 != policy || checkpoint.dispatches.contains(key));
        self.evidence
            .borrow_mut()
            .retain(|key, _| &key.0 != policy || checkpoint.evidence.contains(key));
    }
}

/// One policy's charged memo keys at a point in the run; see
/// [`CompositionMemo::charged_entries_checkpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChargedEntriesCheckpoint {
    policy: PolicyId,
    execution: HashSet<ExecutionDiscoveryKey>,
    matches: HashSet<(PolicyId, SemanticArtifactKey, FrontierSelector)>,
    widened: HashSet<(PolicyId, FrontierSelector)>,
    dispatches: HashSet<(PolicyId, ExactCallSiteKey)>,
    evidence: HashSet<EvidenceKey>,
}

impl PolicyCompositionProvider<'_> {
    /// Actual matches consulted only through endpoints, not preliminary inventory.
    /// Borrow the retained input owners; do not query or allocate another ledger.
    pub(crate) fn for_each_frontier_gap(&self, mut visit: impl FnMut(&FrontierGap)) {
        let matches = self.inputs.consulted_matches.borrow();
        for entry in matches.values() {
            for gap in &entry.value().gaps {
                visit(gap);
            }
        }
    }
}

#[cfg(test)]
impl PolicyCompositionProvider<'_> {
    pub(crate) fn clear_sweeps_for_test(&self) {
        self.inputs.sweeps.borrow_mut().clear();
    }
    pub(crate) fn seed_partial_receipts_for_test(&self, request: &mut SemanticRequest<'_>) {
        for file in self.workspace.analyzer().analyzed_files() {
            let outcome = self
                .workspace
                .materialize_program_semantics(&file, request)
                .unwrap();
            let artifact = outcome.available_value().expect("fixture artifact");
            for row in artifact.procedures() {
                let procedure = artifact
                    .procedure_handle(row.id())
                    .expect("fixture procedure");
                self.partial_flows(&procedure.durable_key(), request)
                    .expect("selected fixture partial flows");
            }
        }
    }

    pub(crate) fn assert_partial_receipts_for_test(
        &self,
        request: &mut SemanticRequest<'_>,
    ) -> Vec<(bool, ProcedurePartialFlows)> {
        use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
        let mut keys: Vec<_> = self.inputs.partial_flows.borrow().keys().copied().collect();
        keys.sort_unstable();
        let mut signature = Vec::new();
        assert!(!keys.is_empty(), "composition must read a procedure");
        for key in keys {
            let procedure = self
                .inputs
                .served
                .borrow()
                .values()
                .find(|entry| entry.value().exact_identity() == key.0)
                .expect("selected owner is served")
                .value()
                .durable_key();
            self.inputs.partial_flows.borrow_mut().remove(&key);
            let (fill, reads) = capture_query_reads(self.workspace.analyzer(), || {
                self.partial_flows(&procedure, request).unwrap()
            });
            let (hit, hit_reads) = capture_query_reads(self.workspace.analyzer(), || {
                self.partial_flows(&procedure, request).unwrap()
            });
            assert!(
                Arc::ptr_eq(&fill, &hit),
                "second request must hit the policy cache"
            );
            assert_eq!(
                reads.digest(),
                hit_reads.digest(),
                "policy partial-flow hit must replay fill reads"
            );
            signature.push((
                self.served_procedure(&procedure).is_candidate_alternate(),
                (*hit).clone(),
            ));
        }
        signature
    }

    /// Plant a frontier match in the run memo, built by a capture that did or
    /// did not depend on its execution.
    pub(crate) fn plant_match_for_test(
        &self,
        artifact: &SemanticArtifactKey,
        selector: FrontierSelector,
        refusals: Vec<RefusalNotice>,
        gaps: Vec<FrontierGap>,
        execution_dependent: bool,
    ) {
        let capability = memo_attribution(self.workspace.analyzer());
        let entry = ReplayingMemoEntry::capture(&capability, || {
            if execution_dependent {
                self.workspace.analyzer().mark_execution_dependent();
            }
            Arc::new(FrontierMatch {
                by_procedure: HashMap::new(),
                gaps,
                file_slice_executed: true,
                refusals,
            })
        });
        let entry = Arc::new(entry);
        let mut binder = self.binder.borrow_mut();
        let budget = binder.semantic_budget();
        let before = budget.replay_snapshot();
        let admission = budget.memo_admission_since(&before, &entry);
        let entry = Arc::new(AdmittedMemoEntry {
            value: entry,
            admission,
        });
        self.memo.record_refusals(&self.policy, &entry);
        self.memo
            .matches
            .borrow_mut()
            .insert((self.policy.clone(), artifact.clone(), selector), entry);
    }

    /// Record that this provider's search consulted a planted match.
    pub(crate) fn consult_for_test(
        &self,
        artifact: &SemanticArtifactKey,
        selector: FrontierSelector,
    ) {
        let entry = self
            .memo
            .matches
            .borrow()
            .get(&(self.policy.clone(), artifact.clone(), selector))
            .cloned()
            .expect("a test consult has a planted frontier entry");
        self.inputs
            .consulted_matches
            .borrow_mut()
            .insert((artifact.clone(), selector), entry);
    }

    /// The gaps a consult of a planted match sees.
    pub(crate) fn consulted_gaps_for_test(
        &self,
        artifact: &SemanticArtifactKey,
        selector: FrontierSelector,
    ) -> Vec<FrontierGap> {
        let (matched, execution_dependent) = self
            .frontier_match(artifact, selector)
            .expect("a planted match is served from the memo");
        matched.gaps_for(execution_dependent).collect()
    }
}

#[cfg(test)]
impl CompositionMemo {
    /// Each map's name and its count of reads answered from a kept entry.
    pub(crate) fn hit_counts_for_test(&self) -> [(&'static str, u64); 6] {
        let hits = &self.hits;
        [
            ("execution", hits.execution.get()),
            ("matches", hits.matches.get()),
            ("widened", hits.widened.get()),
            ("dispatches", hits.dispatches.get()),
            ("std_builtins", hits.std_builtins.get()),
            ("evidence", hits.evidence.get()),
        ]
    }

    pub(crate) fn dispatch_calls_for_test(&self) -> Vec<DurableCallSiteKey> {
        self.dispatches
            .borrow()
            .values()
            .map(|entry| entry.value().record.0.handle.durable_key())
            .collect()
    }
}

/// One call's dispatch as the composition answers it, with the model that
/// covers the call and the record its diagnostics read. A model closes the
/// run boundary, but a partial finding still needs the call's dispatch evidence.
#[derive(PartialEq, Eq)]
pub(crate) struct MemoizedDispatch {
    pub(crate) dispatch: Dispatch,
    pub(crate) model: Option<CallModel>,
    pub(crate) record: (RecordedDispatch, Box<[DispatchBoundary]>),
}

/// A frontier source's selected site: the policy, the source endpoint, the
/// file and the byte range of the selected row.
type EvidenceKey = (
    PolicyId,
    ResolvedEndpointIdentity,
    ProjectFile,
    usize,
    usize,
);

/// One frontier match as a provider consults it: the blob and the selector.
/// The policy is the provider's own.
type ConsultedMatch = (SemanticArtifactKey, FrontierSelector);

/// A frontier match and the reads of its own build. A widened selection's
/// reads stay in its own [`WidenedRowsEntry`], shared by every blob.
type FrontierMatchEntry = Arc<AdmittedMemoEntry<ReplayingMemoEntry<Arc<FrontierMatch>, ReadKey>>>;
type WidenedRowsEntry = Arc<AdmittedMemoEntry<ReplayingMemoEntry<Arc<WidenedRows>, ReadKey>>>;

/// What one selector bound in one blob.
pub(crate) struct FrontierMatch {
    pub(crate) by_procedure: HashMap<DurableProcedureKey, Vec<FrontierEndpoint>>,
    pub(crate) gaps: Vec<FrontierGap>,
    pub(crate) file_slice_executed: bool,
    /// Per-row refusals must survive an earlier first-cause diagnostic.
    pub(crate) refusals: Vec<RefusalNotice>,
}

impl FrontierMatch {
    fn only_proven_sanitizers(&self) -> bool {
        self.gaps.is_empty()
            && self.refusals.is_empty()
            && !self.by_procedure.is_empty()
            && self.by_procedure.values().all(|endpoints| {
                !endpoints.is_empty() && endpoints.iter().all(FrontierEndpoint::is_proven_sanitizer)
            })
    }

    fn has_same_nonkill_inputs(&self, other: &Self) -> bool {
        if self.file_slice_executed != other.file_slice_executed
            || self.refusals != other.refusals
            || self.gaps != other.gaps
            || other
                .by_procedure
                .keys()
                .any(|key| !self.by_procedure.contains_key(key))
        {
            return false;
        }
        self.by_procedure.iter().all(|(key, endpoints)| {
            if !endpoints.iter().all(|endpoint| {
                !matches!(endpoint, FrontierEndpoint::Sanitizer(_))
                    || endpoint.is_proven_sanitizer()
            }) {
                return false;
            }
            match other.by_procedure.get(key) {
                Some(other_endpoints) => {
                    if other_endpoints
                        .iter()
                        .any(|endpoint| matches!(endpoint, FrontierEndpoint::Sanitizer(_)))
                    {
                        return false;
                    }
                    let mut remaining = endpoints
                        .iter()
                        .filter(|endpoint| !matches!(endpoint, FrontierEndpoint::Sanitizer(_)));
                    other_endpoints.iter().all(|other_endpoint| {
                        remaining
                            .next()
                            .is_some_and(|endpoint| endpoint.has_same_inputs(other_endpoint))
                    }) && remaining.next().is_none()
                }
                None => {
                    !endpoints.is_empty()
                        && endpoints.iter().all(FrontierEndpoint::is_proven_sanitizer)
                }
            }
        })
    }

    /// The match's gaps as one consult sees them. A match built by an
    /// execution-dependent capture certifies nothing about a refused row.
    fn gaps_for(&self, execution_dependent: bool) -> impl Iterator<Item = FrontierGap> + '_ {
        self.gaps.iter().cloned().map(move |gap| {
            if execution_dependent {
                gap.into_operational()
            } else {
                gap
            }
        })
    }
}

/// One unsliceable selector's workspace-wide rows by file, and the reasons
/// its evaluation may have missed a row.
struct WidenedRows {
    by_file: HashMap<ProjectFile, Vec<crate::taint_policy::SelectedSite>>,
    gaps: Vec<FrontierGap>,
}

/// One dispatched call as the composition's diagnostics need it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RecordedDispatch {
    pub(crate) handle: CallSiteHandle,
    pub(crate) status: SemanticInputStatus,
    pub(crate) coverage: CallSiteCoverage,
}

impl MemoizedDispatch {
    fn retained_heap(&self, heap: &mut RetainedHeap) {
        self.dispatch.retained_heap(heap);
        if let Some(model) = &self.model {
            model.retained_heap(heap);
        }
        self.record.0.retained_heap(heap);
        heap.owned_slice(&self.record.1);
        let mut artifacts = RetainedArtifactWalker::new(heap);
        for boundary in &self.record.1 {
            boundary.retained_artifacts(&mut artifacts);
        }
        artifacts.finish();
    }
}

impl RecordedDispatch {
    fn retained_heap(&self, heap: &mut RetainedHeap) {
        heap.vec(&self.coverage.entered);
        heap.vec(&self.coverage.bindings);
        if let brokk_bifrost_flow::value_flow::DispatchStatus::ProviderError { detail } =
            &self.coverage.dispatch
        {
            retained_string(detail, heap);
        }
        for binding in &self.coverage.bindings {
            if let brokk_bifrost_flow::value_flow::BindingCoverage::ProviderError { detail } =
                binding
            {
                retained_string(detail, heap);
            }
        }
        let mut artifacts = RetainedArtifactWalker::new(heap);
        artifacts.procedure(self.handle.procedure());
        for handle in &self.coverage.entered {
            artifacts.procedure(handle);
        }
        artifacts.finish();
    }
}

impl FrontierMatch {
    fn retained_heap(&self, heap: &mut RetainedHeap) {
        heap.map(&self.by_procedure);
        for (procedure, endpoints) in &self.by_procedure {
            retained_procedure_key(procedure, heap);
            heap.vec(endpoints);
            for endpoint in endpoints {
                endpoint.retained_heap(heap);
            }
        }
        heap.vec(&self.gaps);
        for gap in &self.gaps {
            gap.retained_heap(heap);
        }
        heap.vec(&self.refusals);
        for refusal in &self.refusals {
            refusal.retained_heap(heap);
        }
    }
}

impl<'a> PolicyCompositionProvider<'a> {
    pub(crate) fn conditional_declines(&self) -> Vec<SanitizerDecline> {
        self.inputs.conditional_declines.borrow().clone()
    }

    fn conditional_partitions(
        &self,
        handle: &ProcedureHandle,
    ) -> Result<ConditionalPartitions, TaintPolicyCompileError> {
        let hits = Cell::new(0);
        let cached = read_shared(
            self.workspace.analyzer(),
            &self.inputs.conditional_partitions,
            &hits,
            (
                handle.exact_identity(),
                self.plan.value_flow().guard_projection_mode(),
            ),
            |f| f(self.binder.borrow_mut().semantic_budget()),
            || {
                self.served_procedure(&handle.durable_key());
                if !self.binder.borrow().has_conditional_sanitizers()
                    && !self.binder.borrow().has_guard_barriers()
                {
                    return Ok(ConditionalPartitions::default());
                }
                let selected = self.binder.borrow_mut().conditional_in(handle)?;
                let observations = self
                    .plan
                    .value_flow()
                    .sinks()
                    .filter(|(_, sink)| {
                        sink.point().procedure().durable_key() == handle.durable_key()
                    })
                    .map(|(_, sink)| sink.point().id())
                    .collect::<Vec<_>>();
                let policy_guards = self.binder.borrow_mut().guards_in(handle, &observations)?;
                let universe = self.plan.universe();
                let guards = selected
                    .iter()
                    .map(|entry| entry.guard.clone())
                    .collect::<Vec<_>>();
                let derived = conditional_guard_edge_kills(handle, &guards);
                let mut by_sanitizer = vec![Vec::new(); selected.len()];
                for decline in derived.declines {
                    self.inputs
                        .conditional_declines
                        .borrow_mut()
                        .push(SanitizerDecline {
                            sanitizer: selected[decline.sanitizer].id.clone(),
                            point: handle
                                .point_handle(decline.point)
                                .expect("validated guard point"),
                            target: None,
                            reason: decline.reason.into(),
                        });
                }
                for kill in derived.kills {
                    if let Err(reason) = &selected[kill.sanitizer].admission {
                        self.inputs
                            .conditional_declines
                            .borrow_mut()
                            .push(SanitizerDecline {
                                sanitizer: selected[kill.sanitizer].id.clone(),
                                point: handle
                                    .point_handle(kill.kill.point)
                                    .expect("validated guard point"),
                                target: Some(kill.kill.target_point),
                                reason: reason.clone(),
                            });
                    } else {
                        by_sanitizer[kill.sanitizer].push(kill.kill);
                    }
                }
                for decline in &policy_guards.declines {
                    let point = decline
                        .guard
                        .and_then(|id| {
                            handle
                                .semantics()
                                .guard_facts()
                                .iter()
                                .find(|guard| guard.id == id)
                                .map(|guard| guard.point)
                        })
                        .and_then(|point| handle.point_handle(point))
                        .unwrap_or_else(|| {
                            handle
                                .point_handle(handle.semantics().entry_point())
                                .expect("entry point")
                        });
                    self.inputs
                        .conditional_declines
                        .borrow_mut()
                        .push(SanitizerDecline {
                            sanitizer: decline.id.clone(),
                            point,
                            target: None,
                            reason: format!(
                                "guard `{}` is undecided: {:?}",
                                decline.id, decline.reason
                            ),
                        });
                }
                let mut removes = selected
                    .iter()
                    .map(|entry| {
                        entry
                            .removes
                            .iter()
                            .map(|label| label.as_str().to_owned())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                for guard in &policy_guards.bindings {
                    removes.push(
                        guard
                            .removes
                            .taint_labels()
                            .iter()
                            .map(|label| label.to_string())
                            .collect(),
                    );
                    by_sanitizer.push(vec![guard.binding.kill.clone()]);
                }
                if by_sanitizer.iter().all(Vec::is_empty) {
                    return Ok(ConditionalPartitions {
                        guard_declines: policy_guards.declines,
                        ..ConditionalPartitions::default()
                    });
                }
                let mut classes_by_kills: HashMap<
                    Vec<usize>,
                    Vec<&brokk_bifrost_flow::taint::SourceClassId>,
                > = HashMap::new();
                for class in universe.classes() {
                    let kills = removes
                        .iter()
                        .enumerate()
                        .filter_map(|(index, removes)| {
                            (!by_sanitizer[index].is_empty()
                                && removes.iter().any(|label| label == class.as_str()))
                            .then_some(index)
                        })
                        .collect::<Vec<_>>();
                    classes_by_kills.entry(kills).or_default().push(class);
                }
                let all = universe
                    .class_set(universe.classes().iter())
                    .expect("the universe contains its own classes");
                let baseline = classes_by_kills.remove(&Vec::new()).map(|classes| {
                    let keep = universe
                        .class_set(classes)
                        .expect("the universe contains its own classes");
                    TaintEdgeFunction::kill(&all.subtract(&keep))
                });
                let mut groups = classes_by_kills
                    .into_iter()
                    .map(|(indexes, classes)| {
                        let keep = universe
                            .class_set(classes)
                            .expect("the universe contains its own classes");
                        let function = TaintEdgeFunction::kill(&all.subtract(&keep));
                        let kills = indexes
                            .into_iter()
                            .flat_map(|index| by_sanitizer[index].clone())
                            .collect();
                        (function, kills)
                    })
                    .collect::<Vec<_>>();
                groups.sort_by(|left, right| left.0.cmp(&right.0));
                let partitions = ConditionalPartitions {
                    baseline,
                    groups,
                    guard_declines: policy_guards.declines,
                };
                Ok(partitions)
            },
            |_| true,
        )?;
        Ok(cached.clone())
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        workspace: &'a WorkspaceAnalyzer,
        execution_budget: SemanticExecutionBudget,
        cache: &'a DiscoveryMaterializationCache<'a>,
        plan: &'a TaintAnalysisPlan,
        external_models: &'a [BoundExternalModel],
        max_callers_per_procedure: usize,
        binder: FrontierEndpointBinder<'a>,
        memo: &'a CompositionMemo,
    ) -> Self {
        Self {
            inputs: ProviderInputBacking {
                barriers: binder.barriers(),
                endpoint_projections_enabled: binder.has_projected_summary_endpoints()
                    || binder.has_projected_return_sources(),
                ..ProviderInputBacking::default()
            },
            workspace,
            discovery: PolicyDiscoveryProvider::with_dispatch_pool(
                workspace,
                execution_budget.clone(),
                cache,
            ),
            execution_budget: execution_budget.clone(),
            plan,
            external_models,
            max_callers_per_procedure,
            barrier_service: crate::taint_barriers::ValueTypeBarrierService::new(
                workspace,
                execution_budget,
            ),
            barrier_fixpoints: Cell::new(0),
            barrier_procedures: RefCell::new(HashSet::new()),
            barrier_filter: RefCell::new(Box::new(LenientValueTypeBarriers)),
            barrier_chop: RefCell::new(HashSet::new()),
            lenient_chop: RefCell::new(HashSet::new()),
            strict_witnesses: RefCell::new(HashSet::new()),
            stored_reads: Cell::new(0),
            computed: Cell::new(0),
            baseline_reads_cost: ProjectionCounter::default(),
            interior_cost: ProjectionCounter::default(),
            overlay_cost: ProjectionCounter::default(),
            dispatches_made: Cell::new(0),
            policy: binder.policy_id().clone(),
            binder: RefCell::new(binder),
            memo,
            endpoint_evaluations: Cell::new(0),
            endpoint_widened: RefCell::new(Vec::new()),
            source_evidence_resolved: Cell::new(0),
        }
    }

    /// Move the existing admitted query inputs after final source judgment and
    /// diagnostic reads. Ordinary composition simply drops this group with self.
    pub(crate) fn into_input_backing(self) -> ProviderInputBacking {
        self.inputs
    }

    /// Link the compile's selected store ends, once for this query. The
    /// compiled metadata belongs to one policy, so links cannot cross a
    /// policy boundary even when channel names coincide.
    pub(crate) fn with_store_inventory(
        mut self,
        writes: &[CompiledStoreEnd],
        reads: &[CompiledStoreEnd],
    ) -> Self {
        self.inputs
            .store_calls
            .extend(writes.iter().chain(reads).map(|end| end.call.exact_key()));
        self.inputs.store_writes = writes
            .iter()
            .map(|write| StoreWriteObservation {
                procedure: write.call.procedure().durable_key(),
                owner: write.call.procedure().clone(),
                point: write.point.id(),
                phase: write.phase,
                carrier: write.carrier.clone(),
            })
            .collect();
        for read in reads {
            let ValueFlowCarrier::Value(value) = &read.carrier else {
                panic!("a bound store read output has a call-result value carrier")
            };
            let row = read
                .call
                .procedure()
                .semantics()
                .call_site(read.call.id())
                .expect("a selected store read call is live");
            let output =
                brokk_bifrost_flow::composition::result_port(row, read.call.id(), value.id())
                    .expect("a bound store read output is a call result");
            let key = (read.call.procedure().exact_identity(), output);
            self.inputs
                .store_by_read
                .entry(key.clone())
                .or_default()
                .insert(read.channel.store().to_owned());
            let answer = self.inputs.store_links.entry(key).or_default();
            if !matches!(read.proof, ProofStatus::Proven)
                || !matches!(read.completeness, EvidenceCompleteness::Complete)
            {
                answer.incomplete = Some("store read endpoint evidence is incomplete".into());
            }
            for (index, write) in writes.iter().enumerate() {
                if write.channel.may_alias(&read.channel) {
                    if !matches!(write.proof, ProofStatus::Proven)
                        || !matches!(write.completeness, EvidenceCompleteness::Complete)
                    {
                        answer.incomplete =
                            Some("store write endpoint evidence is incomplete".into());
                    }
                    answer.writes.push(StoreChannelLink {
                        write: index,
                        write_call: write.call.durable_key(),
                        read_call: read.call.durable_key(),
                        write_site: write
                            .call
                            .locator()
                            .expect("a selected store write call has a locator")
                            .clone(),
                        read_site: read
                            .call
                            .locator()
                            .expect("a selected store read call has a locator")
                            .clone(),
                        read_origin: brokk_bifrost_flow::taint::SourceEventKey::new(
                            read.event.clone(),
                        ),
                        read_phase: read.phase,
                        read_carrier: read.carrier.clone(),
                        uncertain: !matches!(write.proof, ProofStatus::Proven)
                            || !matches!(write.completeness, EvidenceCompleteness::Complete)
                            || !matches!(read.proof, ProofStatus::Proven)
                            || !matches!(read.completeness, EvidenceCompleteness::Complete),
                    });
                }
            }
        }
        self
    }

    pub(crate) fn excluded_callers(
        &self,
    ) -> std::cell::Ref<'_, [(ProjectFile, brokk_bifrost_analysis::analyzer::Range)]> {
        std::cell::Ref::map(self.inputs.excluded_callers.borrow(), |sites| {
            sites.as_slice()
        })
    }

    fn call_storage_index(
        &self,
        procedure: &ProcedureHandle,
        snapshot: &brokk_bifrost_analysis::analyzer::semantic::ValueFlowSnapshot,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<CallStorageRelationIndex>, TaintPolicyCompileError> {
        let hits = Cell::new(0);
        let request = RefCell::new(request);
        let cached = read_shared(
            self.workspace.analyzer(),
            &self.inputs.call_storage_indexes,
            &hits,
            (
                procedure.exact_identity(),
                snapshot.payload_projection().identity,
                self.plan.value_flow().guard_projection_mode(),
            ),
            |f| f(request.borrow_mut().budget),
            || {
                let mut request_ref = request.borrow_mut();
                let request = &mut **request_ref;
                self.procedure(&procedure.durable_key(), request)?;
                Ok::<_, TaintPolicyCompileError>(Arc::new(CallStorageRelationIndex::new(snapshot)))
            },
            |_| true,
        )?;
        Ok(cached.clone())
    }

    /// Points-to evidence runs for frontier sources so far.
    pub(crate) fn source_evidence_resolved(&self) -> u64 {
        self.source_evidence_resolved.get()
    }

    /// Sliced selector evaluations run so far.
    pub(crate) fn endpoint_evaluations(&self) -> u64 {
        self.endpoint_evaluations.get()
    }

    /// The selectors that could not be sliced and why, in the order they
    /// were first evaluated.
    pub(crate) fn endpoint_widened(&self) -> Vec<(FrontierSelector, WidenReason)> {
        self.endpoint_widened.borrow().clone()
    }

    /// The origin metadata of every source the frontier matched.
    pub(crate) fn frontier_sources(&self) -> Vec<CompiledTaintEndpoint> {
        self.inputs.frontier_sources.borrow().clone()
    }

    pub(crate) fn frontier_source_count(&self) -> usize {
        self.inputs.frontier_sources.borrow().len()
    }

    /// Stores whose read outputs the current anchor search consulted, even
    /// when no writer reached that read and the anchor stayed clean.
    pub(crate) fn consulted_stores(&self) -> Vec<String> {
        let mut stores = self
            .inputs
            .consulted_stores
            .borrow()
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        stores.sort();
        stores
    }

    /// What `selector` bound in the blob `artifact`, evaluated once per blob
    /// in the run: sliced to the blob when the selector's query allows it,
    /// otherwise from the selector's workspace-wide rows of that file. The flag
    /// is whether the build of the match depended on its execution; if it did,
    /// no refusal or refusal-derived gap in the match is content.
    fn frontier_match(
        &self,
        artifact: &SemanticArtifactKey,
        selector: FrontierSelector,
    ) -> Result<(Arc<FrontierMatch>, bool), TaintPolicyCompileError> {
        // A hit and a build both make this Output depend on the admitted
        // match. Keep that actual owner when the read below succeeds; the
        // lookup still replays its build reads into this Output's capture.
        let key = (self.policy.clone(), artifact.clone(), selector);
        let capability = memo_attribution(self.workspace.analyzer());
        // A widened selection is one workspace answer for every blob. Read it
        // outside the per-blob entry: each use replays the shared entry's reads
        // into the current capture, and no blob entry retains a copy of them.
        let reason = self.binder.borrow().widen_reason(selector)?;
        let widened = reason
            .map(|reason| self.widened_rows(selector, reason))
            .transpose()?;
        let mut execution_dependent = false;
        let result = ReplayingMemo::new(()).read(&capability, |_, capture| {
            let entry = read_admitted(
                &self.memo.matches,
                key,
                None,
                |f| f(self.binder.borrow_mut().semantic_budget()),
                || {
                    capture.try_build(|| {
                        self.build_frontier_match(artifact, selector, widened.as_ref())
                    })
                },
                |_| true,
                || self.memo.hits.matches.set(self.memo.hits.matches.get() + 1),
            )?;
            execution_dependent = entry.execution_dependent();
            self.memo.record_refusals(&self.policy, &entry);
            self.inputs
                .consulted_matches
                .borrow_mut()
                .insert((artifact.clone(), selector), Arc::clone(&entry));
            Ok::<_, TaintPolicyCompileError>(Arc::clone(&entry.value))
        })?;
        Ok((Arc::clone(&result), execution_dependent))
    }

    /// The selector's workspace-wide rows, evaluated once per policy run. The
    /// read replays the shared entry's reads into the current capture.
    fn widened_rows(
        &self,
        selector: FrontierSelector,
        reason: crate::units::WidenReason,
    ) -> Result<Arc<WidenedRows>, TaintPolicyCompileError> {
        let widened_key = (self.policy.clone(), selector);
        let capability = memo_attribution(self.workspace.analyzer());
        ReplayingMemo::new(())
            .read(&capability, |_, capture| {
                let entry = read_admitted(
                    &self.memo.widened,
                    widened_key,
                    None,
                    |f| f(self.binder.borrow_mut().semantic_budget()),
                    || {
                        capture.try_build(|| {
                            let mut binder = self.binder.borrow_mut();
                            self.endpoint_widened.borrow_mut().push((selector, reason));
                            let _timing = brokk_bifrost_analysis::profiling::scope(
                                "taint.compose.endpoints.widened",
                            );
                            let mut by_file: HashMap<ProjectFile, Vec<_>> = HashMap::new();
                            for site in binder.select_workspace(selector)? {
                                by_file.entry(site.file.clone()).or_default().push(site);
                            }
                            // Gaps of the one workspace-wide evaluation belong
                            // to every blob it answers.
                            let gaps = binder.bind(selector, Vec::new())?.gaps;
                            Ok::<_, TaintPolicyCompileError>(Arc::new(WidenedRows {
                                by_file,
                                gaps,
                            }))
                        })
                    },
                    |_| true,
                    || self.memo.hits.widened.set(self.memo.hits.widened.get() + 1),
                )?;
                Ok(Arc::clone(&entry.value))
            })
            .map(|rows| Arc::clone(&rows))
    }

    fn build_frontier_match(
        &self,
        artifact: &SemanticArtifactKey,
        selector: FrontierSelector,
        widened: Option<&Arc<WidenedRows>>,
    ) -> Result<Arc<FrontierMatch>, TaintPolicyCompileError> {
        let root = self.workspace.analyzer().project().root();
        let file = ProjectFile::new(root.to_path_buf(), artifact.path().as_path());
        let mut binder = self.binder.borrow_mut();
        let (sites, mut gaps, file_slice_executed) = match widened {
            None => {
                self.endpoint_evaluations
                    .set(self.endpoint_evaluations.get() + 1);
                let _timing =
                    brokk_bifrost_analysis::profiling::scope("taint.compose.endpoints.select");
                (binder.select_in_file(selector, &file)?, Vec::new(), true)
            }
            Some(rows) => (
                rows.by_file.get(&file).cloned().unwrap_or_default(),
                rows.gaps.clone(),
                false,
            ),
        };
        let bound = {
            let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.endpoints.bind");
            binder.bind(selector, sites)?
        };
        gaps.extend(bound.gaps);
        let mut by_procedure: HashMap<DurableProcedureKey, Vec<FrontierEndpoint>> = HashMap::new();
        for endpoint in bound.endpoints {
            by_procedure
                .entry(endpoint.procedure())
                .or_default()
                .push(endpoint);
        }
        let matched = Arc::new(FrontierMatch {
            by_procedure,
            gaps,
            file_slice_executed,
            refusals: bound.refusals,
        });
        Ok(matched)
    }

    /// Refusals of this search only, including on the fresh projection path.
    pub(crate) fn refusal_messages(&self) -> Vec<RefusalNotice> {
        self.consulted_refusal_messages()
    }

    /// The refusals of the frontier matches this provider's search consulted:
    /// the rows of the blobs and selectors one Output depends on, however the
    /// run memo came to hold them. Unlike [`Self::refusal_messages`] the answer
    /// is the same whichever Outputs of the run were computed first.
    pub(crate) fn consulted_refusal_messages(&self) -> Vec<RefusalNotice> {
        merged_refusals(self.inputs.consulted_matches.borrow().values())
    }

    /// Observed source-selector evaluations, including those served by the run memo.
    pub(crate) fn source_gap_observations(&self) -> Vec<(usize, String, bool, Vec<String>)> {
        self.memo
            .matches
            .borrow()
            .iter()
            .filter_map(|((policy, artifact, selector), matched)| {
                let super::taint_policy::FrontierSelector::Source(index) = selector else {
                    return None;
                };
                (policy == &self.policy).then(|| {
                    (
                        *index,
                        artifact
                            .path()
                            .as_path()
                            .to_string_lossy()
                            .replace('\\', "/"),
                        matched.value().file_slice_executed,
                        matched
                            .value()
                            .gaps
                            .iter()
                            .map(|gap| gap.message.clone())
                            .collect(),
                    )
                })
            })
            .collect()
    }

    /// The partial-flow answers so far: `(read from the store, computed at
    /// query time)`.
    pub(crate) fn partial_flow_counts(&self) -> (u64, u64) {
        (self.stored_reads.get(), self.computed.get())
    }

    pub(crate) fn projection_counts(&self) -> ((u64, u64), (u64, u64), (u64, u64)) {
        (
            self.baseline_reads_cost.totals(),
            self.interior_cost.totals(),
            self.overlay_cost.totals(),
        )
    }

    pub(crate) fn barrier_work_counts(&self) -> (u64, u64, usize) {
        (
            self.barrier_service.checks(),
            self.barrier_fixpoints.get(),
            self.barrier_procedures.borrow().len(),
        )
    }

    /// The calls this provider dispatched: every distinct call the search
    /// or the openness refinement asked about that the run memo did not
    /// already hold.
    pub(crate) fn dispatches_made(&self) -> usize {
        self.dispatches_made.get()
    }

    /// The handle, dispatch status and coverage of a call this provider
    /// dispatched. `None` for a call it never dispatched.
    pub(crate) fn dispatched_call(
        &self,
        call: &DurableCallSiteKey,
    ) -> Option<(CallSiteHandle, SemanticInputStatus, CallSiteCoverage)> {
        let served = self.inputs.served.borrow();
        let owner = served.values().find(|entry| {
            let key = entry.value().durable_key();
            key.0 == call.0.0 && key.1 == call.0.1
        })?;
        self.inputs
            .dispatched
            .borrow()
            .get(&(owner.value().exact_identity(), call.1))
            .map(|recorded| {
                (
                    recorded.handle.clone(),
                    recorded.status,
                    recorded.coverage.clone(),
                )
            })
    }

    /// The coverage and boundaries of every dispatch this provider recorded,
    /// in the shape the ICFG engine's call-resolution diagnostic reads.
    pub(crate) fn call_resolution_discovery(&self) -> CallResolutionDiscoveryEvidence {
        CallResolutionDiscoveryEvidence {
            coverage: self
                .inputs
                .dispatched
                .borrow()
                .values()
                .map(|recorded| (recorded.handle.durable_key(), recorded.coverage.clone()))
                .collect(),
            boundaries: self.inputs.dispatch_boundaries.borrow().clone(),
        }
    }

    /// The first failure this provider hit.
    pub(crate) fn failure(&self) -> Option<TaintPolicyCompileError> {
        self.discovery.poisoned()
    }

    /// The semantic budget refusal behind [`Self::failure`], when the first
    /// failure was one.
    pub(crate) fn discovery_stop(&self) -> Option<crate::taint_policy::DiscoveryStop> {
        self.discovery.stop()
    }

    /// The live handle of a procedure whose flows this provider served. Its
    /// artifact is the compile's canonical instance, already materialized.
    pub(crate) fn served_procedure(&self, key: &DurableProcedureKey) -> ProcedureHandle {
        let capability = memo_attribution(self.workspace.analyzer());
        ReplayingMemo::new(())
            .read(&capability, |_, _| {
                Ok::<_, std::convert::Infallible>(
                    self.inputs
                        .served
                        .borrow()
                        .values()
                        .find(|entry| {
                            let selected = entry.value().durable_key();
                            selected.0 == key.0 && selected.1 == key.1
                        })
                        .map(|entry| Arc::clone(&entry.value))
                        .expect("served flows have a selected procedure handle"),
                )
            })
            .unwrap()
            .clone()
    }

    fn payload_flow_key(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<PayloadProcedureKey, TaintPolicyCompileError> {
        let handle = self.procedure(key, request)?;
        let projection = self
            .discovery
            .payload_projection_identity(&handle, request)?;
        self.discovery
            .require_outcome(&projection, "payload projection identity")?;
        Ok((
            handle.exact_identity(),
            projection.available_value().copied().flatten(),
            self.plan.value_flow().guard_projection_mode(),
        ))
    }

    fn procedure(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureHandle, TaintPolicyCompileError> {
        let (selected, receipt) =
            brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt::capture(
                self.workspace.analyzer(),
                || self.discovery.selected_procedure(key, request),
            );
        let selected = selected?;
        let hits = Cell::new(0);
        let request = RefCell::new(request);
        let handle = read_shared(
            self.workspace.analyzer(),
            &self.inputs.served,
            &hits,
            selected.exact_identity(),
            |f| f(request.borrow_mut().budget),
            || {
                receipt.replay(self.workspace.analyzer());
                Ok::<_, TaintPolicyCompileError>(selected)
            },
            |_| true,
        )?;
        Ok(handle.clone())
    }
}

/// The default filter keeps undecided values and removes only a proven
/// predicate match. Its classifier and request are borrowed for one fixpoint;
/// neither the filter nor its answers survive the query.
struct ProcedureBarrierFilter<'a, 'w> {
    provider: &'a PolicyCompositionProvider<'w>,
    procedure: &'a ProcedureHandle,
}

impl ObservationFilter for ProcedureBarrierFilter<'_, '_> {
    type Error = TaintPolicyCompileError;

    fn permits(
        &mut self,
        point: ProgramPointId,
        phase: ObservationPhase,
        endpoint: &ValueFlowEndpoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, Self::Error> {
        let value = observation_value(endpoint);
        let Some(value) = value else {
            return Ok(true);
        };
        let observation = BarrierObservation::new(
            self.procedure
                .point_handle(point)
                .expect("a fixpoint point is live"),
            value,
            phase,
        );
        for (_, predicate) in &self.provider.inputs.barriers {
            let decision =
                self.provider
                    .barrier_service
                    .classify(&observation, *predicate, request)?;
            if !self.provider.barrier_filter.borrow().permits(decision) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl PolicyCompositionProvider<'_> {
    fn source_root_interiors(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<InteriorFlows>, TaintPolicyCompileError> {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.interior");
        let interior_cpu_start = ProjectionCounter::start();
        let handle = self.procedure(procedure, request)?;
        handle
            .validate_durable_locator(procedure)
            .map_err(TaintPolicyCompileError::CandidateLocatorRefusal)?;
        let outcome =
            self.discovery
                .procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
        let Some(snapshot) = outcome.available_value() else {
            self.interior_cost.record(interior_cpu_start);
            return Ok(vec![
                brokk_bifrost_flow::composition::unavailable_snapshot_interior(
                    handle,
                    SemanticInputStatus::from_outcome(&outcome),
                    "the procedure's value-flow snapshot is unavailable",
                ),
            ]);
        };
        let flows = brokk_bifrost_flow::composition::interior_source_root_products(
            self,
            handle,
            snapshot,
            seeds,
            observations,
            witnesses,
            &[],
            &self.execution_budget,
            request,
        )?;
        self.interior_cost.record(interior_cpu_start);
        Ok(flows)
    }
}

impl PolicyCompositionProvider<'_> {
    fn stored_source_root_interiors(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<InteriorFlows>, TaintPolicyCompileError> {
        if self.inputs.barriers.is_empty() {
            return self.source_root_interiors(procedure, seeds, observations, witnesses, request);
        }
        let interior_cpu_start = ProjectionCounter::start();
        let handle = self.procedure(procedure, request)?;
        handle
            .validate_durable_locator(procedure)
            .map_err(TaintPolicyCompileError::CandidateLocatorRefusal)?;
        let outcome = file_local_procedure_relations(&handle, &OracleCallContext::empty(), request)
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        let Some(snapshot) = outcome.available_value() else {
            self.interior_cost.record(interior_cpu_start);
            return Ok(vec![
                brokk_bifrost_flow::composition::unavailable_snapshot_interior(
                    handle,
                    SemanticInputStatus::from_outcome(&outcome),
                    "file-local witness relations are unavailable",
                ),
            ]);
        };
        let flows = brokk_bifrost_flow::composition::interior_source_root_products(
            self,
            handle,
            snapshot,
            seeds,
            observations,
            witnesses,
            &[],
            &self.execution_budget,
            request,
        )?;
        self.interior_cost.record(interior_cpu_start);
        Ok(flows)
    }
}

impl brokk_bifrost_flow::composition::InteriorProjectionClient for PolicyCompositionProvider<'_> {
    type Error = TaintPolicyCompileError;

    fn selected_entry_workspace(&self) -> &WorkspaceAnalyzer {
        self.workspace
    }

    fn record_value_obligation_accounting(
        &self,
        handle: &ProcedureHandle,
        gaps: &[brokk_bifrost_analysis::analyzer::semantic::GapKey],
        request: &mut SemanticRequest<'_>,
    ) {
        if gaps.is_empty() {
            return;
        }
        let mut accounted = self.inputs.value_obligation_accounting.borrow_mut();
        if accounted.contains_key(&handle.exact_identity()) {
            return;
        }
        if request
            .budget
            .admit(brokk_bifrost_analysis::analyzer::semantic::SemanticWork {
                nested_entries: gaps.len().saturating_add(1),
                ..Default::default()
            })
            .is_err()
        {
            return;
        }
        accounted.insert(handle.exact_identity(), gaps.into());
    }
    fn implicit_heap_reads(&self) -> bool {
        self.binder.borrow().analysis_type() == crate::definition::PolicyAnalysisType::Taint
    }

    #[allow(clippy::too_many_arguments)]
    fn run_interior_fixpoint(
        &self,
        handle: &ProcedureHandle,
        snapshot: &brokk_bifrost_analysis::analyzer::semantic::ValueFlowSnapshot,
        seeds: &[ExtraSeed],
        observations: &[ExtraObservation],
        witnesses: bool,
        implicit_reads: &[ImplicitHeapRead],
        edge_kills: &[GuardEdgeKill],
        request: &mut SemanticRequest<'_>,
    ) -> Result<ExtendedPartialFlows, Self::Error> {
        let procedure = handle.durable_key();
        if !edge_kills.is_empty()
            || self.plan.value_flow().guard_projection_mode()
                == GuardProjectionMode::PolicyProvedOnly
        {
            compute_partial_flows_in_mode(
                handle,
                snapshot,
                seeds,
                observations,
                witnesses,
                implicit_reads,
                edge_kills,
                self.plan.value_flow().guard_projection_mode(),
                &mut ProcedureBarrierFilter {
                    provider: self,
                    procedure: handle,
                },
                request,
            )
        } else if self.barrier_chop.borrow().contains(&procedure) {
            let _timing = brokk_bifrost_analysis::profiling::scope("taint.barriers.fixpoint");
            self.barrier_fixpoints.set(self.barrier_fixpoints.get() + 1);
            self.barrier_procedures.borrow_mut().insert(procedure);
            compute_partial_flows_filtered(
                handle,
                snapshot,
                seeds,
                observations,
                witnesses,
                implicit_reads,
                &mut ProcedureBarrierFilter {
                    provider: self,
                    procedure: handle,
                },
                request,
            )
        } else {
            Ok(compute_partial_flows_with_implicit_reads(
                handle,
                snapshot,
                seeds,
                observations,
                witnesses,
                implicit_reads,
                request,
            ))
        }
    }
}

impl brokk_bifrost_flow::composition::CallModelSource for PolicyCompositionProvider<'_> {
    type Error = TaintPolicyCompileError;
    type Function = TaintEdgeFunction;

    fn boundary_member_rows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Arc<ProcedurePartialFlows>>, Self::Error> {
        Ok(Some(self.partial_flows(procedure, request)?))
    }

    fn canonical_returned_field(
        &self,
        callee: &DurableProcedureKey,
        caller: &DurableProcedureKey,
        declared: &brokk_bifrost_analysis::analyzer::semantic::SemanticLocator,
        request: &mut SemanticRequest<'_>,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::SemanticLocator> {
        <Self as CompositionProvider>::canonical_returned_field(
            self, callee, caller, declared, request,
        )
    }

    fn dispatch_model(
        &self,
        call: &CallSiteHandle,
        answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<brokk_bifrost_flow::composition::CallModelDecision<Self::Function>, Self::Error>
    {
        if self.inputs.store_calls.contains(&call.exact_key()) {
            // A selected store end replaces this call's value transfer.
            return Ok(brokk_bifrost_flow::composition::CallModelDecision {
                model: Some(CallModel {
                    endpoint_projections: false,
                    summary: None,
                    summary_target: None,
                    transfers: Vec::new(),
                    writeback: Box::default(),
                    receiver_reads: Box::default(),
                    proven: true,
                    completeness: Completeness::Complete,
                    retains_dispatch: false,
                    authored: None,
                }),
                continuation: HopQuality::CERTAIN,
            });
        }
        let models = self.call_models(call, answer)?;
        // Use the ordinary summary-to-call-model application for each
        // adjustment, with its return bound to the original receiver port.
        // All admitted records are complete Identity summaries. Fold only the
        // resulting proven identity self-transfer; keeping it as a receiver
        // write would incorrectly manufacture a mutation for a read-only view.
        if let Some(summaries) = &models.summaries {
            for step in summaries.receiver_adjustments_for_call(call) {
                let summary = summaries
                    .summary_for(&step.summary_locator())
                    .ok_or_else(|| {
                        TaintPolicyCompileError::Model(
                            "receiver adjustment lost its bound summary".to_owned(),
                        )
                    })?;
                let projected = call_model(
                    call,
                    summary.transfers(),
                    summary.effects(),
                    SummaryCallBinding::receiver_adjustment(),
                    true,
                    None,
                    self.plan.universe(),
                );
                // Ordinary model rows retain authored (not derived) proof
                // status. The selected complete std contract authorizes this
                // adjustment; do not promote its transfer evidence to Proven.
                if !projected.completeness.is_complete()
                    || !matches!(projected.transfers.as_slice(), [transfer]
                        if transfer.actual == transfer.output
                            && transfer.function == taint_model_kill(self.plan.universe(), &[]))
                {
                    return Err(TaintPolicyCompileError::Model(
                        "receiver adjustment is not a complete identity self-transfer".to_owned(),
                    ));
                }
            }
        }
        let model = covering_model(
            &models,
            call,
            answer.available_value(),
            self.plan.universe(),
        );
        let continuation =
            continuation_quality(&models, model.as_ref(), call, answer.available_value());
        Ok(brokk_bifrost_flow::composition::CallModelDecision {
            continuation,
            model,
        })
    }

    fn covers_caller_candidate(
        &self,
        call: &CallSiteHandle,
        answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<bool, Self::Error> {
        let models = self.call_models(call, answer)?;
        Ok(covering_model(
            &models,
            call,
            answer.available_value(),
            self.plan.universe(),
        )
        .is_some_and(|model| !model.retains_dispatch))
    }
}

impl brokk_bifrost_flow::composition::LocalOpennessClient<PolicyDiscoveryProvider<'_, '_>>
    for PolicyCompositionProvider<'_>
{
    fn value_obligation_accounted(
        &self,
        handle: &ProcedureHandle,
        gap: brokk_bifrost_analysis::analyzer::semantic::GapKey,
    ) -> bool {
        self.inputs
            .value_obligation_accounting
            .borrow()
            .get(&handle.exact_identity())
            .is_some_and(|gaps| gaps.contains(&gap))
    }
    fn relations_head(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, TaintPolicyCompileError> {
        self.partial_flows(procedure, request)
    }

    fn openness_sweep(
        &self,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, TaintPolicyCompileError> {
        self.openness_sweep(handle, request)
    }

    fn dispatch_completeness(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Completeness, TaintPolicyCompileError> {
        Ok(self.dispatch(call, request)?.0.completeness)
    }
}

impl CompositionProvider for PolicyCompositionProvider<'_> {
    type Error = TaintPolicyCompileError;
    type Fact = TaintClassSet;
    type Function = TaintEdgeFunction;

    fn candidate_input_support(
        &self,
    ) -> brokk_bifrost_flow::taint::compose::CompositionProviderInputSupport {
        brokk_bifrost_flow::taint::compose::CompositionProviderInputSupport::PolicyInputs
    }

    fn endpoint_projections_enabled(&self) -> bool {
        self.inputs.endpoint_projections_enabled
    }

    fn certify_model_content_refusal(
        &self,
        request: &mut SemanticRequest<'_>,
    ) -> brokk_bifrost_flow::taint::compose::IncompleteCause {
        use brokk_bifrost_flow::taint::compose::{IncompleteCause, OperationalCause};
        if request.cancellation.is_cancelled() {
            return IncompleteCause::Operational(OperationalCause::Cancelled);
        }
        if request.stop_observed() {
            return IncompleteCause::Operational(OperationalCause::Budget(
                brokk_bifrost_flow::taint::compose::BudgetLane::Semantic,
            ));
        }
        // Opening a local capture makes the certificate depend on an actual
        // recorded read even for an ephemeral query. capture_query_reads also
        // forwards it into the consuming Output receipt, on fills and memo hits.
        // Acquisition errors never construct a compiler: prepare_in_range
        // admits only Ok(snapshot), so absence here is an input fact.
        let (key, receipt) = brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(
            self.workspace.analyzer(),
            || self.binder.borrow().record_model_content_read(),
        );
        if receipt.keys().contains(&key) {
            IncompleteCause::Content
        } else {
            IncompleteCause::Operational(OperationalCause::Provider)
        }
    }

    fn acquisition_refusal(
        &self,
        error: &Self::Error,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::CandidateLocatorRefusal> {
        self.discovery.locator_refusal(error)
    }

    fn execution_discovery<E>(
        &self,
        budget: brokk_bifrost_flow::taint::compose::CompositionBudget,
        request: &mut SemanticRequest<'_>,
        build: impl FnOnce(
            &mut SemanticRequest<'_>,
        ) -> Result<
            (
                Vec<brokk_bifrost_flow::taint::compose::ExecutionReach>,
                Vec<brokk_bifrost_flow::taint::compose::Incompleteness>,
            ),
            E,
        >,
    ) -> Result<ExecutionDiscovery, E> {
        let key = (
            self.policy.clone(),
            budget.max_procedures,
            budget.max_hops,
            budget.max_callers_per_procedure,
        );
        let request = RefCell::new(request);
        self.memo.execution_discovery(
            self.workspace.analyzer(),
            key,
            |f| f(request.borrow_mut().budget),
            || build(&mut request.borrow_mut()),
        )
    }

    fn admitted_execution_roots(
        &self,
        max_examined: usize,
        request: &mut SemanticRequest<'_>,
    ) -> Result<brokk_bifrost_flow::taint::compose::ExecutionRootInventory, Self::Error> {
        let (roots, causes) =
            PolicyCompositionProvider::admitted_execution_roots(self, max_examined, request)?;
        Ok(brokk_bifrost_flow::taint::compose::ExecutionRootInventory {
            roots,
            coverage: if causes.is_empty() {
                Completeness::Complete
            } else {
                Completeness::operational(
                    brokk_bifrost_flow::taint::compose::OperationalCause::Provider,
                    brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
                        format_args!("{}", causes.join("; ")),
                        format_args!("execution root inventory is incomplete"),
                        causes.iter(),
                    ),
                )
            },
        })
    }

    fn invocations(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Invocations, Self::Error> {
        let handle = self.procedure(procedure, request)?;
        let semantics = handle.semantics();
        let mut reasons = Vec::new();
        for capability in [SemanticCapability::Procedures, SemanticCapability::Calls] {
            if !handle.artifact().capabilities().is_available(capability) {
                reasons.push(format!("unavailable execution capability {capability:?}"));
            }
        }
        // A gap the lowering left because it ran out of budget is a budget
        // stop: a larger budget can lower the body fully.
        let mut budget_gap = false;
        let mut inert_drop = None;
        let mut allocation_lifetimes = None;
        let oracle = self.workspace.semantic_oracle_provider();
        for logical in semantics.logical_gaps() {
            let gap = logical.base;
            // Persisted cleanup gaps are obligations, not missing invocations.
            // Use the same Rust-only, per-value proof as the ICFG consumer.
            if brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::logical_gap_is_discharged(
                &oracle, logical, &handle, request, &mut inert_drop,
            ).map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))? == brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::GapDischargeVerdict::Discharged {
                continue;
            }
            if (gap.capability == SemanticCapability::Calls
                && !matches!(gap.subject, SemanticGapSubject::CallSite(_)))
                || gap.impacts.contains(SemanticGapImpact::CallEvaluation)
            {
                // An allocation lifetime gap the workspace resolver retires
                // (#11428) leaves no execution unrepresented either.
                if logical.member.is_none() {
                    let lifetime_verdict = brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::RelationProjectionHost::allocation_lifetime_discharged(
                        &oracle, gap, &handle, request, &mut allocation_lifetimes,
                    ).map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
                    if lifetime_verdict == brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::GapDischargeVerdict::Discharged {
                        continue;
                    }
                    // A proof the request budget refused is a budget stop, not
                    // content incompleteness: a larger budget can discharge it.
                    budget_gap |= lifetime_verdict == brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::GapDischargeVerdict::RefusedByRequestLimit;
                }
                budget_gap |= gap.kind == SemanticGapKind::ExceededBudget;
                reasons.push(format!(
                    "execution gap at point {:?}: capability {:?}, kind {:?}",
                    gap.point, gap.capability, gap.kind
                ));
            }
        }
        reasons.sort();
        // This is an inventory of body-owned calls, not lexical children.
        // The finite cap also bounds one provider answer before the search
        // applies its total hop budget.
        const MAX_INVOCATIONS: usize = 512;
        if semantics.call_sites().len() > MAX_INVOCATIONS {
            reasons.push("execution invocation inventory exceeded 512 calls".to_owned());
        }
        let sites = semantics
            .call_sites()
            .iter()
            .take(MAX_INVOCATIONS)
            .map(|call| InvocationSite {
                call: (handle.durable_key(), call.id),
                source_site: call.id,
                mode: call.invocation_mode,
            })
            .collect();
        Ok(Invocations {
            sites,
            coverage: if reasons.is_empty() {
                Completeness::Complete
            } else {
                if semantics.call_sites().len() > MAX_INVOCATIONS {
                    Completeness::operational(
                        brokk_bifrost_flow::taint::compose::OperationalCause::Budget(
                            brokk_bifrost_flow::taint::compose::BudgetLane::Hops,
                        ),
                        brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
                            format_args!("{reasons:?}"),
                            format_args!("invocation inventory is incomplete"),
                            reasons.iter(),
                        ),
                    )
                } else if budget_gap {
                    Completeness::operational(
                        brokk_bifrost_flow::taint::compose::OperationalCause::Budget(
                            brokk_bifrost_flow::taint::compose::BudgetLane::Semantic,
                        ),
                        brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
                            format_args!("{reasons:?}"),
                            format_args!("invocation inventory is incomplete"),
                            reasons.iter(),
                        ),
                    )
                } else {
                    Completeness::content(
                        brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
                            format_args!("{reasons:?}"),
                            format_args!("invocation inventory is incomplete"),
                            reasons.iter(),
                        ),
                    )
                }
            },
        })
    }

    fn execution_dispatch(
        &self,
        call: &DurableCallSiteKey,
        incoming: Option<&brokk_bifrost_flow::taint::compose::ExecutionArmContext>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ExecutionDispatch<Self::Function>, Self::Error> {
        let oracle = self.workspace.semantic_oracle_provider();
        let mut prior_calls = Vec::new();
        if let Some(incoming) = incoming {
            for step in incoming.certificate.prefix.iter() {
                let owner = self.procedure(&step.call.0, request)?;
                prior_calls.push(
                    owner
                        .resolve_durable_call(&step.call)
                        .map_err(TaintPolicyCompileError::CandidateLocatorRefusal)?
                        .expect("an execution prefix names an existing call"),
                );
            }
        }
        let context = OracleCallContext::bounded(prior_calls, *oracle.limits());
        let (site, answer) = if incoming.is_some() {
            let handle = self.procedure(&call.0, request)?;
            let site = handle
                .resolve_durable_call(call)
                .map_err(TaintPolicyCompileError::CandidateLocatorRefusal)?
                .expect("an invocation row belongs to its procedure");
            let answer = oracle
                .resolve_call_in_context(&site, &context, request)
                .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
            (site, answer)
        } else {
            let raw = CallStructureProvider::dispatch(&self.discovery, call, request)?;
            (raw.handle, raw.answer)
        };
        let handle = site.procedure().clone();
        let row = handle
            .semantics()
            .call_site(call.1)
            .expect("an invocation row belongs to its procedure");
        let result = answer.available_value();
        let coverage = result.map_or(CandidateCoverage::Open, |result| result.coverage());
        // A singleton complete target set is a restriction of this
        // invocation certificate, not a claim about existential paths in
        // general. Unresolved and multiple-arm dispatches remain open.
        let candidate = result.and_then(|result| {
            if !answer.is_complete()
                || result.coverage() != CandidateCoverage::Exhaustive
                || !result.boundaries().is_empty()
            {
                return None;
            }
            let [candidate] = result.candidates() else {
                return None;
            };
            (candidate.proof() == &ProofStatus::Proven
                && candidate.completeness() == &EvidenceCompleteness::Complete)
                .then_some(candidate)
        });
        // A budget or cancellation stop while proving the callable instance
        // is operational too; without it the arm would look complete.
        let mut instance_stop = None;
        let instance = if let Some(candidate) = candidate
            && candidate.target().semantics().lexical_parent().is_some()
        {
            if let Some(returned) = result.and_then(DispatchResult::returned_callable)
                && returned.closure().durable_key() == candidate.target().durable_key()
            {
                Some(ExecutionCallableInstance {
                    producer: returned.producer_callee().durable_key(),
                    creation_point: returned.creation_point(),
                    creation_event_index: returned.creation_event_index(),
                    creation_value: returned.creation_value(),
                    capture_bindings: returned.capture_bindings().into(),
                    factory_call: Some(returned.producer().durable_key()),
                })
            } else {
                let local = self
                    .workspace
                    .semantic_oracle_provider()
                    .local_callable_target(&handle, row.callee, request)
                    .map_err(|error| {
                        TaintPolicyCompileError::SemanticProvider(error.to_string())
                    })?;
                match local {
                    SemanticOutcome::Complete {
                        value: Some(local), ..
                    } if local.closure.durable_key() == candidate.target().durable_key() => {
                        Some(ExecutionCallableInstance {
                            producer: handle.durable_key(),
                            creation_point: local.creation_point,
                            creation_event_index: local.creation_event_index,
                            creation_value: local.creation.id(),
                            capture_bindings: local.capture_bindings,
                            factory_call: None,
                        })
                    }
                    SemanticOutcome::ExceededBudget { exceeded, .. } => {
                        instance_stop = Some(ExecutionDispatchOutcome::Budget(
                            format!("{exceeded:?}").into(),
                        ));
                        None
                    }
                    SemanticOutcome::Cancelled { .. } => {
                        instance_stop = Some(ExecutionDispatchOutcome::Cancelled(
                            "callable instance lookup cancelled".into(),
                        ));
                        None
                    }
                    _ => None,
                }
            }
        } else {
            None
        };
        Ok(ExecutionDispatch {
            arms: candidate
                .map(|candidate| ExecutionArm {
                    target: ExecutionTarget::Procedure(Box::new(candidate.target().durable_key())),
                    function: TaintEdgeFunction::identity(self.plan.universe()),
                    quality: HopQuality::CERTAIN,
                    timing: row.execution_timing,
                    instance,
                    context: DurableCallContext::of(&context)
                        .expect("a resolved call context has a durable identity"),
                })
                .into_iter()
                .collect(),
            residuals: result
                .into_iter()
                .flat_map(|result| {
                    result
                        .boundaries()
                        .iter()
                        .map(|boundary| boundary.kind.clone())
                })
                .collect(),
            coverage,
            // A budget or cancellation stop in call resolution is operational,
            // even when it left no truncated candidate set behind.
            outcome: match &answer {
                SemanticOutcome::ExceededBudget { exceeded, .. } => {
                    ExecutionDispatchOutcome::Budget(format!("{exceeded:?}").into())
                }
                SemanticOutcome::Cancelled { .. } => {
                    ExecutionDispatchOutcome::Cancelled("call resolution cancelled".into())
                }
                _ => instance_stop.unwrap_or_else(|| {
                    if candidate.is_some() {
                        ExecutionDispatchOutcome::Complete
                    } else {
                        ExecutionDispatchOutcome::Unsupported(
                            "no exact singleton invocation".into(),
                        )
                    }
                }),
            },
        })
    }

    fn execution_endpoints(
        &self,
        _target: &ExecutionTarget,
        _incoming: Option<&brokk_bifrost_flow::taint::compose::ExecutionArmContext>,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ExecutionEndpoints<Self::Fact>, Self::Error> {
        Ok(ExecutionEndpoints {
            sources: Vec::new(),
            status: ExecutionEndpointStatus::Absent,
            covers_overrides: false,
        })
    }

    fn store_writes(&self) -> Vec<StoreWriteObservation> {
        self.inputs.store_writes.clone()
    }

    fn store_links(
        &self,
        procedure: &DurableProcedureKey,
        output: &PartialFlowPort,
    ) -> StoreChannelLinks {
        let key = (
            self.served_procedure(procedure).exact_identity(),
            output.clone(),
        );
        if let Some(stores) = self.inputs.store_by_read.get(&key) {
            self.inputs
                .consulted_stores
                .borrow_mut()
                .extend(stores.iter().cloned());
        }
        self.inputs
            .store_links
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    fn canonical_returned_field(
        &self,
        callee: &DurableProcedureKey,
        caller: &DurableProcedureKey,
        declared: &brokk_bifrost_analysis::analyzer::semantic::SemanticLocator,
        request: &mut SemanticRequest<'_>,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::SemanticLocator> {
        if declared.language()
            == brokk_bifrost_analysis::analyzer::semantic::SemanticLanguage::Standard(
                brokk_bifrost_analysis::analyzer::Language::Go,
            )
        {
            let handle = self.procedure(caller, request).ok()?;
            return Some(brokk_bifrost_analysis::analyzer::semantic::partial_flow::caller_returned_member_locator(declared, &handle));
        }
        if declared.language()
            != brokk_bifrost_analysis::analyzer::semantic::SemanticLanguage::Standard(
                brokk_bifrost_analysis::analyzer::Language::Rust,
            )
        {
            return None;
        }
        let handle = self.procedure(callee, request).ok()?;
        let procedure = handle.semantics().locator();
        let file = file_for_locator(self.workspace, procedure)?;
        let source = self
            .workspace
            .analyzer()
            .project()
            .read_source(&file)
            .ok()?;
        canonical_returned_field_member(&source, procedure, declared)
    }

    fn has_value_type_barriers(&self) -> bool {
        !self.inputs.barriers.is_empty()
    }

    fn modeled_input_locations(
        &self,
        procedure: &ProcedureHandle,
        call: CallSiteId,
        actual: &PartialFlowPort,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<brokk_bifrost_flow::value_flow::CallerContentLocations>, Self::Error> {
        use brokk_bifrost_flow::value_flow::{
            CallerContentLocations, ValueFlowPlanLimits, caller_content_locations,
        };
        let outcome =
            self.discovery
                .procedure_snapshot(procedure, &OracleCallContext::empty(), request)?;
        self.discovery
            .require_outcome(&outcome, "modeled input content origins")?;
        let unavailable = || {
            Some(CallerContentLocations {
                locations: Vec::new(),
                complete: false,
                components: Vec::new(),
                components_complete: false,
            })
        };
        let Some(snapshot) = outcome.available_value() else {
            return Ok(unavailable());
        };
        let row = procedure
            .semantics()
            .call_site(call)
            .expect("a modeled input belongs to its procedure");
        let value =
            brokk_bifrost_analysis::analyzer::semantic::partial_flow::call_input_value(row, actual)
                .and_then(|value| procedure.value_handle(value));
        Ok(value.map_or_else(unavailable, |value| {
            Some(caller_content_locations(
                &value,
                snapshot,
                ValueFlowPlanLimits::default(),
            ))
        }))
    }

    fn may_share_call_storage(
        &self,
        procedure: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, Self::Error> {
        // With no lowered storage location in this interior there is no
        // member read for a call writeback to reach. Avoid demanding dispatch
        // solely because a scalar actual has an untraced origin.
        if procedure.semantics().memory_locations().is_empty() {
            return Ok(false);
        }
        let outcome =
            self.discovery
                .procedure_snapshot(procedure, &OracleCallContext::empty(), request)?;
        let Some(snapshot) = outcome.available_value() else {
            return Ok(true);
        };
        let index = self.call_storage_index(procedure, snapshot, request)?;
        let call = procedure
            .semantics()
            .call_site(call)
            .expect("a call belongs to its procedure");
        // An addressable receiver may be passed by address even when its
        // value alone looks isolated. The selected callee binding decides
        // whether it is a reference or a copy after dispatch.
        if call
            .member_selection
            .as_ref()
            .is_some_and(|selection| selection.receiver_place.is_some())
        {
            return Ok(true);
        }
        Ok(call
            .receiver
            .into_iter()
            .chain(call.arguments.iter().map(|argument| argument.value))
            .any(|value| {
                let actual = CallArgumentEndpoint::Value(
                    procedure.value_handle(value).expect("a call input is live"),
                );
                brokk_bifrost_analysis::analyzer::semantic::argument_shares_storage_with_formal(
                    &actual,
                    brokk_bifrost_analysis::analyzer::semantic::CallPassingMode::Value,
                    brokk_bifrost_analysis::analyzer::semantic::CallWrittenMember::MayTraverseReferent,
                    snapshot,
                    &index,
                ) != brokk_bifrost_analysis::analyzer::semantic::CallStorageSharing::Isolated
            }))
    }

    fn may_have_modeled_storage_output(
        &self,
        procedure: &ProcedureHandle,
        call: CallSiteId,
    ) -> bool {
        use brokk_bifrost_analysis::analyzer::semantic::CallableTarget;

        let row = procedure
            .semantics()
            .call_site(call)
            .expect("a sibling call belongs to its procedure");
        if self.external_models.iter().any(|model| {
            model.call.durable_key() == (procedure.durable_key(), call)
                && model.writes_call_storage()
        }) {
            return true;
        }
        let summaries = self.plan.value_flow().external_summaries();
        let writes_storage = |summary: &SemanticProcedureSummary| {
            summary.transfers().iter().any(|transfer| {
                matches!(
                    transfer.exit().port().root(),
                    SummaryPort::Receiver | SummaryPort::Parameter(_)
                )
            })
        };
        if row.declared_targets.candidates().iter().any(|target| {
            let locator = match target {
                CallableTarget::External(locator) | CallableTarget::Unmaterialized(locator) => {
                    locator
                }
                _ => return false,
            };
            summaries.summary_for(locator).is_some_and(writes_storage)
        }) {
            return true;
        }
        row.member_selection.as_ref().is_some_and(|selection| {
            self.binder
                .borrow()
                .has_active_summary_member(&selection.member)
                || summaries.entries().any(|(_, summary)| {
                    writes_storage(summary)
                        && summary
                            .key()
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(selection.member.as_ref())
                })
        })
    }

    fn call_input_storage_overlap(
        &self,
        procedure: &ProcedureHandle,
        value: brokk_bifrost_analysis::analyzer::semantic::ValueId,
        selectors: &[brokk_bifrost_analysis::analyzer::semantic::partial_flow::HeapSelector],
        tail: brokk_bifrost_analysis::analyzer::semantic::AccessPathTail,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<brokk_bifrost_analysis::analyzer::semantic::CallStorageSharing, Self::Error> {
        use brokk_bifrost_analysis::analyzer::semantic::CallStorageSharing;
        use brokk_bifrost_analysis::analyzer::semantic::partial_flow::heap_selectors;
        use brokk_bifrost_analysis::analyzer::semantic::partial_flow::ports::heap_ports_overlap;
        use brokk_bifrost_flow::value_flow::{ValueFlowPlanLimits, caller_storage_locations};

        let row = procedure
            .semantics()
            .call_site(call)
            .expect("a sibling call belongs to its procedure");
        if row.receiver.is_none() && row.arguments.is_empty() {
            return Ok(CallStorageSharing::Isolated);
        }
        let outcome =
            self.discovery
                .procedure_snapshot(procedure, &OracleCallContext::empty(), request)?;
        let Some(snapshot) = outcome.available_value() else {
            return Ok(CallStorageSharing::Unknown);
        };
        let read = CallArgumentEndpoint::Value(
            procedure
                .value_handle(value)
                .expect("a reader value belongs to its procedure"),
        );
        let read_locations =
            caller_storage_locations(&read, snapshot, ValueFlowPlanLimits::default());
        let index = self.call_storage_index(procedure, snapshot, request)?;
        let mut complete = outcome.is_complete()
            && read_locations.complete
            && read_locations
                .locations
                .iter()
                .any(|location| location.proven_complete);
        let mut possible_input = false;
        for (ordinal, input) in row
            .receiver
            .into_iter()
            .chain(row.arguments.iter().map(|argument| argument.value))
            .enumerate()
        {
            let input = CallArgumentEndpoint::Value(
                procedure
                    .value_handle(input)
                    .expect("a call input belongs to its procedure"),
            );
            let auto_addressed_receiver = ordinal == 0
                && row.receiver.is_some()
                && row
                    .member_selection
                    .as_ref()
                    .is_some_and(|selection| selection.receiver_place.is_some());
            if !auto_addressed_receiver
                && brokk_bifrost_analysis::analyzer::semantic::argument_shares_storage_with_formal(
                    &input,
                    brokk_bifrost_analysis::analyzer::semantic::CallPassingMode::Value,
                    brokk_bifrost_analysis::analyzer::semantic::CallWrittenMember::MayTraverseReferent,
                    snapshot,
                    &index,
                ) == CallStorageSharing::Isolated
            {
                continue;
            }
            possible_input = true;
            let candidate =
                caller_storage_locations(&input, snapshot, ValueFlowPlanLimits::default());
            complete &= candidate.complete;
            for read in read_locations
                .locations
                .iter()
                .filter(|location| location.proven_complete)
            {
                for written in candidate
                    .locations
                    .iter()
                    .filter(|location| location.proven_complete)
                {
                    if read.location.path().root() != written.location.path().root() {
                        continue;
                    }
                    let mut read_selectors =
                        heap_selectors(read.location.path().selectors()).into_vec();
                    read_selectors.extend_from_slice(selectors);
                    let read_heap = PartialFlowPort::Heap {
                        root: Box::new(PartialFlowPort::Receiver),
                        selectors: read_selectors.into_boxed_slice(),
                        tail: if read.location.path().tail()
                            == brokk_bifrost_analysis::analyzer::semantic::AccessPathTail::Summary
                        {
                            read.location.path().tail()
                        } else {
                            tail
                        },
                    };
                    let written_heap = PartialFlowPort::Heap {
                        root: Box::new(PartialFlowPort::Receiver),
                        selectors: heap_selectors(written.location.path().selectors()),
                        tail: written.location.path().tail(),
                    };
                    if heap_ports_overlap(&read_heap, &written_heap) {
                        return Ok(CallStorageSharing::Shares);
                    }
                }
            }
        }
        Ok(if !possible_input || complete {
            CallStorageSharing::Isolated
        } else {
            CallStorageSharing::Unknown
        })
    }

    fn filter_value_type_barriers(&self, chop: &HashSet<DurableProcedureKey>) {
        self.barrier_filter
            .replace(Box::new(LenientValueTypeBarriers));
        self.lenient_chop.replace(chop.clone());
        self.barrier_chop.replace(chop.clone());
        self.inputs.filtered_flows.borrow_mut().clear();
        self.inputs.conditional_partial.borrow_mut().clear();
    }

    fn strict_value_type_barriers(&self, chop: &HashSet<DurableProcedureKey>) {
        self.barrier_filter
            .replace(Box::new(StrictValueTypeBarriers));
        self.barrier_chop.replace(chop.clone());
        self.inputs.filtered_flows.borrow_mut().clear();
        self.inputs.conditional_partial.borrow_mut().clear();
    }

    fn permits_value_type_barrier(&self, decision: ValueTypeBarrierDecision) -> bool {
        self.barrier_filter.borrow().permits(decision)
    }

    fn value_type_barrier_checks(
        &self,
        observations: &[BarrierObservation],
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<ValueTypeBarrierCheck>, Self::Error> {
        let mut checks = Vec::new();
        for observation in observations {
            for (id, predicate) in &self.inputs.barriers {
                let decision = if request.cancellation.is_cancelled() {
                    ValueTypeBarrierDecision::Undecided(ValueTypeBarrierReason::Cancelled)
                } else {
                    self.barrier_service
                        .classify(observation, *predicate, request)?
                };
                checks.push(ValueTypeBarrierCheck {
                    id: id.clone(),
                    observation: observation.clone(),
                    predicate: *predicate,
                    decision,
                });
                if decision == ValueTypeBarrierDecision::ProvenMatch {
                    break;
                }
            }
        }
        Ok(checks)
    }

    fn value_type_barrier_port_checks(
        &self,
        procedure: &DurableProcedureKey,
        port: &PartialFlowPort,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<ValueTypeBarrierCheck>, Self::Error> {
        let handle = self.procedure(procedure, request)?;
        handle
            .validate_durable_locator(procedure)
            .map_err(TaintPolicyCompileError::CandidateLocatorRefusal)?;
        let semantics = handle.semantics();
        let mut observations = Vec::new();
        for call in semantics.call_sites() {
            for (candidate, value) in call_port_values(call) {
                if &candidate == port {
                    observations.push(BarrierObservation::new(
                        handle
                            .point_handle(call.point)
                            .expect("a call point is live"),
                        value,
                        if matches!(
                            candidate,
                            PartialFlowPort::CallResult { .. } | PartialFlowPort::CallThrown { .. }
                        ) {
                            ObservationPhase::AfterEffects
                        } else {
                            ObservationPhase::BeforeEffects
                        },
                    ));
                }
            }
        }
        for value in semantics.values() {
            let matches = match (port, &value.kind) {
                (
                    PartialFlowPort::Receiver,
                    brokk_bifrost_analysis::analyzer::semantic::SemanticValueKind::Receiver {
                        ..
                    },
                ) => true,
                (
                    PartialFlowPort::Parameter { ordinal },
                    brokk_bifrost_analysis::analyzer::semantic::SemanticValueKind::Parameter {
                        ordinal: candidate,
                        ..
                    },
                ) => ordinal == candidate,
                _ => false,
            };
            if matches {
                observations.push(BarrierObservation::new(
                    handle
                        .point_handle(semantics.entry_point())
                        .expect("an entry is live"),
                    value.id,
                    ObservationPhase::BeforeEffects,
                ));
            }
        }
        self.value_type_barrier_checks(&observations, request)
    }

    fn reset_value_type_witnesses(&self) {
        self.strict_witnesses.borrow_mut().clear();
    }

    fn retain_strict_value_type_witness(
        &self,
        source: &BoundSource,
        sink: brokk_bifrost_flow::value_flow::ValueFlowSinkId,
    ) {
        self.strict_witnesses
            .borrow_mut()
            .insert((source.origin.clone(), sink));
    }

    fn prepare_value_type_witness(
        &self,
        source: &BoundSource,
        sink: brokk_bifrost_flow::value_flow::ValueFlowSinkId,
    ) {
        let chop = self.lenient_chop.borrow().clone();
        if self
            .strict_witnesses
            .borrow()
            .contains(&(source.origin.clone(), sink))
        {
            self.strict_value_type_barriers(&chop);
        } else {
            self.filter_value_type_barriers(&chop);
        }
    }

    fn partial_flows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, Self::Error> {
        let projection_key = self.payload_flow_key(procedure, request)?;
        let hits = Cell::new(0);
        let request = RefCell::new(request);
        let cached = read_shared(
            self.workspace.analyzer(),
            if self.barrier_chop.borrow().contains(procedure) {
                &self.inputs.filtered_flows
            } else {
                &self.inputs.partial_flows
            },
            &hits,
            projection_key,
            |f| f(request.borrow_mut().budget),
            || {
                let mut request_ref = request.borrow_mut();
                let request = &mut **request_ref;
                if self.barrier_chop.borrow().contains(procedure) {
                    let handle = self.procedure(procedure, request)?;
                    let mut fixpoint_request =
                        request.staged_with_execution_budget(&self.execution_budget);
                    let outcome = if projection_key.1.is_some() {
                        self.discovery.procedure_snapshot(
                            &handle,
                            &OracleCallContext::empty(),
                            &mut fixpoint_request,
                        )?
                    } else {
                        file_local_procedure_relations(
                            &handle,
                            &OracleCallContext::empty(),
                            &mut fixpoint_request,
                        )
                        .map_err(|error| {
                            TaintPolicyCompileError::SemanticProvider(error.to_string())
                        })?
                    };
                    self.discovery
                        .require_outcome(&outcome, "barrier partial flows")?;
                    let snapshot = outcome.available_value().ok_or_else(|| {
                        TaintPolicyCompileError::SemanticUnavailable(
                            "barrier partial-flow projection is unavailable".to_owned(),
                        )
                    })?;
                    let _timing =
                        brokk_bifrost_analysis::profiling::scope("taint.barriers.fixpoint");
                    self.barrier_fixpoints.set(self.barrier_fixpoints.get() + 1);
                    self.barrier_procedures
                        .borrow_mut()
                        .insert(procedure.clone());
                    let overlay_cpu_start = ProjectionCounter::start();
                    let filtered = compute_partial_flows_in_mode(
                        &handle,
                        snapshot,
                        &[],
                        &[],
                        false,
                        &[],
                        &[],
                        projection_key.2,
                        &mut ProcedureBarrierFilter {
                            provider: self,
                            procedure: &handle,
                        },
                        &mut fixpoint_request,
                    )?
                    .partial;
                    self.overlay_cost.record(overlay_cpu_start);
                    let stored = self.inputs.partial_flows.borrow();
                    let baseline = stored
                        .get(&projection_key)
                        .expect("the chop only names procedures read by the baseline search");
                    let baseline = baseline.value();
                    debug_assert!(
                        filtered
                            .flows
                            .iter()
                            .all(|flow| baseline.flows.iter().any(|original| baseline.ports
                                [original.from.index()]
                                == filtered.ports[flow.from.index()]
                                && baseline.ports[original.to.index()]
                                    == filtered.ports[flow.to.index()])),
                        "barrier filtering only removes stored port flows"
                    );
                    drop(stored);
                    let filtered = Arc::new(filtered);
                    return Ok(filtered);
                }
                let baseline_cpu_start = ProjectionCounter::start();
                let handle = self.procedure(procedure, request)?;
                if projection_key.2 == GuardProjectionMode::PolicyProvedOnly {
                    let mut fixpoint_request =
                        request.staged_with_execution_budget(&self.execution_budget);
                    let outcome = if projection_key.1.is_some() {
                        self.discovery.procedure_snapshot(
                            &handle,
                            &OracleCallContext::empty(),
                            &mut fixpoint_request,
                        )?
                    } else {
                        file_local_procedure_relations(
                            &handle,
                            &OracleCallContext::empty(),
                            &mut fixpoint_request,
                        )
                        .map_err(|error| {
                            TaintPolicyCompileError::SemanticProvider(error.to_string())
                        })?
                    };
                    self.discovery
                        .require_outcome(&outcome, "policy-proved partial flows")?;
                    let flows = brokk_bifrost_analysis::analyzer::semantic::partial_flow::partial_flows_from_projection_in_mode(
                            &handle, Ok(outcome), projection_key.2, &mut fixpoint_request)
                            .ok_or_else(|| TaintPolicyCompileError::SemanticUnavailable("unfiltered guard baseline cancelled".into()))?;
                    self.baseline_reads_cost.record(baseline_cpu_start);
                    self.computed.set(self.computed.get() + 1);
                    self.announce_refinement_calls(&handle, request)?;
                    return Ok(Arc::new(flows));
                }
                let selected = self
                    .discovery
                    .selected_procedure_and_flows_handle(&handle, request)?;
                let flows = Arc::new(selected.flows);
                self.baseline_reads_cost.record(baseline_cpu_start);
                self.computed.set(self.computed.get() + 1);
                self.announce_refinement_calls(&selected.procedure, request)?;
                Ok(flows)
            },
            |_| true,
        )?;
        Ok(cached.clone())
    }

    fn projected_partial_flows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<(Option<TaintEdgeFunction>, Arc<ProcedurePartialFlows>)>, Self::Error> {
        let projection_key = self.payload_flow_key(procedure, request)?;
        let hits = Cell::new(0);
        let request = RefCell::new(request);
        let cached = read_shared(
            self.workspace.analyzer(),
            &self.inputs.conditional_partial,
            &hits,
            projection_key,
            |f| f(request.borrow_mut().budget),
            || {
                let mut request_ref = request.borrow_mut();
                let request = &mut **request_ref;
                let baseline = self.partial_flows(procedure, request)?;
                let handle = self.procedure(procedure, request)?;
                let partitions = self.conditional_partitions(&handle)?;
                if partitions.groups.is_empty() {
                    return Ok(vec![(None, baseline)]);
                }
                let mut projected = Vec::new();
                if let Some(function) = partitions.baseline {
                    projected.push((Some(function), baseline.clone()));
                }
                let mut fixpoint_request =
                    request.staged_with_execution_budget(&self.execution_budget);
                let outcome = if projection_key.1.is_some() {
                    self.discovery.procedure_snapshot(
                        &handle,
                        &OracleCallContext::empty(),
                        &mut fixpoint_request,
                    )?
                } else {
                    file_local_procedure_relations(
                        &handle,
                        &OracleCallContext::empty(),
                        &mut fixpoint_request,
                    )
                    .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?
                };
                for (function, kills) in partitions.groups {
                    let partial = if let Some(snapshot) = outcome.available_value() {
                        compute_partial_flows_in_mode(
                            &handle,
                            snapshot,
                            &[],
                            &[],
                            false,
                            &[],
                            &kills,
                            self.plan.value_flow().guard_projection_mode(),
                            &mut ProcedureBarrierFilter {
                                provider: self,
                                procedure: &handle,
                            },
                            &mut fixpoint_request,
                        )?
                        .partial
                    } else {
                        (*baseline).clone().with_failed_projection(
                            "conditional sanitizer projection unavailable".into(),
                        )
                    };
                    projected.push((Some(function), Arc::new(partial)));
                }
                Ok(projected)
            },
            |_| true,
        )?;
        Ok(cached.clone())
    }

    fn interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, Self::Error> {
        self.source_root_interiors(procedure, seeds, observations, witnesses, request)
            .map(brokk_bifrost_flow::composition::merge_interior_source_products)
    }

    fn projected_interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<(Option<TaintEdgeFunction>, InteriorFlows)>, Self::Error> {
        let handle = self.procedure(procedure, request)?;
        handle
            .validate_durable_locator(procedure)
            .map_err(TaintPolicyCompileError::CandidateLocatorRefusal)?;
        let partitions = self.conditional_partitions(&handle)?;
        if partitions.groups.is_empty() {
            return Ok(self
                .source_root_interiors(procedure, seeds, observations, witnesses, request)?
                .into_iter()
                .map(|flows| (None, flows))
                .collect());
        }
        let mut projected = Vec::new();
        if let Some(function) = partitions.baseline {
            projected.extend(
                self.source_root_interiors(procedure, seeds, observations, witnesses, request)?
                    .into_iter()
                    .map(|flows| (Some(function.clone()), flows)),
            );
        }
        let outcome =
            self.discovery
                .procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
        for (function, kills) in partitions.groups {
            let flows = if let Some(snapshot) = outcome.available_value() {
                brokk_bifrost_flow::composition::interior_source_root_products(
                    self,
                    handle.clone(),
                    snapshot,
                    seeds,
                    observations,
                    witnesses,
                    &kills,
                    &self.execution_budget,
                    request,
                )?
            } else {
                vec![
                    brokk_bifrost_flow::composition::unavailable_snapshot_interior(
                        handle.clone(),
                        SemanticInputStatus::from_outcome(&outcome),
                        "conditional sanitizer projection unavailable",
                    ),
                ]
            };
            projected.extend(flows.into_iter().map(|flow| (Some(function.clone()), flow)));
        }
        Ok(projected)
    }

    fn stored_interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, Self::Error> {
        self.stored_source_root_interiors(procedure, seeds, observations, witnesses, request)
            .map(brokk_bifrost_flow::composition::merge_interior_source_products)
    }

    fn projected_stored_interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<(Option<TaintEdgeFunction>, InteriorFlows)>, Self::Error> {
        let handle = self.procedure(procedure, request)?;
        handle
            .validate_durable_locator(procedure)
            .map_err(TaintPolicyCompileError::CandidateLocatorRefusal)?;
        let partitions = self.conditional_partitions(&handle)?;
        if partitions.groups.is_empty() {
            return Ok(self
                .stored_source_root_interiors(procedure, seeds, observations, witnesses, request)?
                .into_iter()
                .map(|flows| (None, flows))
                .collect());
        }
        let mut projected = Vec::new();
        if let Some(function) = partitions.baseline {
            projected.extend(
                self.stored_source_root_interiors(
                    procedure,
                    seeds,
                    observations,
                    witnesses,
                    request,
                )?
                .into_iter()
                .map(|flows| (Some(function.clone()), flows)),
            );
        }
        let outcome = file_local_procedure_relations(&handle, &OracleCallContext::empty(), request)
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        for (function, kills) in partitions.groups {
            let flows = if let Some(snapshot) = outcome.available_value() {
                brokk_bifrost_flow::composition::interior_source_root_products(
                    self,
                    handle.clone(),
                    snapshot,
                    seeds,
                    observations,
                    witnesses,
                    &kills,
                    &self.execution_budget,
                    request,
                )?
            } else {
                vec![
                    brokk_bifrost_flow::composition::unavailable_snapshot_interior(
                        handle.clone(),
                        SemanticInputStatus::from_outcome(&outcome),
                        "conditional sanitizer witness projection unavailable",
                    ),
                ]
            };
            projected.extend(flows.into_iter().map(|flow| (Some(function.clone()), flow)));
        }
        Ok(projected)
    }

    fn dispatch(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(Dispatch, Option<CallModel>), Self::Error> {
        let selected = self.procedure(&call.0, request)?;
        selected
            .validate_durable_locator(&call.0)
            .map_err(TaintPolicyCompileError::CandidateLocatorRefusal)?;
        let exact_call = (selected.exact_identity(), call.1);
        let key = (self.policy.clone(), exact_call);
        // The run memo outlives each batch's discovery materialization.
        // Admitted hits replay the fill's reads; rejected entries recompute
        // under the consuming request's ledger.
        let request = RefCell::new(request);
        let memoized = read_shared(
            self.workspace.analyzer(),
            &self.memo.dispatches,
            &self.memo.hits.dispatches,
            key,
            |f| f(request.borrow_mut().budget),
            || {
                let memoized = self.dispatch_uncached(call, &mut request.borrow_mut())?;
                self.dispatches_made.set(self.dispatches_made.get() + 1);
                Ok::<_, TaintPolicyCompileError>(memoized)
            },
            // Keep dispatches for later batches whose dependencies remain
            // resident, avoiding repeated work when admission succeeds (#9095).
            |_| true,
        )?;
        let (record, boundaries) = &memoized.record;
        self.record_dispatch(record, boundaries);
        // `authored_models` reads every dispatched call's model.
        let answer = (memoized.dispatch.clone(), memoized.model.clone());
        self.inputs
            .models
            .borrow_mut()
            .insert(exact_call, memoized.0);
        Ok(answer)
    }

    fn callers(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Callers, Self::Error> {
        CallStructureProvider::callers(
            &self.discovery,
            |call, answer| {
                brokk_bifrost_flow::composition::CallModelSource::covers_caller_candidate(
                    self, call, answer,
                )
            },
            procedure,
            self.max_callers_per_procedure,
            &self.execution_budget,
            &self.inputs.excluded_callers,
            request,
        )
    }

    fn lexical_parent(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<DurableProcedureKey>, Self::Error> {
        CallStructureProvider::lexical_parent(&self.discovery, procedure, request)
    }

    fn authored_models(&self) -> Vec<Box<[AuthoredArmClosure]>> {
        let models = self.inputs.models.borrow();
        let mut authored = models
            .iter()
            .filter_map(|(call, entry)| {
                Some((call, entry.value().model.as_ref()?.authored.clone()?))
            })
            .collect::<Vec<_>>();
        authored.sort_unstable_by_key(|(call, _)| *call);
        authored.into_iter().map(|(_, closures)| closures).collect()
    }

    fn unmodeled_call_behavior(&self) -> UnmodeledCallBehavior {
        self.plan.value_flow().unmodeled_call_behavior()
    }

    /// The call's receiver and arguments, and its singular result and thrown
    /// value: the values `build_call_fallback_profiles` gives the ICFG
    /// engine's fallback. A multi-value call's indexed results are not
    /// fallback outputs there either.
    fn fallback_ports(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<FallbackPorts, Self::Error> {
        let handle = self.procedure(&call.0, request)?;
        handle
            .validate_durable_locator(&call.0)
            .map_err(TaintPolicyCompileError::CandidateLocatorRefusal)?;
        let row = handle.semantics().call_site(call.1).ok_or_else(|| {
            TaintPolicyCompileError::SemanticUnavailable(format!(
                "call {:?} is not in its procedure",
                call.1
            ))
        })?;
        Ok(brokk_bifrost_flow::composition::fallback_ports(row))
    }

    fn openness(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Openness, Self::Error> {
        let identity = self.procedure(procedure, request)?.exact_identity();
        let hits = Cell::new(0);
        let request = RefCell::new(request);
        let cached = read_shared(
            self.workspace.analyzer(),
            &self.inputs.openness_memo,
            &hits,
            (identity, self.plan.value_flow().guard_projection_mode()),
            |f| f(request.borrow_mut().budget),
            || {
                let mut request_ref = request.borrow_mut();
                let request = &mut **request_ref;
                let openness = self.decide_openness(procedure, request)?;
                Ok(openness)
            },
            |_| true,
        )?;
        Ok(cached.clone())
    }

    fn endpoints(
        &self,
        procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureEndpoints, Self::Error> {
        self.endpoints_with_causes(procedure, _request)
            .map(|answer| answer.endpoints)
    }

    fn endpoints_with_causes(
        &self,
        procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureEndpointAnswer, Self::Error> {
        let selectors = self.binder.borrow().selectors();
        let mut endpoints = Vec::new();
        let mut gaps = Vec::new();
        for selector in selectors {
            let (matched, execution_dependent) = self.frontier_match(&procedure.0, selector)?;
            endpoints.extend(
                matched
                    .by_procedure
                    .get(procedure)
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
            gaps.extend(matched.gaps_for(execution_dependent));
        }
        endpoints.extend(self.binder.borrow().entry_points_in(procedure));
        let (mut answer, sources, unjudged) =
            self.binder.borrow().procedure_endpoints(endpoints)?;
        self.inputs.frontier_sources.borrow_mut().extend(sources);
        self.inputs
            .unjudged
            .borrow_mut()
            .extend(unjudged.into_iter().map(|source| {
                (
                    source.origin.clone(),
                    SourceJudgment {
                        source,
                        answer: None,
                    },
                )
            }));
        let mut causes = match &answer.completeness {
            Completeness::Complete => Vec::new(),
            Completeness::Incomplete { cause, .. } => vec![*cause],
        };
        if !gaps.is_empty() {
            for gap in &gaps {
                for cause in gap.causes() {
                    if !causes.contains(&cause) {
                        causes.push(cause);
                    }
                }
            }
            gaps.sort_by(|a, b| a.message.cmp(&b.message));
            let message = format!(
                "the policy endpoints of this procedure may be incomplete: {:?}",
                gaps.iter().map(|gap| &gap.message).collect::<Vec<_>>()
            );
            let cause = causes
                .iter()
                .copied()
                .find(|cause| {
                    matches!(
                        cause,
                        brokk_bifrost_flow::taint::compose::IncompleteCause::Operational(_)
                    )
                })
                .or_else(|| causes.first().copied())
                .expect("a frontier gap carries a typed cause or an uncertified Provider");
            answer.completeness = Completeness::Incomplete {
                cause,
                reason: message.into(),
            };
        }
        if causes.iter().any(|cause| {
            matches!(
                cause,
                brokk_bifrost_flow::taint::compose::IncompleteCause::Operational(_)
            )
        }) {
            causes.retain(|cause| {
                *cause != brokk_bifrost_flow::taint::compose::IncompleteCause::Content
            });
        }

        Ok(ProcedureEndpointAnswer {
            endpoints: answer,
            causes,
        })
    }

    fn source_evidence(
        &self,
        source: &BoundSource,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<HopQuality, Self::Error> {
        let unjudged = self.inputs.unjudged.borrow();
        let judged = unjudged
            .get(&source.origin)
            .expect("the search judges only sources this provider answered with unknown evidence");
        let selection = &judged.source.selection;
        let key = (
            self.policy.clone(),
            judged.source.identity.clone(),
            selection.file.clone(),
            selection.span.start,
            selection.span.end,
        );
        let quality = read_shared(
            self.workspace.analyzer(),
            &self.memo.evidence,
            &self.memo.hits.evidence,
            key,
            |f| f(self.binder.borrow_mut().semantic_budget()),
            || {
                self.source_evidence_resolved
                    .set(self.source_evidence_resolved.get() + 1);
                let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.points_to");
                self.binder.borrow_mut().source_evidence(selection)
            },
            |_| true,
        )?;
        let answer = *quality;
        drop(unjudged);
        self.inputs
            .unjudged
            .borrow_mut()
            .get_mut(&source.origin)
            .expect("the judged source remains in this provider")
            .answer = Some(quality.0);
        Ok(answer)
    }
}

impl PolicyCompositionProvider<'_> {
    /// Only authored policy entries and Go runtime/harness entries can start
    /// an execution certificate. A bounded, incomplete survey never refutes
    /// a root already admitted by positive evidence.
    pub(crate) fn admitted_execution_roots(
        &self,
        max_examined: usize,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(Vec<DurableProcedureKey>, Vec<&'static str>), TaintPolicyCompileError> {
        let mut roots = self.binder.borrow().execution_entry_roots();
        let mut examined = 0usize;
        let mut causes = Vec::new();
        let mut note = |cause| {
            if !causes.contains(&cause) {
                causes.push(cause);
            }
        };
        let analyzer = self.workspace.analyzer();
        'files: for file in analyzer
            .analyzed_files()
            .into_iter()
            .filter(|file| file.language() == Language::Go)
        {
            let mut artifact = None;
            for declaration in analyzer.declarations(&file) {
                if request.cancellation.is_cancelled() {
                    note("execution-root survey cancelled");
                    break 'files;
                }
                if examined >= max_examined {
                    note("execution-root census limit reached");
                    break 'files;
                }
                examined += 1;
                let support = language_support_for_hook(Language::Go, "implicit_entry_point")
                    .expect("Go semantic files have registered language support");
                match support.implicit_entry_point(analyzer, &declaration) {
                    Some(true) => {}
                    Some(false) => continue,
                    None => {
                        note("Go entry-point evidence unknown");
                        continue;
                    }
                }
                if artifact.is_none() {
                    let outcome = self
                        .workspace
                        .materialize_program_semantics(&file, request)
                        .map_err(|error| {
                            TaintPolicyCompileError::SemanticProvider(error.to_string())
                        })?;
                    if !outcome.is_complete() {
                        note("Go entry semantic artifact incomplete");
                    }
                    artifact = outcome.available_value().cloned();
                }
                let Some(artifact) = &artifact else {
                    note("Go entry semantic artifact unavailable");
                    continue;
                };
                let lookup = procedures_for_definition_with_limits(
                    analyzer,
                    &declaration,
                    artifact,
                    max_examined.saturating_sub(examined),
                    request.cancellation,
                );
                examined += lookup.examined;
                if lookup.status != ProcedureRangeLookupStatus::Complete {
                    note("Go entry procedure lookup incomplete");
                    continue;
                }
                if lookup.handles.len() != 1 {
                    note("Go entry procedure is not unique");
                    continue;
                }
                roots.push(
                    self.procedure(&lookup.handles[0].durable_key(), request)?
                        .durable_key(),
                );
            }
        }
        for root in &mut roots {
            *root = self.procedure(root, request)?.durable_key();
        }
        roots.sort_unstable();
        roots.dedup();
        Ok((roots, causes))
    }

    /// Dispatch one call the run memo does not hold: resolve it, decide its
    /// models, and bind each candidate.
    fn dispatch_uncached(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<MemoizedDispatch, TaintPolicyCompileError> {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.dispatch");
        let raw = CallStructureProvider::dispatch(&self.discovery, call, request)?;
        let local = brokk_bifrost_flow::composition::dispatch_from_structure(
            &self.discovery,
            self,
            raw,
            request,
        )?;
        Ok(MemoizedDispatch {
            dispatch: local.dispatch,
            model: local.model,
            record: (
                RecordedDispatch {
                    handle: local.handle,
                    status: local.status,
                    coverage: local.coverage,
                },
                local.boundaries,
            ),
        })
    }

    /// The models of one call, from the policy's bound external models, the
    /// call's dispatch `answer` and its semantics, as the ICFG engine's plan
    /// holds the same answers for every call
    /// of a discovered region; these are the same rules applied to the one
    /// call. The bound external models and a proven format-result identity
    /// merge into one model; otherwise a proven Rust std builtin models the
    /// call.
    fn call_models(
        &self,
        call: &CallSiteHandle,
        answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<CallModels, TaintPolicyCompileError> {
        let receiver_storage_available = self.plan.value_flow().receiver_storage_is_available(call);
        let key = call.exact_key();
        let group = self
            .external_models
            .iter()
            .filter(|model| model.call.exact_key() == key)
            .collect::<Vec<_>>();
        let format = intrinsic_format_result_identity(answer);
        let universe = self.plan.universe();
        let curated = if !group.is_empty() || format.is_some() {
            Some(ExternalCallSeams::new(call, &group, format, universe).model(universe)?)
        } else {
            self.std_builtin(call)?
                .map(|builtin| intrinsic_call_model(&builtin))
                .transpose()?
        };
        let Some(result) = answer.available_value() else {
            return Ok(CallModels {
                curated,
                summaries: None,
                resolved_external: false,
                receiver_storage_available,
            });
        };
        let mut targets = Vec::new();
        let mut unmaterialized = Vec::new();
        for boundary in result.boundaries() {
            if let Some(target) = boundary.exact_external_target()
                && !targets.contains(target)
            {
                targets.push(target.clone());
            }
            if let Some(target) = boundary.unmaterialized_external_target()
                && !unmaterialized.contains(target)
            {
                unmaterialized.push(target.clone());
            }
        }
        let _timing =
            brokk_bifrost_analysis::profiling::scope("taint.compose.call_models.summaries");
        let summaries = self.binder.borrow().external_summaries(
            &targets,
            &unmaterialized,
            call.procedure().artifact().key(),
            self.unmodeled_call_behavior(),
        )?;
        // Target-set proof is independent of the language and of whether a
        // summary claims all overrides. One proven external target in an
        // exhaustive answer has no residual dynamic-dispatch arm. An open
        // receiver (including dyn Trait) cannot satisfy this proof.
        let resolved_external = answer.is_complete()
            && result.coverage() == CandidateCoverage::Exhaustive
            && result.candidates().is_empty()
            && matches!(result.boundaries(), [boundary]
                if boundary.proof == ProofStatus::Proven
                    && matches!(boundary.kind,
                        DispatchBoundaryKind::External(Some(_))
                            | DispatchBoundaryKind::Unmaterialized(_)));
        Ok(CallModels {
            curated,
            summaries,
            resolved_external,
            receiver_storage_available,
        })
    }

    /// The Rust std operation `call` invokes, classified once per run.
    fn std_builtin(
        &self,
        call: &CallSiteHandle,
    ) -> Result<Option<IntrinsicCall>, TaintPolicyCompileError> {
        let builtin = read_shared_unbudgeted(
            self.workspace.analyzer(),
            &self.memo.std_builtins,
            &self.memo.hits.std_builtins,
            call.exact_key(),
            || {
                let _timing = brokk_bifrost_analysis::profiling::scope(
                    "taint.compose.call_models.std_builtin",
                );
                language_intrinsic_call(self.workspace, call)
                    .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))
            },
            |_| true,
        )?;
        Ok(builtin.clone())
    }

    /// Keep the first record of a dispatched call and its boundaries.
    fn record_dispatch(&self, record: &RecordedDispatch, boundaries: &[DispatchBoundary]) {
        let call = record.handle.exact_key();
        let mut dispatched = self.inputs.dispatched.borrow_mut();
        if dispatched.contains_key(&call) {
            return;
        }
        dispatched.insert(call, record.clone());
        self.inputs
            .dispatch_boundaries
            .borrow_mut()
            .extend(boundaries.iter().cloned());
    }

    /// The workspace gap sweep of one procedure, with each relevant gap that
    /// a complete dispatch of its call answers taken out (the call-target
    /// refinement rule of the ICFG engine, #1952). A gap is answered when
    /// its call dispatches completely, including a call a model covers.
    fn decide_openness(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Openness, TaintPolicyCompileError> {
        use brokk_bifrost_flow::taint::compose::{BudgetLane, IncompleteCause, OperationalCause};
        let mut openness = brokk_bifrost_flow::composition::decide_openness(
            &self.discovery,
            self,
            procedure,
            request,
        )?;
        if self.plan.value_flow().guard_projection_mode() == GuardProjectionMode::LegacyAutomatic {
            return Ok(openness);
        }
        let handle = self.procedure(procedure, request)?;
        let partitions = self.conditional_partitions(&handle)?;
        if !partitions.guard_declines.is_empty() {
            use brokk_bifrost_analysis::analyzer::semantic::partial_flow::guard_bindings::GuardBindingReason;
            let cause = partitions
                .guard_declines
                .iter()
                .find_map(|decline| match decline.reason {
                    GuardBindingReason::Cancelled => {
                        Some(IncompleteCause::Operational(OperationalCause::Cancelled))
                    }
                    GuardBindingReason::BudgetExceeded => Some(IncompleteCause::Operational(
                        OperationalCause::Budget(BudgetLane::Semantic),
                    )),
                    _ => None,
                })
                .unwrap_or(IncompleteCause::Content);
            let guard_reason = partitions
                .guard_declines
                .iter()
                .map(|decline| format!("guard `{}` is undecided: {:?}", decline.id, decline.reason))
                .collect::<Vec<_>>()
                .join("; ");
            match &mut openness {
                Openness::Closed => {
                    openness = Openness::Open {
                        residual: Box::default(),
                        residual_causes: Box::default(),
                        relation_cause: Some(cause),
                        cause,
                        blocked: None,
                        status: SemanticInputStatus::Unproven,
                        reason: guard_reason.into(),
                    }
                }
                Openness::Open {
                    reason,
                    relation_cause,
                    cause: existing,
                    ..
                } => {
                    *reason = format!("{reason}; {guard_reason}").into();
                    if !matches!(existing, IncompleteCause::Operational(_)) {
                        *existing = cause;
                    }
                    if !matches!(relation_cause, Some(IncompleteCause::Operational(_))) {
                        *relation_cause = Some(cause);
                    }
                }
            }
        }
        Ok(openness)
    }

    /// The gap sweep of one procedure: whether it is open and the gaps that
    /// keep it open, computed once per compile.
    fn openness_sweep(
        &self,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, TaintPolicyCompileError> {
        let hits = Cell::new(0);
        let request = RefCell::new(request);
        let cached = read_shared(
            self.workspace.analyzer(),
            &self.inputs.sweeps,
            &hits,
            handle.exact_identity(),
            |f| f(request.borrow_mut().budget),
            || {
                let mut request_ref = request.borrow_mut();
                let request = &mut **request_ref;
                let sweep = brokk_bifrost_flow::composition::openness_sweep(
                    &self.discovery,
                    handle,
                    &self.execution_budget,
                    request,
                )?;
                Ok(sweep)
            },
            |_| true,
        )?;
        Ok(cached.clone())
    }

    /// Announce the calls the openness decision of `procedure` will dispatch
    /// (its refinement calls) to the dispatch pool, so they are resolved in
    /// the batch of the next dispatch in the procedure's file: the search's
    /// next call there or, failing that, the first refinement call.
    fn announce_refinement_calls(
        &self,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), TaintPolicyCompileError> {
        let sweep = self.openness_sweep(handle, request)?;
        let memo = self.memo.dispatches.borrow();
        let calls = brokk_bifrost_flow::composition::refinement_calls(handle, &sweep, |call| {
            memo.contains_key(&(self.policy.clone(), (handle.exact_identity(), call)))
        });
        self.discovery.expect_calls(&calls);
        Ok(())
    }
}

/// The best proof and the best completeness of a call's own continuation
/// edges, as the ICFG engine's summary solve projects them for taint, which
/// takes resolved call-to-return edges (`process_call` in the dataflow
/// summary solver, and the call-transfer projection beneath it):
///
/// - each dispatch boundary projects a continuation edge with its own proof
///   and completeness, and so does each candidate the projection turns into
///   a boundary (every candidate of a detached call, and a deferred callee:
///   async or generator), with the candidate's proof and a partial
///   completeness;
/// - a call with a candidate body the solver enters, or one a curated model
///   replaces when no boundary remains or the model is proven complete in
///   every transfer, also has the caller's own proven and complete edge;
/// - a curated model proven complete drops the boundary edges.
///
/// A value may take any of the edges, so each axis is the best over them. A
/// dispatch with no answer projects no edge there; the fixpoint keeps the
/// value across the call anyway, so that call is neither proven nor complete.
fn continuation_quality(
    models: &CallModels,
    model: Option<&CallModel>,
    call: &CallSiteHandle,
    result: Option<&DispatchResult>,
) -> HopQuality {
    let Some(result) = result else {
        return HopQuality::UNCERTAIN;
    };
    let row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .expect("a dispatched call is a call of its procedure");
    let curated_proven = models
        .curated
        .as_ref()
        .is_some_and(CuratedCallModel::is_proven_complete);
    // A transfer's quality does not certify the call's continuation. An
    // authored closure certifies a residual arm only when covering-model
    // selection proved every other arm. An exact external arm is certified by
    // a complete, effect-free authored summary with complete call evidence.
    // Exact dispatch selects one implementation, so it needs no
    // `covers_overrides` claim (`target_needs_override_claim`, #12846); pack
    // validation refuses that claim on a receiverless target, so requiring it
    // left every exact free-function summary unproven (#12568).
    let authored_closed = model.is_some_and(|model| {
        let residual = result
            .boundaries()
            .iter()
            .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Unresolved));
        model.completeness.is_complete()
            && model
                .authored
                .as_ref()
                .is_some_and(|closures| !closures.is_empty())
            && result.boundaries().iter().all(|boundary| {
                matches!(boundary.kind, DispatchBoundaryKind::Unresolved)
                    || boundary.proof == ProofStatus::Proven
            })
            && (residual
                || (models.resolved_external
                    && brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::scoped_call_dispatch_gap(call.procedure().semantics(), row).is_none()
                    && [row.evidence, row.target_evidence].iter().all(|evidence| {
                        let evidence = call
                            .procedure()
                            .semantics()
                            .evidence_row(*evidence)
                            .expect("a call names live evidence");
                        evidence.proof == ProofStatus::Proven
                            && evidence.completeness == EvidenceCompleteness::Complete
                    })
                    && result.boundaries().iter().all(|boundary| {
                        models
                            .summary_for_boundary(&boundary.kind)
                            .is_some_and(|(summary, _)| summary.effects().is_empty())
                    })))
    });
    let replaced = models.curated.is_some() || authored_closed;
    let proven_model = curated_proven || authored_closed;
    let mut boundaries = result
        .boundaries()
        .iter()
        .map(|boundary| {
            HopQuality::new(
                boundary.proof == ProofStatus::Proven,
                boundary.completeness == EvidenceCompleteness::Complete,
            )
        })
        .collect::<Vec<_>>();
    let mut entered = false;
    for candidate in result.candidates() {
        let deferred = row.invocation_mode == CallInvocationMode::Detached
            || candidate
                .target()
                .semantics()
                .properties()
                .invocation
                .is_deferred();
        if deferred {
            boundaries.push(HopQuality::new(
                *candidate.proof() == ProofStatus::Proven,
                false,
            ));
        } else {
            entered = true;
        }
    }
    let mut best = HopQuality::UNCERTAIN;
    if entered || (replaced && (boundaries.is_empty() || proven_model)) {
        best = HopQuality::CERTAIN;
    }
    if !proven_model {
        for boundary in boundaries {
            best = best.join(boundary);
        }
    }
    best
}

/// The selected model for a call, if any.
///
/// A curated model of the call replaces the call outright, as the ICFG
/// engine's `call_replaced_by_model` does. One selected partial summary yields
/// a retains-dispatch model: its declared transfers join the original dispatch,
/// candidate bodies and residual, and its completeness stays partial. Two
/// partial boundaries yield no model. A complete bound summary replaces only a
/// candidate-free call when it closes every open boundary with proven coverage.
fn covering_model(
    models: &CallModels,
    call: &CallSiteHandle,
    result: Option<&DispatchResult>,
    universe: &TaintUniverse,
) -> Option<CallModel> {
    if let Some(curated) = &models.curated {
        return Some(models.with_receiver_storage(call_model(
            call,
            curated.transfers(),
            curated.effects(),
            SummaryCallBinding::default(),
            curated.is_proven_complete(),
            None,
            universe,
        )));
    }
    let result = result?;
    // A partial summary states usable positive edges, but cannot cover the
    // boundary. Keep the original candidates, dispatch and unmodeled residual.
    let mut partial = None;
    for boundary in result.boundaries() {
        if let Some((summary, mapping)) = models.summary_for_boundary(&boundary.kind)
            && !summary.completeness().is_complete()
            && partial
                .replace((summary, mapping, boundary.kind.clone()))
                .is_some()
        {
            return None;
        }
    }
    if let Some((summary, mapping, target)) = partial {
        let mut model = models.with_receiver_storage(call_model(
            call,
            summary.transfers(),
            summary.effects(),
            mapping,
            summary
                .transfers()
                .iter()
                .all(|transfer| transfer.evidence().is_proven()),
            Some(Box::default()),
            universe,
        ));
        model.completeness =
            Completeness::content("the selected procedure summary has unknown effects");
        model.retains_dispatch = true;
        model.summary = Some(summary.key().clone());
        model.summary_target = Some(target);
        return Some(model);
    }
    // Complete summaries are replacement models only for a candidate-free
    // call. A body candidate still owns its original dispatch path.
    if !result.candidates().is_empty() {
        return None;
    }
    let kinds = result
        .boundaries()
        .iter()
        .map(|boundary| &boundary.kind)
        .collect::<Vec<_>>();
    let has_residual = kinds
        .iter()
        .any(|kind| matches!(kind, DispatchBoundaryKind::Unresolved));
    let closures = if has_residual {
        authored_call_closures(
            call,
            &kinds,
            models.summaries.as_ref()?,
            models.resolved_external,
        )
    } else {
        Vec::new()
    };
    // One authored closure can discharge both the named external arm and its
    // residual implementation-family arm; the shared helper deduplicates it.
    if has_residual && closures.is_empty() {
        return None;
    }
    let mut covering = None;
    for boundary in result.boundaries() {
        if has_residual && matches!(boundary.kind, DispatchBoundaryKind::Unresolved) {
            // An authored summary of the sibling external member closes this
            // otherwise open implementation-family arm only when every arm
            // passed the shared closure guards above.
            continue;
        }
        if boundary.proof != ProofStatus::Proven {
            return None;
        }
        // The summary is looked up for every proven boundary, complete or
        // not: the resolver can close a boundary from the very summary that
        // carries the transfers.
        match models.summary_for_boundary(&boundary.kind) {
            Some((summary, mapping)) => {
                if covering.replace((summary, mapping)).is_some() {
                    return None;
                }
            }
            // A complete boundary no summary names closes only as a resolved
            // constructor, the same rule the ICFG engine applies.
            None if boundary.completeness == EvidenceCompleteness::Complete
                && models.resolved_external
                && closes_as_resolved_constructor(&boundary.kind) => {}
            None => return None,
        }
    }
    let (summary, mapping) = covering?;
    debug_assert!(summary.completeness().is_complete());
    // An authored summary is a claim, not a derived body (#1916); the
    // closures it gives the call's boundaries are what a finding through it
    // and a run resting on it name.
    let authored = matches!(
        summary.key().identity().origin(),
        SummaryOrigin::External(_)
    )
    .then(|| {
        let summaries = models
            .summaries
            .as_ref()
            .expect("a covering summary is one of the call's bound summaries");
        if has_residual {
            closures.into_boxed_slice()
        } else {
            authored_call_closures(call, &kinds, summaries, models.resolved_external)
                .into_boxed_slice()
        }
    });
    let mut model = models.with_receiver_storage(call_model(
        call,
        summary.transfers(),
        summary.effects(),
        mapping,
        true,
        authored,
        universe,
    ));
    model.summary = Some(summary.key().clone());
    if has_residual {
        // The override closure proves the member behavior, not which
        // implementation's receiver or argument storage the write reaches.
        // Keep the transfer for path discovery, then withhold only paths
        // whose accepted label actually depends on that output.
        for transfer in &mut model.transfers {
            transfer.unresolved_output_storage = matches!(
                transfer.output,
                PartialFlowPort::CallReceiver { .. } | PartialFlowPort::CallArgument { .. }
            );
        }
    }
    Some(model)
}

/// The models of one call (`PolicyCompositionProvider::call_models`).
struct CallModels {
    /// The curated model that replaces the call: its bound external models
    /// merged with a format-result identity, or a Rust std builtin.
    curated: Option<CuratedCallModel>,
    /// The authored summaries of the external targets the call's dispatch
    /// boundaries name.
    summaries: Option<ExternalSemanticSummarySet>,
    /// Whether dispatch proves one exhaustive external target, independently
    /// of an authored override-coverage claim or the language of the receiver.
    resolved_external: bool,
    receiver_storage_available: bool,
}

impl CallModels {
    fn with_receiver_storage(&self, mut model: CallModel) -> CallModel {
        let is_receiver = |port: &PartialFlowPort| {
            matches!(port, PartialFlowPort::CallReceiver { .. })
                || (model.endpoint_projections
                    && matches!(port, PartialFlowPort::Heap { root, .. }
                    if matches!(root.as_ref(), PartialFlowPort::CallReceiver { .. })))
        };
        if !self.receiver_storage_available
            && model
                .transfers
                .iter()
                .any(|transfer| is_receiver(&transfer.actual) || is_receiver(&transfer.output))
        {
            model.completeness = content_incomplete("the member receiver storage is not proven")
                .preserving_operational_cause(&model.completeness);
            model.transfers.retain(|transfer| {
                !is_receiver(&transfer.actual) && !is_receiver(&transfer.output)
            });
        }
        model
    }

    /// The authored summary that closes one of the call's dispatch
    /// boundaries, with its actual-to-formal mapping.
    fn summary_for_boundary(
        &self,
        boundary: &brokk_bifrost_analysis::analyzer::semantic::DispatchBoundaryKind,
    ) -> Option<(&SemanticProcedureSummary, SummaryCallBinding<'_>)> {
        let target = boundary.target_locator()?;
        self.summaries
            .as_ref()?
            .summary_for_boundary(boundary)
            .map(|(summary, shape)| (summary, SummaryCallBinding::new(target, shape)))
    }
}

/// The composition port of the call actual that binds one summary formal.
fn parameter_flow_port(
    call: &CallSiteHandle,
    row: &SemanticCallSite,
    actual_to_formal: SummaryCallBinding<'_>,
    formal: u32,
) -> Option<PartialFlowPort> {
    match actual_to_formal.parameter_actual(call, formal)? {
        SummaryCallActual::Receiver => row
            .receiver
            .is_some()
            .then_some(PartialFlowPort::CallReceiver { call: call.id() }),
        SummaryCallActual::Argument(index) => {
            (index < row.arguments.len()).then(|| PartialFlowPort::CallArgument {
                call: call.id(),
                ordinal: u32::try_from(index).expect("a call's argument count fits u32"),
            })
        }
    }
}

/// A model from one summary's transfers and effects, read at one call. A
/// transfer whose input or output the call does not bind is incomplete.
fn call_model(
    call: &CallSiteHandle,
    transfers: &[SummaryTransfer],
    effects: &[SummaryEffect],
    actual_to_formal: SummaryCallBinding<'_>,
    proven: bool,
    authored: Option<Box<[AuthoredArmClosure]>>,
    universe: &TaintUniverse,
) -> CallModel {
    let row = call.procedure().semantics().call_site(call.id());
    let mut model_transfers = Vec::new();
    let mut completeness = Completeness::Complete;
    for transfer in transfers {
        let exit = transfer.exit();
        let actual = match (row, transfer.input().root()) {
            (Some(row), SummaryPort::Receiver) => actual_to_formal
                .receiver_value(call)
                .or(row.receiver)
                .and_then(|receiver| {
                    if row.receiver == Some(receiver) {
                        Some(PartialFlowPort::CallReceiver { call: call.id() })
                    } else {
                        row.arguments
                            .iter()
                            .position(|argument| argument.value == receiver)
                            .map(|index| PartialFlowPort::CallArgument {
                                call: call.id(),
                                ordinal: u32::try_from(index).expect("argument index fits u32"),
                            })
                    }
                }),
            (Some(row), SummaryPort::Parameter(formal)) => {
                parameter_flow_port(call, row, actual_to_formal, *formal)
            }
            _ => None,
        };
        let input_carried = matches!(
            transfer.input().root(),
            SummaryPort::Receiver | SummaryPort::Parameter(_)
        );
        if exit.kind() != SummaryExitKind::Normal || !input_carried {
            completeness =
                content_incomplete("the model writes a port the composition does not carry");
            continue;
        }
        let output_port = if actual_to_formal.is_receiver_adjustment()
            && matches!(exit.port(), SummaryPort::NormalReturn)
        {
            &SummaryPort::Receiver
        } else {
            exit.port().root()
        };
        let output = match (row, output_port) {
            (Some(row), SummaryPort::NormalReturn) if row.result.is_some() => {
                Some(PartialFlowPort::CallResult {
                    call: call.id(),
                    ordinal: None,
                })
            }
            (Some(row), SummaryPort::IndexedNormalReturn(ordinal))
                if row.normal_result(*ordinal as usize).is_some() =>
            {
                Some(PartialFlowPort::CallResult {
                    call: call.id(),
                    ordinal: Some(*ordinal),
                })
            }
            (Some(row), SummaryPort::Receiver) => actual_to_formal
                .receiver_value(call)
                .or(row.receiver)
                .and_then(|receiver| {
                    if row.receiver == Some(receiver) {
                        Some(PartialFlowPort::CallReceiver { call: call.id() })
                    } else {
                        row.arguments
                            .iter()
                            .position(|argument| argument.value == receiver)
                            .map(|index| PartialFlowPort::CallArgument {
                                call: call.id(),
                                ordinal: u32::try_from(index).expect("argument index fits u32"),
                            })
                    }
                }),
            (Some(row), SummaryPort::Parameter(formal)) => {
                parameter_flow_port(call, row, actual_to_formal, *formal)
            }
            _ => None,
        };
        let output = output.and_then(|root| {
            brokk_bifrost_flow::project_summary_endpoint(
                call.procedure().semantics().locator(),
                root,
                exit.port().projection(),
            )
        });
        let actual = actual.and_then(|root| {
            brokk_bifrost_flow::project_summary_endpoint(
                call.procedure().semantics().locator(),
                root,
                transfer.input().projection(),
            )
        });
        let Some(output) = output else {
            completeness = content_incomplete("the model writes an output the call does not bind");
            continue;
        };
        let Some(actual) = actual else {
            completeness = content_incomplete("the model reads an input the call does not bind");
            continue;
        };
        let mut removed = BTreeSet::new();
        for effect in effects {
            if let SummaryEffectKey::Sanitize {
                input,
                output,
                removed: labels,
            } = effect.key()
                && input == transfer.input()
                && output == exit.port()
            {
                removed.extend(labels.iter().cloned());
            }
        }
        model_transfers.push(ModelTransfer {
            actual,
            output,
            function: taint_model_kill(universe, &removed.into_iter().collect::<Vec<_>>()),
            proven: transfer.evidence().is_proven(),
            unresolved_output_storage: false,
            preserves_member_contents: transfer.preserves_member_contents(),
        });
    }
    CallModel {
        endpoint_projections: transfers.iter().any(|transfer| {
            transfer.input().projection().is_some() || transfer.exit().port().projection().is_some()
        }),
        summary: None,
        summary_target: None,
        transfers: model_transfers,
        writeback: Box::default(),
        receiver_reads: Box::default(),
        proven,
        completeness,
        authored,
        retains_dispatch: false,
    }
}

fn content_incomplete(reason: impl Into<Box<str>>) -> Completeness {
    Completeness::content(reason)
}

#[cfg(test)]
#[path = "taint_compose_provider/override_claim_tests.rs"]
mod override_claim_tests;
