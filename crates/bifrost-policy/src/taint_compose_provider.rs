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

use super::taint_policy::language_intrinsic_call;
use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
use brokk_bifrost_analysis::analyzer::semantic::IntrinsicCall;
use brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator;
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    ReplayingMemo, ReplayingMemoEntry, memo_attribution,
};
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
    ExtendedPartialFlows, ExtraObservation, ExtraSeed, ImplicitHeapRead, ObservationFilter,
    PartialFlowOutcome, PartialFlowPort, ProcedurePartialFlows, compute_partial_flows_filtered,
    compute_partial_flows_with_edge_kills, compute_partial_flows_with_implicit_reads,
    file_local_procedure_relations, observation_value,
};
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::ProcedureOpenness;
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    ProcedureRangeLookupStatus, procedures_for_definition_with_limits,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    BarrierObservation, CallArgumentEndpoint, CallInvocationMode, CallSiteHandle, CallSiteId,
    CallStorageRelationIndex, CandidateCoverage, DispatchBoundary, DispatchBoundaryKind,
    DispatchOracle, DispatchResult, DurableCallContext, EvidenceCompleteness,
    LenientValueTypeBarriers, ObservationPhase, OracleCallContext, ProcedureHandle,
    ProcedureInvocationKind, ProgramPointId, ProofStatus, SemanticArtifactKey, SemanticCapability,
    SemanticExecutionBudget, SemanticGapImpact, SemanticGapKind, SemanticGapSubject,
    SemanticOutcome, SemanticRequest, StrictValueTypeBarriers, ValueFlowEndpoint,
    ValueTypeBarrierDecision, ValueTypeBarrierFilter, ValueTypeBarrierReason, ValueTypePredicate,
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
    Openness, ProcedureEndpoints, StoreChannelLink, StoreChannelLinks, StoreWriteObservation,
    ValueTypeBarrierCheck, taint_model_kill,
};
use brokk_bifrost_flow::taint::{
    SourceEventKey, TaintAnalysisPlan, TaintClassSet, TaintEdgeFunction, TaintUniverse,
};
use brokk_bifrost_flow::value_flow::{
    AuthoredArmClosure, CallSiteCoverage, DurableCallSiteKey, DurableProcedureKey,
    SummaryCallBinding, ValueFlowCarrier, ValueFlowProvider, authored_call_closures,
    closes_as_resolved_constructor,
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

#[derive(Clone, Default)]
struct ConditionalPartitions {
    baseline: Option<TaintEdgeFunction>,
    groups: Vec<(TaintEdgeFunction, Vec<GuardEdgeKill>)>,
}

type ConditionalPartialFlows = Vec<(Option<TaintEdgeFunction>, Arc<ProcedurePartialFlows>)>;

/// The composition's provider over one workspace, one compile and one plan.
pub(crate) struct PolicyCompositionProvider<'a> {
    workspace: &'a WorkspaceAnalyzer,
    discovery: PolicyDiscoveryProvider<'a, 'a>,
    cache: &'a DiscoveryMaterializationCache<'a>,
    execution_budget: SemanticExecutionBudget,
    plan: &'a TaintAnalysisPlan,
    /// The policy's bound external models, sorted by call.
    external_models: &'a [BoundExternalModel],
    /// Incoming calls kept per procedure, the composition's caller lane.
    max_callers_per_procedure: usize,
    /// Partial flows by procedure: the first read or computation per compile.
    partial_flows: RefCell<HashMap<DurableProcedureKey, Arc<ProcedurePartialFlows>>>,
    conditional_partitions: RefCell<HashMap<DurableProcedureKey, ConditionalPartitions>>,
    conditional_declines: RefCell<Vec<SanitizerDecline>>,
    conditional_partial: RefCell<HashMap<DurableProcedureKey, ConditionalPartialFlows>>,
    /// Incoming relation indexes for the compile's immutable procedure snapshots.
    call_storage_indexes: RefCell<HashMap<DurableProcedureKey, Arc<CallStorageRelationIndex>>>,
    barriers: Vec<(Box<str>, ValueTypePredicate)>,
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
    filtered_flows: RefCell<HashMap<DurableProcedureKey, Arc<ProcedurePartialFlows>>>,
    /// Partial-flow answers read from the store.
    stored_reads: Cell<u64>,
    /// Partial-flow answers computed at query time.
    computed: Cell<u64>,
    baseline_reads_cost: ProjectionCounter,
    interior_cost: ProjectionCounter,
    overlay_cost: ProjectionCounter,
    /// Openness per procedure, decided once per compile.
    openness_memo: RefCell<HashMap<DurableProcedureKey, Openness>>,
    /// The gap sweep of each procedure whose partial flows the search read.
    /// It runs at that read, before the openness decision needs it, so the
    /// procedure's refinement calls join its file's next dispatch batch.
    sweeps: RefCell<HashMap<DurableProcedureKey, ProcedureOpenness>>,
    /// Calls this provider dispatched; the run memo answered every other
    /// dispatch request.
    dispatches_made: Cell<usize>,
    /// The covering models of every call whose dispatch this provider read,
    /// from the run memo or its own resolution.
    models: RefCell<HashMap<DurableCallSiteKey, Option<CallModel>>>,
    /// Every dispatched call, recorded in the shape the ICFG engine's
    /// call-resolution diagnostic reads. The first record of a call wins.
    dispatched: RefCell<HashMap<DurableCallSiteKey, RecordedDispatch>>,
    /// The boundaries of every recorded dispatch, for the same diagnostic.
    dispatch_boundaries: RefCell<Vec<DispatchBoundary>>,
    /// Selects and binds the policy's sources, sanitizers and transforms.
    binder: RefCell<FrontierEndpointBinder<'a>>,
    /// The policy whose endpoints the binder matches, the memo's key.
    policy: PolicyId,
    /// The frontier matches this provider's search consulted, whether the
    /// run memo held them or this provider built them. The provider answers
    /// one Output, so these are the only matches whose refusals the Output
    /// depends on; the memo's other matches belong to Outputs that ran
    /// before this one and must not leak into its product.
    consulted_matches: RefCell<BTreeSet<ConsultedMatch>>,
    /// The run's frontier matches and dispatches, shared with the run's other
    /// batches.
    memo: &'a CompositionMemo,
    /// Sliced selector evaluations this batch ran; the memo answered the
    /// rest.
    endpoint_evaluations: Cell<u64>,
    /// The selectors this batch could not slice, with the reason, in the
    /// order they were first evaluated.
    endpoint_widened: RefCell<Vec<(FrontierSelector, WidenReason)>>,
    /// The origin metadata of every source answered, which the projection
    /// reads to attribute a finding's origins to the policy's sources.
    frontier_sources: RefCell<Vec<CompiledTaintEndpoint>>,
    /// The sources answered with unknown evidence, by origin: the row to
    /// judge each from and the endpoint it was bound for.
    unjudged: RefCell<HashMap<SourceEventKey, UnjudgedSource>>,
    /// Points-to evidence runs this batch made; the memo answered the rest.
    source_evidence_resolved: Cell<u64>,
    /// Config-inactive reverse sites excluded during this composition batch.
    /// These are configuration exclusions, never incomplete discovery.
    excluded_callers: RefCell<Vec<(ProjectFile, brokk_bifrost_analysis::analyzer::Range)>>,
    store_writes: Vec<StoreWriteObservation>,
    store_links: HashMap<(DurableProcedureKey, PartialFlowPort), StoreChannelLinks>,
    store_by_read: HashMap<(DurableProcedureKey, PartialFlowPort), HashSet<String>>,
    consulted_stores: RefCell<HashSet<String>>,
    store_calls: HashSet<DurableCallSiteKey>,
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
    dispatches: RefCell<HashMap<(PolicyId, DurableCallSiteKey), Arc<DispatchEntry>>>,
    std_builtins: RefCell<HashMap<DurableCallSiteKey, Arc<StdBuiltinEntry>>>,
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

/// Borrow the ledger only for capture/probe, never across the cold build.
/// Rejected entries and borrowed handles close before the replacement fill.
pub(crate) fn read_admitted<K: Eq + std::hash::Hash, T: Send + Sync + 'static, E>(
    entries: &RefCell<HashMap<K, Arc<AdmittedMemoEntry<T>>>>,
    key: K,
    reacquirer: Option<&dyn brokk_bifrost_analysis::analyzer::semantic::MemoDependencyReacquirer>,
    with_budget: impl Fn(
        &mut dyn FnMut(&mut brokk_bifrost_analysis::analyzer::semantic::SemanticBudget),
    ),
    build: impl FnOnce() -> Result<T, E>,
    keep: impl FnOnce(&T) -> bool,
    hit: impl FnOnce(),
) -> Result<Arc<AdmittedMemoEntry<T>>, E> {
    let cached = entries.borrow().get(&key).cloned();
    if let Some(entry) = cached {
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
        entries.borrow_mut().remove(&key);
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
    let entry = Arc::new(AdmittedMemoEntry {
        value,
        admission: admission.unwrap(),
    });
    if keep(&entry.value) {
        entries.borrow_mut().insert(key, Arc::clone(&entry));
    }
    Ok(entry)
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
) -> Result<impl std::ops::Deref<Target = V>, E> {
    let capability = memo_attribution(analyzer);
    ReplayingMemo::new(()).read(&capability, |_, capture| {
        let entry = read_admitted(
            entries,
            key,
            None,
            with_budget,
            || capture.try_build(build),
            |entry| keep(entry.value()),
            || hits.set(hits.get() + 1),
        )?;
        Ok(Arc::clone(&entry.value))
    })
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

/// The refusals of `entries`, one notice per refused row. A verdict from a build
/// that depended on its execution describes this run, not the recorded inputs,
/// so it is operational. When two matches refuse the same row, the operational
/// notice is the one kept: sorting puts it first, and de-duplication keeps the
/// first of a run.
fn merged_refusals<'m>(
    entries: impl Iterator<Item = &'m FrontierMatchEntry>,
) -> Vec<RefusalNotice> {
    let mut messages = entries
        .flat_map(|entry| {
            let execution_dependent = entry.execution_dependent();
            entry.value().refusals.iter().cloned().map(move |refusal| {
                if execution_dependent {
                    refusal.into_operational()
                } else {
                    refusal
                }
            })
        })
        .collect::<Vec<_>>();
    normalize_refusals(&mut messages);
    messages
}

fn normalize_refusals(messages: &mut Vec<RefusalNotice>) {
    use brokk_bifrost_flow::taint::compose::IncompleteCause;
    messages.sort_by(|left, right| {
        left.message.cmp(&right.message).then_with(|| {
            (left.cause() == IncompleteCause::Content)
                .cmp(&(right.cause() == IncompleteCause::Content))
        })
    });
    messages.dedup_by(|left, right| left.message == right.message);
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
    dispatches: HashSet<(PolicyId, DurableCallSiteKey)>,
    evidence: HashSet<EvidenceKey>,
}

#[cfg(test)]
impl PolicyCompositionProvider<'_> {
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
        self.consulted_matches
            .borrow_mut()
            .insert((artifact.clone(), selector));
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
            .keys()
            .map(|(_, call)| call.clone())
            .collect()
    }
}

/// One call's dispatch as the composition answers it, with the model that
/// covers the call and the record its diagnostics read. A model closes the
/// run boundary, but a partial finding still needs the call's dispatch evidence.
struct MemoizedDispatch {
    dispatch: Dispatch,
    model: Option<CallModel>,
    record: (RecordedDispatch, Box<[DispatchBoundary]>),
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
struct FrontierMatch {
    by_procedure: HashMap<DurableProcedureKey, Vec<FrontierEndpoint>>,
    gaps: Vec<FrontierGap>,
    file_slice_executed: bool,
    /// Per-row refusals must survive an earlier first-cause diagnostic.
    refusals: Vec<RefusalNotice>,
}

impl FrontierMatch {
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
#[derive(Clone)]
struct RecordedDispatch {
    handle: CallSiteHandle,
    status: SemanticInputStatus,
    coverage: CallSiteCoverage,
}

impl<'a> PolicyCompositionProvider<'a> {
    pub(crate) fn conditional_declines(&self) -> Vec<SanitizerDecline> {
        self.conditional_declines.borrow().clone()
    }

    fn conditional_partitions(
        &self,
        handle: &ProcedureHandle,
    ) -> Result<ConditionalPartitions, TaintPolicyCompileError> {
        let key = handle.durable_key();
        if let Some(partitions) = self.conditional_partitions.borrow().get(&key) {
            return Ok(partitions.clone());
        }
        if !self.binder.borrow().has_conditional_sanitizers() {
            return Ok(ConditionalPartitions::default());
        }
        let selected = self.binder.borrow_mut().conditional_in(handle)?;
        let universe = self.plan.universe();
        let guards = selected
            .iter()
            .map(|entry| entry.guard.clone())
            .collect::<Vec<_>>();
        let derived = conditional_guard_edge_kills(handle, &guards);
        let mut by_sanitizer = vec![Vec::new(); selected.len()];
        for decline in derived.declines {
            self.conditional_declines
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
                self.conditional_declines
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
        if by_sanitizer.iter().all(Vec::is_empty) {
            let partitions = ConditionalPartitions::default();
            self.conditional_partitions
                .borrow_mut()
                .insert(key, partitions.clone());
            return Ok(partitions);
        }
        let mut classes_by_kills: HashMap<
            Vec<usize>,
            Vec<&brokk_bifrost_flow::taint::SourceClassId>,
        > = HashMap::new();
        for class in universe.classes() {
            let kills = selected
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    (!by_sanitizer[index].is_empty()
                        && entry
                            .removes
                            .iter()
                            .any(|label| label.as_str() == class.as_str()))
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
        let partitions = ConditionalPartitions { baseline, groups };
        self.conditional_partitions
            .borrow_mut()
            .insert(key, partitions.clone());
        Ok(partitions)
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
            workspace,
            discovery: PolicyDiscoveryProvider::with_dispatch_pool(
                workspace,
                execution_budget.clone(),
                cache,
            ),
            cache,
            execution_budget: execution_budget.clone(),
            plan,
            external_models,
            max_callers_per_procedure,
            barriers: binder.barriers(),
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
            filtered_flows: RefCell::new(HashMap::new()),
            partial_flows: RefCell::new(HashMap::new()),
            conditional_partitions: RefCell::new(HashMap::new()),
            conditional_declines: RefCell::new(Vec::new()),
            conditional_partial: RefCell::new(HashMap::new()),
            call_storage_indexes: RefCell::new(HashMap::new()),
            stored_reads: Cell::new(0),
            computed: Cell::new(0),
            baseline_reads_cost: ProjectionCounter::default(),
            interior_cost: ProjectionCounter::default(),
            overlay_cost: ProjectionCounter::default(),
            openness_memo: RefCell::new(HashMap::new()),
            sweeps: RefCell::new(HashMap::new()),
            dispatches_made: Cell::new(0),
            models: RefCell::new(HashMap::new()),
            dispatched: RefCell::new(HashMap::new()),
            dispatch_boundaries: RefCell::new(Vec::new()),
            policy: binder.policy_id().clone(),
            consulted_matches: RefCell::new(BTreeSet::new()),
            binder: RefCell::new(binder),
            memo,
            endpoint_evaluations: Cell::new(0),
            endpoint_widened: RefCell::new(Vec::new()),
            frontier_sources: RefCell::new(Vec::new()),
            unjudged: RefCell::new(HashMap::new()),
            source_evidence_resolved: Cell::new(0),
            excluded_callers: RefCell::new(Vec::new()),
            store_writes: Vec::new(),
            store_links: HashMap::new(),
            store_by_read: HashMap::new(),
            consulted_stores: RefCell::new(HashSet::new()),
            store_calls: HashSet::new(),
        }
    }

    /// Link the compile's selected store ends, once for this query. The
    /// compiled metadata belongs to one policy, so links cannot cross a
    /// policy boundary even when channel names coincide.
    pub(crate) fn with_store_inventory(
        mut self,
        writes: &[CompiledStoreEnd],
        reads: &[CompiledStoreEnd],
    ) -> Self {
        self.store_calls
            .extend(writes.iter().chain(reads).map(|end| end.call.durable_key()));
        self.store_writes = writes
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
            let key = (read.call.procedure().durable_key(), output);
            self.store_by_read
                .entry(key.clone())
                .or_default()
                .insert(read.channel.store().to_owned());
            let answer = self.store_links.entry(key).or_default();
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
        std::cell::Ref::map(self.excluded_callers.borrow(), |sites| sites.as_slice())
    }

    fn call_storage_index(
        &self,
        procedure: &ProcedureHandle,
        snapshot: &brokk_bifrost_analysis::analyzer::semantic::ValueFlowSnapshot,
    ) -> Arc<CallStorageRelationIndex> {
        Arc::clone(
            self.call_storage_indexes
                .borrow_mut()
                .entry(procedure.durable_key())
                .or_insert_with(|| Arc::new(CallStorageRelationIndex::new(snapshot))),
        )
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
        self.frontier_sources.borrow().clone()
    }

    pub(crate) fn frontier_source_count(&self) -> usize {
        self.frontier_sources.borrow().len()
    }

    /// Stores whose read outputs the current anchor search consulted, even
    /// when no writer reached that read and the anchor stayed clean.
    pub(crate) fn consulted_stores(&self) -> Vec<String> {
        let mut stores = self
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
        // Record the consult before the memo lookup: a hit and a build both
        // make this Output depend on the match, and the entry replays the
        // reads of its build into this Output's capture either way.
        self.consulted_matches
            .borrow_mut()
            .insert((artifact.clone(), selector));
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
        let matches = self.memo.matches.borrow();
        merged_refusals(self.consulted_matches.borrow().iter().filter_map(
            |(artifact, selector)| matches.get(&(self.policy.clone(), artifact.clone(), *selector)),
        ))
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
        self.dispatched.borrow().get(call).map(|recorded| {
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
                .dispatched
                .borrow()
                .iter()
                .map(|(call, recorded)| (call.clone(), recorded.coverage.clone()))
                .collect(),
            boundaries: self.dispatch_boundaries.borrow().clone(),
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
        self.cache
            .artifacts
            .borrow()
            .get(&key.0)
            .and_then(|artifact| artifact.procedure_handle(key.1))
            .expect("a procedure the composition visited has a materialized artifact")
    }

    fn procedure(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureHandle, TaintPolicyCompileError> {
        self.discovery.procedure(key, request)
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
        for (_, predicate) in &self.provider.barriers {
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

impl brokk_bifrost_flow::composition::InteriorProjectionClient for PolicyCompositionProvider<'_> {
    type Error = TaintPolicyCompileError;

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
        if !edge_kills.is_empty() {
            compute_partial_flows_with_edge_kills(
                handle,
                snapshot,
                seeds,
                observations,
                witnesses,
                implicit_reads,
                edge_kills,
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
        if self.store_calls.contains(&call.durable_key()) {
            // A selected store end replaces this call's value transfer.
            return Ok(brokk_bifrost_flow::composition::CallModelDecision {
                model: Some(CallModel {
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
    fn relations_head(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, TaintPolicyCompileError> {
        self.partial_flows(procedure, request)
    }

    fn openness_sweep(
        &self,
        procedure: &DurableProcedureKey,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, TaintPolicyCompileError> {
        self.openness_sweep(procedure, handle, request)
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
                    causes.join("; "),
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
        for gap in semantics.gaps() {
            if (gap.capability == SemanticCapability::Calls
                && !matches!(gap.subject, SemanticGapSubject::CallSite(_)))
                || gap.impacts.contains(SemanticGapImpact::CallEvaluation)
            {
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
                call: (procedure.clone(), call.id),
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
                        format!("{reasons:?}"),
                    )
                } else if budget_gap {
                    Completeness::operational(
                        brokk_bifrost_flow::taint::compose::OperationalCause::Budget(
                            brokk_bifrost_flow::taint::compose::BudgetLane::Semantic,
                        ),
                        format!("{reasons:?}"),
                    )
                } else {
                    Completeness::content(format!("{reasons:?}"))
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
                        .call_site_handle(step.call.1)
                        .expect("an execution prefix names an existing call"),
                );
            }
        }
        let context = OracleCallContext::bounded(prior_calls, *oracle.limits());
        let (site, answer) = if incoming.is_some() {
            let handle = self.procedure(&call.0, request)?;
            let site = handle
                .call_site_handle(call.1)
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
        self.store_writes.clone()
    }

    fn store_links(
        &self,
        procedure: &DurableProcedureKey,
        output: &PartialFlowPort,
    ) -> StoreChannelLinks {
        let key = (procedure.clone(), output.clone());
        if let Some(stores) = self.store_by_read.get(&key) {
            self.consulted_stores
                .borrow_mut()
                .extend(stores.iter().cloned());
        }
        self.store_links.get(&key).cloned().unwrap_or_default()
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
        !self.barriers.is_empty()
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
        let index = self.call_storage_index(procedure, snapshot);
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
                    transfer.exit().port(),
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
        let index = self.call_storage_index(procedure, snapshot);
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
        self.filtered_flows.borrow_mut().clear();
        self.conditional_partial.borrow_mut().clear();
    }

    fn strict_value_type_barriers(&self, chop: &HashSet<DurableProcedureKey>) {
        self.barrier_filter
            .replace(Box::new(StrictValueTypeBarriers));
        self.barrier_chop.replace(chop.clone());
        self.filtered_flows.borrow_mut().clear();
        self.conditional_partial.borrow_mut().clear();
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
            for (id, predicate) in &self.barriers {
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
        if self.barrier_chop.borrow().contains(procedure) {
            if let Some(flows) = self.filtered_flows.borrow().get(procedure) {
                return Ok(Arc::clone(flows));
            }
            let handle = self.procedure(procedure, request)?;
            let mut fixpoint_request = request.staged_with_execution_budget(&self.execution_budget);
            let outcome = file_local_procedure_relations(
                &handle,
                &OracleCallContext::empty(),
                &mut fixpoint_request,
            )
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
            self.discovery
                .require_outcome(&outcome, "barrier partial flows")?;
            let snapshot = outcome.available_value().ok_or_else(|| {
                TaintPolicyCompileError::SemanticUnavailable(
                    "barrier partial-flow projection is unavailable".to_owned(),
                )
            })?;
            let _timing = brokk_bifrost_analysis::profiling::scope("taint.barriers.fixpoint");
            self.barrier_fixpoints.set(self.barrier_fixpoints.get() + 1);
            self.barrier_procedures
                .borrow_mut()
                .insert(procedure.clone());
            let overlay_cpu_start = ProjectionCounter::start();
            let filtered = compute_partial_flows_filtered(
                &handle,
                snapshot,
                &[],
                &[],
                false,
                &[],
                &mut ProcedureBarrierFilter {
                    provider: self,
                    procedure: &handle,
                },
                &mut fixpoint_request,
            )?
            .partial;
            self.overlay_cost.record(overlay_cpu_start);
            let stored = self.partial_flows.borrow();
            let baseline = stored
                .get(procedure)
                .expect("the chop only names procedures read by the baseline search");
            debug_assert!(
                filtered.flows.iter().all(|flow| baseline
                    .flows
                    .iter()
                    .any(|original| baseline.ports[original.from.index()]
                        == filtered.ports[flow.from.index()]
                        && baseline.ports[original.to.index()] == filtered.ports[flow.to.index()])),
                "barrier filtering only removes stored port flows"
            );
            drop(stored);
            let filtered = Arc::new(filtered);
            self.filtered_flows
                .borrow_mut()
                .insert(procedure.clone(), Arc::clone(&filtered));
            return Ok(filtered);
        }
        if let Some(flows) = self.partial_flows.borrow().get(procedure) {
            return Ok(Arc::clone(flows));
        }
        let handle = self.procedure(procedure, request)?;
        let baseline_cpu_start = ProjectionCounter::start();
        let stored =
            brokk_bifrost_flow::composition::stored_partial_flows(&self.discovery, &handle)?;
        self.baseline_reads_cost.record(baseline_cpu_start);
        let flows = match stored {
            Some(flows)
                if matches!(
                    flows.outcome,
                    PartialFlowOutcome::Complete | PartialFlowOutcome::ExceededBudget
                ) =>
            {
                self.stored_reads.set(self.stored_reads.get() + 1);
                Arc::new(flows)
            }
            _ => {
                let flows = brokk_bifrost_flow::composition::project_partial_flows(
                    &self.discovery,
                    &handle,
                    &self.execution_budget,
                    request,
                )?;
                self.computed.set(self.computed.get() + 1);
                Arc::new(flows)
            }
        };
        self.partial_flows
            .borrow_mut()
            .insert(procedure.clone(), Arc::clone(&flows));
        self.announce_refinement_calls(procedure, &handle, request)?;
        Ok(flows)
    }

    fn projected_partial_flows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<(Option<TaintEdgeFunction>, Arc<ProcedurePartialFlows>)>, Self::Error> {
        if let Some(cached) = self.conditional_partial.borrow().get(procedure) {
            return Ok(cached.clone());
        }
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
        let mut fixpoint_request = request.staged_with_execution_budget(&self.execution_budget);
        let outcome = file_local_procedure_relations(
            &handle,
            &OracleCallContext::empty(),
            &mut fixpoint_request,
        )
        .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        for (function, kills) in partitions.groups {
            let partial = if let Some(snapshot) = outcome.available_value() {
                compute_partial_flows_with_edge_kills(
                    &handle,
                    snapshot,
                    &[],
                    &[],
                    false,
                    &[],
                    &kills,
                    &mut ProcedureBarrierFilter {
                        provider: self,
                        procedure: &handle,
                    },
                    &mut fixpoint_request,
                )?
                .partial
            } else {
                (*baseline)
                    .clone()
                    .with_failed_projection("conditional sanitizer projection unavailable".into())
            };
            projected.push((Some(function), Arc::new(partial)));
        }
        self.conditional_partial
            .borrow_mut()
            .insert(procedure.clone(), projected.clone());
        Ok(projected)
    }

    fn interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, Self::Error> {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.interior");
        let interior_cpu_start = ProjectionCounter::start();
        let handle = self.procedure(procedure, request)?;
        let outcome =
            self.discovery
                .procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
        let Some(snapshot) = outcome.available_value() else {
            self.interior_cost.record(interior_cpu_start);
            return Ok(
                brokk_bifrost_flow::composition::unavailable_snapshot_interior(
                    handle,
                    SemanticInputStatus::from_outcome(&outcome),
                    "the procedure's value-flow snapshot is unavailable",
                ),
            );
        };
        let flows = brokk_bifrost_flow::composition::interior_from_snapshot(
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

    fn projected_interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<(Option<TaintEdgeFunction>, InteriorFlows)>, Self::Error> {
        let handle = self.procedure(procedure, request)?;
        let partitions = self.conditional_partitions(&handle)?;
        if partitions.groups.is_empty() {
            return Ok(vec![(
                None,
                self.interior_flows(procedure, seeds, observations, witnesses, request)?,
            )]);
        }
        let mut projected = Vec::new();
        if let Some(function) = partitions.baseline {
            projected.push((
                Some(function),
                self.interior_flows(procedure, seeds, observations, witnesses, request)?,
            ));
        }
        let outcome =
            self.discovery
                .procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
        for (function, kills) in partitions.groups {
            let flows = if let Some(snapshot) = outcome.available_value() {
                brokk_bifrost_flow::composition::interior_from_snapshot(
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
                brokk_bifrost_flow::composition::unavailable_snapshot_interior(
                    handle.clone(),
                    SemanticInputStatus::from_outcome(&outcome),
                    "conditional sanitizer projection unavailable",
                )
            };
            projected.push((Some(function), flows));
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
        if self.barriers.is_empty() {
            return self.interior_flows(procedure, seeds, observations, witnesses, request);
        }
        let interior_cpu_start = ProjectionCounter::start();
        let handle = self.procedure(procedure, request)?;
        let outcome = file_local_procedure_relations(&handle, &OracleCallContext::empty(), request)
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        let Some(snapshot) = outcome.available_value() else {
            self.interior_cost.record(interior_cpu_start);
            return Ok(
                brokk_bifrost_flow::composition::unavailable_snapshot_interior(
                    handle,
                    SemanticInputStatus::from_outcome(&outcome),
                    "file-local witness relations are unavailable",
                ),
            );
        };
        let flows = brokk_bifrost_flow::composition::interior_from_snapshot(
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

    fn projected_stored_interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<(Option<TaintEdgeFunction>, InteriorFlows)>, Self::Error> {
        let handle = self.procedure(procedure, request)?;
        let partitions = self.conditional_partitions(&handle)?;
        if partitions.groups.is_empty() {
            return Ok(vec![(
                None,
                self.stored_interior_flows(procedure, seeds, observations, witnesses, request)?,
            )]);
        }
        let mut projected = Vec::new();
        if let Some(function) = partitions.baseline {
            projected.push((
                Some(function),
                self.stored_interior_flows(procedure, seeds, observations, witnesses, request)?,
            ));
        }
        let outcome = file_local_procedure_relations(&handle, &OracleCallContext::empty(), request)
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        for (function, kills) in partitions.groups {
            let flows = if let Some(snapshot) = outcome.available_value() {
                brokk_bifrost_flow::composition::interior_from_snapshot(
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
                brokk_bifrost_flow::composition::unavailable_snapshot_interior(
                    handle.clone(),
                    SemanticInputStatus::from_outcome(&outcome),
                    "conditional sanitizer witness projection unavailable",
                )
            };
            projected.push((Some(function), flows));
        }
        Ok(projected)
    }

    fn dispatch(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(Dispatch, Option<CallModel>), Self::Error> {
        let key = (self.policy.clone(), call.clone());
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
        self.record_dispatch(call, record, boundaries);
        // `authored_models` reads every dispatched call's model.
        self.models
            .borrow_mut()
            .insert(call.clone(), memoized.model.clone());
        Ok((memoized.dispatch.clone(), memoized.model.clone()))
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
            &self.excluded_callers,
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
        let models = self.models.borrow();
        let mut authored = models
            .iter()
            .filter_map(|(call, model)| Some((call, model.as_ref()?.authored.clone()?)))
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
        if let Some(openness) = self.openness_memo.borrow().get(procedure) {
            return Ok(openness.clone());
        }
        let openness = self.decide_openness(procedure, request)?;
        self.openness_memo
            .borrow_mut()
            .insert(procedure.clone(), openness.clone());
        Ok(openness)
    }

    fn endpoints(
        &self,
        procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureEndpoints, Self::Error> {
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
        self.frontier_sources.borrow_mut().extend(sources);
        self.unjudged.borrow_mut().extend(
            unjudged
                .into_iter()
                .map(|source| (source.origin.clone(), source)),
        );
        if !gaps.is_empty() {
            let content = gaps.iter().all(FrontierGap::is_content);
            gaps.sort_by(|a, b| a.message.cmp(&b.message));
            let message = format!(
                "the policy endpoints of this procedure may be incomplete: {:?}",
                gaps.iter().map(|gap| &gap.message).collect::<Vec<_>>()
            );
            answer.completeness = if content {
                Completeness::content(message)
            } else {
                Completeness::operational(
                    brokk_bifrost_flow::taint::compose::OperationalCause::Provider,
                    message,
                )
            }
            .preserving_operational_cause(&answer.completeness);
        }
        Ok(answer)
    }

    fn source_evidence(
        &self,
        source: &BoundSource,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<HopQuality, Self::Error> {
        let unjudged = self.unjudged.borrow();
        let judged = unjudged
            .get(&source.origin)
            .expect("the search judges only sources this provider answered with unknown evidence");
        let selection = &judged.selection;
        let key = (
            self.policy.clone(),
            judged.identity.clone(),
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
        Ok(*quality)
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
                roots.push(lookup.handles[0].durable_key());
            }
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
        let key = call.durable_key();
        let group = self
            .external_models
            .iter()
            .filter(|model| model.call.durable_key() == key)
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
            call.durable_key(),
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
    fn record_dispatch(
        &self,
        call: &DurableCallSiteKey,
        record: &RecordedDispatch,
        boundaries: &[DispatchBoundary],
    ) {
        let mut dispatched = self.dispatched.borrow_mut();
        if dispatched.contains_key(call) {
            return;
        }
        dispatched.insert(call.clone(), record.clone());
        self.dispatch_boundaries
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
        brokk_bifrost_flow::composition::decide_openness(&self.discovery, self, procedure, request)
    }

    /// The gap sweep of one procedure: whether it is open and the gaps that
    /// keep it open, computed once per compile.
    fn openness_sweep(
        &self,
        procedure: &DurableProcedureKey,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, TaintPolicyCompileError> {
        if let Some(sweep) = self.sweeps.borrow().get(procedure) {
            return Ok(sweep.clone());
        }
        let sweep = brokk_bifrost_flow::composition::openness_sweep(
            &self.discovery,
            handle,
            &self.execution_budget,
            request,
        )?;
        self.sweeps
            .borrow_mut()
            .insert(procedure.clone(), sweep.clone());
        Ok(sweep)
    }

    /// Announce the calls the openness decision of `procedure` will dispatch
    /// (its refinement calls) to the dispatch pool, so they are resolved in
    /// the batch of the next dispatch in the procedure's file: the search's
    /// next call there or, failing that, the first refinement call.
    fn announce_refinement_calls(
        &self,
        procedure: &DurableProcedureKey,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), TaintPolicyCompileError> {
        let sweep = self.openness_sweep(procedure, handle, request)?;
        let memo = self.memo.dispatches.borrow();
        let calls = brokk_bifrost_flow::composition::refinement_calls(handle, &sweep, |call| {
            memo.contains_key(&(self.policy.clone(), (procedure.clone(), call)))
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
    // selection proved every other arm. An exact external arm needs its own
    // override-coverage claim and complete call evidence; the summary's data
    // transfer alone does not certify its continuation.
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
                    && model.authored.as_ref().is_some_and(|closures| {
                        closures.iter().all(|closure| closure.origin().covers_overrides())
                    })
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
            || candidate.target().semantics().properties().invocation
                == ProcedureInvocationKind::Deferred;
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
        if !self.receiver_storage_available
            && model.transfers.iter().any(|transfer| {
                matches!(transfer.actual, PartialFlowPort::CallReceiver { .. })
                    || matches!(transfer.output, PartialFlowPort::CallReceiver { .. })
            })
        {
            model.completeness = content_incomplete("the member receiver storage is not proven")
                .preserving_operational_cause(&model.completeness);
            model.transfers.retain(|transfer| {
                !matches!(transfer.actual, PartialFlowPort::CallReceiver { .. })
                    && !matches!(transfer.output, PartialFlowPort::CallReceiver { .. })
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
            .map(|(summary, mapping)| (summary, SummaryCallBinding::new(target, mapping)))
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
        let actual = match (row, transfer.input()) {
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
            (Some(row), SummaryPort::Parameter(formal)) => actual_to_formal
                .parameter_index(call, *formal)
                .filter(|index| index < &row.arguments.len())
                .map(|index| PartialFlowPort::CallArgument {
                    call: call.id(),
                    ordinal: u32::try_from(index).expect("a call's argument count fits u32"),
                }),
            _ => None,
        };
        let input_carried = matches!(
            transfer.input(),
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
            exit.port()
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
            (Some(row), SummaryPort::Parameter(formal)) => actual_to_formal
                .parameter_index(call, *formal)
                .filter(|index| *index < row.arguments.len())
                .map(|index| PartialFlowPort::CallArgument {
                    call: call.id(),
                    ordinal: u32::try_from(index).expect("argument index fits u32"),
                }),
            _ => None,
        };
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
        });
    }
    CallModel {
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
