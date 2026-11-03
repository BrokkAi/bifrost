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
use brokk_bifrost_analysis::analyzer::semantic::IntrinsicCall;
use brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator;
use brokk_bifrost_rust_analysis::analyzer::rust::semantic::canonical_returned_field_member;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

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
use brokk_bifrost_analysis::analyzer::semantic::{
    BarrierObservation, CallArgumentEndpoint, CallInvocationMode, CallSiteHandle, CallSiteId,
    CallStorageRelationIndex, CandidateCoverage, DispatchBoundary, DispatchBoundaryKind,
    DispatchResult, EvidenceCompleteness, LenientValueTypeBarriers, ObservationPhase,
    OracleCallContext, ProcedureHandle, ProcedureInvocationKind, ProgramPointId, ProofStatus,
    SemanticArtifactKey, SemanticExecutionBudget, SemanticOutcome, SemanticRequest,
    StrictValueTypeBarriers, ValueFlowEndpoint, ValueTypeBarrierDecision, ValueTypeBarrierFilter,
    ValueTypeBarrierReason, ValueTypePredicate,
};
use brokk_bifrost_analysis::analyzer::{ProjectFile, WorkspaceAnalyzer};
use brokk_bifrost_flow::dataflow::{
    CuratedCallModel, ExternalSemanticSummarySet, SemanticInputStatus, SemanticProcedureSummary,
    SummaryEffect, SummaryEffectKey, SummaryExitKind, SummaryOrigin, SummaryPort, SummaryTransfer,
    UnmodeledCallBehavior,
};
use brokk_bifrost_flow::taint::compose::{
    BoundSource, CallModel, Callers, Completeness, CompositionProvider, Dispatch, FallbackPorts,
    HopQuality, InteriorFlows, InteriorObservation, InteriorSeed, ModelTransfer, Openness,
    ProcedureEndpoints, StoreChannelLink, StoreChannelLinks, StoreWriteObservation,
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
    FrontierSelector, PolicyDiscoveryProvider, RefusalNotice, SanitizerDecline,
    TaintPolicyCompileError, UnjudgedSource, intrinsic_call_model,
    intrinsic_format_result_identity,
};
use crate::units::WidenReason;

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
/// - Each call's Rust std builtin classification, which reads only the
///   call's source and resolution and so is shared by every policy.
#[derive(Default)]
pub(crate) struct CompositionMemo {
    matches:
        RefCell<HashMap<(PolicyId, SemanticArtifactKey, FrontierSelector), Arc<FrontierMatch>>>,
    widened: RefCell<HashMap<(PolicyId, FrontierSelector), Arc<WidenedRows>>>,
    dispatches: RefCell<HashMap<(PolicyId, DurableCallSiteKey), Arc<MemoizedDispatch>>>,
    std_builtins: RefCell<HashMap<DurableCallSiteKey, Option<IntrinsicCall>>>,
    /// The evidence of each frontier matched-value source that reached a
    /// sink, by policy, endpoint and selected site. Judging one is a
    /// points-to question, so the run asks it once for a site however many
    /// batches report a flow from it.
    evidence: RefCell<HashMap<EvidenceKey, HopQuality>>,
}

#[cfg(test)]
impl CompositionMemo {
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

/// What one selector bound in one blob.
struct FrontierMatch {
    by_procedure: HashMap<DurableProcedureKey, Vec<FrontierEndpoint>>,
    gaps: Vec<String>,
    /// Per-row refusals must survive an earlier first-cause diagnostic.
    refusals: Vec<RefusalNotice>,
}

/// One unsliceable selector's workspace-wide rows by file, and the reasons
/// its evaluation may have missed a row.
struct WidenedRows {
    by_file: HashMap<ProjectFile, Vec<crate::taint_policy::SelectedSite>>,
    gaps: Vec<String>,
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

    /// What `selector` bound in the blob `artifact`, evaluated once per blob
    /// in the run: sliced to the blob when the selector's query allows it,
    /// otherwise from the selector's workspace-wide rows of that file.
    fn frontier_match(
        &self,
        artifact: &SemanticArtifactKey,
        selector: FrontierSelector,
    ) -> Result<Arc<FrontierMatch>, TaintPolicyCompileError> {
        let key = (self.policy.clone(), artifact.clone(), selector);
        if let Some(matched) = self.memo.matches.borrow().get(&key) {
            return Ok(Arc::clone(matched));
        }
        let root = self.workspace.analyzer().project().root();
        let file = ProjectFile::new(root.to_path_buf(), artifact.path().as_path());
        let mut binder = self.binder.borrow_mut();
        let (sites, mut gaps) = match binder.widen_reason(selector)? {
            None => {
                self.endpoint_evaluations
                    .set(self.endpoint_evaluations.get() + 1);
                let _timing =
                    brokk_bifrost_analysis::profiling::scope("taint.compose.endpoints.select");
                (binder.select_in_file(selector, &file)?, Vec::new())
            }
            Some(reason) => {
                let widened_key = (self.policy.clone(), selector);
                let cached = self.memo.widened.borrow().get(&widened_key).cloned();
                let rows = match cached {
                    Some(rows) => rows,
                    None => {
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
                        let rows = Arc::new(WidenedRows { by_file, gaps });
                        self.memo
                            .widened
                            .borrow_mut()
                            .insert(widened_key, Arc::clone(&rows));
                        rows
                    }
                };
                (
                    rows.by_file.get(&file).cloned().unwrap_or_default(),
                    rows.gaps.clone(),
                )
            }
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
            refusals: bound.refusals,
        });
        self.memo
            .matches
            .borrow_mut()
            .insert(key, Arc::clone(&matched));
        Ok(matched)
    }

    /// Every refused frontier row of this policy, including cached matches
    /// served by earlier batches. The run retains them independently of its
    /// first path-relevant incompleteness (#4919).
    pub(crate) fn refusal_messages(&self) -> Vec<RefusalNotice> {
        let mut messages = self
            .memo
            .matches
            .borrow()
            .iter()
            .filter(|((policy, _, _), _)| policy == &self.policy)
            .flat_map(|(_, matched)| matched.refusals.iter().cloned())
            .collect::<Vec<_>>();
        messages.sort_by(|left, right| left.message.cmp(&right.message));
        messages.dedup_by(|left, right| left.message == right.message);
        messages
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
                    transfers: Vec::new(),
                    proven: true,
                    completeness: Completeness::Complete,
                    authored: None,
                }),
                continuation: HopQuality::CERTAIN,
            });
        }
        let models = self.call_models(call, answer)?;
        Ok(brokk_bifrost_flow::composition::CallModelDecision {
            continuation: continuation_quality(&models, call, answer.available_value()),
            model: covering_model(
                &models,
                call,
                answer.available_value(),
                self.plan.universe(),
            ),
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
        .is_some())
    }
}

impl brokk_bifrost_flow::composition::LocalOpennessClient<PolicyDiscoveryProvider<'_, '_>>
    for PolicyCompositionProvider<'_>
{
    fn relations_complete(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, TaintPolicyCompileError> {
        Ok(self.partial_flows(procedure, request)?.relations_complete)
    }

    fn openness_sweep(
        &self,
        procedure: &DurableProcedureKey,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, TaintPolicyCompileError> {
        self.openness_sweep(procedure, handle, request)
    }

    fn dispatch_complete(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, TaintPolicyCompileError> {
        Ok(matches!(
            self.dispatch(call, request)?.completeness,
            Completeness::Complete
        ))
    }
}

impl CompositionProvider for PolicyCompositionProvider<'_> {
    type Error = TaintPolicyCompileError;
    type Fact = TaintClassSet;
    type Function = TaintEdgeFunction;

    fn store_writes(&self) -> Vec<StoreWriteObservation> {
        self.store_writes.clone()
    }

    fn store_links(
        &self,
        procedure: &DurableProcedureKey,
        output: &PartialFlowPort,
    ) -> StoreChannelLinks {
        self.store_links
            .get(&(procedure.clone(), output.clone()))
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
                let mut open = (*baseline).clone();
                open.outcome = PartialFlowOutcome::Error;
                open.detail = Some("conditional sanitizer projection unavailable".into());
                open.open = true;
                open.relations_complete = false;
                open
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
            return Ok(brokk_bifrost_flow::composition::incomplete_interior(
                handle,
                "the procedure's value-flow snapshot is unavailable",
            ));
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
                brokk_bifrost_flow::composition::incomplete_interior(
                    handle.clone(),
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
            return Ok(brokk_bifrost_flow::composition::incomplete_interior(
                handle,
                "file-local witness relations are unavailable",
            ));
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
                brokk_bifrost_flow::composition::incomplete_interior(
                    handle.clone(),
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
    ) -> Result<Dispatch, Self::Error> {
        let key = (self.policy.clone(), call.clone());
        let memoized = self.memo.dispatches.borrow().get(&key).cloned();
        let memoized = match memoized {
            // The run memo outlives each batch's discovery materialization.
            // Re-resolving here would charge the next batch for the same call.
            Some(memoized) => memoized,
            None => {
                let memoized = Arc::new(self.dispatch_uncached(call, request)?);
                self.dispatches_made.set(self.dispatches_made.get() + 1);
                self.memo
                    .dispatches
                    .borrow_mut()
                    .insert(key, Arc::clone(&memoized));
                memoized
            }
        };
        let (record, boundaries) = &memoized.record;
        self.record_dispatch(call, record, boundaries);
        self.models
            .borrow_mut()
            .insert(call.clone(), memoized.model.clone());
        Ok(memoized.dispatch.clone())
    }

    fn callers(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Callers, Self::Error> {
        brokk_bifrost_flow::composition::callers(
            &self.discovery,
            self,
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
        let handle = self.procedure(procedure, request)?;
        Ok(handle
            .semantics()
            .lexical_parent()
            .map(|parent| (procedure.0.clone(), parent)))
    }

    fn model(&self, call: &DurableCallSiteKey) -> Option<CallModel> {
        self.models
            .borrow()
            .get(call)
            .expect("the search asks a call's model only after its dispatch")
            .clone()
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
            let matched = self.frontier_match(&procedure.0, selector)?;
            endpoints.extend(
                matched
                    .by_procedure
                    .get(procedure)
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
            gaps.extend(matched.gaps.iter().cloned());
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
            answer.completeness = incomplete(format!(
                "the policy endpoints of this procedure may be incomplete: {gaps:?}"
            ));
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
        if let Some(quality) = self.memo.evidence.borrow().get(&key) {
            return Ok(*quality);
        }
        self.source_evidence_resolved
            .set(self.source_evidence_resolved.get() + 1);
        let quality = {
            let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.points_to");
            self.binder.borrow_mut().source_evidence(selection)?
        };
        self.memo.evidence.borrow_mut().insert(key, quality);
        Ok(quality)
    }
}

impl PolicyCompositionProvider<'_> {
    /// Dispatch one call the run memo does not hold: resolve it, decide its
    /// models, and bind each candidate.
    fn dispatch_uncached(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<MemoizedDispatch, TaintPolicyCompileError> {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.dispatch");
        let local = brokk_bifrost_flow::composition::dispatch_uncached(
            &self.discovery,
            self,
            call,
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
        let key = call.durable_key();
        if let Some(builtin) = self.memo.std_builtins.borrow().get(&key) {
            return Ok(builtin.clone());
        }
        let _timing =
            brokk_bifrost_analysis::profiling::scope("taint.compose.call_models.std_builtin");
        let builtin = language_intrinsic_call(self.workspace, call)
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
        self.memo
            .std_builtins
            .borrow_mut()
            .insert(key, builtin.clone());
        Ok(builtin)
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
    let replaced = models.curated.is_some();
    let proven_model = models
        .curated
        .as_ref()
        .is_some_and(CuratedCallModel::is_proven_complete);
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

/// The model that covers a call, if any.
///
/// A curated model of the call replaces the call outright, as the ICFG
/// engine's `call_replaced_by_model` does. Otherwise a bound external summary
/// covers the call when it closes every boundary the call leaves open: each
/// such boundary is proven, the call has no resolved candidate body, and
/// exactly one summary closes the open boundaries and is itself complete. Any
/// other case is no model, and the call stays a boundary.
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
    if !result.candidates().is_empty() {
        return None;
    }
    let mut covering = None;
    for boundary in result.boundaries() {
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
    if !summary.completeness().is_complete() {
        return None;
    }
    // An authored summary is a claim, not a derived body (#1916); the
    // closures it gives the call's boundaries are what a finding through it
    // and a run resting on it name.
    let authored = matches!(
        summary.key().identity().origin(),
        SummaryOrigin::External(_)
    )
    .then(|| {
        let kinds = result
            .boundaries()
            .iter()
            .map(|boundary| &boundary.kind)
            .collect::<Vec<_>>();
        let summaries = models
            .summaries
            .as_ref()
            .expect("a covering summary is one of the call's bound summaries");
        authored_call_closures(call, &kinds, summaries, models.resolved_external).into_boxed_slice()
    });
    Some(models.with_receiver_storage(call_model(
        call,
        summary.transfers(),
        summary.effects(),
        mapping,
        true,
        authored,
        universe,
    )))
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
            && model
                .transfers
                .iter()
                .any(|transfer| matches!(transfer.actual, PartialFlowPort::CallReceiver { .. }))
        {
            model.completeness = incomplete("the member receiver storage is not proven");
            model.transfers.retain(|transfer| {
                !matches!(transfer.actual, PartialFlowPort::CallReceiver { .. })
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
/// transfer whose input the call does not bind, or whose output is not the
/// normal return, is incomplete: the composition does not carry that port.
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
        if exit.kind() != SummaryExitKind::Normal
            || exit.port() != &SummaryPort::NormalReturn
            || !input_carried
        {
            completeness = incomplete("the model writes a port the composition does not carry");
            continue;
        }
        let Some(actual) = actual else {
            completeness = incomplete("the model reads an input the call does not bind");
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
                && output == &SummaryPort::NormalReturn
            {
                removed.extend(labels.iter().cloned());
            }
        }
        model_transfers.push(ModelTransfer {
            actual,
            function: taint_model_kill(universe, &removed.into_iter().collect::<Vec<_>>()),
        });
    }
    CallModel {
        transfers: model_transfers,
        proven,
        completeness,
        authored,
    }
}

fn incomplete(reason: impl Into<Box<str>>) -> Completeness {
    Completeness::Incomplete {
        reason: reason.into(),
    }
}
