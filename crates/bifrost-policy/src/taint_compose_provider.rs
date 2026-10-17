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

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::semantic::partial_flow::ports::call_port_values;
use brokk_bifrost_analysis::analyzer::semantic::partial_flow::{
    ExtendedPartialFlows, ExtraObservation, ExtraPhase, ExtraSeed, ExtraTarget, ImplicitHeapRead,
    ObservationFilter, PartialFlowOutcome, PartialFlowPort, ProcedurePartialFlows,
    call_input_value, caller_exact_read_location, caller_location_carriers, compute_partial_flows,
    compute_partial_flows_filtered, compute_partial_flows_with_implicit_reads,
    exact_location_covers_read, file_local_procedure_relations, input_port_seed, join_crossed,
    observation_value,
};
use brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator;
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    GapOpenness, ProcedureOpenness, RustStdBuiltinCall, abort_paths_run_user_code,
    classify_gap_openness, rust_std_builtin_call,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    AccessPathRoot, BarrierObservation, CallArgumentEndpoint, CallBinding, CallBindings,
    CallInvocationMode, CallSiteHandle, CallSiteId, CandidateCoverage, DispatchBoundary,
    DispatchBoundaryKind, DispatchResult, EvidenceCompleteness, LenientValueTypeBarriers,
    ObservationPhase, OracleCallContext, ProcedureHandle, ProcedureInvocationKind,
    ProcedurePortHandle, ProcedurePortKind, ProgramPointId, ProofStatus, SemanticArtifact,
    SemanticArtifactKey, SemanticCallSite, SemanticCapability, SemanticExecutionBudget,
    SemanticGapId, SemanticLanguage, SemanticOutcome, SemanticRequest, StrictValueTypeBarriers,
    ValueFlowEndpoint, ValueId, ValueTypeBarrierDecision, ValueTypeBarrierFilter,
    ValueTypeBarrierReason, ValueTypePredicate,
};
use brokk_bifrost_analysis::analyzer::usages::{
    CallRelationLimits, CallRelationService, UsageProofAuthority,
};
use brokk_bifrost_analysis::analyzer::{
    AnalyzerQueryScope, Language, ProjectFile, QueryScope, WorkspaceAnalyzer,
};
use brokk_bifrost_flow::dataflow::{
    CuratedCallModel, ExternalSemanticSummarySet, SemanticInputStatus, SemanticProcedureSummary,
    SummaryEffect, SummaryEffectKey, SummaryExitKind, SummaryOrigin, SummaryPort, SummaryTransfer,
    UnmodeledCallBehavior,
};
use brokk_bifrost_flow::taint::compose::{
    BlockedGap, BoundSource, CallModel, Callers, Completeness, CompositionProvider, Dispatch,
    DispatchCandidate as ComposeCandidate, FallbackPorts, HopQuality, InteriorFlow, InteriorFlows,
    InteriorObservation, InteriorSeed, InteriorTarget, InteriorWitnessStep, ModelTransfer,
    Openness, ProcedureEndpoints, ValueTypeBarrierCheck,
};
use brokk_bifrost_flow::taint::{SourceEventKey, TaintAnalysisPlan};
use brokk_bifrost_flow::value_flow::{
    AuthoredArmClosure, BindingCoverage, CallSiteCoverage, DurableCallSiteKey, DurableProcedureKey,
    SummaryCallBinding, ValueFlowCarrier, ValueFlowObservationPhase, ValueFlowPlanLimits,
    ValueFlowProvider, authored_call_closures, caller_content_locations,
    closes_as_resolved_constructor,
};

use crate::definition::PolicyId;
use crate::resolved::ResolvedEndpointIdentity;
use crate::taint_policy::{
    BoundExternalModel, CallResolutionDiscoveryEvidence, CompiledTaintEndpoint,
    DiscoveryMaterializationCache, ExternalCallSeams, FrontierEndpoint, FrontierEndpointBinder,
    FrontierSelector, PolicyDiscoveryProvider, RefusalNotice, TaintPolicyCompileError,
    UnjudgedSource, rust_format_result_identity, rust_std_builtin_model,
};
use crate::units::WidenReason;

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
    std_builtins: RefCell<HashMap<DurableCallSiteKey, Option<RustStdBuiltinCall>>>,
    /// The evidence of each frontier matched-value source that reached a
    /// sink, by policy, endpoint and selected site. Judging one is a
    /// points-to question, so the run asks it once for a site however many
    /// batches report a flow from it.
    evidence: RefCell<HashMap<EvidenceKey, HopQuality>>,
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
            stored_reads: Cell::new(0),
            computed: Cell::new(0),
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
        }
    }

    pub(crate) fn excluded_callers(
        &self,
    ) -> std::cell::Ref<'_, [(ProjectFile, brokk_bifrost_analysis::analyzer::Range)]> {
        std::cell::Ref::map(self.excluded_callers.borrow(), |sites| sites.as_slice())
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

    /// The live procedure of a durable key. The artifact is the compile's
    /// canonical instance for the key when one exists, so every handle of one
    /// compile names the same rows.
    fn procedure(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureHandle, TaintPolicyCompileError> {
        let cached = self.cache.artifacts.borrow().get(&key.0).cloned();
        let artifact = match cached {
            Some(artifact) => artifact,
            None => {
                let root = self.workspace.analyzer().project().root();
                let file = ProjectFile::new(root.to_path_buf(), key.0.path().as_path());
                let outcome = self
                    .workspace
                    .materialize_program_semantics(
                        &file,
                        &mut request.staged_with_execution_budget(&self.execution_budget),
                    )
                    .map_err(|error| {
                        TaintPolicyCompileError::SemanticProvider(error.to_string())
                    })?;
                self.discovery
                    .require_outcome(&outcome, "composition procedure lookup")?;
                let artifact = outcome.available_value().cloned().ok_or_else(|| {
                    TaintPolicyCompileError::SemanticUnavailable(format!(
                        "composition could not materialize {}",
                        key.0.path()
                    ))
                })?;
                if artifact.key() != &key.0 {
                    return Err(TaintPolicyCompileError::SemanticUnavailable(format!(
                        "the artifact of {} changed during composition",
                        key.0.path()
                    )));
                }
                self.cache
                    .artifacts
                    .borrow_mut()
                    .insert(key.0.clone(), Arc::clone(&artifact));
                artifact
            }
        };
        artifact.procedure_handle(key.1).ok_or_else(|| {
            TaintPolicyCompileError::SemanticUnavailable(format!(
                "procedure {:?} is not in the artifact of {}",
                key.1,
                key.0.path()
            ))
        })
    }
}

/// The default filter keeps undecided values and removes only a proven
/// predicate match. Its classifier and request are borrowed for one fixpoint;
/// neither the filter nor its answers survive the query.
struct ProcedureBarrierFilter<'a, 'w, 'r> {
    provider: &'a PolicyCompositionProvider<'w>,
    procedure: &'a ProcedureHandle,
    request: &'a mut SemanticRequest<'r>,
}

impl ObservationFilter for ProcedureBarrierFilter<'_, '_, '_> {
    type Error = TaintPolicyCompileError;

    fn permits(
        &mut self,
        point: ProgramPointId,
        phase: ObservationPhase,
        endpoint: &ValueFlowEndpoint,
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
                    .classify(&observation, *predicate, self.request)?;
            if !self.provider.barrier_filter.borrow().permits(decision) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl PolicyCompositionProvider<'_> {
    fn interior_from_snapshot(
        &self,
        handle: ProcedureHandle,
        snapshot: &brokk_bifrost_analysis::analyzer::semantic::ValueFlowSnapshot,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, TaintPolicyCompileError> {
        let procedure = handle.durable_key();
        let mut extra_seeds = Vec::with_capacity(seeds.len());
        // The request seed index of each extra seed. A heap input port that no
        // relation reads carries no value the run can follow, so it has none.
        let mut request_of_extra = Vec::with_capacity(seeds.len());
        for (index, seed) in seeds.iter().enumerate() {
            let extra = match seed {
                InteriorSeed::Source {
                    point,
                    phase,
                    carrier,
                } => Some(ExtraSeed {
                    point: *point,
                    phase: extra_phase(phase),
                    carrier: endpoint_of(carrier),
                }),
                InteriorSeed::Port(port) => match input_port_seed(&handle, snapshot, port) {
                    Some(seed) => Some(seed),
                    None if matches!(port, PartialFlowPort::Heap { .. }) => None,
                    None => {
                        return Ok(incomplete_interior(
                            handle,
                            "an input port seed is not live in its procedure",
                        ));
                    }
                },
            };
            if let Some(extra) = extra {
                extra_seeds.push(extra);
                request_of_extra.push(index);
            }
        }
        let mut implicit_reads = Vec::new();
        let mut extra_observations = Vec::with_capacity(observations.len());
        // The request observation of each extra observation, and whether the
        // evidence that names its carrier is uncertain. A caller-side location
        // can be backed by several caller locations, each its own carrier.
        let mut observation_of_extra = Vec::with_capacity(observations.len());
        let mut completeness = Completeness::Complete;
        for (index, observation) in observations.iter().enumerate() {
            match observation {
                InteriorObservation::Sink {
                    point,
                    phase,
                    carrier,
                } => {
                    extra_observations.push(ExtraObservation {
                        point: *point,
                        phase: extra_phase(phase),
                        carrier: endpoint_of(carrier),
                    });
                    observation_of_extra.push((index, false));
                }
                InteriorObservation::Location(location) => {
                    let site = handle
                        .semantics()
                        .call_site(location.call)
                        .expect("a caller-side location names a call of its procedure");
                    let value = call_input_value(site, &location.actual)
                        .expect("a caller-side location is rooted at a call input of its call");
                    let actual = handle
                        .value_handle(value)
                        .expect("a call's input is a live value of its procedure");
                    // The callee reads what the caller left in the storage
                    // behind the actual, found as the ICFG engine's
                    // call-location rules find it.
                    let origins =
                        caller_content_locations(&actual, snapshot, ValueFlowPlanLimits::default());
                    if !origins.complete {
                        completeness = incomplete(
                            "the storage behind a caller-side location's actual is not fully known",
                        );
                    }
                    let several = !origins.complete || origins.locations.len() > 1;
                    for origin in &origins.locations {
                        // Track containing-value taint at the substituted read
                        // so a later strong write can kill that descendant.
                        if self.binder.borrow().analysis_type()
                            == crate::definition::PolicyAnalysisType::Taint
                            && let Some(read) = caller_exact_read_location(
                                &handle,
                                &origin.location,
                                &location.selectors,
                                location.tail,
                            )
                        {
                            let mut seed_carriers = Vec::new();
                            for seed in &extra_seeds {
                                if let ValueFlowEndpoint::Port(port) = &seed.carrier
                                    && matches!(read.path().root(),
                                        AccessPathRoot::ProcedurePort(root) | AccessPathRoot::CaptureSlot(root)
                                            if root == port)
                                {
                                    seed_carriers.push((seed.carrier.clone(), false));
                                    continue;
                                }
                                let value = match &seed.carrier {
                                    ValueFlowEndpoint::Value(value) => Some(value.clone()),
                                    ValueFlowEndpoint::Port(_) => handle
                                        .semantics()
                                        .values()
                                        .iter()
                                        .map(|value| {
                                            handle
                                                .value_handle(value.id)
                                                .expect("a procedure's semantic value is live")
                                        })
                                        .find(|value| {
                                            ValueFlowEndpoint::for_value(value.clone())
                                                == seed.carrier
                                        }),
                                    ValueFlowEndpoint::Location(_) => None,
                                };
                                let Some(value) = value else {
                                    continue;
                                };
                                let seed_origins = caller_content_locations(
                                    &value,
                                    snapshot,
                                    ValueFlowPlanLimits::default(),
                                );
                                if !seed_origins.complete {
                                    completeness = incomplete(
                                        "the storage behind a taint source is not fully known",
                                    );
                                }
                                for seed_origin in &seed_origins.locations {
                                    if exact_location_covers_read(&seed_origin.location, &read) {
                                        seed_carriers.push((
                                            seed.carrier.clone(),
                                            !seed_origins.complete
                                                || seed_origins.locations.len() > 1
                                                || !seed_origin.proven_complete,
                                        ));
                                        break;
                                    }
                                }
                            }
                            extra_observations.push(ExtraObservation {
                                point: site.point,
                                phase: ExtraPhase::BeforeEffects,
                                carrier: ValueFlowEndpoint::Location(Box::new(read.clone())),
                            });
                            observation_of_extra.push((index, several || !origin.proven_complete));
                            implicit_reads.push(ImplicitHeapRead {
                                location: read,
                                seed_carriers,
                            });
                        }
                        for carrier in caller_location_carriers(
                            snapshot,
                            &origin.location,
                            &location.selectors,
                            location.tail,
                        ) {
                            extra_observations.push(ExtraObservation {
                                point: site.point,
                                phase: ExtraPhase::BeforeEffects,
                                carrier,
                            });
                            observation_of_extra.push((index, several || !origin.proven_complete));
                        }
                    }
                }
            }
        }
        let ExtendedPartialFlows { partial, flows } =
            if self.barrier_chop.borrow().contains(&procedure) {
                let _timing = brokk_bifrost_analysis::profiling::scope("taint.barriers.fixpoint");
                self.barrier_fixpoints.set(self.barrier_fixpoints.get() + 1);
                self.barrier_procedures
                    .borrow_mut()
                    .insert(procedure.clone());
                compute_partial_flows_filtered(
                    &handle,
                    snapshot,
                    &extra_seeds,
                    &extra_observations,
                    witnesses,
                    &implicit_reads,
                    &mut ProcedureBarrierFilter {
                        provider: self,
                        procedure: &handle,
                        request,
                    },
                )?
            } else {
                compute_partial_flows_with_implicit_reads(
                    &handle,
                    snapshot,
                    &extra_seeds,
                    &extra_observations,
                    witnesses,
                    &implicit_reads,
                )
            };
        if partial.outcome != PartialFlowOutcome::Complete {
            completeness = incomplete(format!(
                "the procedure's relations are {:?}",
                partial.outcome
            ));
        }
        // One flow per seed and target. When two carriers of one observation
        // both carry a seed, the uncertain derivation is kept and the crossed
        // calls of both are joined, as the fixpoint does for one carrier.
        let mut mapped: Vec<InteriorFlow> = Vec::with_capacity(flows.len());
        let mut index_of = HashMap::new();
        for flow in flows {
            let (target, uncertain) = match flow.target {
                ExtraTarget::Observation(extra) => {
                    let (index, uncertain) = observation_of_extra[extra];
                    (
                        InteriorTarget::Observation(index),
                        flow.uncertain || uncertain,
                    )
                }
                ExtraTarget::Port(port) => (
                    InteriorTarget::Port(partial.ports[port.index()].clone()),
                    flow.uncertain,
                ),
            };
            let interior = InteriorFlow {
                seed: request_of_extra[flow.seed],
                target,
                uncertain,
                crossed: flow.crossed,
                witness: flow.witness.map(|steps| {
                    steps
                        .iter()
                        .map(|step| InteriorWitnessStep {
                            point: step.point,
                            event: step.event,
                            source: step.source,
                            target: step.target,
                            phase: step.phase,
                        })
                        .collect()
                }),
            };
            match index_of.entry((interior.seed, interior.target.clone())) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(mapped.len());
                    mapped.push(interior);
                }
                std::collections::hash_map::Entry::Occupied(entry) => {
                    let kept = &mut mapped[*entry.get()];
                    let crossed = join_crossed(&kept.crossed, &interior.crossed);
                    if interior.uncertain && !kept.uncertain {
                        *kept = interior;
                    }
                    kept.crossed = crossed;
                }
            }
        }
        let flows = mapped;
        Ok(InteriorFlows {
            procedure: handle,
            flows,
            completeness,
        })
    }
}

impl CompositionProvider for PolicyCompositionProvider<'_> {
    type Error = TaintPolicyCompileError;

    fn has_value_type_barriers(&self) -> bool {
        !self.barriers.is_empty()
    }

    fn filter_value_type_barriers(&self, chop: &HashSet<DurableProcedureKey>) {
        self.barrier_filter
            .replace(Box::new(LenientValueTypeBarriers));
        self.lenient_chop.replace(chop.clone());
        self.barrier_chop.replace(chop.clone());
        self.filtered_flows.borrow_mut().clear();
    }

    fn strict_value_type_barriers(&self, chop: &HashSet<DurableProcedureKey>) {
        self.barrier_filter
            .replace(Box::new(StrictValueTypeBarriers));
        self.barrier_chop.replace(chop.clone());
        self.filtered_flows.borrow_mut().clear();
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
            let outcome =
                file_local_procedure_relations(&handle, &OracleCallContext::empty(), request)
                    .map_err(|error| {
                        TaintPolicyCompileError::SemanticProvider(error.to_string())
                    })?;
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
                    request,
                },
            )?
            .partial;
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
        let stored = self
            .workspace
            .stored_partial_flows(&handle)
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        let flows = match stored {
            Some(flows) if flows.outcome == PartialFlowOutcome::Complete => {
                self.stored_reads.set(self.stored_reads.get() + 1);
                Arc::new(flows)
            }
            _ => {
                let outcome = file_local_procedure_relations(
                    &handle,
                    &OracleCallContext::empty(),
                    &mut request.staged_with_execution_budget(&self.execution_budget),
                )
                .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
                self.discovery
                    .require_outcome(&outcome, "composition partial flows")?;
                let snapshot = outcome.available_value().ok_or_else(|| {
                    TaintPolicyCompileError::SemanticUnavailable(
                        "composition could not project the procedure's relations".to_owned(),
                    )
                })?;
                self.computed.set(self.computed.get() + 1);
                Arc::new(compute_partial_flows(&handle, snapshot))
            }
        };
        self.partial_flows
            .borrow_mut()
            .insert(procedure.clone(), Arc::clone(&flows));
        self.announce_refinement_calls(procedure, &handle, request)?;
        Ok(flows)
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
        let handle = self.procedure(procedure, request)?;
        let outcome =
            self.discovery
                .procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
        let Some(snapshot) = outcome.available_value() else {
            return Ok(incomplete_interior(
                handle,
                "the procedure's value-flow snapshot is unavailable",
            ));
        };
        self.interior_from_snapshot(handle, snapshot, seeds, observations, witnesses, request)
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
        let handle = self.procedure(procedure, request)?;
        let outcome = file_local_procedure_relations(&handle, &OracleCallContext::empty(), request)
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        let Some(snapshot) = outcome.available_value() else {
            return Ok(incomplete_interior(
                handle,
                "file-local witness relations are unavailable",
            ));
        };
        self.interior_from_snapshot(handle, snapshot, seeds, observations, witnesses, request)
    }

    fn dispatch(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Dispatch, Self::Error> {
        let key = (self.policy.clone(), call.clone());
        let memoized = self.memo.dispatches.borrow().get(&key).cloned();
        let memoized = match memoized {
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
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.callers");
        let handle = self.procedure(procedure, request)?;
        let analyzer = self.workspace.analyzer();
        let Some(file) = file_for_locator(self.workspace, handle.semantics().locator()) else {
            return Ok(Callers {
                calls: Vec::new(),
                completeness: incomplete("the procedure's file is not known"),
            });
        };
        let span = handle.semantics().locator().anchor().span();
        let (start, end) = (span.start_byte() as usize, span.end_byte() as usize);
        let mut matching = Vec::new();
        for declaration in analyzer.declarations(&file).iter() {
            if declaration.is_callable()
                && analyzer
                    .ranges(declaration)
                    .iter()
                    .any(|range| range.start_byte == start && range.end_byte == end)
            {
                matching.push(declaration.clone());
            }
        }
        let [target] = matching.as_slice() else {
            return Ok(Callers {
                calls: Vec::new(),
                completeness: incomplete(format!(
                    "{} callable declarations match the procedure's span",
                    matching.len()
                )),
            });
        };
        let scope = AnalyzerQueryScope::with_cancellation(analyzer, request.cancellation);
        // The enumeration stops at the caller lane. Its truncation is reported
        // as incomplete, the same as the composition's own truncation below.
        let limits = CallRelationLimits {
            max_files: usize::MAX,
            max_source_bytes: usize::MAX,
            max_candidates: self.max_callers_per_procedure,
        };
        let mut sites = CallRelationService::incoming_bounded(
            analyzer,
            scope.token(),
            target,
            limits,
            Some(request.cancellation),
        );
        let mut completeness = Completeness::Complete;
        if sites.truncated || sites.cancelled {
            completeness = incomplete("the incoming-call enumeration was truncated or cancelled");
        }
        // The reverse inventory is a name-based candidate list, and a site's
        // `UsageProof` says only whether the reverse resolver could prove that
        // the site calls the target. The ICFG never enumerates callers: its
        // region is a forward closure from the root, so it sees only forward
        // dispatch answers. Each retained site is therefore dispatched forward
        // and that dispatch decides. The target among the candidates makes the
        // site a caller. Otherwise a complete dispatch (a model-covered call
        // and an exact external boundary included) refutes the site, and an
        // incomplete one leaves the enumeration incomplete, because the site
        // might still call the target. The dispatch's own uncertainty reaches
        // the search on the hop (`Hop::Caller { uncertain }`), so the reverse
        // proof is not read here.
        if sites.proof_authority != UsageProofAuthority::Native
            && sites.sites.is_empty()
            && handle.artifact().key().language() == SemanticLanguage::Standard(Language::Rust)
        {
            completeness = incomplete("no certified reverse inventory");
        }
        let compiled = self
            .workspace
            .semantic_oracle_provider()
            .caller_sites_compiled(&sites.sites, request.cancellation)
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        assert_eq!(compiled.len(), sites.sites.len());
        let mut compiled = compiled.into_iter();
        sites.sites.retain(|site| {
            if compiled
                .next()
                .expect("one activity answer per caller site")
            {
                true
            } else {
                self.excluded_callers
                    .borrow_mut()
                    .push((site.file.clone(), site.range));
                false
            }
        });
        self.discovery.prefetch_callers(&sites.sites, request)?;
        let target_key = handle.durable_key();
        let mut calls = Vec::new();
        let mut seen = HashSet::new();
        for site in &sites.sites {
            let outcome = self
                .workspace
                .materialize_program_semantics(
                    &site.file,
                    &mut request.staged_with_execution_budget(&self.execution_budget),
                )
                .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
            self.discovery
                .require_outcome(&outcome, "composition callers")?;
            let Some(caller) = outcome.available_value().cloned() else {
                completeness = incomplete("the caller's file has no semantic artifact");
                continue;
            };
            let matched =
                self.matching_calls(&caller, (site.range.start_byte, site.range.end_byte));
            if matched.is_empty() {
                completeness = incomplete("an incoming call site has no semantic call");
            }
            for (caller_handle, call_handle) in matched {
                let answer = self.discovery.resolve_call(&call_handle, request)?;
                let Some(result) = answer.available_value() else {
                    completeness = incomplete("the dispatch of an incoming call has no answer");
                    continue;
                };
                let confirmed = result
                    .candidates()
                    .iter()
                    .any(|candidate| candidate.target().durable_key() == target_key);
                if confirmed {
                    let key = (caller_handle.durable_key(), call_handle.id());
                    if seen.insert(key.clone()) {
                        calls.push(key);
                    }
                } else {
                    let models = self.call_models(&call_handle, &answer)?;
                    if covering_model(&models, &call_handle, Some(result)).is_none()
                        && !dispatch_completeness(&answer, result).is_complete()
                    {
                        completeness = incomplete(
                            "an incoming candidate's dispatch is incomplete and does not name the procedure",
                        );
                    }
                }
            }
        }
        Ok(Callers {
            calls,
            completeness,
        })
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
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for (port, _) in call_port_values(row) {
            match port {
                PartialFlowPort::CallReceiver { .. } | PartialFlowPort::CallArgument { .. } => {
                    inputs.push(port);
                }
                PartialFlowPort::CallResult { ordinal: None, .. }
                | PartialFlowPort::CallThrown { .. } => outputs.push(port),
                PartialFlowPort::CallResult {
                    ordinal: Some(_), ..
                } => {}
                _ => unreachable!("call_port_values yields only call ports"),
            }
        }
        Ok(FallbackPorts {
            inputs: inputs.into_boxed_slice(),
            outputs: outputs.into_boxed_slice(),
        })
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
        let handle = self.procedure(&call.0, request)?;
        let call_handle = handle.call_site_handle(call.1).ok_or_else(|| {
            TaintPolicyCompileError::SemanticUnavailable(format!(
                "call {:?} is not in its procedure",
                call.1
            ))
        })?;
        let answer = {
            let _timing =
                brokk_bifrost_analysis::profiling::scope("taint.compose.dispatch.resolve");
            self.discovery.resolve_call(&call_handle, request)?
        };
        let result = answer.available_value();
        let status = SemanticInputStatus::from_outcome(&answer);
        let mut record = RecordedDispatch {
            handle: call_handle.clone(),
            status,
            coverage: result.map_or_else(
                || CallSiteCoverage::unavailable(status),
                |result| CallSiteCoverage::from_dispatch(status, result),
            ),
        };
        let boundaries = result
            .map(|result| result.boundaries().into())
            .unwrap_or_default();
        let models = self.call_models(&call_handle, &answer)?;
        let continuation = continuation_quality(&models, &call_handle, result);
        // A call a model covers is not a boundary: the model replaces it, and
        // the candidate set beneath it is not read.
        let model = covering_model(&models, &call_handle, result);
        if let Some(model) = model {
            return Ok(MemoizedDispatch {
                dispatch: Dispatch {
                    candidates: Vec::new(),
                    completeness: Completeness::Complete,
                    continuation,
                },
                model: Some(model),
                record: (record, boundaries),
            });
        }
        let Some(result) = result else {
            return Ok(MemoizedDispatch {
                dispatch: Dispatch {
                    candidates: Vec::new(),
                    completeness: incomplete("the dispatch of the call has no answer"),
                    continuation,
                },
                model: None,
                record: (record, boundaries),
            });
        };
        let mut completeness = dispatch_completeness(&answer, result);
        let mut candidates = Vec::new();
        let mut entered = Vec::new();
        let mut bindings = Vec::new();
        for candidate in result.candidates() {
            let outcome = self.discovery.call_bindings(
                &call_handle,
                candidate,
                &OracleCallContext::empty(),
                request,
            )?;
            bindings.push(BindingCoverage::Answered {
                status: SemanticInputStatus::from_outcome(&outcome),
            });
            let composed = outcome
                .available_value()
                .ok_or_else(|| "the call bindings have no answer".to_owned())
                .and_then(|bindings| {
                    composition_candidate(&call_handle, candidate.target().durable_key(), bindings)
                });
            match composed {
                Ok(composed) => {
                    entered.push(candidate.target().clone());
                    candidates.push(composed);
                }
                Err(reason) => completeness = incomplete(reason),
            }
        }
        record.coverage.entered = entered;
        record.coverage.bindings = bindings;
        Ok(MemoizedDispatch {
            dispatch: Dispatch {
                candidates,
                completeness,
                continuation,
            },
            model: None,
            record: (record, boundaries),
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
        let key = call.durable_key();
        let group = self
            .external_models
            .iter()
            .filter(|model| model.call.durable_key() == key)
            .collect::<Vec<_>>();
        let format = rust_format_result_identity(answer);
        let universe = self.plan.universe();
        let curated = if !group.is_empty() || format.is_some() {
            Some(ExternalCallSeams::new(call, &group, format, universe).model(universe)?)
        } else {
            self.std_builtin(call)?
                .map(|builtin| rust_std_builtin_model(&builtin))
                .transpose()?
        };
        let Some(result) = answer.available_value() else {
            return Ok(CallModels {
                curated,
                summaries: None,
                resolved_external: false,
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
        })
    }

    /// The Rust std operation `call` invokes, classified once per run.
    fn std_builtin(
        &self,
        call: &CallSiteHandle,
    ) -> Result<Option<RustStdBuiltinCall>, TaintPolicyCompileError> {
        let key = call.durable_key();
        if let Some(builtin) = self.memo.std_builtins.borrow().get(&key) {
            return Ok(builtin.clone());
        }
        let _timing =
            brokk_bifrost_analysis::profiling::scope("taint.compose.call_models.std_builtin");
        let builtin = rust_std_builtin_call(self.workspace, call)
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
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.openness");
        let handle = self.procedure(procedure, request)?;
        // The ICFG engine blocks a snapshot with an unproven relation before
        // it classifies any gap (`classify_snapshot_openness`), and a gap sweep
        // cannot see the relation. The head's fact answers it from the
        // memoized partial-flow read the search already made. The head keeps
        // only the projection's status label, which does not determine a
        // `SemanticInputStatus` (an unsupported capability or an exceeded
        // budget carry data), so the status comes from `snapshot_status`, on
        // this path only.
        if !self.partial_flows(procedure, request)?.relations_complete {
            return Ok(Openness::Open {
                residual: Box::default(),
                blocked: None,
                status: self.snapshot_status(&handle, request)?,
                reason: "a relation of the procedure is not proven complete".into(),
            });
        }
        let sweep = self.openness_sweep(procedure, &handle, request)?;
        if !sweep.open {
            return Ok(Openness::Closed);
        }
        if sweep.relevant_gaps.is_empty() {
            // The procedure is open with no gap to refine: a value-flow
            // capability or a Go builtin assumption. No dispatch answers it.
            return Ok(Openness::Open {
                residual: Box::default(),
                blocked: None,
                status: self.snapshot_status(&handle, request)?,
                reason: "a value-flow capability or builtin assumption keeps the procedure open"
                    .into(),
            });
        }
        let abort_user_code = abort_paths_run_user_code(handle.semantics());
        let mut answered: HashMap<CallSiteId, bool> = HashMap::new();
        let mut residual: Vec<DurableCallSiteKey> = Vec::new();
        let mut blocked: Vec<(SemanticGapId, SemanticCapability)> = Vec::new();
        for gap_id in &sweep.relevant_gaps {
            let gap = handle
                .semantics()
                .gap(*gap_id)
                .expect("a relevant gap is a gap of its procedure");
            match classify_gap_openness(handle.semantics(), gap, abort_user_code) {
                GapOpenness::RefinementCall(call) => {
                    let complete = match answered.get(&call) {
                        Some(complete) => *complete,
                        None => {
                            let dispatch = self.dispatch(&(procedure.clone(), call), request)?;
                            let complete = matches!(dispatch.completeness, Completeness::Complete);
                            answered.insert(call, complete);
                            complete
                        }
                    };
                    let key = (procedure.clone(), call);
                    if !complete && !residual.contains(&key) {
                        residual.push(key);
                    }
                }
                GapOpenness::Blocked => blocked.push((*gap_id, gap.capability)),
                GapOpenness::Irrelevant | GapOpenness::Discharged => unreachable!(
                    "the gap sweep keeps a gap open only when classification leaves it: {gap:?}"
                ),
            }
        }
        if residual.is_empty() && blocked.is_empty() {
            return Ok(Openness::Closed);
        }
        let reason = format!(
            "residual calls {residual:?} and blocked gaps {blocked:?} keep the procedure open"
        );
        // A blocked gap decides the diagnostic even when residual calls
        // remain: the ICFG engine's plan returns its blocked gap whenever one
        // exists in the procedure (`classify_snapshot_openness`).
        let blocked = blocked.first().map(|(gap, capability)| BlockedGap {
            gap: handle
                .gap_handle(*gap)
                .expect("a blocked gap is a gap of its procedure"),
            capability: *capability,
        });
        Ok(Openness::Open {
            residual: residual.into_boxed_slice(),
            blocked,
            status: self.snapshot_status(&handle, request)?,
            reason: reason.into(),
        })
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
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.openness.sweep");
        let outcome = self
            .workspace
            .semantic_oracle_provider()
            .procedure_openness(
                handle,
                &OracleCallContext::empty(),
                &mut request.staged_with_execution_budget(&self.execution_budget),
            )
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        self.discovery
            .require_outcome(&outcome, "composition openness")?;
        let sweep = outcome.available_value().cloned().ok_or_else(|| {
            TaintPolicyCompileError::SemanticUnavailable(
                "composition could not decide the procedure's openness".to_owned(),
            )
        })?;
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
        if !sweep.open {
            return Ok(());
        }
        let abort_user_code = abort_paths_run_user_code(handle.semantics());
        let memo = self.memo.dispatches.borrow();
        let mut calls = Vec::new();
        let mut seen = HashSet::new();
        for gap_id in &sweep.relevant_gaps {
            let gap = handle
                .semantics()
                .gap(*gap_id)
                .expect("a relevant gap is a gap of its procedure");
            let GapOpenness::RefinementCall(call) =
                classify_gap_openness(handle.semantics(), gap, abort_user_code)
            else {
                continue;
            };
            if seen.insert(call)
                && !memo.contains_key(&(self.policy.clone(), (procedure.clone(), call)))
                && let Some(call) = handle.call_site_handle(call)
            {
                calls.push(call);
            }
        }
        self.discovery.expect_calls(&calls);
        Ok(())
    }

    /// The snapshot input status the ICFG engine attaches to a procedure. It
    /// reads the discovery provider's cached snapshot, the one its plan reads.
    /// The gap sweep's own outcome is always complete, so it cannot supply
    /// this status.
    fn snapshot_status(
        &self,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticInputStatus, TaintPolicyCompileError> {
        let outcome =
            self.discovery
                .procedure_snapshot(handle, &OracleCallContext::empty(), request)?;
        Ok(SemanticInputStatus::from_outcome(&outcome))
    }

    /// The calls of `caller` whose source range is `range`, with their live
    /// procedure handles. A caller file can hold more than one call at one
    /// range, so every match is returned and each is confirmed separately.
    fn matching_calls(
        &self,
        caller: &Arc<SemanticArtifact>,
        range: (usize, usize),
    ) -> Vec<(ProcedureHandle, CallSiteHandle)> {
        let mut matched = Vec::new();
        for procedure in caller.procedures() {
            let Some(handle) = caller.procedure_handle(procedure.id()) else {
                continue;
            };
            for row in procedure.call_sites() {
                let Some(mapping) = procedure.source_mapping(row.source) else {
                    continue;
                };
                let span = mapping.locator.anchor().span();
                if (span.start_byte() as usize, span.end_byte() as usize) != range {
                    continue;
                }
                if let Some(call) = handle.call_site_handle(row.id) {
                    matched.push((handle.clone(), call));
                }
            }
        }
        matched
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
        .map(|boundary| HopQuality {
            proven: boundary.proof == ProofStatus::Proven,
            complete: boundary.completeness == EvidenceCompleteness::Complete,
        })
        .collect::<Vec<_>>();
    let mut entered = false;
    for candidate in result.candidates() {
        let deferred = row.invocation_mode == CallInvocationMode::Detached
            || candidate.target().semantics().properties().invocation
                == ProcedureInvocationKind::Deferred;
        if deferred {
            boundaries.push(HopQuality {
                proven: *candidate.proof() == ProofStatus::Proven,
                complete: false,
            });
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
) -> Option<CallModel> {
    if let Some(curated) = &models.curated {
        return Some(call_model(
            call,
            curated.transfers(),
            curated.effects(),
            SummaryCallBinding::default(),
            curated.is_proven_complete(),
            None,
        ));
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
    Some(call_model(
        call,
        summary.transfers(),
        summary.effects(),
        mapping,
        true,
        authored,
    ))
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
}

impl CallModels {
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
            moved: None,
            removed: removed.into_iter().collect(),
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

fn incomplete_interior(procedure: ProcedureHandle, reason: &str) -> InteriorFlows {
    InteriorFlows {
        procedure,
        flows: Vec::new(),
        completeness: incomplete(reason),
    }
}

fn extra_phase(phase: &ValueFlowObservationPhase) -> ExtraPhase {
    match phase {
        ValueFlowObservationPhase::BeforeEffects => ExtraPhase::BeforeEffects,
        ValueFlowObservationPhase::AfterEffects => ExtraPhase::AfterEffects,
    }
}

fn endpoint_of(carrier: &ValueFlowCarrier) -> ValueFlowEndpoint {
    match carrier {
        ValueFlowCarrier::Value(value) => ValueFlowEndpoint::Value(value.clone()),
        ValueFlowCarrier::Port(port) => ValueFlowEndpoint::Port(port.clone()),
        ValueFlowCarrier::Location(location) => ValueFlowEndpoint::Location(location.clone()),
    }
}

/// Whether a dispatch answer covers every candidate and every boundary is
/// proven and complete. Only a call no model covers reaches this check.
fn dispatch_completeness(
    answer: &SemanticOutcome<DispatchResult>,
    result: &DispatchResult,
) -> Completeness {
    if !matches!(answer, SemanticOutcome::Complete { .. }) {
        return incomplete("the dispatch answer is not complete");
    }
    if result.coverage() != CandidateCoverage::Exhaustive {
        return incomplete(format!("the dispatch coverage is {:?}", result.coverage()));
    }
    if result.boundaries().iter().any(|boundary| {
        boundary.proof != ProofStatus::Proven
            || boundary.completeness != EvidenceCompleteness::Complete
    }) {
        return incomplete("the dispatch leaves a boundary that is not proven and complete");
    }
    Completeness::Complete
}

/// One dispatch candidate as the composition reads it: each binding of the
/// candidate, mapped from the call's value to its call port and from the
/// callee's formal or return to its port. A binding whose value is not a
/// port of the call, or that binds a location rather than a value, has no
/// port and makes the candidate unusable; the error names why.
fn composition_candidate(
    call: &CallSiteHandle,
    callee: DurableProcedureKey,
    bindings: &CallBindings,
) -> Result<ComposeCandidate, String> {
    let call_id = call.id();
    let row = call
        .procedure()
        .semantics()
        .call_site(call_id)
        .ok_or("the call is not a call of its procedure")?;
    let mut arguments = Vec::new();
    let mut returns = Vec::new();
    for binding in bindings.bindings() {
        match binding {
            CallBinding::Receiver { formal, .. } => arguments.push((
                PartialFlowPort::CallReceiver { call: call_id },
                formal_port(formal)?,
            )),
            CallBinding::ArgumentGroup(group) => {
                for mapping in group.mappings() {
                    let mapping = mapping.value();
                    let actual = match mapping.actual() {
                        CallArgumentEndpoint::Value(value) => value.id(),
                        CallArgumentEndpoint::Location { .. } => {
                            return Err("an argument binds a location, not a value".to_owned());
                        }
                    };
                    arguments.push((
                        actual_port(row, call_id, actual)?,
                        formal_port(mapping.formal())?,
                    ));
                }
            }
            CallBinding::ImplicitArgument { source, formal, .. } => arguments.push((
                actual_port(row, call_id, source.id())?,
                formal_port(formal)?,
            )),
            CallBinding::NormalReturn { formal, result, .. } => returns.push((
                return_port(formal)?,
                result_port(row, call_id, result.id())?,
            )),
            CallBinding::ExceptionalReturn { formal, result, .. } => returns.push((
                return_port(formal)?,
                thrown_port(row, call_id, result.id())?,
            )),
        }
    }
    Ok(ComposeCandidate {
        procedure: callee,
        arguments: arguments.into_boxed_slice(),
        returns: returns.into_boxed_slice(),
    })
}

fn actual_port(
    row: &SemanticCallSite,
    call: brokk_bifrost_analysis::analyzer::semantic::CallSiteId,
    value: ValueId,
) -> Result<PartialFlowPort, String> {
    if row.receiver == Some(value) {
        return Ok(PartialFlowPort::CallReceiver { call });
    }
    row.arguments
        .iter()
        .position(|argument| argument.value == value)
        .map(|ordinal| PartialFlowPort::CallArgument {
            call,
            ordinal: u32::try_from(ordinal).expect("a call's argument count fits u32"),
        })
        .ok_or_else(|| "a bound actual is not a receiver or argument of the call".to_owned())
}

fn result_port(
    row: &SemanticCallSite,
    call: brokk_bifrost_analysis::analyzer::semantic::CallSiteId,
    value: ValueId,
) -> Result<PartialFlowPort, String> {
    if row.result == Some(value) {
        return Ok(PartialFlowPort::CallResult {
            call,
            ordinal: None,
        });
    }
    row.normal_results
        .iter()
        .position(|&result| result == value)
        .map(|ordinal| PartialFlowPort::CallResult {
            call,
            ordinal: Some(u32::try_from(ordinal).expect("a call's result count fits u32")),
        })
        .ok_or_else(|| "a bound result is not a result of the call".to_owned())
}

fn thrown_port(
    row: &SemanticCallSite,
    call: brokk_bifrost_analysis::analyzer::semantic::CallSiteId,
    value: ValueId,
) -> Result<PartialFlowPort, String> {
    if row.thrown == Some(value) {
        return Ok(PartialFlowPort::CallThrown { call });
    }
    Err("a bound thrown value is not the thrown value of the call".to_owned())
}

/// The callee's input port (receiver or parameter) of a formal.
fn formal_port(formal: &ProcedurePortHandle) -> Result<PartialFlowPort, String> {
    match formal.kind() {
        ProcedurePortKind::Receiver => Ok(PartialFlowPort::Receiver),
        ProcedurePortKind::Parameter { ordinal } => Ok(PartialFlowPort::Parameter { ordinal }),
        _ => Err("a formal is not an input port".to_owned()),
    }
}

/// The callee's return port of a formal.
fn return_port(formal: &ProcedurePortHandle) -> Result<PartialFlowPort, String> {
    match formal.kind() {
        ProcedurePortKind::NormalReturn => Ok(PartialFlowPort::NormalReturn),
        ProcedurePortKind::IndexedNormalReturn { ordinal } => {
            Ok(PartialFlowPort::IndexedNormalReturn { ordinal })
        }
        ProcedurePortKind::ExceptionalReturn => Ok(PartialFlowPort::ExceptionalReturn),
        _ => Err("a return formal is not a return port".to_owned()),
    }
}
