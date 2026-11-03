//! Label-free local transfer operations shared by composition clients.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::analyzer::semantic::partial_flow::rules::GuardEdgeKill;
use crate::analyzer::semantic::partial_flow::{
    ExtendedPartialFlows, ExtraObservation, ExtraPhase, ExtraSeed, ExtraTarget, ImplicitHeapRead,
    PartialFlowOutcome, PartialFlowPort, ProcedurePartialFlows, call_input_value,
    caller_exact_read_location, caller_location_carriers, compute_partial_flows,
    compute_partial_flows_with_implicit_reads, exact_location_covers_read,
    file_local_procedure_relations, input_port_seed, join_crossed, ports::call_port_values,
};
use crate::analyzer::semantic::type_flow::file_for_locator;
use crate::analyzer::semantic::workspace_oracle::{
    GapOpenness, ProcedureOpenness, abort_paths_run_user_code, classify_gap_openness,
};
use crate::analyzer::semantic::{
    AccessPathRoot, CallArgumentEndpoint, CallBinding, CallBindings, CallSiteHandle, CallSiteId,
    CallStorageRelationIndex, CandidateCoverage, ControlContinuation, DispatchBoundary,
    DispatchResult, EvidenceCompleteness, IntrinsicCall, IntrinsicTransfer, OracleCallContext,
    ProcedureHandle, ProcedurePortHandle, ProcedurePortKind, ProofStatus, SemanticArtifact,
    SemanticArtifactKey, SemanticCallSite, SemanticCapability, SemanticExecutionBudget,
    SemanticGapId, SemanticOutcome, SemanticProviderError, SemanticRequest, ValueFlowEndpoint,
    ValueFlowSnapshot, ValueId,
};
use crate::analyzer::usages::call_relations::CallerInventoryCoverage;
use crate::analyzer::usages::{CallRelationLimits, CallRelationService, CallSite};
use crate::analyzer::workspace_authority::{
    CaptureScopedMemo, OwnedMemoCapability, workspace_memo_attribution,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope, WorkspaceAnalyzer};
use crate::dataflow::SemanticInputStatus;
use crate::taint::compose::bound_return_member_matches;
use crate::taint::compose::{
    BlockedGap, CallModel, Callers, Completeness, Dispatch, DispatchCandidate as ComposeCandidate,
    FallbackPorts, HopQuality, InteriorFlow, InteriorFlows, InteriorObservation, InteriorSeed,
    InteriorTarget, InteriorWitnessStep, ModelTransfer, Openness, ProcedureEndpoints,
    WritebackBinding,
};
use crate::value_flow::{
    BindingCoverage, CallSiteCoverage, DurableCallSiteKey, DurableProcedureKey, ValueFlowCarrier,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowPlanLimits, ValueFlowProvider,
    WorkspaceValueFlowProvider, caller_content_locations, caller_storage_locations,
};

/// Query-local discovery for one composed value-flow question.
pub struct WorkspaceCompositionDiscovery<'a> {
    workspace: &'a WorkspaceAnalyzer,
    provider: WorkspaceValueFlowProvider<'a>,
    artifacts: RefCell<HashMap<SemanticArtifactKey, Arc<SemanticArtifact>>>,
}

/// The calling language's proven intrinsic, shared by composition clients.
pub fn language_intrinsic_call(
    workspace: &WorkspaceAnalyzer,
    call: &CallSiteHandle,
) -> Result<Option<IntrinsicCall>, SemanticProviderError> {
    match crate::analyzer::languages::language_support(
        call.procedure().artifact().key().language().language(),
    ) {
        Some(support) => support.intrinsic_call(workspace, call),
        None => Ok(None),
    }
}

/// The admitted value-flow client has no authored models. It still uses the
/// same language intrinsic classification as policy composition.
pub struct UnitCallModels<'a> {
    workspace: &'a WorkspaceAnalyzer,
}

impl<'a> UnitCallModels<'a> {
    pub fn new(workspace: &'a WorkspaceAnalyzer) -> Self {
        Self { workspace }
    }

    fn intrinsic_model(
        &self,
        call: &CallSiteHandle,
    ) -> Result<Option<CallModel<()>>, SemanticProviderError> {
        let Some(intrinsic) = language_intrinsic_call(self.workspace, call)? else {
            return Ok(None);
        };
        let actual = match intrinsic.transfer {
            IntrinsicTransfer::ReceiverToResult => {
                Some(PartialFlowPort::CallReceiver { call: call.id() })
            }
            IntrinsicTransfer::ArgumentToResult => Some(PartialFlowPort::CallArgument {
                call: call.id(),
                ordinal: 0,
            }),
            IntrinsicTransfer::FreshResult => None,
        };
        Ok(Some(CallModel {
            transfers: actual
                .into_iter()
                .map(|actual| ModelTransfer {
                    actual,
                    function: (),
                })
                .collect(),
            proven: true,
            completeness: Completeness::Complete,
            authored: None,
        }))
    }
}

impl CallModelSource for UnitCallModels<'_> {
    type Error = SemanticProviderError;
    type Function = ();

    fn dispatch_model(
        &self,
        call: &CallSiteHandle,
        _answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<CallModelDecision<()>, Self::Error> {
        Ok(CallModelDecision {
            model: self.intrinsic_model(call)?,
            continuation: HopQuality::CERTAIN,
        })
    }

    fn covers_caller_candidate(
        &self,
        call: &CallSiteHandle,
        _answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<bool, Self::Error> {
        Ok(self.intrinsic_model(call)?.is_some())
    }
}

impl<'a> WorkspaceCompositionDiscovery<'a> {
    pub fn new(workspace: &'a WorkspaceAnalyzer, provider: WorkspaceValueFlowProvider<'a>) -> Self {
        Self {
            workspace,
            provider,
            artifacts: RefCell::new(HashMap::new()),
        }
    }
}

impl ValueFlowProvider for WorkspaceCompositionDiscovery<'_> {
    type Error = SemanticProviderError;

    fn procedure_snapshot(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, Self::Error> {
        self.provider
            .procedure_snapshot(procedure, context, request)
    }

    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, Self::Error> {
        self.provider.resolve_call(call, request)
    }

    fn call_bindings(
        &self,
        call: &CallSiteHandle,
        candidate: &crate::analyzer::semantic::DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, Self::Error> {
        self.provider
            .call_bindings(call, candidate, context, request)
    }
}

impl LocalTransferDiscovery for WorkspaceCompositionDiscovery<'_> {
    fn workspace(&self) -> &WorkspaceAnalyzer {
        self.workspace
    }

    fn procedure(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureHandle, Self::Error> {
        let artifact = if let Some(cached) = self.artifacts.borrow().get(&key.0).cloned() {
            cached
        } else {
            let root = self.workspace.analyzer().project().root();
            let file =
                crate::analyzer::ProjectFile::new(root.to_path_buf(), key.0.path().as_path());
            let outcome = self
                .workspace
                .materialize_program_semantics(&file, request)?;
            self.require_outcome(&outcome, "composition procedure lookup")?;
            let artifact = outcome.available_value().cloned().ok_or_else(|| {
                self.unavailable(format!(
                    "composition could not materialize {}",
                    key.0.path()
                ))
            })?;
            if artifact.key() != &key.0 {
                return Err(self.unavailable(format!(
                    "the artifact of {} changed during composition",
                    key.0.path()
                )));
            }
            self.artifacts
                .borrow_mut()
                .insert(key.0.clone(), Arc::clone(&artifact));
            artifact
        };
        let handle = artifact.procedure_handle(key.1).ok_or_else(|| {
            self.unavailable(format!("procedure {:?} is not in {}", key.1, key.0.path()))
        })?;
        debug_assert_eq!(artifact.key(), &key.0);
        if crate::analyzer::read_attribution_records_reads(|| {
            self.workspace.analyzer().read_ledger_attached()
        }) {
            self.workspace
                .analyzer()
                .record_read(crate::analyzer::ReadKey::semantic_artifact(artifact.key()));
        }
        Ok(handle)
    }

    fn require_outcome<T>(
        &self,
        outcome: &SemanticOutcome<T>,
        operation: &str,
    ) -> Result<(), Self::Error> {
        match outcome {
            SemanticOutcome::Cancelled { .. } | SemanticOutcome::ExceededBudget { .. } => {
                Err(self.unavailable(format!("{operation} was interrupted")))
            }
            _ => Ok(()),
        }
    }

    fn prefetch_callers(
        &self,
        _sites: &[CallSite],
        _request: &SemanticRequest<'_>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn expect_calls(&self, _calls: &[CallSiteHandle]) {}
    fn provider_error(&self, detail: String) -> Self::Error {
        SemanticProviderError::internal(detail)
    }
    fn unavailable(&self, detail: String) -> Self::Error {
        SemanticProviderError::internal(detail)
    }
}

/// Query-local discovery for shared composition. Implementations replay their
/// consumer's artifact and dispatch reads even when a memo supplies the answer.
pub trait LocalTransferDiscovery: ValueFlowProvider {
    fn workspace(&self) -> &WorkspaceAnalyzer;
    fn procedure(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureHandle, Self::Error>;
    fn require_outcome<T>(
        &self,
        outcome: &SemanticOutcome<T>,
        operation: &str,
    ) -> Result<(), Self::Error>;
    fn prefetch_callers(
        &self,
        sites: &[CallSite],
        request: &SemanticRequest<'_>,
    ) -> Result<(), Self::Error>;
    fn expect_calls(&self, calls: &[CallSiteHandle]);
    fn provider_error(&self, detail: String) -> Self::Error;
    fn unavailable(&self, detail: String) -> Self::Error;
}

/// A client's decision about one call after the raw dispatch has been read.
/// Both methods are required so caller certification cannot assume an absent
/// model means a complete answer.
pub trait CallModelSource {
    type Error: std::fmt::Display;
    type Function: Clone + Eq + std::hash::Hash + std::fmt::Debug;

    fn dispatch_model(
        &self,
        call: &CallSiteHandle,
        answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<CallModelDecision<Self::Function>, Self::Error>;

    fn covers_caller_candidate(
        &self,
        call: &CallSiteHandle,
        answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<bool, Self::Error>;

    fn boundary_member_rows(
        &self,
        _procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Arc<ProcedurePartialFlows>>, Self::Error> {
        Ok(None)
    }

    fn canonical_returned_field(
        &self,
        _callee: &DurableProcedureKey,
        _caller: &DurableProcedureKey,
        _declared: &crate::analyzer::semantic::SemanticLocator,
        _request: &mut SemanticRequest<'_>,
    ) -> Option<crate::analyzer::semantic::SemanticLocator> {
        None
    }
}

/// Query-local answers needed by the label-free openness decision.
pub trait LocalOpennessClient<D: LocalTransferDiscovery> {
    fn relations_complete(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, D::Error>;
    fn openness_sweep(
        &self,
        procedure: &DurableProcedureKey,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, D::Error>;
    fn dispatch_complete(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, D::Error>;
}

/// The client decides whether containing-value reads apply and runs the
/// fixpoint with any client-specific observation filter.
pub trait InteriorProjectionClient {
    type Error: std::fmt::Display;

    fn implicit_heap_reads(&self) -> bool;
    #[allow(clippy::too_many_arguments)]
    fn run_interior_fixpoint(
        &self,
        handle: &ProcedureHandle,
        snapshot: &ValueFlowSnapshot,
        seeds: &[ExtraSeed],
        observations: &[ExtraObservation],
        witnesses: bool,
        implicit_reads: &[ImplicitHeapRead],
        edge_kills: &[GuardEdgeKill],
        request: &mut SemanticRequest<'_>,
    ) -> Result<ExtendedPartialFlows, Self::Error>;
}

/// One admitted RQL value-flow search. All memos die with this value.
type UnitDispatchMemo = HashMap<DurableCallSiteKey, (Dispatch, Option<CallModel<()>>)>;

pub struct UnitCompositionProvider<'a> {
    discovery: WorkspaceCompositionDiscovery<'a>,
    models: UnitCallModels<'a>,
    plan: &'a ValueFlowPlan,
    execution_budget: SemanticExecutionBudget,
    max_callers: usize,
    attribution: OwnedMemoCapability,
    partial: CaptureScopedMemo<RefCell<HashMap<DurableProcedureKey, Arc<ProcedurePartialFlows>>>>,
    dispatches: RefCell<UnitDispatchMemo>,
    sweeps: CaptureScopedMemo<RefCell<HashMap<DurableProcedureKey, ProcedureOpenness>>>,
    openness: CaptureScopedMemo<RefCell<HashMap<DurableProcedureKey, Openness>>>,
    /// Write-only diagnostic inventory for excluded reverse-call candidates.
    excluded_callers: RefCell<Vec<(crate::analyzer::ProjectFile, crate::analyzer::Range)>>,
}

impl<'a> UnitCompositionProvider<'a> {
    pub fn new(
        workspace: &'a WorkspaceAnalyzer,
        provider: WorkspaceValueFlowProvider<'a>,
        plan: &'a ValueFlowPlan,
        execution_budget: SemanticExecutionBudget,
        max_callers: usize,
    ) -> Self {
        assert!(plan.composition_exclusion().is_none());
        Self {
            discovery: WorkspaceCompositionDiscovery::new(workspace, provider),
            models: UnitCallModels::new(workspace),
            plan,
            execution_budget,
            max_callers,
            attribution: workspace_memo_attribution(workspace),
            partial: CaptureScopedMemo::new(RefCell::new(HashMap::new())),
            dispatches: RefCell::new(HashMap::new()),
            sweeps: CaptureScopedMemo::new(RefCell::new(HashMap::new())),
            openness: CaptureScopedMemo::new(RefCell::new(HashMap::new())),
            excluded_callers: RefCell::new(Vec::new()),
        }
    }
}

impl CallModelSource for UnitCompositionProvider<'_> {
    type Error = SemanticProviderError;
    type Function = ();

    fn boundary_member_rows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Arc<ProcedurePartialFlows>>, Self::Error> {
        Ok(Some(
            <Self as crate::taint::compose::CompositionProvider>::partial_flows(
                self, procedure, request,
            )?,
        ))
    }

    fn dispatch_model(
        &self,
        call: &CallSiteHandle,
        answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<CallModelDecision<()>, Self::Error> {
        self.models.dispatch_model(call, answer)
    }

    fn covers_caller_candidate(
        &self,
        call: &CallSiteHandle,
        answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<bool, Self::Error> {
        self.models.covers_caller_candidate(call, answer)
    }
}

impl InteriorProjectionClient for UnitCompositionProvider<'_> {
    type Error = SemanticProviderError;

    fn implicit_heap_reads(&self) -> bool {
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn run_interior_fixpoint(
        &self,
        handle: &ProcedureHandle,
        snapshot: &ValueFlowSnapshot,
        seeds: &[ExtraSeed],
        observations: &[ExtraObservation],
        witnesses: bool,
        implicit_reads: &[ImplicitHeapRead],
        edge_kills: &[GuardEdgeKill],
        request: &mut SemanticRequest<'_>,
    ) -> Result<ExtendedPartialFlows, Self::Error> {
        assert!(
            edge_kills.is_empty(),
            "unit value flow has no conditional sanitizer labels"
        );
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

impl LocalOpennessClient<WorkspaceCompositionDiscovery<'_>> for UnitCompositionProvider<'_> {
    fn relations_complete(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, SemanticProviderError> {
        Ok(
            crate::taint::compose::CompositionProvider::partial_flows(self, procedure, request)?
                .relations_complete,
        )
    }

    fn openness_sweep(
        &self,
        procedure: &DurableProcedureKey,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, SemanticProviderError> {
        if let Some(sweep) = self.sweeps.read(&self.attribution.capability(), |memo| {
            memo.borrow().get(procedure).cloned()
        }) {
            return Ok(sweep);
        }
        let sweep = openness_sweep(&self.discovery, handle, &self.execution_budget, request)?;
        self.sweeps.read(&self.attribution.capability(), |memo| {
            memo.borrow_mut().insert(procedure.clone(), sweep.clone());
        });
        Ok(sweep)
    }

    fn dispatch_complete(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, SemanticProviderError> {
        Ok(matches!(
            crate::taint::compose::CompositionProvider::dispatch(self, call, request)?.completeness,
            Completeness::Complete
        ))
    }
}

impl crate::taint::compose::CompositionProvider for UnitCompositionProvider<'_> {
    type Error = SemanticProviderError;
    type Fact = ();
    type Function = ();

    fn partial_flows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, Self::Error> {
        if let Some(flows) = self.partial.read(&self.attribution.capability(), |memo| {
            memo.borrow().get(procedure).cloned()
        }) {
            return Ok(flows);
        }
        let handle = self.discovery.procedure(procedure, request)?;
        let flows = match stored_partial_flows(&self.discovery, &handle)? {
            Some(flows) => flows,
            None => {
                project_partial_flows(&self.discovery, &handle, &self.execution_budget, request)?
            }
        };
        let flows = Arc::new(flows);
        self.partial.read(&self.attribution.capability(), |memo| {
            memo.borrow_mut()
                .insert(procedure.clone(), Arc::clone(&flows));
        });
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
        let handle = self.discovery.procedure(procedure, request)?;
        let answer =
            self.discovery
                .procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
        let Some(snapshot) = answer.available_value() else {
            return Ok(incomplete_interior(
                handle,
                "the procedure's value-flow snapshot is unavailable",
            ));
        };
        interior_from_snapshot(
            self,
            handle,
            snapshot,
            seeds,
            observations,
            witnesses,
            &[],
            &self.execution_budget,
            request,
        )
    }

    fn dispatch(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Dispatch, Self::Error> {
        if let Some((dispatch, _)) = self.dispatches.borrow().get(call) {
            let handle = self.discovery.procedure(&call.0, request)?;
            let site = handle.call_site_handle(call.1).ok_or_else(|| {
                self.discovery
                    .unavailable(format!("call {:?} is not in its procedure", call.1))
            })?;
            let key = site.durable_key();
            debug_assert_eq!(&key, call);
            self.discovery.resolve_call(&site, request)?;
            return Ok(dispatch.clone());
        }
        let local = dispatch_uncached(&self.discovery, self, call, request)?;
        let answer = local.dispatch.clone();
        self.dispatches
            .borrow_mut()
            .insert(call.clone(), (local.dispatch, local.model));
        Ok(answer)
    }

    fn callers(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Callers, Self::Error> {
        callers(
            &self.discovery,
            self,
            procedure,
            self.max_callers,
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
        let handle = self.discovery.procedure(procedure, request)?;
        Ok(handle
            .semantics()
            .lexical_parent()
            .map(|parent| (procedure.0.clone(), parent)))
    }

    fn model(&self, call: &DurableCallSiteKey) -> Option<CallModel<()>> {
        self.dispatches
            .borrow()
            .get(call)
            .expect("model follows dispatch")
            .1
            .clone()
    }

    fn unmodeled_call_behavior(&self) -> crate::dataflow::UnmodeledCallBehavior {
        self.plan.unmodeled_call_behavior()
    }

    fn fallback_ports(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<FallbackPorts, Self::Error> {
        let handle = self.discovery.procedure(&call.0, request)?;
        let site = handle.semantics().call_site(call.1).ok_or_else(|| {
            self.discovery
                .unavailable(format!("call {:?} is not in its procedure", call.1))
        })?;
        Ok(fallback_ports(site))
    }

    fn authored_models(&self) -> Vec<Box<[crate::value_flow::AuthoredArmClosure]>> {
        Vec::new()
    }

    fn openness(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Openness, Self::Error> {
        if let Some(openness) = self.openness.read(&self.attribution.capability(), |memo| {
            memo.borrow().get(procedure).cloned()
        }) {
            return Ok(openness);
        }
        let openness = decide_openness(&self.discovery, self, procedure, request)?;
        self.openness.read(&self.attribution.capability(), |memo| {
            memo.borrow_mut()
                .insert(procedure.clone(), openness.clone());
        });
        Ok(openness)
    }

    fn endpoints(
        &self,
        _procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureEndpoints<(), ()>, Self::Error> {
        Ok(ProcedureEndpoints::none())
    }

    fn source_evidence(
        &self,
        _source: &crate::taint::compose::BoundSource<()>,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<HopQuality, Self::Error> {
        Ok(HopQuality::CERTAIN)
    }
}

pub struct CallModelDecision<Function> {
    pub model: Option<CallModel<Function>>,
    pub continuation: HopQuality,
}

/// A raw call answer and the coverage facts a consumer reports in its own diagnostics.
pub struct LocalDispatch<Function> {
    pub dispatch: Dispatch,
    pub model: Option<CallModel<Function>>,
    pub handle: CallSiteHandle,
    pub status: SemanticInputStatus,
    pub coverage: CallSiteCoverage,
    pub boundaries: Box<[DispatchBoundary]>,
}

/// Project a local interior run, retaining all carrier and path uncertainty.
#[allow(clippy::too_many_arguments)]
pub fn interior_from_snapshot<C: InteriorProjectionClient>(
    client: &C,
    handle: ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    seeds: &[InteriorSeed],
    observations: &[InteriorObservation],
    witnesses: bool,
    edge_kills: &[GuardEdgeKill],
    execution_budget: &SemanticExecutionBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<InteriorFlows, C::Error> {
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
                None if matches!(port, PartialFlowPort::Heap { root, .. }
                    if matches!(root.as_ref(), PartialFlowPort::CallResult { .. })) =>
                {
                    return Ok(incomplete_interior(
                        handle,
                        "a call-result member has no live continuation seed",
                    ));
                }
                None if matches!(port, PartialFlowPort::Heap { .. }) => None,
                None => {
                    return Ok(incomplete_interior(
                        handle,
                        "an input port seed is not live in its procedure",
                    ));
                }
            },
            InteriorSeed::Writeback {
                call,
                storage,
                selectors,
                tail,
            } => {
                let site = handle
                    .semantics()
                    .call_site(*call)
                    .expect("a writeback seed names a call of its procedure");
                let ControlContinuation::Target(point) = site.normal_continuation else {
                    return Ok(incomplete_interior(
                        handle,
                        "a heap writeback has no known normal-return continuation",
                    ));
                };
                let Some(location) = caller_exact_read_location(&handle, storage, selectors, *tail)
                else {
                    return Ok(incomplete_interior(
                        handle,
                        "a heap writeback has no exact caller location",
                    ));
                };
                Some(ExtraSeed {
                    point,
                    phase: ExtraPhase::BeforeEffects,
                    carrier: ValueFlowEndpoint::Location(Box::new(location)),
                })
            }
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
    let mut pending_member_reads = HashSet::new();
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
                if origins.locations.is_empty() {
                    completeness = incomplete("a caller-side member input has no storage origin");
                }
                for origin in &origins.locations {
                    // Track containing-value taint at the substituted read
                    // so a later strong write can kill that descendant.
                    let mut bound_by_implicit_read = false;
                    let mut implicit_observation = None;
                    if client.implicit_heap_reads()
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
                                        ValueFlowEndpoint::for_value(value.clone()) == seed.carrier
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
                        implicit_observation = Some(extra_observations.len() - 1);
                        bound_by_implicit_read = !seed_carriers.is_empty()
                            || extra_seeds.iter().any(|seed| matches!(&seed.carrier,
                                ValueFlowEndpoint::Location(location) if exact_location_covers_read(location, &read)));
                        implicit_reads.push(ImplicitHeapRead {
                            location: read,
                            seed_carriers,
                        });
                    }
                    let carriers = caller_location_carriers(
                        snapshot,
                        &origin.location,
                        &location.selectors,
                        location.tail,
                    );
                    if carriers.is_empty() && !bound_by_implicit_read {
                        let actual_endpoint = ValueFlowEndpoint::for_value(actual.clone());
                        let copied_actual = snapshot.relations().iter().any(|relation| {
                            relation.target == actual_endpoint
                                && relation.transfer.is_some_and(|transfer| {
                                    transfer.kind
                                        == crate::analyzer::semantic::TransferKind::AggregateCopy
                                })
                        });
                        if copied_actual {
                            if let Some(extra) = implicit_observation {
                                pending_member_reads.insert(extra);
                            } else {
                                completeness =
                                    incomplete("a caller-side member input has no bound carrier");
                            }
                        }
                    }
                    for carrier in carriers {
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
    let mut fixpoint_request = request.staged_with_execution_budget(execution_budget);
    let ExtendedPartialFlows { partial, flows } = client.run_interior_fixpoint(
        &handle,
        snapshot,
        &extra_seeds,
        &extra_observations,
        witnesses,
        &implicit_reads,
        edge_kills,
        &mut fixpoint_request,
    )?;
    if partial.outcome != PartialFlowOutcome::Complete {
        completeness = incomplete(format!(
            "the procedure's relations are {:?}",
            partial.outcome
        ));
    }
    if !partial.relations_complete {
        completeness =
            incomplete("the procedure's relations or boundary member ports are incomplete");
    }
    let mut result_contents = handle
        .semantics()
        .call_sites()
        .iter()
        .flat_map(|call| {
            call.result
                .into_iter()
                .chain(call.normal_results.iter().copied())
        })
        .collect::<HashSet<_>>();
    loop {
        let mut changed = false;
        for relation in snapshot.relations() {
            if relation
                .transfer
                .is_some_and(|transfer| !transfer.preserves_member_contents())
            {
                continue;
            }
            if let (ValueFlowEndpoint::Value(source), ValueFlowEndpoint::Value(target)) =
                (&relation.source, &relation.target)
                && result_contents.contains(&source.id())
            {
                changed |= result_contents.insert(target.id());
            }
        }
        if !changed {
            break;
        }
    }
    if !partial.ports.iter().any(|port| {
        matches!(port, PartialFlowPort::Heap { root, .. }
        if matches!(root.as_ref(), PartialFlowPort::CallResult { .. }))
    }) && handle
        .semantics()
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .any(|event| {
            if let crate::analyzer::semantic::SemanticEffect::MemoryLoad { location, .. } =
                event.effect
            {
                return handle
                    .semantics()
                    .memory_location(location)
                    .is_some_and(|row| match &row.kind {
                        crate::analyzer::semantic::MemoryLocationKind::Field { base, .. }
                        | crate::analyzer::semantic::MemoryLocationKind::Property {
                            base, ..
                        }
                        | crate::analyzer::semantic::MemoryLocationKind::Index { base, .. } => {
                            result_contents.contains(base)
                        }
                        _ => false,
                    });
            }
            false
        })
    {
        completeness = incomplete("a call-result member read has no returned-member binding");
    }
    // One flow per seed and target. When two carriers of one observation
    // both carry a seed, the uncertain derivation is kept and the crossed
    // calls of both are joined, as the fixpoint does for one carrier.
    let mut mapped: Vec<InteriorFlow> = Vec::with_capacity(flows.len());
    let mut index_of = HashMap::new();
    for flow in flows {
        let (target, uncertain) = match flow.target {
            ExtraTarget::Observation(extra) => {
                pending_member_reads.remove(&extra);
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
    if !pending_member_reads.is_empty() {
        completeness = incomplete("a caller-side member input has no bound carrier");
    }
    Ok(InteriorFlows {
        procedure: handle,
        flows,
        completeness,
    })
}

/// Decide whether local gaps leave this procedure open after call refinement.
pub fn decide_openness<D, C>(
    discovery: &D,
    client: &C,
    procedure: &DurableProcedureKey,
    request: &mut SemanticRequest<'_>,
) -> Result<Openness, D::Error>
where
    D: LocalTransferDiscovery,
    C: LocalOpennessClient<D>,
{
    let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.openness");
    let handle = discovery.procedure(procedure, request)?;
    // The ICFG engine blocks a snapshot with an unproven relation before
    // it classifies any gap (`classify_snapshot_openness`), and a gap sweep
    // cannot see the relation. The head's fact answers it from the
    // memoized partial-flow read the search already made. The head keeps
    // only the projection's status label, which does not determine a
    // `SemanticInputStatus` (an unsupported capability or an exceeded
    // budget carry data), so the status comes from `snapshot_status`, on
    // this path only.
    if !client.relations_complete(procedure, request)? {
        return Ok(Openness::Open {
            residual: Box::default(),
            blocked: None,
            status: snapshot_status(discovery, &handle, request)?,
            reason: "the procedure has incomplete boundary member coverage".into(),
        });
    }
    let sweep = client.openness_sweep(procedure, &handle, request)?;
    if !sweep.open {
        return Ok(Openness::Closed);
    }
    if sweep.relevant_gaps.is_empty() {
        // The procedure is open with no gap to refine: a value-flow
        // capability or a Go builtin assumption. No dispatch answers it.
        return Ok(Openness::Open {
            residual: Box::default(),
            blocked: None,
            status: snapshot_status(discovery, &handle, request)?,
            reason: "a value-flow capability or builtin assumption keeps the procedure open".into(),
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
                        let complete =
                            client.dispatch_complete(&(procedure.clone(), call), request)?;
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
    let reason =
        format!("residual calls {residual:?} and blocked gaps {blocked:?} keep the procedure open");
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
        status: snapshot_status(discovery, &handle, request)?,
        reason: reason.into(),
    })
}

/// Read the same cached snapshot that discovery uses for local flows.
pub fn snapshot_status<D: LocalTransferDiscovery>(
    discovery: &D,
    handle: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticInputStatus, D::Error> {
    let outcome = discovery.procedure_snapshot(handle, &OracleCallContext::empty(), request)?;
    Ok(SemanticInputStatus::from_outcome(&outcome))
}

/// The workspace gap sweep, memoized only for this composition query.
pub fn openness_sweep<D: LocalTransferDiscovery>(
    discovery: &D,
    handle: &ProcedureHandle,
    execution_budget: &SemanticExecutionBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<ProcedureOpenness, D::Error> {
    let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.openness.sweep");
    let outcome = discovery
        .workspace()
        .semantic_oracle_provider()
        .procedure_openness(
            handle,
            &OracleCallContext::empty(),
            &mut request.staged_with_execution_budget(execution_budget),
        )
        .map_err(|error| discovery.provider_error(error.to_string()))?;
    discovery.require_outcome(&outcome, "composition openness")?;
    outcome.available_value().cloned().ok_or_else(|| {
        discovery.unavailable("composition could not decide the procedure's openness".to_owned())
    })
}

/// The refinement calls that should be prefetched before dispatch.
pub fn refinement_calls(
    handle: &ProcedureHandle,
    sweep: &ProcedureOpenness,
    mut is_memoized: impl FnMut(CallSiteId) -> bool,
) -> Vec<CallSiteHandle> {
    if !sweep.open {
        return Vec::new();
    }
    let abort_user_code = abort_paths_run_user_code(handle.semantics());
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
            && !is_memoized(call)
            && let Some(call) = handle.call_site_handle(call)
        {
            calls.push(call);
        }
    }
    calls
}

pub fn dispatch_uncached<D, M>(
    discovery: &D,
    models: &M,
    call: &DurableCallSiteKey,
    request: &mut SemanticRequest<'_>,
) -> Result<LocalDispatch<M::Function>, D::Error>
where
    D: LocalTransferDiscovery,
    M: CallModelSource<Error = D::Error>,
{
    let handle = discovery.procedure(&call.0, request)?;
    let call_handle = handle.call_site_handle(call.1).ok_or_else(|| {
        discovery.unavailable(format!("call {:?} is not in its procedure", call.1))
    })?;
    let answer = {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.dispatch.resolve");
        discovery.resolve_call(&call_handle, request)?
    };
    let result = answer.available_value();
    let status = SemanticInputStatus::from_outcome(&answer);
    let mut coverage = result.map_or_else(
        || CallSiteCoverage::unavailable(status),
        |result| CallSiteCoverage::from_dispatch(status, result),
    );
    let boundaries = result
        .map(|result| result.boundaries().into())
        .unwrap_or_default();
    let decision = models.dispatch_model(&call_handle, &answer)?;
    let continuation = decision.continuation;
    if let Some(model) = decision.model {
        return Ok(LocalDispatch {
            dispatch: Dispatch {
                candidates: Vec::new(),
                completeness: Completeness::Complete,
                continuation,
            },
            model: Some(model),
            handle: call_handle,
            status,
            coverage,
            boundaries,
        });
    }
    let Some(result) = result else {
        return Ok(LocalDispatch {
            dispatch: Dispatch {
                candidates: Vec::new(),
                completeness: Completeness::Incomplete {
                    reason: "the dispatch of the call has no answer".into(),
                },
                continuation,
            },
            model: None,
            handle: call_handle,
            status,
            coverage,
            boundaries,
        });
    };
    let mut completeness = dispatch_completeness(&answer, result);
    let mut candidates = Vec::new();
    let mut entered = Vec::new();
    let mut bindings = Vec::new();
    let snapshot_outcome =
        discovery.procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
    let snapshot_index = snapshot_outcome
        .available_value()
        .map(CallStorageRelationIndex::new);
    for candidate in result.candidates() {
        let outcome = discovery.call_bindings(
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
                composition_candidate(
                    &call_handle,
                    candidate.target().durable_key(),
                    bindings,
                    snapshot_outcome.available_value(),
                    snapshot_index.as_ref(),
                )
            });
        match composed {
            Ok(composed) => {
                if let (Some(callee_rows), Some(caller_rows)) = (
                    models.boundary_member_rows(&composed.procedure, request)?,
                    models.boundary_member_rows(&call_handle.procedure().durable_key(), request)?,
                ) && (!callee_rows.relations_complete
                    || !returned_members_bound(
                        &callee_rows.ports,
                        &caller_rows.ports,
                        &composed.returns,
                        |field| {
                            models.canonical_returned_field(
                                &composed.procedure,
                                &call_handle.procedure().durable_key(),
                                field,
                                request,
                            )
                        },
                    ))
                {
                    completeness = Completeness::Incomplete {
                        reason: "a callee's boundary-member coverage is incomplete".into(),
                    };
                }
                entered.push(candidate.target().clone());
                candidates.push(composed);
            }
            Err(reason) => {
                completeness = Completeness::Incomplete {
                    reason: reason.into(),
                }
            }
        }
    }
    coverage.entered = entered;
    coverage.bindings = bindings;
    Ok(LocalDispatch {
        dispatch: Dispatch {
            candidates,
            completeness,
            continuation,
        },
        model: None,
        handle: call_handle,
        status,
        coverage,
        boundaries,
    })
}

fn returned_members_bound(
    callee_ports: &[PartialFlowPort],
    caller_ports: &[PartialFlowPort],
    returns: &[(PartialFlowPort, PartialFlowPort)],
    mut canonical_field: impl FnMut(
        &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<crate::analyzer::semantic::SemanticLocator>,
) -> bool {
    let callee_covered = callee_ports.iter().all(|port| {
        let PartialFlowPort::Heap { root, .. } = port else {
            return true;
        };
        if !matches!(
            root.as_ref(),
            PartialFlowPort::NormalReturn | PartialFlowPort::IndexedNormalReturn { .. }
        ) {
            return true;
        }
        returns.iter().any(|(returned, result)| {
            returned == root.as_ref()
                && caller_ports.iter().any(|caller| {
                    bound_return_member_matches(
                        caller,
                        port,
                        result,
                        returned,
                        &mut canonical_field,
                    )
                })
        })
    });
    callee_covered
        && caller_ports.iter().all(|port| {
            let PartialFlowPort::Heap { root, .. } = port else {
                return true;
            };
            if !matches!(root.as_ref(), PartialFlowPort::CallResult { .. })
                || !returns.iter().any(|(_, result)| result == root.as_ref())
            {
                return true;
            }
            returns
                .iter()
                .filter(|(_, result)| result == root.as_ref())
                .all(|(returned, result)| {
                    callee_ports.iter().any(|callee_port| {
                        bound_return_member_matches(
                            port,
                            callee_port,
                            result,
                            returned,
                            &mut canonical_field,
                        )
                    })
                })
        })
}

/// Read the published local flows for one canonical procedure.
pub fn stored_partial_flows<D: LocalTransferDiscovery>(
    discovery: &D,
    handle: &ProcedureHandle,
) -> Result<Option<ProcedurePartialFlows>, D::Error> {
    discovery
        .workspace()
        .stored_partial_flows(handle)
        .map_err(|error| discovery.provider_error(error.to_string()))
}

/// Reproject one procedure when its published rows cannot answer the query.
pub fn project_partial_flows<D: LocalTransferDiscovery>(
    discovery: &D,
    handle: &ProcedureHandle,
    execution_budget: &SemanticExecutionBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<ProcedurePartialFlows, D::Error> {
    let mut fixpoint_request = request.staged_with_execution_budget(execution_budget);
    let outcome =
        file_local_procedure_relations(handle, &OracleCallContext::empty(), &mut fixpoint_request)
            .map_err(|error| discovery.provider_error(error.to_string()))?;
    discovery.require_outcome(&outcome, "composition partial flows")?;
    let snapshot = outcome.available_value().ok_or_else(|| {
        discovery.unavailable("composition could not project the procedure's relations".to_owned())
    })?;
    Ok(compute_partial_flows(
        handle,
        snapshot,
        &mut fixpoint_request,
    ))
}

/// The semantic calls at one source range. One range can name several calls.
pub fn matching_calls(
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

/// Call inputs and the singular result and thrown output used by the ICFG fallback.
pub fn fallback_ports(row: &SemanticCallSite) -> FallbackPorts {
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
    FallbackPorts {
        inputs: inputs.into_boxed_slice(),
        outputs: outputs.into_boxed_slice(),
    }
}

/// One dispatch candidate as the composition reads it: each binding of the
/// candidate, mapped from the call's value to its call port and from the
/// callee's formal or return to its port. A binding whose value is not a
/// port of the call, or that binds a location rather than a value, has no
/// port and makes the candidate unusable; the error names why.
pub fn composition_candidate(
    call: &CallSiteHandle,
    callee: DurableProcedureKey,
    bindings: &CallBindings,
    snapshot: Option<&crate::analyzer::semantic::ValueFlowSnapshot>,
    snapshot_index: Option<&CallStorageRelationIndex>,
) -> Result<ComposeCandidate, String> {
    let call_id = call.id();
    let row = call
        .procedure()
        .semantics()
        .call_site(call_id)
        .ok_or("the call is not a call of its procedure")?;
    let mut arguments = Vec::new();
    let mut writeback = Vec::new();
    let mut returns = Vec::new();
    let mut direct_fields_by_formal = HashMap::new();
    for binding in bindings.bindings() {
        match binding {
            CallBinding::Receiver { formal, .. } => arguments.push((
                PartialFlowPort::CallReceiver { call: call_id },
                formal_port(formal)?,
            )),
            CallBinding::ArgumentGroup(group) => {
                for mapping in group.mappings() {
                    let proof = mapping.proof() == &ProofStatus::Proven;
                    let complete = group.coverage() == CandidateCoverage::Exhaustive
                        && mapping.completeness() == &EvidenceCompleteness::Complete;
                    let mapping = mapping.value();
                    let actual = match mapping.actual() {
                        CallArgumentEndpoint::Value(value) => value.id(),
                        CallArgumentEndpoint::Location { .. } => {
                            return Err("an argument binds a location, not a value".to_owned());
                        }
                    };
                    let actual_port = actual_port(row, call_id, actual)?;
                    let formal_port = formal_port(mapping.formal())?;
                    let storage = snapshot.map(|snapshot| {
                        caller_storage_locations(
                            mapping.actual(),
                            snapshot,
                            ValueFlowPlanLimits::default(),
                        )
                    });
                    let storage_complete = storage.as_ref().is_some_and(|storage| storage.complete);
                    let storage_locations = storage
                        .into_iter()
                        .flat_map(|storage| storage.locations)
                        .filter(|location| location.proven_complete)
                        .map(|location| location.location)
                        .collect::<Vec<_>>();
                    writeback.push(WritebackBinding {
                        actual: actual_port.clone(),
                        formal: formal_port.clone(),
                        shares_storage: snapshot.zip(snapshot_index).map_or(
                            crate::analyzer::semantic::CallStorageSharing::Unknown,
                            |(snapshot, index)| {
                            crate::analyzer::semantic::argument_shares_storage_with_formal(
                                mapping.actual(), mapping.mode(), crate::analyzer::semantic::CallWrittenMember::MayTraverseReferent, snapshot, index,
                            )
                        }),
                        direct_field_sharing: snapshot.zip(snapshot_index).map_or(
                            crate::analyzer::semantic::CallStorageSharing::Unknown,
                            |(snapshot, index)| {
                                crate::analyzer::semantic::argument_shares_storage_with_formal(
                                    mapping.actual(), mapping.mode(), crate::analyzer::semantic::CallWrittenMember::DirectField, snapshot, index,
                                )
                            },
                        ),
                        direct_fields: direct_fields_by_formal
                            .entry(formal_port.clone())
                            .or_insert_with(|| crate::analyzer::semantic::direct_formal_store_fields(bindings.callee(), &formal_port))
                            .clone(),
                        conversion_preserves_identity: mapping.preserves_reference_identity(),
                        proven: proof,
                        complete: complete && storage_complete,
                        storage: storage_locations.into_boxed_slice(),
                    });
                    arguments.push((actual_port, formal_port));
                }
            }
            CallBinding::ImplicitArgument { .. } => {
                return Err("an implicit argument has no call port".to_owned());
            }
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
        writeback: writeback.into_boxed_slice(),
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

pub fn result_port(
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

/// Whether a dispatch answer covers every candidate and all boundaries are certain.
pub fn dispatch_completeness(
    answer: &SemanticOutcome<DispatchResult>,
    result: &DispatchResult,
) -> Completeness {
    let incomplete = |reason: String| Completeness::Incomplete {
        reason: reason.into(),
    };
    if !matches!(answer, SemanticOutcome::Complete { .. }) {
        return incomplete("the dispatch answer is not complete".to_owned());
    }
    if result.coverage() != CandidateCoverage::Exhaustive {
        return incomplete(format!("the dispatch coverage is {:?}", result.coverage()));
    }
    if result.boundaries().iter().any(|boundary| {
        boundary.proof != ProofStatus::Proven
            || boundary.completeness != EvidenceCompleteness::Complete
    }) {
        return incomplete(
            "the dispatch leaves a boundary that is not proven and complete".to_owned(),
        );
    }
    Completeness::Complete
}

fn incomplete(reason: impl Into<Box<str>>) -> Completeness {
    Completeness::Incomplete {
        reason: reason.into(),
    }
}

pub fn callers<D, M>(
    discovery: &D,
    models: &M,
    procedure: &DurableProcedureKey,
    max_callers_per_procedure: usize,
    execution_budget: &SemanticExecutionBudget,
    excluded_callers: &std::cell::RefCell<
        Vec<(crate::analyzer::ProjectFile, crate::analyzer::Range)>,
    >,
    request: &mut SemanticRequest<'_>,
) -> Result<crate::taint::compose::Callers, D::Error>
where
    D: LocalTransferDiscovery,
    M: CallModelSource<Error = D::Error>,
{
    let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.callers");
    let handle = discovery.procedure(procedure, request)?;
    let workspace = discovery.workspace();
    let analyzer = workspace.analyzer();
    let Some(file) = file_for_locator(workspace, handle.semantics().locator()) else {
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
        max_candidates: max_callers_per_procedure,
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
    // proof is not read here. A truncated or cancelled enumeration also
    // leaves the inventory uncertified; its reason above is the more
    // specific one, so it is kept.
    if matches!(completeness, Completeness::Complete)
        && sites.caller_inventory != CallerInventoryCoverage::Complete
    {
        completeness = incomplete("no certified reverse inventory");
    }
    let compiled = workspace
        .semantic_oracle_provider()
        .caller_sites_compiled(&sites.sites, request.cancellation)
        .map_err(|error| discovery.provider_error(error.to_string()))?;
    assert_eq!(compiled.len(), sites.sites.len());
    let mut compiled = compiled.into_iter();
    sites.sites.retain(|site| {
        if compiled
            .next()
            .expect("one activity answer per caller site")
        {
            true
        } else {
            excluded_callers
                .borrow_mut()
                .push((site.file.clone(), site.range));
            false
        }
    });
    discovery.prefetch_callers(&sites.sites, request)?;
    let target_key = handle.durable_key();
    let mut calls = Vec::new();
    let mut seen = HashSet::new();
    for site in &sites.sites {
        let outcome = workspace
            .materialize_program_semantics(
                &site.file,
                &mut request.staged_with_execution_budget(execution_budget),
            )
            .map_err(|error| discovery.provider_error(error.to_string()))?;
        discovery.require_outcome(&outcome, "composition callers")?;
        let Some(caller) = outcome.available_value().cloned() else {
            completeness = incomplete("the caller's file has no semantic artifact");
            continue;
        };
        let matched = matching_calls(&caller, (site.range.start_byte, site.range.end_byte));
        if matched.is_empty() {
            completeness = incomplete("an incoming call site has no semantic call");
        }
        for (caller_handle, call_handle) in matched {
            let answer = discovery.resolve_call(&call_handle, request)?;
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
                if !CallModelSource::covers_caller_candidate(models, &call_handle, &answer)?
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

pub fn incomplete_interior(procedure: ProcedureHandle, reason: &str) -> InteriorFlows {
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
