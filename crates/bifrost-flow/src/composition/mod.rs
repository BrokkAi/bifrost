//! Label-free local transfer operations shared by composition clients.

mod call_structure;
pub use call_structure::{CallStructureDispatch, CallStructureProvider};

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::rc::Rc;
use std::sync::Arc;

use crate::analyzer::reuse_verdict::{CarriesReuseVerdict, ReuseVerdict};
use crate::analyzer::semantic::partial_flow::rules::GuardEdgeKill;
use crate::analyzer::semantic::partial_flow::{
    ExtendedPartialFlows, ExtraObservation, ExtraPhase, ExtraSeed, ExtraTarget, ImplicitHeapRead,
    PartialFlowOutcome, PartialFlowPort, ProcedurePartialFlows, call_input_value,
    caller_exact_read_location, caller_location_carriers, caller_read_location,
    compute_partial_flows, compute_partial_flows_with_implicit_reads, exact_location_covers_read,
    file_local_procedure_relations, input_port_seed, join_crossed,
    ports::{call_port_values, written_heap_ports},
};
use crate::analyzer::semantic::type_flow::file_for_locator;
use crate::analyzer::semantic::workspace_oracle::{
    GapOpenness, ProcedureOpenness, abort_paths_run_user_code, classify_gap_openness,
};
use crate::analyzer::semantic::{
    AccessPath, AccessPathAtPoint, AccessPathRoot, AliasQuery, AliasRelation, CallArgumentEndpoint,
    CallBinding, CallBindings, CallSiteHandle, CallSiteId, CallStorageRelationIndex,
    CandidateCoverage, ControlContinuation, DispatchBoundary, DispatchResult, EvidenceCompleteness,
    ExactCallSiteKey, ExactProcedureIdentity, FreshObjectPublicationQuery, HeapOracle,
    IntrinsicCall, IntrinsicTransfer, ObservationPhase, OracleCallContext, ProcedureHandle,
    ProcedurePortHandle, ProcedurePortKind, ProgramPointId, ProofStatus, SemanticArtifact,
    SemanticArtifactKey, SemanticCallSite, SemanticCapability, SemanticExecutionBudget,
    SemanticGapKind, SemanticOutcome, SemanticProviderError, SemanticRequest, ValueAtPoint,
    ValueFlowEndpoint, ValueFlowSnapshot, ValueId,
};
use crate::analyzer::usages::call_relations::CallerInventoryCoverage;
use crate::analyzer::usages::{CallRelationLimits, CallRelationService, CallSite};
use crate::analyzer::workspace_authority::{
    CaptureScopedMemo, OwnedMemoCapability, ReplayingMemo, ReplayingMemoEntry,
    workspace_memo_attribution,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope, WorkspaceAnalyzer};
use crate::dataflow::SemanticInputStatus;
use crate::taint::compose::bound_return_member_matches;
use crate::taint::compose::{
    BlockedGap, BudgetLane, CallHandoff, CallHandoffBinding, CallHandoffExit, CallHandoffInventory,
    CallModel, CallObjectContinuity, Callers, Completeness, Dispatch,
    DispatchCandidate as ComposeCandidate, ExecutionSource, ExternalBodyUnavailableGap,
    FallbackPorts, HopQuality, IncompleteCause, InteriorFlow, InteriorFlows, InteriorObservation,
    InteriorSeed, InteriorTarget, InteriorWitnessStep, ModelTransfer, ObjectAnchor,
    ObjectAnchorRole, ObjectAnchorSite, ObjectPredecessor, ObjectRelation, Openness,
    OperationalCause, ProcedureEndpoints, WritebackBinding,
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
    attribution: OwnedMemoCapability,
    artifacts: CompositionMap<SemanticArtifactKey, Arc<SemanticArtifact>>,
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
            endpoint_projections: false,
            summary: None,
            summary_target: None,
            transfers: actual
                .into_iter()
                .map(|actual| ModelTransfer {
                    actual,
                    output: PartialFlowPort::CallResult {
                        call: call.id(),
                        ordinal: None,
                    },
                    function: (),
                    proven: true,
                    unresolved_output_storage: false,
                    preserves_member_contents: false,
                })
                .collect(),
            writeback: Box::default(),
            receiver_reads: Box::default(),
            proven: true,
            completeness: Completeness::Complete,
            retains_dispatch: false,
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

/// Protocol events and object continuity are the typestate client's call
/// semantics. A value-transfer intrinsic does not replace a callee body for
/// the tracked object, so this client leaves candidates visible to handoff.
pub struct TypestateCallModels;

fn typestate_object_role(role: crate::typestate::TypestateObjectRole) -> ObjectAnchorRole {
    use crate::typestate::TypestateObjectRole as R;
    match role {
        R::MatchedValue => ObjectAnchorRole::MatchedValue,
        R::AllocationResult => ObjectAnchorRole::AllocationResult,
        R::Receiver => ObjectAnchorRole::Receiver,
        R::Argument => ObjectAnchorRole::Argument,
        R::FormalReceiver => ObjectAnchorRole::FormalReceiver,
        R::FormalArgument { ordinal } => ObjectAnchorRole::FormalArgument(ordinal),
        R::NormalReturn => ObjectAnchorRole::NormalReturn,
        R::ExceptionalReturn => ObjectAnchorRole::ExceptionalReturn,
        R::FieldBase => ObjectAnchorRole::FieldBase,
        R::FieldValue => ObjectAnchorRole::FieldValue,
        R::FieldLocation => ObjectAnchorRole::FieldLocation,
        R::EscapedObject => ObjectAnchorRole::EscapedObject,
        R::CurrentObject => ObjectAnchorRole::CurrentObject,
    }
}

impl CallModelSource for TypestateCallModels {
    type Error = SemanticProviderError;
    type Function = crate::typestate::TypestateComposeFunction;

    fn dispatch_model(
        &self,
        _call: &CallSiteHandle,
        _answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<CallModelDecision<Self::Function>, Self::Error> {
        Ok(CallModelDecision {
            model: None,
            continuation: HopQuality::CERTAIN,
        })
    }

    fn covers_caller_candidate(
        &self,
        _call: &CallSiteHandle,
        _answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

impl<'a> WorkspaceCompositionDiscovery<'a> {
    pub fn new(workspace: &'a WorkspaceAnalyzer, provider: WorkspaceValueFlowProvider<'a>) -> Self {
        Self {
            workspace,
            provider,
            attribution: workspace_memo_attribution(workspace),
            artifacts: ReplayingMemo::new(RefCell::new(HashMap::new())),
        }
    }

    pub(crate) fn modeled_fresh_call_result_origin(
        &self,
        call: &CallSiteHandle,
        result: &crate::analyzer::semantic::ValueHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<
        Option<brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::heap::ModeledFreshCallResultOrigin>,
        SemanticProviderError,
    >{
        let dispatch = self.provider.resolve_call(call, request)?;
        brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::heap::ModeledFreshResultOracle::modeled_fresh_call_result_origin(
            self.provider.oracle(),
            call,
            result,
            context,
            &dispatch,
            request,
        )
    }
}

impl ValueFlowProvider for WorkspaceCompositionDiscovery<'_> {
    type Error = SemanticProviderError;
    fn payload_projection_identity(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<crate::analyzer::semantic::StableDigest>>, Self::Error> {
        self.provider
            .payload_projection_identity(procedure, request)
    }

    fn payload_constructor_output(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Option<ValueFlowEndpoint>>, Self::Error> {
        self.provider.payload_constructor_output(call, request)
    }
    fn selected_executable_procedure(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ProcedureHandle>, Self::Error> {
        WorkspaceValueFlowProvider::select_executable_procedure(self.workspace, procedure, request)
    }

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
    fn call_conversion_may_run_user_code(
        &self,
        call: &CallSiteHandle,
        dispatch: &SemanticOutcome<DispatchResult>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<bool>, Self::Error> {
        self.provider
            .oracle()
            .call_conversion_may_run_user_code(call, dispatch, request)
    }

    fn workspace(&self) -> &WorkspaceAnalyzer {
        self.workspace
    }

    fn refuse_locator(
        &self,
        refusal: crate::analyzer::semantic::CandidateLocatorRefusal,
    ) -> Self::Error {
        SemanticProviderError::CandidateLocatorRefusal(refusal)
    }

    fn locator_refusal(
        &self,
        error: &Self::Error,
    ) -> Option<crate::analyzer::semantic::CandidateLocatorRefusal> {
        match error {
            SemanticProviderError::CandidateLocatorRefusal(refusal) => Some(*refusal),
            _ => None,
        }
    }

    fn procedure(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureHandle, Self::Error> {
        // A hit replays the reads of the fill that materialized the artifact,
        // the semantic-model read among them, so a warm query records the
        // same inputs as a cold one (#11953).
        let artifact = self
            .artifacts
            .read(&self.attribution.capability(), |memo, capture| {
                if let Some(entry) = memo.borrow().get(&key.0).cloned() {
                    return Ok::<_, SemanticProviderError>(entry);
                }
                let entry = Arc::new(capture.try_build(|| {
                    let root = self.workspace.analyzer().project().root();
                    let file = crate::analyzer::ProjectFile::new(
                        root.to_path_buf(),
                        key.0.path().as_path(),
                    );
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
                    Ok::<_, SemanticProviderError>(artifact)
                })?);
                memo.borrow_mut().insert(key.0.clone(), Arc::clone(&entry));
                Ok(entry)
            })?;
        let artifact = Arc::clone(&artifact);
        // Structural discovery supplies the base body to the selection owner.
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
    fn refuse_locator(
        &self,
        refusal: crate::analyzer::semantic::CandidateLocatorRefusal,
    ) -> Self::Error;
    fn locator_refusal(
        &self,
        error: &Self::Error,
    ) -> Option<crate::analyzer::semantic::CandidateLocatorRefusal>;

    /// Reacquire a body before reading a retained procedure-local locator.
    fn locator_procedure(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureHandle, Self::Error> {
        let handle = self.selected_procedure(key, request)?;
        handle
            .validate_durable_locator(key)
            .map_err(|error| self.refuse_locator(error))?;
        Ok(handle)
    }

    /// Select an executable handle without acquiring its flows.
    fn selected_procedure(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureHandle, Self::Error> {
        let base = self.procedure(key, request)?;
        self.selected_procedure_handle(&base, request)
    }

    fn selected_procedure_handle(
        &self,
        base: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureHandle, Self::Error> {
        let outcome = self
            .workspace()
            .executable_procedure_handle(base, request)
            .map_err(|error| self.provider_error(error.to_string()))?;
        self.require_outcome(&outcome, "selected procedure handle")?;
        outcome
            .available_value()
            .map(|selected| {
                let handle = &selected.handle;
                let side = &selected.side;
                debug_assert!(
                    *side != crate::analyzer::semantic::service::CandidateProcedureSide::Base
                        || !handle.is_candidate_alternate()
                );
                handle.clone()
            })
            .ok_or_else(|| self.unavailable("selected procedure handle unavailable".to_owned()))
    }

    /// Acquire one executable interpretation, paired flows, and all underlying reads.
    fn selected_procedure_and_flows(
        &self,
        key: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::service::SelectedCandidateProcedure<
            crate::analyzer::i_analyzer::QueryReadReceipt,
        >,
        Self::Error,
    > {
        let (selected, receipt) = crate::analyzer::i_analyzer::QueryReadReceipt::capture(
            self.workspace().analyzer(),
            || {
                let base = self.procedure(key, request)?;
                self.selected_procedure_and_flows_handle(&base, request)
            },
        );
        receipt.replay(self.workspace().analyzer());
        let mut selected = selected?;
        selected.admissions = receipt;
        Ok(selected)
    }

    fn selected_procedure_and_flows_handle(
        &self,
        base: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::service::SelectedCandidateProcedure<
            crate::analyzer::i_analyzer::QueryReadReceipt,
        >,
        Self::Error,
    > {
        use crate::analyzer::semantic::service::CandidateProcedureOutcome;
        let (outcome, receipt) = crate::analyzer::i_analyzer::QueryReadReceipt::capture(
            self.workspace().analyzer(),
            || {
                use crate::analyzer::semantic::ProcedureInterpretation;
                use crate::analyzer::semantic::service::SelectedCandidateProcedure;
                let executable = self
                    .workspace()
                    .executable_procedure_handle(base, request)
                    .map_err(|error| self.provider_error(error.to_string()))?;
                self.require_outcome(&executable, "selected executable procedure")?;
                let selected = executable.available_value().ok_or_else(|| {
                    self.unavailable("selected executable procedure unavailable".to_owned())
                })?;
                let (side, procedure, flows) = if selected.handle.interpretation()
                    == ProcedureInterpretation::ExecutableAlternate
                {
                    // A refined body cannot consume the base body's stored flows.
                    (selected.side, selected.handle.clone(), None)
                } else {
                    match self
                        .workspace()
                        .selected_procedure_and_flows(base, request)
                        .map_err(|error| self.provider_error(error.to_string()))?
                    {
                        CandidateProcedureOutcome::Selected(selected) => {
                            (selected.side, selected.procedure, Some(selected.flows))
                        }
                        CandidateProcedureOutcome::Cancelled => {
                            return Ok(CandidateProcedureOutcome::Cancelled);
                        }
                        CandidateProcedureOutcome::ExceededBudget(exceeded) => {
                            return Ok(CandidateProcedureOutcome::ExceededBudget(exceeded));
                        }
                    }
                };
                let projection = self.payload_projection_identity(&procedure, request)?;
                self.require_outcome(&projection, "selected payload projection")?;
                let flows = match flows {
                    Some(flows) if !projection.available_value().is_some_and(Option::is_some) => {
                        flows
                    }
                    _ => {
                        let snapshot = self.procedure_snapshot(
                            &procedure,
                            &OracleCallContext::empty(),
                            request,
                        )?;
                        self.require_outcome(&snapshot, "selected payload relations")?;
                        let snapshot = snapshot.available_value().ok_or_else(|| {
                            self.unavailable("selected payload relations unavailable".to_owned())
                        })?;
                        crate::analyzer::semantic::partial_flow::compute_partial_flows(
                            &procedure, snapshot, request,
                        )
                    }
                };
                Ok(CandidateProcedureOutcome::Selected(
                    SelectedCandidateProcedure {
                        side,
                        procedure,
                        flows,
                        admissions: (),
                    },
                ))
            },
        );
        receipt.replay(self.workspace().analyzer());
        match outcome? {
            CandidateProcedureOutcome::Selected(selected) => Ok(
                crate::analyzer::semantic::service::SelectedCandidateProcedure {
                    side: selected.side,
                    procedure: selected.procedure,
                    flows: selected.flows,
                    admissions: receipt,
                },
            ),
            CandidateProcedureOutcome::Cancelled => {
                self.require_outcome(
                    &SemanticOutcome::<()>::Cancelled {
                        partial: None,
                        work: Default::default(),
                    },
                    "selected procedure acquisition",
                )?;
                unreachable!("discovery must reject a cancelled acquisition")
            }
            CandidateProcedureOutcome::ExceededBudget(exceeded) => {
                self.require_outcome(
                    &SemanticOutcome::<()>::ExceededBudget {
                        partial: None,
                        exceeded,
                        work: Default::default(),
                    },
                    "selected procedure acquisition",
                )?;
                unreachable!("discovery must reject a budget-stopped acquisition")
            }
        }
    }

    fn call_conversion_may_run_user_code(
        &self,
        call: &CallSiteHandle,
        dispatch: &SemanticOutcome<DispatchResult>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<bool>, Self::Error>;
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
    /// The procedure's partial-flow head, whose relation completeness the
    /// openness decision reads.
    fn relations_head(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, D::Error>;
    fn openness_sweep(
        &self,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, D::Error>;
    /// A client may retire a global value obligation only after its actual
    /// interior requests have accounted for that exact obligation.
    fn value_obligation_accounted(
        &self,
        _handle: &ProcedureHandle,
        _gap: crate::analyzer::semantic::GapKey,
    ) -> bool {
        false
    }
    fn dispatch_completeness(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Completeness, D::Error>;
}

/// The client decides whether containing-value reads apply and runs the
/// fixpoint with any client-specific observation filter.
pub trait InteriorProjectionClient {
    type Error: std::fmt::Display;

    fn selected_entry_workspace(&self) -> &WorkspaceAnalyzer;

    fn record_value_obligation_accounting(
        &self,
        _handle: &ProcedureHandle,
        _gaps: &[crate::analyzer::semantic::GapKey],
        _request: &mut SemanticRequest<'_>,
    ) {
    }
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
type UnitDispatchMemo = CompositionMap<ExactCallSiteKey, (Dispatch, Option<CallModel<()>>)>;

/// Owned by the per-query composition provider and released when it drops.
/// All composition and ordered answer memos share this query-local limit.
pub(crate) struct CompositionMemoBudget {
    remaining: Cell<usize>,
}

impl CompositionMemoBudget {
    pub(crate) fn new(bytes: usize) -> Self {
        Self {
            remaining: Cell::new(bytes),
        }
    }

    pub(crate) fn try_charge(&self, bytes: usize) -> bool {
        let Some(remaining) = self.remaining.get().checked_sub(bytes) else {
            return false;
        };
        self.remaining.set(remaining);
        true
    }
}

type CompositionEntry<T> = Arc<ReplayingMemoEntry<T, crate::analyzer::ReadKey>>;
type CompositionMap<K, V> = ReplayingMemo<RefCell<HashMap<K, CompositionEntry<V>>>>;

// The typed operational signals are PartialFlowOutcome::ExceededBudget,
// SemanticInputStatus::{Cancelled, ExceededBudget}, and composition
// Incompleteness::{Cancelled, Budget}. A request stop also blocks insertion.
pub(crate) fn admit_composition_entry<K: Eq + Hash + Clone, V>(
    memo: &RefCell<HashMap<K, CompositionEntry<V>>>,
    key: &K,
    entry: impl Into<CompositionEntry<V>>,
    budget: &CompositionMemoBudget,
    operational_stop: bool,
) -> CompositionEntry<V> {
    let entry = entry.into();
    if !operational_stop {
        let heap = RefCell::new(crate::analyzer::store::cache_budget::RetainedHeap::default());
        let bytes = entry
            .retained_bytes(|key| {
                crate::analyzer::store::cache_budget::retained_read_key(
                    &mut heap.borrow_mut(),
                    key,
                );
                0
            })
            .saturating_add(heap.into_inner().total());
        if budget.try_charge(bytes) {
            memo.borrow_mut().insert(key.clone(), Arc::clone(&entry));
            return entry;
        }
    }
    // Not retained. The build already forwarded its reads to the live
    // capture, and `MemoReadCapture::finish` does not replay them twice.
    entry
}

fn partial_flows_weight(flows: &ProcedurePartialFlows) -> usize {
    std::mem::size_of::<Arc<ProcedurePartialFlows>>() + flows.retained_bytes()
}

fn openness_weight(openness: &Openness) -> usize {
    match openness {
        Openness::Closed => std::mem::size_of::<Openness>(),
        Openness::Open {
            residual, reason, ..
        } => {
            std::mem::size_of::<Openness>()
                + std::mem::size_of_val(residual.as_ref())
                + reason.len()
        }
    }
}

fn dispatch_weight(dispatch: &Dispatch) -> usize {
    let mut bytes = std::mem::size_of::<Dispatch>()
        + dispatch.candidates.capacity() * std::mem::size_of::<ComposeCandidate>();
    for candidate in &dispatch.candidates {
        bytes += candidate
            .written_heap_ports
            .as_ref()
            .map_or(0, |ports| std::mem::size_of_val(ports.as_ref()));
        bytes += std::mem::size_of_val(candidate.arguments.as_ref());
        bytes += std::mem::size_of_val(candidate.writeback.as_ref());
        bytes += std::mem::size_of_val(candidate.returns.as_ref());
        for binding in candidate.writeback.iter() {
            bytes += std::mem::size_of_val(binding.direct_fields.as_ref());
            bytes += std::mem::size_of_val(binding.storage.as_ref());
        }
    }
    bytes
}

pub struct UnitCompositionProvider<'a> {
    discovery: WorkspaceCompositionDiscovery<'a>,
    models: UnitCallModels<'a>,
    plan: &'a ValueFlowPlan,
    execution_budget: SemanticExecutionBudget,
    max_callers: usize,
    attribution: OwnedMemoCapability,
    memo_budget: Rc<CompositionMemoBudget>,
    partial: CompositionMap<
        ExactProcedureIdentity,
        crate::analyzer::usages::common::AdmittedMemoValue<Arc<ProcedurePartialFlows>>,
    >,
    dispatches: UnitDispatchMemo,
    sweeps: CompositionMap<ExactProcedureIdentity, ProcedureOpenness>,
    openness: CompositionMap<ExactProcedureIdentity, Openness>,
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
        max_retained_bytes: usize,
    ) -> Self {
        assert!(plan.composition_exclusion().is_none());
        Self {
            discovery: WorkspaceCompositionDiscovery::new(workspace, provider),
            models: UnitCallModels::new(workspace),
            plan,
            execution_budget,
            max_callers,
            attribution: workspace_memo_attribution(workspace),
            memo_budget: Rc::new(CompositionMemoBudget::new(max_retained_bytes)),
            partial: ReplayingMemo::new(RefCell::new(HashMap::new())),
            dispatches: ReplayingMemo::new(RefCell::new(HashMap::new())),
            sweeps: ReplayingMemo::new(RefCell::new(HashMap::new())),
            openness: ReplayingMemo::new(RefCell::new(HashMap::new())),
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

    fn selected_entry_workspace(&self) -> &WorkspaceAnalyzer {
        self.discovery.workspace
    }

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
    fn relations_head(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, SemanticProviderError> {
        crate::taint::compose::CompositionProvider::partial_flows(self, procedure, request)
    }

    fn openness_sweep(
        &self,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, SemanticProviderError> {
        let key = handle.exact_identity();
        let answer = self.sweeps.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, SemanticProviderError> {
                if let Some(entry) = memo.borrow().get(&key).cloned() {
                    return Ok(entry);
                }
                let entry = capture.try_build_weighted(|| {
                    let sweep =
                        openness_sweep(&self.discovery, handle, &self.execution_budget, request)?;
                    let weight =
                        brokk_bifrost_core::retention_budget::RetainedBytes::retained_bytes(&sweep);
                    Ok::<_, SemanticProviderError>((sweep, weight))
                })?;
                Ok(admit_composition_entry(
                    memo,
                    &key,
                    entry,
                    &self.memo_budget,
                    request.stop_observed(),
                ))
            },
        )?;
        Ok((*answer).clone())
    }

    fn dispatch_completeness(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Completeness, SemanticProviderError> {
        Ok(
            crate::taint::compose::CompositionProvider::dispatch(self, call, request)?
                .0
                .completeness,
        )
    }
}

enum PartialFlowMemoReadError {
    Provider(SemanticProviderError),
    Unretained(Arc<ProcedurePartialFlows>),
}

impl crate::taint::compose::CompositionProvider for UnitCompositionProvider<'_> {
    type Error = SemanticProviderError;
    type Fact = ();
    type Function = ();

    fn acquisition_refusal(
        &self,
        error: &Self::Error,
    ) -> Option<crate::analyzer::semantic::CandidateLocatorRefusal> {
        self.discovery.locator_refusal(error)
    }

    fn partial_flows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, Self::Error> {
        use crate::analyzer::usages::common::{
            MemoValueAdmission, QueryMemoOwner, try_capture_partial_flow_memo_entry,
        };
        let memo_key = self
            .discovery
            .selected_procedure(procedure, request)?
            .exact_identity();
        let flows = self.partial.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, PartialFlowMemoReadError> {
                if let Some(entry) = memo.borrow().get(&memo_key).cloned() {
                    return Ok(entry);
                }
                let admission = try_capture_partial_flow_memo_entry(
                    QueryMemoOwner::CompositionPartialFlow,
                    self.discovery.workspace().analyzer(),
                    capture,
                    request,
                    |request| {
                        let selected = self
                            .discovery
                            .selected_procedure_and_flows(procedure, request)?;
                        Ok(Arc::new(selected.flows))
                    },
                    |flows| partial_flows_weight(flows),
                    || self.discovery.artifacts.clear(),
                )
                .map_err(PartialFlowMemoReadError::Provider)?;
                match admission {
                    MemoValueAdmission::Admitted(entry) => Ok(admit_composition_entry(
                        memo,
                        &memo_key,
                        entry,
                        &self.memo_budget,
                        false,
                    )),
                    MemoValueAdmission::Unretained(flows) => {
                        Err(PartialFlowMemoReadError::Unretained(flows))
                    }
                }
            },
        );
        match flows {
            Ok(flows) => Ok(Arc::clone(&flows)),
            Err(PartialFlowMemoReadError::Unretained(flows)) => Ok(flows),
            Err(PartialFlowMemoReadError::Provider(error)) => Err(error),
        }
    }

    fn interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, Self::Error> {
        let handle = self.discovery.selected_procedure(procedure, request)?;
        let answer =
            self.discovery
                .procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
        let Some(snapshot) = answer.available_value() else {
            return Ok(unavailable_snapshot_interior(
                handle,
                SemanticInputStatus::from_outcome(&answer),
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
    ) -> Result<(Dispatch, Option<CallModel<()>>), Self::Error> {
        let memo_key = (
            self.discovery
                .locator_procedure(&call.0, request)?
                .exact_identity(),
            call.1,
        );
        let entry = self.dispatches.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, SemanticProviderError> {
                if let Some(entry) = memo.borrow().get(&memo_key).cloned() {
                    return Ok(entry);
                }
                let entry = capture.try_build_weighted(|| {
                    let raw = self.discovery.dispatch(call, request)?;
                    let local = dispatch_from_structure(&self.discovery, self, raw, request)?;
                    let weight = dispatch_weight(&local.dispatch)
                        + std::mem::size_of::<Option<CallModel<()>>>()
                        + local.model.as_ref().map_or(0, |model| {
                            model.transfers.capacity() * std::mem::size_of::<ModelTransfer<()>>()
                                + std::mem::size_of_val(model.writeback.as_ref())
                                + std::mem::size_of_val(model.receiver_reads.as_ref())
                                + model
                                    .authored
                                    .as_ref()
                                    .map_or(0, |arms| std::mem::size_of_val(arms.as_ref()))
                        });
                    Ok::<_, SemanticProviderError>(((local.dispatch, local.model), weight))
                })?;
                // The model returns with its dispatch, so a refused build is
                // not retained: the next dispatch of the call recomputes it.
                let operational_stop = request.stop_observed();
                Ok(admit_composition_entry(
                    memo,
                    &memo_key,
                    entry,
                    &self.memo_budget,
                    operational_stop,
                ))
            },
        )?;
        Ok(entry.clone())
    }

    fn callers(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Callers, Self::Error> {
        CallStructureProvider::callers(
            &self.discovery,
            |call, answer| CallModelSource::covers_caller_candidate(self, call, answer),
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
        CallStructureProvider::lexical_parent(&self.discovery, procedure, request)
    }

    fn unmodeled_call_behavior(&self) -> crate::dataflow::UnmodeledCallBehavior {
        self.plan.unmodeled_call_behavior()
    }

    fn fallback_ports(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<FallbackPorts, Self::Error> {
        let handle = self.discovery.locator_procedure(&call.0, request)?;
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
        let memo_key = self
            .discovery
            .selected_procedure(procedure, request)?
            .exact_identity();
        let openness = self.openness.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, SemanticProviderError> {
                if let Some(entry) = memo.borrow().get(&memo_key).cloned() {
                    return Ok(entry);
                }
                let entry = capture.try_build_weighted(|| {
                    let openness = decide_openness(&self.discovery, self, procedure, request)?;
                    let weight = openness_weight(&openness);
                    Ok::<_, SemanticProviderError>((openness, weight))
                })?;
                let operational_stop = request.stop_observed()
                    || matches!(
                        entry.value(),
                        Openness::Open {
                            status: SemanticInputStatus::Cancelled
                                | SemanticInputStatus::ExceededBudget { .. },
                            ..
                        }
                    );
                Ok(admit_composition_entry(
                    memo,
                    &memo_key,
                    entry,
                    &self.memo_budget,
                    operational_stop,
                ))
            },
        )?;
        Ok((*openness).clone())
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

/// Execution stops observed while searching one subject's composition roots.
#[derive(Debug, Default, Clone, Copy)]
pub struct CompositionExecutionObservation {
    pub search_stopped: bool,
    pub nested_summary_stopped: bool,
    pub recursive_pending_used: bool,
}

impl CompositionExecutionObservation {
    pub fn execution_dependent(self) -> bool {
        self.search_stopped || self.nested_summary_stopped || self.recursive_pending_used
    }
}

/// One selected subject's typed composition client. Value-flow discovery
/// supplies the label-free local graph, while this client owns dispatch,
/// ordered labels, and object handoff for the query lifetime.
pub struct TypestateCompositionProvider<'a> {
    discovery: Rc<WorkspaceCompositionDiscovery<'a>>,
    execution_budget: SemanticExecutionBudget,
    composition_budget: crate::taint::compose::CompositionBudget,
    max_callers: usize,
    attribution: OwnedMemoCapability,
    memo_budget: Rc<CompositionMemoBudget>,
    recursive_pending_used: Rc<Cell<bool>>,
    nested_execution_incomplete: Rc<Cell<bool>>,
    excluded_callers: RefCell<Vec<(crate::analyzer::ProjectFile, crate::analyzer::Range)>>,
    ordered: CaptureScopedMemo<RefCell<crate::typestate::ordered::TypestateOrderedRelations<'a>>>,
    protocol: &'a crate::typestate::CompiledProtocol,
    subject: &'a crate::typestate::BoundTypestateSubject,
    bindings: &'a crate::typestate::TypestateBindingPlan,
    context: crate::typestate::TypestateBindingContext,
    local: CompositionMap<ExactProcedureIdentity, Arc<ProcedurePartialFlows>>,
    dispatches: CompositionMap<ExactCallSiteKey, Dispatch>,
    formal_entry: Option<(DurableProcedureKey, PartialFlowPort)>,
    summaries: Rc<CompositionMap<TypestateSummaryKey, TypestateSummary>>,
    pending_summaries: Rc<RefCell<HashSet<TypestateSummaryKey>>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct TypestateSummaryKey {
    callee: ExactProcedureIdentity,
    formal: PartialFlowPort,
    exit: CallHandoffExit,
}

#[derive(Clone)]
struct TypestateSummary {
    reaches: Vec<(crate::typestate::TypestateComposeFunction, HopQuality)>,
    complete: bool,
}

struct AliasGuardCall<'a> {
    guard: &'a crate::typestate::TypestateAliasGuard,
    site: &'a CallSiteHandle,
    candidate: &'a ComposeCandidate,
    exit: CallHandoffExit,
    dispatch: &'a SemanticOutcome<DispatchResult>,
    bindings_outcome: &'a SemanticOutcome<CallBindings>,
    bindings: &'a CallBindings,
}

struct FormalPairSeparation {
    call: DurableCallSiteKey,
    candidate: DurableProcedureKey,
    context: OracleCallContext,
    first: u32,
    second: u32,
    subject: crate::typestate::TypestateSubjectId,
    exits: [CallHandoffExit; 2],
}

enum PairDecision {
    Separated(Box<FormalPairSeparation>),
    Alias,
    MayAlias,
    Unresolved(Option<crate::typestate::TypestateSubjectId>),
}

fn contains_candidate<'a, T: PartialEq + 'a>(
    subject: &T,
    mut candidates: impl Iterator<Item = &'a T>,
) -> bool {
    candidates.any(|candidate| candidate == subject)
}

#[cfg(test)]
#[test]
fn guard_candidate_membership_requires_subject() {
    let subject = 7;
    assert!(contains_candidate(&subject, [3, 7, 9].iter()));
    assert!(!contains_candidate(&subject, [3, 8, 9].iter()));
    assert!(!contains_candidate(&subject, [].iter()));
}

impl<'a> TypestateCompositionProvider<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        discovery: WorkspaceCompositionDiscovery<'a>,
        execution_budget: SemanticExecutionBudget,
        composition_budget: crate::taint::compose::CompositionBudget,
        protocol: &'a crate::typestate::CompiledProtocol,
        bindings: &'a crate::typestate::TypestateBindingPlan,
        subject: &'a crate::typestate::BoundTypestateSubject,
        context: crate::typestate::TypestateBindingContext,
        max_retained_bytes: usize,
    ) -> Self {
        assert!(bindings.subject(subject.id()).is_some());
        let workspace = discovery.workspace;
        let discovery = Rc::new(discovery);
        let memo_budget = Rc::new(CompositionMemoBudget::new(max_retained_bytes));
        Self {
            discovery: Rc::clone(&discovery),
            execution_budget,
            composition_budget,
            max_callers: composition_budget.max_callers_per_procedure,
            attribution: workspace_memo_attribution(workspace),
            memo_budget: Rc::clone(&memo_budget),
            recursive_pending_used: Rc::new(Cell::new(false)),
            nested_execution_incomplete: Rc::new(Cell::new(false)),
            excluded_callers: RefCell::new(Vec::new()),
            ordered: CaptureScopedMemo::new(RefCell::new(
                crate::typestate::ordered::TypestateOrderedRelations::new(
                    workspace,
                    Rc::clone(&discovery),
                    protocol,
                    bindings,
                    subject.id(),
                    Rc::clone(&memo_budget),
                ),
            )),
            protocol,
            subject,
            bindings,
            context,
            local: ReplayingMemo::new(RefCell::new(HashMap::new())),
            dispatches: ReplayingMemo::new(RefCell::new(HashMap::new())),
            formal_entry: None,
            summaries: Rc::new(ReplayingMemo::new(RefCell::new(HashMap::new()))),
            pending_summaries: Rc::new(RefCell::new(HashSet::new())),
        }
    }

    pub fn recursive_pending_used(&self) -> bool {
        self.recursive_pending_used.get()
    }

    pub fn execution_observation<L: crate::taint::compose::ComposeLabels>(
        &self,
        outcome: &crate::taint::compose::SearchOutcome<L>,
    ) -> CompositionExecutionObservation {
        CompositionExecutionObservation {
            search_stopped: outcome.incomplete.iter().any(|reason| {
                matches!(
                    reason,
                    crate::taint::compose::Incompleteness::Cancelled
                        | crate::taint::compose::Incompleteness::Budget(_)
                )
            }),
            nested_summary_stopped: self.nested_execution_incomplete.get(),
            recursive_pending_used: self.recursive_pending_used(),
        }
    }

    fn callee_summary(
        &self,
        callee: &DurableProcedureKey,
        key: TypestateSummaryKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<TypestateSummary, SemanticProviderError> {
        let incomplete = || {
            vec![(
                crate::typestate::TypestateComposeFunction::incomplete(
                    crate::typestate::TypestateUncertainty::IncompleteAnalysis,
                ),
                HopQuality::UNCERTAIN,
            )]
        };
        if !self.pending_summaries.borrow_mut().insert(key.clone()) {
            self.recursive_pending_used.set(true);
            return Ok(TypestateSummary {
                reaches: incomplete(),
                complete: false,
            });
        }
        let result = self.summaries.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, SemanticProviderError> {
                if let Some(entry) = memo.borrow().get(&key).cloned() {
                    return Ok(entry);
                }
                let operational_incomplete = Cell::new(false);
                let recursive_pending_before = Cell::new(false);
                let entry = capture.try_build_weighted(|| {
                    recursive_pending_before.set(self.recursive_pending_used.get());
                    let nested = Self {
                        discovery: Rc::clone(&self.discovery),
                        execution_budget: self.execution_budget.clone(),
                        composition_budget: self.composition_budget,
                        max_callers: self.max_callers,
                        attribution: self.attribution.clone(),
                        memo_budget: Rc::clone(&self.memo_budget),
                        recursive_pending_used: Rc::clone(&self.recursive_pending_used),
                        nested_execution_incomplete: Rc::clone(&self.nested_execution_incomplete),
                        excluded_callers: RefCell::new(Vec::new()),
                        ordered: CaptureScopedMemo::new(RefCell::new(
                            crate::typestate::ordered::TypestateOrderedRelations::new(
                                self.discovery.workspace,
                                Rc::clone(&self.discovery),
                                self.protocol,
                                self.bindings,
                                self.subject.id(),
                                Rc::clone(&self.memo_budget),
                            ),
                        )),
                        protocol: self.protocol,
                        subject: self.subject,
                        bindings: self.bindings,
                        // A formal-entry summary describes its formal's referent, not
                        // a caller object. Never import caller-specific facts here;
                        // a nested step needing them stays Unknown at its handoff.
                        context: crate::typestate::TypestateBindingContext::root(),
                        local: ReplayingMemo::new(RefCell::new(HashMap::new())),
                        dispatches: ReplayingMemo::new(RefCell::new(HashMap::new())),
                        formal_entry: Some((callee.clone(), key.formal.clone())),
                        summaries: Rc::clone(&self.summaries),
                        pending_summaries: Rc::clone(&self.pending_summaries),
                    };
                    let site = match key.exit {
                        CallHandoffExit::Normal => ObjectAnchorSite::NormalExit,
                        CallHandoffExit::Exceptional => ObjectAnchorSite::ExceptionalExit,
                    };
                    let root = ObjectAnchor {
                        procedure: callee.clone(),
                        site,
                        role: ObjectAnchorRole::CurrentObject,
                        object: self.subject.object().clone(),
                    };
                    let outcome = crate::taint::compose::search_object_roots(
                        vec![root],
                        crate::typestate::TypestateComposeLabels::new(self.protocol, self.bindings),
                        &nested,
                        self.composition_budget,
                        request,
                    )
                    .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
                    let quality = HopQuality::from_uncertain(!outcome.incomplete.is_empty());
                    let mut reaches: Vec<_> = outcome
                        .object_reaches
                        .iter()
                        .filter(|reach| !outcome.functions.function(reach.function).is_absent())
                        .map(|reach| {
                            (
                                if quality.proven {
                                    outcome.functions.function(reach.function).clone()
                                } else {
                                    crate::typestate::TypestateComposeFunction::unproven_hop_loss()
                                        .then(outcome.functions.function(reach.function).clone())
                                },
                                reach.quality.conjoin(quality),
                            )
                        })
                        .collect();
                    let complete = outcome.incomplete.is_empty();
                    let stopped_incomplete = outcome.incomplete.iter().any(|reason| {
                        matches!(
                            reason,
                            crate::taint::compose::Incompleteness::Cancelled
                                | crate::taint::compose::Incompleteness::Budget(_)
                        )
                    });
                    operational_incomplete.set(stopped_incomplete);
                    if stopped_incomplete {
                        self.nested_execution_incomplete.set(true);
                    }
                    if reaches.is_empty() && !complete {
                        reaches = incomplete();
                    }
                    let summary = TypestateSummary { reaches, complete };
                    let weight = std::mem::size_of::<TypestateSummary>()
                        + summary.reaches.capacity()
                            * std::mem::size_of::<(
                                crate::typestate::TypestateComposeFunction,
                                HopQuality,
                            )>();
                    Ok::<_, SemanticProviderError>((summary, weight))
                })?;
                let operational_stop = request.stop_observed()
                    || operational_incomplete.get()
                    || self.recursive_pending_used.get()
                    || recursive_pending_before.get();
                if operational_stop {
                    self.nested_execution_incomplete.set(true);
                }
                Ok(admit_composition_entry(
                    memo,
                    &key,
                    entry,
                    &self.memo_budget,
                    operational_stop,
                ))
            },
        );
        self.pending_summaries.borrow_mut().remove(&key);
        Ok((*result?).clone())
    }

    fn resolve_alias_guard(
        &self,
        selected: AliasGuardCall<'_>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<crate::typestate::TypestateGuardResolution, SemanticProviderError> {
        use crate::typestate::TypestateGuardResolution as Resolution;
        let AliasGuardCall {
            guard,
            site: call,
            candidate,
            exit,
            dispatch,
            bindings_outcome,
            bindings,
        } = selected;
        let unresolved = || Resolution::Open(guard.clone());
        if guard.procedure() != &candidate.procedure
            || !crate::typestate::ordered::exact_selected_call_binding(
                dispatch,
                bindings_outcome,
                bindings,
                call,
            )
        {
            return Ok(unresolved());
        }
        let raw = project_call_handoffs(
            call,
            bindings,
            candidate,
            &HashSet::new(),
            CallObjectContinuity::Unknown,
        )
        .map_err(SemanticProviderError::internal)?;
        let actual_for = |formal: &PartialFlowPort| {
            let mut matches = candidate
                .arguments
                .iter()
                .enumerate()
                .filter(|(_, (_, bound))| bound == formal);
            let (index, (actual, _)) = matches.next()?;
            if matches.next().is_some()
                || !raw.iter().any(|handoff| {
                    handoff.argument_index == index
                        && handoff.exit == exit
                        && handoff.continuity == CallObjectContinuity::Reference
                        && handoff.quality.is_certain()
                })
            {
                return None;
            }
            Some(actual.clone())
        };
        let (Some(first), Some(second)) = (actual_for(guard.first()), actual_for(guard.second()))
        else {
            return Ok(unresolved());
        };
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("selected call has a semantic row");
        let (Some(first_value), Some(second_value)) = (
            call_input_value(row, &first),
            call_input_value(row, &second),
        ) else {
            return Ok(unresolved());
        };
        if self.formal_entry.is_some() {
            let (Some(first_ordinal), Some(second_ordinal)) = (
                crate::typestate::ordered::exact_parameter_origin(call.procedure(), first_value),
                crate::typestate::ordered::exact_parameter_origin(call.procedure(), second_value),
            ) else {
                return Ok(unresolved());
            };
            return Ok(if first_ordinal == second_ordinal {
                Resolution::Alias
            } else {
                Resolution::Keep(crate::typestate::TypestateAliasGuard::new(
                    call.procedure().durable_key(),
                    PartialFlowPort::Parameter {
                        ordinal: first_ordinal,
                    },
                    PartialFlowPort::Parameter {
                        ordinal: second_ordinal,
                    },
                ))
            });
        }
        Ok(
            match self.formal_pair_separation(
                AliasGuardCall {
                    guard,
                    site: call,
                    candidate,
                    exit,
                    dispatch,
                    bindings_outcome,
                    bindings,
                },
                request,
            )? {
                PairDecision::Separated(_) => Resolution::NoAlias,
                PairDecision::Alias => Resolution::Alias,
                PairDecision::MayAlias => Resolution::Keep(guard.clone()),
                PairDecision::Unresolved(Some(subject)) => {
                    let open = guard
                        .clone()
                        .with_candidate_member_subject(subject)
                        .with_selected_site(call.durable_key());
                    debug_assert_eq!(open.candidate_member_subject(), Some(self.subject.id()));
                    Resolution::Open(open)
                }
                PairDecision::Unresolved(None) => unresolved(),
            },
        )
    }

    fn formal_pair_separation(
        &self,
        selected: AliasGuardCall<'_>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<PairDecision, SemanticProviderError> {
        let AliasGuardCall {
            guard,
            site: call,
            candidate,
            exit,
            dispatch,
            bindings_outcome,
            bindings,
        } = selected;
        let unresolved = || PairDecision::Unresolved(None);
        if guard.procedure() != &candidate.procedure
            || !crate::typestate::ordered::exact_selected_call_binding(
                dispatch,
                bindings_outcome,
                bindings,
                call,
            )
        {
            return Ok(unresolved());
        }
        let raw = project_call_handoffs(
            call,
            bindings,
            candidate,
            &HashSet::new(),
            CallObjectContinuity::Unknown,
        )
        .map_err(SemanticProviderError::internal)?;
        let actual_for = |formal: &PartialFlowPort| {
            let mut matches = candidate
                .arguments
                .iter()
                .enumerate()
                .filter(|(_, (_, bound))| bound == formal);
            let (index, (actual, _)) = matches.next()?;
            if matches.next().is_some()
                || !raw.iter().any(|handoff| {
                    handoff.argument_index == index
                        && handoff.exit == exit
                        && handoff.continuity == CallObjectContinuity::Reference
                        && handoff.quality.is_certain()
                })
            {
                return None;
            }
            Some(actual.clone())
        };
        let (Some(first), Some(second)) = (actual_for(guard.first()), actual_for(guard.second()))
        else {
            return Ok(unresolved());
        };
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("selected call has a semantic row");
        let (Some(first_value), Some(second_value)) = (
            call_input_value(row, &first),
            call_input_value(row, &second),
        ) else {
            return Ok(unresolved());
        };
        let Some(point) = call.procedure().point_handle(row.point) else {
            return Ok(unresolved());
        };
        let oracle = self.discovery.workspace.semantic_oracle_provider();
        let observe = |value| {
            let value = call.procedure().value_handle(value)?;
            let at = ValueAtPoint::new(
                value.clone(),
                point.clone(),
                ObservationPhase::BeforeEffects,
                bindings.context().clone(),
            )
            .ok()?;
            let path =
                AccessPath::exact(AccessPathRoot::Value(value), Vec::new(), *oracle.limits())
                    .ok()?;
            let access = AccessPathAtPoint::new(
                path,
                point.clone(),
                ObservationPhase::BeforeEffects,
                bindings.context().clone(),
            )
            .ok()?;
            Some((at, access))
        };
        let (Some((first_value, first_path)), Some((second_value, second_path))) =
            (observe(first_value), observe(second_value))
        else {
            return Ok(unresolved());
        };
        let mut member = None;
        for (index, (value, path)) in [(&first_value, &first_path), (&second_value, &second_path)]
            .into_iter()
            .enumerate()
        {
            let pointees = oracle.pointees(value, request)?;
            let Some(objects) = pointees.available_value().map(|result| result.objects()) else {
                return Ok(PairDecision::Unresolved(member));
            };
            if index == 0
                && let Ok(Some(projected)) =
                    crate::analyzer::semantic::workspace_oracle::heap::rehome_object_at_point(
                        self.subject.object().clone(),
                        value,
                    )
                && contains_candidate(
                    &projected,
                    objects
                        .candidates()
                        .iter()
                        .map(|candidate| candidate.value()),
                )
            {
                member = Some(self.subject.id());
            }
            if !pointees.is_complete()
                || !objects.coverage().is_exhaustive()
                || objects.candidates().is_empty()
                || !objects
                    .candidates()
                    .iter()
                    .all(|candidate| candidate.is_proven_complete())
            {
                return Ok(PairDecision::Unresolved(member));
            }
            let locations_outcome = oracle.locations(path, request)?;
            let Some(locations) = locations_outcome
                .available_value()
                .map(|result| result.locations())
            else {
                return Ok(PairDecision::Unresolved(member));
            };
            if !locations_outcome.is_complete()
                || !locations.coverage().is_exhaustive()
                || locations.candidates().is_empty()
                || !locations
                    .candidates()
                    .iter()
                    .all(|candidate| candidate.is_proven_complete())
            {
                return Ok(PairDecision::Unresolved(member));
            }
        }
        let unresolved = || PairDecision::Unresolved(member);
        let alias_query = AliasQuery::new(first_path, second_path)
            .expect("both referent paths use the same call point and context");
        let alias = oracle.alias(&alias_query, request)?;
        let Some(answer) = alias.available_value().map(|result| result.answer()) else {
            return Ok(unresolved());
        };
        if !alias.is_complete() || !answer.is_proven_complete() {
            return Ok(unresolved());
        }
        if *answer.value() == AliasRelation::Disjoint {
            let (
                PartialFlowPort::Parameter {
                    ordinal: tracked_formal,
                },
                PartialFlowPort::Parameter {
                    ordinal: other_formal,
                },
            ) = (guard.first(), guard.second())
            else {
                return Ok(unresolved());
            };
            let mut saw_fresh_start = false;
            for seed in self.bindings.initial_seeds().iter().filter(|seed| {
                seed.subject() == self.subject.id() && seed.site().context() == &self.context
            }) {
                let start = match seed.site() {
                    crate::typestate::TypestateObservationSite::ProgramPoint { point, .. } => {
                        point.clone()
                    }
                    crate::typestate::TypestateObservationSite::CallSite {
                        call: seed_call,
                        ..
                    } => {
                        let Some(seed_row) =
                            seed_call.procedure().semantics().call_site(seed_call.id())
                        else {
                            return Ok(unresolved());
                        };
                        let Some(point) = seed_call.procedure().point_handle(seed_row.point) else {
                            return Ok(unresolved());
                        };
                        point
                    }
                };
                if start.procedure() != call.procedure() {
                    return Ok(unresolved());
                }
                saw_fresh_start = true;
                let Ok(publication_query) = FreshObjectPublicationQuery::new(
                    self.subject.object().clone(),
                    start,
                    point.clone(),
                    bindings.context().clone(),
                ) else {
                    return Ok(unresolved());
                };
                let publications = oracle.fresh_object_publications(&publication_query, request)?;
                let Some(result) = publications.available_value() else {
                    return Ok(unresolved());
                };
                if !publications.is_complete()
                    || result.publications().coverage() != CandidateCoverage::Exhaustive
                    || !result.publications().candidates().is_empty()
                {
                    return Ok(unresolved());
                }
            }
            if !saw_fresh_start {
                return Ok(unresolved());
            }
            let Some(targets) = dispatch.available_value() else {
                return Ok(unresolved());
            };
            let [target] = targets.candidates() else {
                return Ok(unresolved());
            };
            let certificate = oracle.formal_footprint_certificate(
                call,
                target.target(),
                bindings.context(),
                *tracked_formal as usize,
                *other_formal as usize,
                request,
            )?;
            return Ok(match certificate.verdict {
                crate::analyzer::semantic::workspace_oracle::FootprintVerdict::Proven => {
                    PairDecision::Separated(Box::new(FormalPairSeparation {
                        call: call.durable_key(),
                        candidate: candidate.procedure.clone(),
                        context: bindings.context().clone(),
                        first: *tracked_formal,
                        second: *other_formal,
                        subject: self.subject.id(),
                        exits: [CallHandoffExit::Normal, CallHandoffExit::Exceptional],
                    }))
                }
                crate::analyzer::semantic::workspace_oracle::FootprintVerdict::Unknown(_reason) => {
                    unresolved()
                }
            });
        }
        Ok(match answer.value() {
            AliasRelation::Disjoint => unreachable!("disjoint was handled above"),
            AliasRelation::MustAlias => PairDecision::Alias,
            AliasRelation::MayAlias => PairDecision::MayAlias,
        })
    }

    /// The tracked subject's terminal obligations, with no value carrier at
    /// a procedure exit. Keep binding IDs: two obligations may share an
    /// anchor while requiring different final states.
    pub fn terminal_roots(
        &self,
    ) -> Vec<(crate::typestate::TypestateTerminalBindingId, ObjectAnchor)> {
        let mut roots = Vec::new();
        for terminal in self.bindings.terminal_bindings().iter().filter(|terminal| {
            terminal.subject() == self.subject.id() && terminal.site().context() == &self.context
        }) {
            let expectation = self
                .protocol
                .terminal_expectation(terminal.expectation())
                .expect("terminal binding names a compiled expectation");
            let (procedure, site) = match terminal.site() {
                crate::typestate::TypestateObservationSite::ProgramPoint { point, .. } => {
                    let site = match expectation.on() {
                        crate::typestate::ProtocolTerminalObservationSpec::AnalysisRootExit {
                            kind: crate::typestate::ProtocolProcedureExitKind::Normal,
                        } => ObjectAnchorSite::NormalExit,
                        crate::typestate::ProtocolTerminalObservationSpec::AnalysisRootExit {
                            kind: crate::typestate::ProtocolProcedureExitKind::Exceptional,
                        } => ObjectAnchorSite::ExceptionalExit,
                        crate::typestate::ProtocolTerminalObservationSpec::Event { .. } => {
                            ObjectAnchorSite::ProgramPoint(point.id())
                        }
                    };
                    (point.procedure().durable_key(), site)
                }
                crate::typestate::TypestateObservationSite::CallSite { call, .. } => (
                    call.procedure().durable_key(),
                    ObjectAnchorSite::CallSite(call.id()),
                ),
            };
            let anchor = ObjectAnchor {
                procedure,
                site,
                role: typestate_object_role(terminal.role()),
                object: self.subject.object().clone(),
            };
            roots.push((terminal.id(), anchor));
        }
        roots
    }

    /// Project the search's retained object path into the witness format
    /// already used by policy findings. Event steps come from the path's
    /// label fold; call steps come from its retained handoff hops.
    pub fn witness_for_reach(
        &self,
        reach: &crate::taint::compose::ObjectReach<crate::typestate::TypestateComposeFact>,
        outcome: &crate::taint::compose::SearchOutcome<
            crate::typestate::TypestateComposeLabels<'_>,
        >,
        request: &mut SemanticRequest<'_>,
    ) -> Result<crate::dataflow::SummaryWitness, SemanticProviderError> {
        use crate::analyzer::semantic::{ControlEdgeKind, IcfgEdgeKind};
        use crate::dataflow::{SummaryWitnessStepKind, WitnessReconstructionWork};
        let seed = reach
            .source
            .seed_point
            .clone()
            .expect("a typestate source has a seed point");
        let mut steps = vec![crate::taint::compose::composed_witness_step(
            SummaryWitnessStepKind::Seed,
            seed,
            None,
            crate::taint::compose::HopQuality::CERTAIN,
        )];
        for (hop, observation) in reach
            .hops
            .iter()
            .zip(crate::typestate::fold_object_reach(reach, outcome))
        {
            for event in observation.events {
                let binding = self
                    .bindings
                    .event_binding(event.binding)
                    .expect("retained label names a compiled event binding");
                let (point, origin) = match binding.site() {
                    crate::typestate::TypestateObservationSite::ProgramPoint { point, .. } => {
                        (point.clone(), None)
                    }
                    crate::typestate::TypestateObservationSite::CallSite { call, .. } => {
                        let site = call
                            .procedure()
                            .semantics()
                            .call_site(call.id())
                            .expect("a bound call belongs to its procedure");
                        (
                            call.procedure()
                                .point_handle(site.point)
                                .expect("a bound call point belongs to its procedure"),
                            Some(call.clone()),
                        )
                    }
                };
                steps.push(crate::taint::compose::composed_witness_step(
                    SummaryWitnessStepKind::Edge(IcfgEdgeKind::Intraprocedural(
                        ControlEdgeKind::Normal,
                    )),
                    point,
                    origin,
                    observation.quality,
                ));
            }
            if let crate::taint::compose::Hop::CallHandoff { call, exit, .. } = hop {
                let handle = self.discovery.locator_procedure(&call.0, request)?;
                let site = handle
                    .semantics()
                    .call_site(call.1)
                    .expect("a retained call belongs to its procedure");
                let point = handle
                    .point_handle(site.point)
                    .expect("a retained call point belongs to its procedure");
                let origin = handle
                    .resolve_durable_call(call)
                    .map_err(|error| self.discovery.refuse_locator(error))?
                    .expect("a retained call belongs to its procedure");
                let return_kind = match exit {
                    CallHandoffExit::Normal => IcfgEdgeKind::NormalReturn,
                    CallHandoffExit::Exceptional => IcfgEdgeKind::ExceptionalReturn,
                };
                for kind in [IcfgEdgeKind::Call, return_kind] {
                    steps.push(crate::taint::compose::composed_witness_step(
                        SummaryWitnessStepKind::Edge(kind),
                        point.clone(),
                        Some(origin.clone()),
                        hop.quality(),
                    ));
                }
            }
        }
        let emitted = steps.len();
        let retained_bytes = std::mem::size_of::<crate::dataflow::SummaryWitness>()
            .saturating_add(std::mem::size_of_val(steps.as_slice()));
        Ok(crate::dataflow::SummaryWitness::from_parts(
            steps,
            crate::taint::compose::composed_path_quality(reach.quality),
            None,
            0,
            false,
            retained_bytes,
            WitnessReconstructionWork::new(0, emitted),
        ))
    }

    fn locate_admitted_relations(
        &self,
        path: &mut crate::typestate::ComposedTerminalPath,
        subject: crate::typestate::TypestateSubjectId,
        definitive: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), SemanticProviderError> {
        if !path.admitted(subject, definitive) {
            return Ok(());
        }
        let mut sites = Vec::new();
        for event in path.first_unproven.iter() {
            let crate::typestate::FirstUnprovenEvent::Relation(relation) = event else {
                continue;
            };
            if relation.subject() != subject
                || sites
                    .iter()
                    .filter(|(kind, _)| kind == &relation.kind())
                    .count()
                    >= crate::typestate::MAX_TYPESTATE_WITNESSES_PER_FINDING
            {
                continue;
            }
            let key = relation.site();
            let procedure = self.discovery.locator_procedure(&key.0, request)?;
            let call = procedure
                .resolve_durable_call(key)
                .map_err(|error| self.discovery.refuse_locator(error))?
                .expect("retained relation names a call");
            let site = call
                .locator()
                .expect("retained relation call has source mapping")
                .clone();
            let entry = (relation.kind(), site);
            if !sites.contains(&entry) {
                sites.push(entry);
            }
        }
        path.relation_sites = sites.into_boxed_slice();
        Ok(())
    }

    /// Collect event and terminal findings from one selected subject's object search.
    pub fn composed_findings(
        &self,
        outcome: &crate::taint::compose::SearchOutcome<
            crate::typestate::TypestateComposeLabels<'_>,
        >,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(Vec<crate::typestate::TypestateFinding>, bool), SemanticProviderError> {
        let mut findings = Vec::new();
        let mut admission_complete = true;
        for (binding_id, anchor) in self.terminal_roots() {
            let mut paths = Vec::new();
            let mut complete = outcome.incomplete.is_empty();
            for reach in outcome
                .object_reaches
                .iter()
                .filter(|reach| reach.root == anchor)
            {
                complete &= reach.quality.is_certain();
                let reached = outcome
                    .functions
                    .labels()
                    .apply_with_grouped_first_unproven(
                        outcome.functions.function(reach.function),
                        &reach.source.fact,
                    );
                let witness = self.witness_for_reach(reach, outcome, request)?;
                paths.extend(reached.into_iter().map(|(fact, first_unproven)| {
                    crate::typestate::ComposedTerminalPath {
                        fact,
                        first_unproven,
                        quality: reach.quality,
                        witness: witness.clone(),
                        relation_sites: Box::new([]),
                    }
                }));
            }
            let binding = self
                .bindings
                .terminal_binding(binding_id)
                .expect("compiled terminal");
            let binding_definitive = binding.quality().is_definitive()
                && self
                    .bindings
                    .subject(binding.subject())
                    .is_some_and(|subject| subject.quality().is_definitive());
            complete &= paths.iter().all(|path| {
                let state = path
                    .fact
                    .state_observation()
                    .map(|(_, state, _, _)| state)
                    .or_else(|| path.fact.terminal_observation().map(|(_, state)| state));
                let expectation = self
                    .protocol
                    .terminal_expectation(binding.expectation())
                    .expect("compiled expectation");
                state.is_none_or(|state| {
                    expectation.expected_states().binary_search(&state).is_ok()
                        || path.all_admitted(binding.subject(), binding_definitive)
                })
            });
            admission_complete &= complete;
            for path in &mut paths {
                self.locate_admitted_relations(
                    path,
                    binding.subject(),
                    binding_definitive,
                    request,
                )?;
            }
            if let Some(finding) = crate::typestate::composed_terminal_finding(
                self.protocol,
                self.bindings,
                binding_id,
                &paths,
                complete,
            ) {
                findings.push(finding);
            }
        }
        let mut violations: HashMap<
            crate::typestate::TypestateViolation,
            Vec<crate::typestate::ComposedTerminalPath>,
        > = HashMap::new();
        let mut non_violations = HashSet::new();
        for reach in &outcome.object_reaches {
            let reached = outcome
                .functions
                .labels()
                .apply_with_grouped_first_unproven(
                    outcome.functions.function(reach.function),
                    &reach.source.fact,
                );
            let witness = self.witness_for_reach(reach, outcome, request)?;
            for (fact, first_unproven) in reached {
                if let Some(violation) = fact.violation() {
                    violations.entry(violation).or_default().push(
                        crate::typestate::ComposedTerminalPath {
                            fact,
                            first_unproven,
                            quality: reach.quality,
                            witness: witness.clone(),
                            relation_sites: Box::new([]),
                        },
                    );
                }
                if let Some(binding) = fact.non_violation_binding() {
                    non_violations.insert(binding);
                }
            }
        }
        let competing_bindings = violations
            .keys()
            .map(|violation| violation.event_binding())
            .collect::<Vec<_>>();
        for (violation, mut paths) in violations {
            let binding = self
                .bindings
                .event_binding(violation.event_binding())
                .expect("compiled event");
            let definitive = binding.quality().is_definitive()
                && self
                    .bindings
                    .subject(binding.subject())
                    .is_some_and(|subject| subject.quality().is_definitive());
            for path in &mut paths {
                self.locate_admitted_relations(path, binding.subject(), definitive, request)?;
            }
            let has_competing = non_violations.contains(&violation.event_binding())
                || competing_bindings
                    .iter()
                    .filter(|binding| **binding == violation.event_binding())
                    .count()
                    > 1;
            let binding = self
                .bindings
                .event_binding(violation.event_binding())
                .expect("compiled event");
            let binding_definitive = binding.quality().is_definitive()
                && self
                    .bindings
                    .subject(binding.subject())
                    .is_some_and(|subject| subject.quality().is_definitive());
            let complete = outcome.incomplete.is_empty()
                && paths.iter().all(|path| {
                    path.quality.is_certain()
                        && path.all_admitted(binding.subject(), binding_definitive)
                });
            admission_complete &= complete;
            if let Some(finding) = crate::typestate::composed_error_finding(
                self.protocol,
                self.bindings,
                violation,
                &paths,
                complete,
                has_competing,
            ) {
                findings.push(finding);
            }
        }
        findings
            .sort_by(|left, right| (left.site(), left.kind()).cmp(&(right.site(), right.kind())));
        Ok((findings, admission_complete))
    }
}

impl CallModelSource for TypestateCompositionProvider<'_> {
    type Error = SemanticProviderError;
    type Function = crate::typestate::TypestateComposeFunction;

    fn dispatch_model(
        &self,
        call: &CallSiteHandle,
        answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<CallModelDecision<Self::Function>, Self::Error> {
        TypestateCallModels.dispatch_model(call, answer)
    }

    fn covers_caller_candidate(
        &self,
        call: &CallSiteHandle,
        answer: &SemanticOutcome<DispatchResult>,
    ) -> Result<bool, Self::Error> {
        TypestateCallModels.covers_caller_candidate(call, answer)
    }
}

impl LocalOpennessClient<WorkspaceCompositionDiscovery<'_>> for TypestateCompositionProvider<'_> {
    fn relations_head(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, SemanticProviderError> {
        crate::taint::compose::CompositionProvider::partial_flows(self, procedure, request)
    }

    fn openness_sweep(
        &self,
        handle: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureOpenness, SemanticProviderError> {
        openness_sweep(
            self.discovery.as_ref(),
            handle,
            &self.execution_budget,
            request,
        )
    }

    fn dispatch_completeness(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Completeness, SemanticProviderError> {
        Ok(
            crate::taint::compose::CompositionProvider::dispatch(self, call, request)?
                .0
                .completeness,
        )
    }
}

impl crate::taint::compose::CompositionProvider for TypestateCompositionProvider<'_> {
    type Error = SemanticProviderError;
    type Fact = crate::typestate::TypestateComposeFact;
    type Function = crate::typestate::TypestateComposeFunction;

    fn acquisition_refusal(
        &self,
        error: &Self::Error,
    ) -> Option<crate::analyzer::semantic::CandidateLocatorRefusal> {
        self.discovery.locator_refusal(error)
    }

    fn object_relation(
        &self,
        procedure: &DurableProcedureKey,
        at: &crate::taint::compose::Endpoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ObjectRelation<Self::Fact, Self::Function>, Self::Error> {
        let mut relation = ObjectRelation::none();
        if let crate::taint::compose::Endpoint::Object(anchor) = at
            && (&anchor.procedure != procedure || &anchor.object != self.subject.object())
        {
            return Ok(relation);
        }
        if let (
            AccessPathRoot::CallResult(origin),
            crate::taint::compose::Endpoint::Port(PartialFlowPort::CallThrown { call }),
        ) = (self.subject.object().identity(), at)
            && origin.call().procedure().durable_key() == *procedure
            && origin.call().id() == *call
        {
            // The acquired object exists only on this call's normal arm.
            // Its exceptional arm has neither an object source nor a handoff.
            relation.cross_call = false;
            return Ok(relation);
        }
        let handle = self.discovery.selected_procedure(procedure, request)?;
        relation.complete = self
            .discovery
            .workspace
            .has_complete_semantic_ir_rows(handle.artifact().key())?;
        if let Some((callee, formal)) = &self.formal_entry
            && callee == procedure
        {
            let predecessor = crate::taint::compose::Endpoint::Port(formal.clone());
            if &predecessor == at {
                relation.sources.push(ExecutionSource {
                    identity: self
                        .subject
                        .key()
                        .public_canonical_rendering()
                        .into_boxed_str(),
                    fact: crate::typestate::TypestateComposeFact::formal_entry(
                        self.bindings,
                        self.subject.id(),
                        self.protocol.initial_state(),
                    ),
                    provenance: format!("typestate formal entry {formal:?}").into(),
                    seed_point: Some(
                        handle
                            .point_handle(handle.semantics().entry_point())
                            .expect("a formal entry belongs to its procedure"),
                    ),
                });
            } else if let Some((function, quality)) =
                self.ordered.read(&self.attribution.capability(), |memo| {
                    memo.borrow_mut().object_segment(
                        &handle,
                        &self.context,
                        self.formal_entry.as_ref().map(|(_, port)| port),
                        (&predecessor, at),
                        None,
                        request,
                    )
                })?
            {
                relation.predecessors.push(ObjectPredecessor {
                    from: predecessor,
                    function,
                    quality,
                });
            }
        }
        for seed in self.bindings.initial_seeds().iter().filter(|seed| {
            self.formal_entry.is_none()
                && seed.subject() == self.subject.id()
                && seed.site().context() == &self.context
        }) {
            let (site, seed_procedure) = match seed.site() {
                crate::typestate::TypestateObservationSite::ProgramPoint { point, .. } => (
                    ObjectAnchorSite::ProgramPoint(point.id()),
                    point.procedure().durable_key(),
                ),
                crate::typestate::TypestateObservationSite::CallSite { call, .. } => (
                    ObjectAnchorSite::CallSite(call.id()),
                    call.procedure().durable_key(),
                ),
            };
            if &seed_procedure != procedure {
                continue;
            }
            // Conditional seeds are attached to the control edge's source;
            // the ordered relation enters only through that exact edge.
            let site = seed.activation_edge().map_or(site, |edge| {
                let row = edge
                    .procedure()
                    .semantics()
                    .control_edge(edge.id())
                    .expect("validated control-edge activation resolves");
                ObjectAnchorSite::ProgramPoint(row.source_point)
            });
            let predecessor = crate::taint::compose::Endpoint::Object(Box::new(ObjectAnchor {
                procedure: procedure.clone(),
                site,
                role: typestate_object_role(seed.role()),
                object: self.subject.object().clone(),
            }));
            if &predecessor == at {
                relation.sources.push(ExecutionSource {
                    identity: self
                        .subject
                        .key()
                        .public_canonical_rendering()
                        .into_boxed_str(),
                    fact: crate::typestate::TypestateComposeFact::from_initial_seed(
                        self.bindings,
                        seed,
                    ),
                    provenance: format!("typestate initial seed {:?}", seed.site().identity())
                        .into(),
                    // ICFG starts its typestate witness at the procedure's
                    // zero-fact seed, not at this bound initial state's site.
                    seed_point: Some(
                        handle
                            .point_handle(handle.semantics().entry_point())
                            .expect("a bound seed procedure has an entry point"),
                    ),
                });
            } else if let Some((function, quality)) =
                self.ordered.read(&self.attribution.capability(), |memo| {
                    memo.borrow_mut().object_segment(
                        &handle,
                        &self.context,
                        self.formal_entry.as_ref().map(|(_, port)| port),
                        (&predecessor, at),
                        seed.activation_edge(),
                        request,
                    )
                })?
            {
                // The initial seed reaches this continuation directly, so
                // the object starts here and has no pre-call state to follow.
                if matches!(
                    at,
                    crate::taint::compose::Endpoint::Port(
                        PartialFlowPort::CallResult { .. } | PartialFlowPort::CallThrown { .. }
                    )
                ) {
                    relation.cross_call = false;
                }
                relation.predecessors.push(ObjectPredecessor {
                    from: predecessor,
                    function,
                    quality,
                });
            }
        }
        for call in handle.semantics().call_sites() {
            for port in [
                (
                    call.normal_continuation.target(),
                    PartialFlowPort::CallResult {
                        call: call.id,
                        ordinal: None,
                    },
                ),
                (
                    call.exceptional_continuation.target(),
                    PartialFlowPort::CallThrown { call: call.id },
                ),
            ] {
                if port.0.is_none() {
                    continue;
                }
                // A seed at the continuation point already observes this
                // call's result. The reverse edge back into that same port
                // would form a zero-length cycle with the seed-to-port edge.
                if matches!(at, crate::taint::compose::Endpoint::Object(anchor)
                    if anchor.site == ObjectAnchorSite::CallSite(call.id)
                        || matches!(anchor.site, ObjectAnchorSite::ProgramPoint(point)
                            if Some(point) == port.0))
                {
                    continue;
                }
                let predecessor = crate::taint::compose::Endpoint::Port(port.1);
                if &predecessor == at {
                    continue;
                }
                if let Some((function, quality)) =
                    self.ordered.read(&self.attribution.capability(), |memo| {
                        memo.borrow_mut().object_segment(
                            &handle,
                            &self.context,
                            self.formal_entry.as_ref().map(|(_, port)| port),
                            (&predecessor, at),
                            None,
                            request,
                        )
                    })?
                {
                    relation.predecessors.push(ObjectPredecessor {
                        from: predecessor,
                        function,
                        quality,
                    });
                }
            }
        }
        Ok(relation)
    }

    fn partial_flows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, Self::Error> {
        let memo_key = self
            .discovery
            .selected_procedure(procedure, request)?
            .exact_identity();
        let flows = self.local.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, SemanticProviderError> {
                if let Some(entry) = memo.borrow().get(&memo_key).cloned() {
                    return Ok(entry);
                }
                let entry = capture.try_build_weighted(|| {
                let selected = self.discovery.selected_procedure_and_flows(procedure, request)?;
                let handle = selected.procedure;
                let mut flows = selected.flows;
                for exit in [
                    PartialFlowPort::NormalReturn,
                    PartialFlowPort::ExceptionalReturn,
                ] {
                    let has_exit = handle.semantics().points().iter().any(|point| {
                        point.events.iter().any(|event| match exit {
                            PartialFlowPort::NormalReturn => matches!(
                                event.effect,
                                crate::analyzer::semantic::SemanticEffect::NormalExit
                            ),
                            PartialFlowPort::ExceptionalReturn => matches!(
                                event.effect,
                                crate::analyzer::semantic::SemanticEffect::ExceptionalExit
                            ),
                            _ => unreachable!("the exit list contains only procedure exits"),
                        })
                    });
                    if has_exit && !flows.ports.contains(&exit) {
                        flows.ports.push(exit);
                    }
                }
                for call in handle.semantics().call_sites() {
                    for continuation in [
                        (
                            call.normal_continuation.target(),
                            PartialFlowPort::CallResult {
                                call: call.id,
                                ordinal: None,
                            },
                        ),
                        (
                            call.exceptional_continuation.target(),
                            PartialFlowPort::CallThrown { call: call.id },
                        ),
                    ] {
                        if continuation.0.is_none() {
                            continue;
                        }
                        let source = if let Some(index) =
                            flows.ports.iter().position(|port| port == &continuation.1)
                        {
                            crate::analyzer::semantic::partial_flow::ports::PortId::try_from_index(index)
                                .expect("a procedure's port count fits u32")
                        } else {
                            let id =
                                crate::analyzer::semantic::partial_flow::ports::PortId::try_from_index(
                                    flows.ports.len(),
                                )
                                .expect("a procedure's port count fits u32");
                            flows.ports.push(continuation.1.clone());
                            id
                        };
                        let targets: Vec<_> = flows
                            .ports
                            .iter()
                            .enumerate()
                            .filter(|(_, port)| {
                                matches!(
                                    port,
                                    PartialFlowPort::CallReceiver { .. }
                                        | PartialFlowPort::CallArgument { .. }
                                        | PartialFlowPort::NormalReturn
                                        | PartialFlowPort::ExceptionalReturn
                                )
                            })
                            .map(|(index, port)| (index, port.clone()))
                            .collect();
                        for (index, target) in targets {
                            if self.ordered.read(&self.attribution.capability(), |memo| {
                                memo.borrow_mut()
                                    .locally_reaches(&handle, &continuation.1, &target)
                            })? {
                                let target_exact = match &target {
                                    PartialFlowPort::CallReceiver { call }
                                    | PartialFlowPort::CallArgument { call, .. } => {
                                        let site = handle
                                            .semantics()
                                            .call_site(*call)
                                            .expect("a call port names its procedure's call");
                                        let value = call_input_value(site, &target)
                                            .expect("a call input has a value");
                                        let query = ValueAtPoint::new(
                                            handle
                                                .value_handle(value)
                                                .expect("a call value belongs to its procedure"),
                                            handle
                                                .point_handle(site.point)
                                                .expect("a call point belongs to its procedure"),
                                            ObservationPhase::BeforeEffects,
                                            self.context.runtime().clone(),
                                        )
                                        .map_err(|error| {
                                            SemanticProviderError::internal(error.to_string())
                                        })?;
                                        let outcome = self
                                            .discovery
                                            .workspace
                                            .semantic_oracle_provider()
                                            .pointees(&query, request)?;
                                        outcome.is_complete() && outcome.available_value().is_some_and(|points| {
                                            points.objects().coverage().is_exhaustive()
                                                && matches!(points.objects().candidates(), [object]
                                                    if object.is_proven_complete() && object.value() == self.subject.object())
                                        }) && self.subject.quality().is_definitive()
                                    }
                                    PartialFlowPort::NormalReturn | PartialFlowPort::ExceptionalReturn => {
                                        true
                                    }
                                    _ => false,
                                };
                                let target =
                                    crate::analyzer::semantic::partial_flow::ports::PortId::try_from_index(
                                        index,
                                    )
                                    .expect("a procedure's port count fits u32");
                                flows
                                    .flows
                                    .push(crate::analyzer::semantic::partial_flow::PartialFlow {
                                        from: source,
                                        to: target,
                                        uncertain: !target_exact,
                                        crossed: vec![Vec::new().into_boxed_slice()].into_boxed_slice(),
                                    });
                            }
                        }
                    }
                }
                    let weight = partial_flows_weight(&flows);
                    Ok::<_, SemanticProviderError>((Arc::new(flows), weight))
                })?;
                let operational_stop = request.stop_observed()
                    || entry.value().outcome == PartialFlowOutcome::ExceededBudget;
                Ok(admit_composition_entry(
                    memo, &memo_key, entry, &self.memo_budget, operational_stop,
                ))
            },
        )?;
        Ok(Arc::clone(&flows))
    }

    fn interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        _seeds: &[InteriorSeed],
        _observations: &[InteriorObservation],
        _witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, Self::Error> {
        let handle = self.discovery.selected_procedure(procedure, request)?;
        Ok(incomplete_interior(
            handle,
            "object roots use ordered semantic IR, not value-flow interior",
        ))
    }

    fn dispatch(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(Dispatch, Option<CallModel<Self::Function>>), Self::Error> {
        let memo_key = (
            self.discovery
                .locator_procedure(&call.0, request)?
                .exact_identity(),
            call.1,
        );
        let answer = self.dispatches.read(
            &self.attribution.capability(),
            |memo, capture| -> Result<_, SemanticProviderError> {
                if let Some(entry) = memo.borrow().get(&memo_key).cloned() {
                    return Ok(entry);
                }
                let entry = capture.try_build_weighted(|| {
                    let raw = self.discovery.dispatch(call, request)?;
                    let answer =
                        dispatch_from_structure(self.discovery.as_ref(), self, raw, request)?
                            .dispatch;
                    let weight = dispatch_weight(&answer);
                    Ok::<_, SemanticProviderError>((answer, weight))
                })?;
                Ok(admit_composition_entry(
                    memo,
                    &memo_key,
                    entry,
                    &self.memo_budget,
                    request.stop_observed(),
                ))
            },
        )?;
        // Typestate composition replaces no call with a model.
        Ok(((*answer).clone(), None))
    }

    fn callers(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Callers, Self::Error> {
        CallStructureProvider::callers(
            self.discovery.as_ref(),
            |call, answer| CallModelSource::covers_caller_candidate(self, call, answer),
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
        CallStructureProvider::lexical_parent(self.discovery.as_ref(), procedure, request)
    }

    fn certified_object_origin(
        &self,
        root: &ObjectAnchor,
        call: &DurableCallSiteKey,
        port: &PartialFlowPort,
        gap: &ExternalBodyUnavailableGap,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<()>, Self::Error> {
        use crate::analyzer::semantic::{
            AbstractObjectIdentity, EvidenceCompleteness, ObjectCardinality,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::CompiledSummaryOutput;

        let PartialFlowPort::CallResult {
            call: port_call,
            ordinal,
        } = port
        else {
            return Ok(None);
        };
        if *port_call != call.1
            || root.procedure != call.0
            || root.object != *self.subject.object()
            || root.object.cardinality() != ObjectCardinality::Unknown
            || self.context.runtime().was_truncated()
            || request.stop_observed()
        {
            return Ok(None);
        }
        let AbstractObjectIdentity::Value(object_value) = root.object.identity() else {
            return Ok(None);
        };
        let handle = self.discovery.locator_procedure(&call.0, request)?;
        let Some(call_handle) = handle
            .resolve_durable_call(call)
            .map_err(|error| self.discovery.refuse_locator(error))?
        else {
            return Ok(None);
        };
        let Some(row) = handle.semantics().call_site(call.1) else {
            return Ok(None);
        };
        let ControlContinuation::Target(normal_point) = row.normal_continuation else {
            return Ok(None);
        };
        // The source must be this call's actual normal continuation seed.
        if !self.bindings.initial_seeds().iter().any(|seed| {
            seed.subject() == self.subject.id()
                && seed.site().context() == &self.context
                && matches!(seed.site(), crate::typestate::TypestateObservationSite::ProgramPoint { point, .. }
                    if point.procedure().durable_key() == call.0 && point.id() == normal_point)
        }) {
            return Ok(None);
        }
        let Some(result_id) = row
            .normal_result_values()
            .nth(ordinal.unwrap_or(0) as usize)
        else {
            return Ok(None);
        };
        if object_value.procedure().durable_key() != call.0 || object_value.id() != result_id {
            return Ok(None);
        }
        let Some(result) = handle.value_handle(result_id) else {
            return Ok(None);
        };
        let Some(origin) = self.discovery.modeled_fresh_call_result_origin(
            &call_handle,
            &result,
            self.context.runtime(),
            request,
        )?
        else {
            return Ok(None);
        };
        if !origin.proves_complete_fresh_result()
            || origin.call != call_handle
            || origin.result != result
            || origin.caller_context != *self.context.runtime()
            || !gap.matches_origin_target(&origin.target)
            || ordinal.unwrap_or(0) != origin.ordinal
            || !origin.dispatch.is_complete()
        {
            return Ok(None);
        }
        let Some(raw) = origin.dispatch.available_value() else {
            return Ok(None);
        };
        if raw.coverage() != CandidateCoverage::Exhaustive {
            return Ok(None);
        }
        let [boundary] = raw.boundaries() else {
            return Ok(None);
        };
        if boundary.proof != ProofStatus::Proven
            || !matches!(boundary.completeness, EvidenceCompleteness::Partial(_))
            || boundary.partial_cause
                != Some(crate::analyzer::semantic::DispatchBoundaryPartialCause::ExternalBodyUnavailable)
            || boundary.unmaterialized_external_target() != Some(&gap.target)
        {
            return Ok(None);
        }
        let summary = &origin.summary.record;
        if !summary.ordinary_heap_unchanged
            || !summary.no_concurrency_effects
            || summary.normal_continuation_absent
            || !summary.concurrency_effects.is_empty()
            || !summary.returned_callables.is_empty()
            || !summary.conditional_indirect_writes.is_empty()
            || summary
                .transfers
                .iter()
                .any(|transfer| match &transfer.output {
                    CompiledSummaryOutput::NormalReturn { .. } => origin.ordinal == 0,
                    CompiledSummaryOutput::IndexedNormalReturn { ordinal, .. } => {
                        *ordinal == origin.ordinal
                    }
                    CompiledSummaryOutput::Heap { .. }
                    | CompiledSummaryOutput::Capture { .. }
                    | CompiledSummaryOutput::Receiver { .. } => true,
                    CompiledSummaryOutput::ExceptionalReturn { .. } => false,
                })
        {
            return Ok(None);
        }
        Ok(Some(()))
    }

    fn unmodeled_call_behavior(&self) -> crate::dataflow::UnmodeledCallBehavior {
        crate::dataflow::UnmodeledCallBehavior::RequireModel
    }

    fn fallback_ports(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<FallbackPorts, Self::Error> {
        let handle = self.discovery.locator_procedure(&call.0, request)?;
        let site = handle
            .semantics()
            .call_site(call.1)
            .expect("a selected call belongs to its procedure");
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
        decide_openness(self.discovery.as_ref(), self, procedure, request)
    }

    fn endpoints(
        &self,
        _procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureEndpoints<Self::Fact, Self::Function>, Self::Error> {
        Ok(ProcedureEndpoints::none())
    }

    fn source_evidence(
        &self,
        _source: &crate::taint::compose::BoundSource<Self::Fact>,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<HopQuality, Self::Error> {
        Ok(HopQuality::CERTAIN)
    }

    fn may_share_call_storage(
        &self,
        _procedure: &ProcedureHandle,
        _call: CallSiteId,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn local_function(
        &self,
        procedure: &DurableProcedureKey,
        from: &crate::taint::compose::Endpoint,
        to: &crate::taint::compose::Endpoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<(Self::Function, HopQuality)>, Self::Error> {
        let (
            crate::taint::compose::Endpoint::Port(from),
            crate::taint::compose::Endpoint::Port(to),
        ) = (from, to)
        else {
            return Ok(None);
        };
        let handle = self.discovery.selected_procedure(procedure, request)?;
        self.ordered
            .read(&self.attribution.capability(), |memo| {
                memo.borrow_mut()
                    .between_ports(&handle, &self.context, from, to, request)
            })
            .map(Some)
    }

    fn unproven_object_continuations(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<crate::taint::compose::ObjectPredecessor<Self::Function>>, Self::Error> {
        let procedure = self.discovery.locator_procedure(&call.0, request)?;
        let site = procedure
            .semantics()
            .call_sites()
            .iter()
            .find(|site| site.id == call.1)
            .expect("call belongs to procedure");
        let call_handle = procedure
            .resolve_durable_call(call)
            .map_err(|error| self.discovery.refuse_locator(error))?
            .expect("call belongs to procedure");
        let answer = self.discovery.resolve_call(&call_handle, request)?;
        let conversion =
            self.discovery
                .call_conversion_may_run_user_code(&call_handle, &answer, request)?;
        // The check charges discovery work even on memo hits, so an
        // interrupted check must stop the search, as the dispatch projection
        // does, rather than read as "no conversion" and drop this path.
        self.discovery
            .require_outcome(&conversion, "argument conversion effects")?;
        let conversion_open = conversion.available_value().copied().unwrap_or(true);
        let unresolved = answer
            .available_value()
            .is_none_or(|dispatch| dispatch.candidates().is_empty());
        if !conversion_open && !unresolved {
            return Ok(Vec::new());
        }
        let mut continuations = Vec::new();
        for (ordinal, argument) in site.arguments.iter().enumerate() {
            let (exact, _) = crate::typestate::ordered::call_actual_continuity(
                self.discovery.workspace(),
                crate::typestate::ordered::MoveBindingQuery {
                    discovery: self.discovery.as_ref(),
                    procedure: &procedure,
                    call: site,
                    context: self.context.runtime(),
                    subject: self.subject,
                    tracked_formal: self.formal_entry.as_ref().map(|(_, port)| port),
                    actual: argument.value,
                },
                request,
            )?;
            if exact {
                let port = PartialFlowPort::CallArgument {
                    call: call.1,
                    ordinal: u32::try_from(ordinal).expect("argument ordinal fits u32"),
                };
                let continuation = PartialFlowPort::CallResult {
                    call: call.1,
                    ordinal: None,
                };
                let relation = if conversion_open && !unresolved {
                    crate::typestate::FirstUnprovenRelation::UnprovenConversion {
                        call: Box::new(call.clone()),
                        argument: port.clone(),
                        continuation,
                        subject: self.subject.id(),
                    }
                } else {
                    crate::typestate::FirstUnprovenRelation::UnresolvedCall {
                        call: Box::new(call.clone()),
                        argument: port.clone(),
                        continuation,
                        subject: self.subject.id(),
                    }
                };
                continuations.push(crate::taint::compose::ObjectPredecessor {
                    from: crate::taint::compose::Endpoint::Port(port),
                    function: crate::typestate::TypestateComposeFunction::first_unproven(relation),
                    quality: HopQuality::UNCERTAIN,
                });
            }
        }
        Ok(continuations)
    }

    fn call_handoffs(
        &self,
        call: &DurableCallSiteKey,
        candidate: &ComposeCandidate,
        exit: CallHandoffExit,
        request: &mut SemanticRequest<'_>,
    ) -> Result<CallHandoffInventory<Self::Function>, Self::Error> {
        let handle = self.discovery.locator_procedure(&call.0, request)?;
        let site = handle
            .resolve_durable_call(call)
            .map_err(|error| self.discovery.refuse_locator(error))?
            .expect("a selected call belongs to its procedure");
        let answer = self.discovery.resolve_call(&site, request)?;
        let Some(target) = answer.available_value().and_then(|dispatch| {
            dispatch
                .candidates()
                .iter()
                .find(|target| target.target().durable_key() == candidate.procedure)
        }) else {
            return Ok(CallHandoffInventory {
                handoffs: Vec::new(),
                complete: false,
            });
        };
        let bindings_outcome =
            self.discovery
                .call_bindings(&site, target, self.context.runtime(), request)?;
        let Some(bindings) = bindings_outcome.available_value() else {
            return Ok(CallHandoffInventory {
                handoffs: Vec::new(),
                complete: false,
            });
        };
        let handoffs = self.ordered.read(&self.attribution.capability(), |memo| {
            memo.borrow_mut().handoffs(
                crate::typestate::ordered::OrderedHandoffQuery {
                    call: &site,
                    dispatch: &answer,
                    bindings,
                    candidate,
                    subject: self.subject,
                    exit,
                    tracked_formal: self.formal_entry.as_ref().map(|(key, port)| (key, port)),
                },
                request,
            )
        })?;
        let mut composed = Vec::new();
        let mut complete =
            bindings_outcome.is_complete() && bindings.coverage() == CandidateCoverage::Exhaustive;
        let mut separations = HashSet::new();
        if self.formal_entry.is_none() {
            for first in &handoffs {
                let crate::typestate::CallSubjectMapping::Associated(association) = &first.mapping
                else {
                    continue;
                };
                let first_formal = &candidate.arguments[first.handoff.binding.argument_index].1;
                let PartialFlowPort::Parameter {
                    ordinal: first_ordinal,
                } = first_formal
                else {
                    continue;
                };
                if !association.identifies(
                    call,
                    &candidate.procedure,
                    bindings.context(),
                    self.subject.id(),
                    first_formal,
                ) || first.handoff.binding.exit != exit
                {
                    continue;
                }
                for second in &handoffs {
                    let (crate::typestate::CallSubjectMapping::SubjectUnproven(port)
                    | crate::typestate::CallSubjectMapping::SeparationCandidate(port)) =
                        &second.mapping
                    else {
                        continue;
                    };
                    let second_formal =
                        &candidate.arguments[second.handoff.binding.argument_index].1;
                    let PartialFlowPort::Parameter {
                        ordinal: second_ordinal,
                    } = second_formal
                    else {
                        continue;
                    };
                    if first_ordinal == second_ordinal
                        || !second.discharge_eligible
                        || second.handoff.binding.exit != exit
                        || !port.identifies(
                            call,
                            &candidate.procedure,
                            bindings.context(),
                            second_formal,
                        )
                        || !port.same_observation(association)
                    {
                        continue;
                    }
                    let guard = crate::typestate::TypestateAliasGuard::new(
                        candidate.procedure.clone(),
                        first_formal.clone(),
                        second_formal.clone(),
                    );
                    let PairDecision::Separated(proof) = self.formal_pair_separation(
                        AliasGuardCall {
                            guard: &guard,
                            site: &site,
                            candidate,
                            exit,
                            dispatch: &answer,
                            bindings_outcome: &bindings_outcome,
                            bindings,
                        },
                        request,
                    )?
                    else {
                        continue;
                    };
                    if proof.call == *call
                        && proof.candidate == candidate.procedure
                        && proof.context == *bindings.context()
                        && proof.first == *first_ordinal
                        && proof.second == *second_ordinal
                        && proof.subject == self.subject.id()
                        && proof.exits.contains(&exit)
                    {
                        separations.insert(second.handoff.binding.argument_index);
                    }
                }
            }
        }
        for ordered in handoffs {
            // The tracked object is F1's exact referent; F1 and F2 are disjoint
            // before effects; it was never published; the footprint excludes
            // F2-rooted effects on F1. It cannot enter F2 at this exit.
            if matches!(
                ordered.mapping,
                crate::typestate::CallSubjectMapping::SubjectUnproven(_)
                    | crate::typestate::CallSubjectMapping::SeparationCandidate(_)
            ) && separations.contains(&ordered.handoff.binding.argument_index)
            {
                continue;
            }
            let conditional_guard = if let (
                Some((
                    procedure,
                    first @ PartialFlowPort::Parameter {
                        ordinal: first_ordinal,
                    },
                )),
                crate::typestate::CallSubjectMapping::SubjectUnproven(port)
                | crate::typestate::CallSubjectMapping::SeparationCandidate(port),
            ) = (&self.formal_entry, &ordered.mapping)
                && ordered.discharge_eligible
                && ordered.handoff.binding.exit == exit
                && port.subject() == self.subject.id()
            {
                let index = ordered.handoff.binding.argument_index;
                let formal = &candidate.arguments[index].1;
                let row = site
                    .procedure()
                    .semantics()
                    .call_site(site.id())
                    .expect("selected call has a semantic row");
                let second = if row.receiver.is_none()
                    && port.identifies(call, &candidate.procedure, bindings.context(), formal)
                    && let (Some(argument), Some(actual)) = (
                        row.arguments.get(index),
                        call_input_value(row, &candidate.arguments[index].0),
                    )
                    && argument.value == actual
                {
                    let language = site.procedure().artifact().key().language().language();
                    match crate::analyzer::languages::language_support_for_hook(
                        language,
                        "direct_formal_referent_at_call",
                    ) {
                        Some(support) => support.direct_formal_referent_at_call(
                            self.discovery.workspace,
                            site.procedure(),
                            row,
                            u32::try_from(index).expect("argument index fits u32"),
                            request,
                        )?,
                        None => None,
                    }
                } else {
                    None
                };
                second
                    .filter(|second| second != first_ordinal)
                    .map(|second| {
                        // This formal-i summary is composed only after the caller's
                        // associated F1 handoff; the guard asks whether formal j
                        // reaches that same referent at this selected call.
                        crate::typestate::TypestateAliasGuard::new(
                            procedure.clone(),
                            first.clone(),
                            PartialFlowPort::Parameter { ordinal: second },
                        )
                    })
            } else {
                None
            };
            let handoff = ordered.handoff;
            let formal = &candidate.arguments[handoff.binding.argument_index].1;
            let key = TypestateSummaryKey {
                callee: self
                    .discovery
                    .selected_procedure(&candidate.procedure, request)?
                    .exact_identity(),
                formal: formal.clone(),
                exit,
            };
            let summary = self.callee_summary(&candidate.procedure, key, request)?;
            complete &= summary.complete;
            for (function, quality) in summary.reaches {
                let function = function.try_rewrite_guards(|guard| {
                    self.resolve_alias_guard(
                        AliasGuardCall {
                            guard,
                            site: &site,
                            candidate,
                            exit,
                            dispatch: &answer,
                            bindings_outcome: &bindings_outcome,
                            bindings,
                        },
                        request,
                    )
                })?;
                if function.is_absent() {
                    continue;
                }
                let mut binding = handoff.binding.clone();
                let mut function = if let Some(guard) = &conditional_guard {
                    // The raw binding was certain; only SubjectUnproven made
                    // the ordered mapping uncertain. Keep callee quality.
                    debug_assert!(ordered.discharge_eligible);
                    debug_assert_eq!(handoff.binding.quality, HopQuality::UNCERTAIN);
                    binding.quality = HopQuality::CERTAIN;
                    let alias_arm = match &ordered.mapping {
                        crate::typestate::CallSubjectMapping::SubjectUnproven(port) => {
                            crate::typestate::TypestateComposeFunction::first_unproven(
                                crate::typestate::FirstUnprovenRelation::handoff(port.clone()),
                            )
                            .then(function)
                        }
                        // No candidate membership: no relation. The evaluator
                        // marks this unresolved alias arm Lost; the facts stay
                        // those of the plain callee function, as before #9658.
                        crate::typestate::CallSubjectMapping::SeparationCandidate(_) => function,
                        _ => unreachable!("conditional guard requires a selected mapping"),
                    };
                    crate::typestate::TypestateComposeFunction::guarded(
                        guard.clone(),
                        crate::typestate::TypestateComposeFunction::absent(),
                        alias_arm,
                    )
                } else {
                    handoff.function.clone().then(function)
                };
                if !quality.proven {
                    function = function
                        .then(crate::typestate::TypestateComposeFunction::unproven_hop_loss());
                }
                if !bindings_outcome.is_complete() {
                    function = crate::typestate::TypestateComposeFunction::unproven_hop_loss()
                        .then(function);
                }
                binding.quality = binding.quality.conjoin(quality);
                if !bindings_outcome.is_complete() {
                    binding.quality = binding.quality.conjoin(HopQuality::UNCERTAIN);
                }
                composed.push(CallHandoff { binding, function });
            }
        }
        Ok(CallHandoffInventory {
            handoffs: composed,
            complete,
        })
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

/// Project independent source-root products through the existing worklist.
/// Ordinary boundary/partial-flow products are neither replaced nor stored by
/// this entry point. Each selected product contains only its certified seed.
#[allow(clippy::too_many_arguments)]
pub fn interior_source_root_products<C: InteriorProjectionClient>(
    client: &C,
    handle: ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    seeds: &[InteriorSeed],
    observations: &[InteriorObservation],
    witnesses: bool,
    edge_kills: &[GuardEdgeKill],
    execution_budget: &SemanticExecutionBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<Vec<InteriorFlows>, C::Error> {
    let partitions =
        crate::value_flow::partition_source_roots(seeds.iter().map(|seed| match seed {
            InteriorSeed::Source { selected_entry, .. } => selected_entry.clone(),
            _ => None,
        }));
    let mut products = Vec::with_capacity(partitions.len());
    for partition in partitions {
        let selected_seeds = partition
            .indices
            .iter()
            .map(|&index| seeds[index].clone())
            .collect::<Vec<_>>();
        let (root, snapshot) = match &partition.entry {
            Some(entry) => {
                let [
                    InteriorSeed::Source {
                        point,
                        phase,
                        carrier,
                        ..
                    },
                ] = selected_seeds.as_slice()
                else {
                    unreachable!("selected products have one source root");
                };
                let root = entry.observation().point().procedure();
                if root.durable_key() != handle.durable_key()
                    || root
                        .point_handle(*point)
                        .is_none_or(|point| !entry.matches_source(&point, *phase, carrier))
                {
                    products.push(incomplete_interior(
                        handle.clone(),
                        "selected entry names another source root",
                    ));
                    continue;
                }
                entry.replay_reads(client.selected_entry_workspace());
                (root.clone(), entry.selected_snapshot())
            }
            None => (handle.clone(), snapshot),
        };
        let mut product = interior_from_snapshot(
            client,
            root,
            snapshot,
            &selected_seeds,
            observations,
            witnesses,
            edge_kills,
            execution_budget,
            request,
        )?;
        for flow in &mut product.flows {
            flow.seed = partition.indices[flow.seed];
        }
        products.push(product);
    }
    Ok(products)
}

/// A legacy caller requesting one aggregate keeps all residual uncertainty.
/// Root-aware callers consume the independent products without merging status.
pub fn merge_interior_source_products(products: Vec<InteriorFlows>) -> InteriorFlows {
    let mut products = products.into_iter();
    let mut answer = products
        .next()
        .expect("source partitioning retains an ordinary empty root");
    for product in products {
        answer.flows.extend(product.flows);
        if !matches!(product.completeness, Completeness::Complete) {
            answer.completeness = product
                .completeness
                .preserving_operational_cause(&answer.completeness);
        }
    }
    answer
}

/// A component explicitly produced by an admitted projected model. Keep its
/// point-local selector evidence; native IR need not contain this component.
/// Search and witness reconstruction use the same construction.
pub(crate) fn projected_return_seed(
    handle: &ProcedureHandle,
    port: &PartialFlowPort,
) -> Option<InteriorSeed> {
    let PartialFlowPort::Heap {
        root,
        selectors,
        tail,
    } = port
    else {
        return None;
    };
    let PartialFlowPort::CallResult { call, ordinal } = root.as_ref() else {
        return None;
    };
    let row = handle.semantics().call_site(*call)?;
    let result = match ordinal {
        None => row.result?,
        Some(ordinal) => row.normal_result(*ordinal as usize)?,
    };
    let ControlContinuation::Target(point) = row.normal_continuation else {
        return None;
    };
    let value = handle.value_handle(result).expect("a call result is live");
    let origin = crate::value_flow::value_location(
        &value,
        crate::analyzer::semantic::OracleLimits::default(),
    )
    .ok()?;
    let location = caller_read_location(handle, &origin, selectors, *tail);
    Some(InteriorSeed::Source {
        point,
        phase: ValueFlowObservationPhase::AfterEffects,
        carrier: ValueFlowCarrier::Location(Box::new(location)),
        selected_entry: None,
    })
}

fn implicit_read_seed_carriers(
    handle: &ProcedureHandle,
    snapshot: &ValueFlowSnapshot,
    extra_seeds: &[ExtraSeed],
    read: &crate::analyzer::semantic::AbstractLocation,
    completeness: &mut Completeness,
) -> Vec<(ValueFlowEndpoint, bool)> {
    let mut seed_carriers = Vec::new();
    for seed in extra_seeds {
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
                .find(|value| ValueFlowEndpoint::for_value(value.clone()) == seed.carrier),
            ValueFlowEndpoint::Location(_) => None,
        };
        let Some(value) = value else {
            continue;
        };
        let seed_origins =
            caller_content_locations(&value, snapshot, ValueFlowPlanLimits::default());
        if !seed_origins.complete {
            *completeness =
                content_incomplete("the storage behind a taint source is not fully known")
                    .preserving_operational_cause(completeness);
        }
        for seed_origin in &seed_origins.locations {
            if exact_location_covers_read(&seed_origin.location, read) {
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
    seed_carriers
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
                ..
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
                    completeness = content_incomplete(
                        "the storage behind a caller-side location's actual is not fully known",
                    )
                    .preserving_operational_cause(&completeness);
                }
                let several = !origins.complete || origins.locations.len() > 1;
                if origins.locations.is_empty() {
                    completeness =
                        content_incomplete("a caller-side member input has no storage origin")
                            .preserving_operational_cause(&completeness);
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
                        let seed_carriers = implicit_read_seed_carriers(
                            &handle,
                            snapshot,
                            &extra_seeds,
                            &read,
                            &mut completeness,
                        );
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
                    let mut carriers = caller_location_carriers(
                        snapshot,
                        &origin.location,
                        &location.selectors,
                        location.tail,
                    );
                    let read = caller_read_location(
                        &handle,
                        &origin.location,
                        &location.selectors,
                        location.tail,
                    );
                    if !read.path().is_exact() {
                        // An authored Element read may have no native snapshot
                        // carrier. Observe that same uncertain location without
                        // manufacturing a source or exact prefix coverage.
                        let endpoint = ValueFlowEndpoint::Location(Box::new(read));
                        carriers.retain(|carrier| carrier != &endpoint);
                        extra_observations.push(ExtraObservation {
                            point: site.point,
                            phase: ExtraPhase::BeforeEffects,
                            carrier: endpoint,
                        });
                        observation_of_extra.push((index, true));
                        completeness = content_incomplete(
                            "a summarized caller-side element observation is uncertain",
                        )
                        .preserving_operational_cause(&completeness);
                    }
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
                                completeness = content_incomplete(
                                    "a caller-side member input has no bound carrier",
                                )
                                .preserving_operational_cause(&completeness);
                            }
                        }
                    }
                    for carrier in carriers {
                        let uncertain = several
                            || !origin.proven_complete
                            || matches!(&carrier, ValueFlowEndpoint::Location(location) if !location.path().is_exact());
                        extra_observations.push(ExtraObservation {
                            point: site.point,
                            phase: ExtraPhase::BeforeEffects,
                            carrier,
                        });
                        observation_of_extra.push((index, uncertain));
                    }
                }
            }
        }
    }
    if client.implicit_heap_reads() {
        let mut known_reads = implicit_reads
            .iter()
            .map(|read| read.location.clone())
            .collect::<HashSet<_>>();
        for selected in &snapshot.payload_projection().replacements {
            for relation in &selected.relations {
                let ValueFlowEndpoint::Location(location) = &relation.source else {
                    continue;
                };
                if !known_reads.insert(location.as_ref().clone()) {
                    continue;
                }
                let seed_carriers = implicit_read_seed_carriers(
                    &handle,
                    snapshot,
                    &extra_seeds,
                    location,
                    &mut completeness,
                );
                implicit_reads.push(ImplicitHeapRead {
                    location: location.as_ref().clone(),
                    seed_carriers,
                });
            }
        }
    }
    let value_obligations = handle
        .semantics()
        .logical_gaps()
        .filter(|gap| {
            gap.base.discharge == crate::analyzer::semantic::SemanticGapDischarge::DataDependency
        })
        .collect::<Vec<_>>();
    let has_interference = handle.semantics().points().iter().any(|point| {
        point.events.iter().any(|event| {
            event.effect == crate::analyzer::semantic::SemanticEffect::MemoryInterference
        })
    });
    let call_dependency_edges =
        handle
            .semantics()
            .call_sites()
            .iter()
            .fold(0usize, |count, call| {
                count
                    .saturating_add(call.arguments.len())
                    .saturating_add(call.normal_result_values().count())
                    .saturating_add(2)
            });
    let dependency_work = crate::analyzer::semantic::SemanticWork {
        events: snapshot
            .relations()
            .len()
            .saturating_add(call_dependency_edges)
            .saturating_mul(4),
        values: handle.semantics().values().len(),
        control_edges: handle.semantics().control_edges().len(),
        nested_entries: snapshot
            .relations()
            .len()
            .saturating_add(call_dependency_edges)
            .saturating_mul(4)
            .saturating_add(handle.semantics().values().len()),
        ..Default::default()
    };
    let dependency_requested = !value_obligations.is_empty() || has_interference;
    let dependency_admitted = !dependency_requested
        || (!request.cancellation.is_cancelled()
            && request.budget.admit(dependency_work).is_ok()
            && request.charge_execution_traversal(
                dependency_work
                    .events
                    .saturating_add(dependency_work.values)
                    .saturating_add(dependency_work.control_edges),
            ));
    if dependency_requested && !dependency_admitted {
        completeness = Completeness::operational(
            if request.cancellation.is_cancelled() {
                OperationalCause::Cancelled
            } else {
                OperationalCause::Budget(BudgetLane::Semantic)
            },
            "requested dependency accounting did not finish",
        )
        .preserving_operational_cause(&completeness);
    }
    if dependency_requested && dependency_admitted {
        let roots = extra_seeds
            .iter()
            .map(|seed| crate::value_flow::ValueFlowCarrier::from(&seed.carrier))
            .chain(extra_observations.iter().map(|observation| {
                crate::value_flow::ValueFlowCarrier::from(&observation.carrier)
            }));
        let dependencies = crate::value_flow::snapshot_data_dependencies(snapshot, roots);
        for obligation in &value_obligations {
            if let crate::analyzer::semantic::SemanticGapSubject::Value(value) =
                obligation.subject()
                && handle.value_handle(value).is_some_and(|value| {
                    dependencies.contains(&crate::value_flow::ValueFlowCarrier::for_value(value))
                })
            {
                completeness =
                    content_incomplete("requested data depends on a withheld value producer")
                        .preserving_operational_cause(&completeness);
            }
        }
        if has_interference {
            let ownership =
                crate::analyzer::semantic::workspace_oracle::MemoryInterferenceOwnership::new(
                    &handle,
                );
            let affected =
                crate::analyzer::semantic::workspace_oracle::memory_interference_successors(
                    handle.semantics(),
                );
            let prefix = |point: ProgramPointId| {
                handle.semantics().point(point).is_some_and(|point| {
                    point.events.first().is_some_and(|event| {
                        event.effect
                            == crate::analyzer::semantic::SemanticEffect::MemoryInterference
                    })
                })
            };
            let unknown_read =
                crate::value_flow::snapshot_has_unknown_memory_dependency(snapshot, &dependencies)
                    || extra_observations.iter().any(|observation| {
                        let ValueFlowEndpoint::Location(location) = &observation.carrier else {
                            return false;
                        };
                        (affected.contains(&observation.point)
                            || (observation.phase == ExtraPhase::AfterEffects
                                && prefix(observation.point)))
                            && ownership.may_modify(location)
                    });
            if unknown_read {
                completeness =
                    content_incomplete("MemoryInterference leaves requested shared memory unknown")
                        .preserving_operational_cause(&completeness);
            }
        }
        let keys = value_obligations
            .iter()
            .map(|gap| gap.key())
            .collect::<Vec<_>>();
        client.record_value_obligation_accounting(&handle, &keys, request);
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
        let reason = format!("the procedure's relations are {:?}", partial.outcome);
        completeness = match partial.outcome {
            PartialFlowOutcome::ExceededBudget | PartialFlowOutcome::Truncated => {
                Completeness::operational(OperationalCause::Budget(BudgetLane::Semantic), reason)
            }
            PartialFlowOutcome::Error => {
                Completeness::operational(OperationalCause::Provider, reason)
            }
            PartialFlowOutcome::Complete => unreachable!("checked incomplete partial flows"),
        }
        .preserving_operational_cause(&completeness);
    }
    if !partial.relations_proven() {
        completeness =
            content_incomplete("the procedure's relations or boundary member ports are incomplete")
                .preserving_operational_cause(&completeness);
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
        completeness =
            content_incomplete("a call-result member read has no returned-member binding")
                .preserving_operational_cause(&completeness);
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
        completeness = content_incomplete("a caller-side member input has no bound carrier")
            .preserving_operational_cause(&completeness);
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
    let handle = discovery.selected_procedure(procedure, request)?;
    let procedure = &handle.durable_key();
    // The ICFG engine blocks a snapshot with an unproven relation before
    // it classifies any gap (`classify_snapshot_openness`), and a gap sweep
    // cannot see the relation. The head's fact answers it from the
    // memoized partial-flow read the search already made. The head keeps
    // only the projection's status label, which does not determine a
    // `SemanticInputStatus` (an unsupported capability or an exceeded
    // budget carry data), so the status comes from the head's own
    // derivation, the file-local projection `project_partial_flows` runs,
    // on this path only. The workspace snapshot reads cross-file hooks and
    // describes a different derivation from the one that opened the
    // procedure (#10400).
    let head = client.relations_head(&handle.durable_key(), request)?;
    let relation = if !head.relations_proven() {
        let outcome = file_local_procedure_relations(&handle, &OracleCallContext::empty(), request)
            .map_err(|error| discovery.provider_error(error.to_string()))?;
        let status = SemanticInputStatus::from_outcome(&outcome);
        // A gap that lowering left because it ran out of budget reads as
        // Unproven with open coverage, and the projection's execution marker
        // cannot tell it from a member call's content gap. A larger lowering
        // budget can close it, so it is a budget stop, as ICFG
        // (`semantic_gap_quality`) and the composition provider's invocation
        // inventory already treat it.
        let budget_limited = handle
            .semantics()
            .gaps()
            .iter()
            .any(|gap| gap.kind == SemanticGapKind::ExceededBudget)
            || outcome
                .available_value()
                .is_some_and(|snapshot| snapshot.coverage() == CandidateCoverage::Truncated);
        Some((
            status,
            file_local_promotion_cause(head.outcome, status, budget_limited),
        ))
    } else {
        None
    };
    let sweep = client.openness_sweep(&handle, request)?;
    if !sweep.open && relation.is_none() {
        return Ok(Openness::Closed);
    }
    if sweep.relevant_gaps.is_empty() {
        // Preserve an unproven relation independently of gaps the workspace
        // can refine. Otherwise this is the existing capability/builtin gap.
        let status = match relation {
            Some((status, _)) => status,
            None => snapshot_status(discovery, &handle, request)?,
        };
        return Ok(Openness::Open {
            residual: Box::default(),
            residual_causes: Box::default(),
            relation_cause: relation.map(|(_, cause)| cause),
            cause: relation.map_or_else(|| status_cause(status), |(_, cause)| cause),
            blocked: None,
            status,
            reason: "a local relation, value-flow capability or builtin assumption keeps the procedure open".into(),
        });
    }
    let abort_user_code = abort_paths_run_user_code(handle.semantics());
    let mut answered: HashMap<CallSiteId, Option<IncompleteCause>> = HashMap::new();
    let mut residual: Vec<DurableCallSiteKey> = Vec::new();
    let mut residual_causes = Vec::new();
    let mut blocked: Vec<(crate::analyzer::semantic::GapKey, SemanticCapability)> = Vec::new();
    // Whether the sweep named a gap this handle's procedure does not have.
    // Then the sweep read another interpretation of the procedure (#11842):
    // no gap can be named, and the sweep's answer cannot be trusted to be
    // closed, so the procedure stays open (#11826). The other gaps are still
    // classified, so their residual calls and causes are reported as usual.
    let mut foreign_gap = false;
    for gap_id in &sweep.relevant_gaps {
        let Some(gap) = handle.semantics().logical_gap(*gap_id) else {
            foreign_gap = true;
            continue;
        };
        if gap.base.discharge == crate::analyzer::semantic::SemanticGapDischarge::DataDependency
            && client.value_obligation_accounted(&handle, *gap_id)
        {
            continue;
        }
        match classify_gap_openness(handle.semantics(), gap, abort_user_code) {
            GapOpenness::RefinementCall(call) => {
                let cause = match answered.get(&call) {
                    Some(cause) => *cause,
                    None => {
                        let completeness =
                            client.dispatch_completeness(&(procedure.clone(), call), request)?;
                        let cause = match completeness {
                            Completeness::Complete => None,
                            Completeness::Incomplete { cause, .. } => Some(cause),
                        };
                        answered.insert(call, cause);
                        cause
                    }
                };
                let key = (procedure.clone(), call);
                if let Some(cause) = cause
                    && !residual.contains(&key)
                {
                    residual.push(key);
                    residual_causes.push(cause);
                }
            }
            // The sweep is the workspace host's answer (memoized, possibly
            // under another handle of the procedure) and kept this gap open;
            // the local classification here reads only the procedure's own
            // semantics. Both apply the same value-flow test, so they agree
            // when they read the same semantics. A real run disagreed on the
            // Rust lowering's unmodeled-Drop `Calls` gap and crashed the
            // whole analysis here (#11826); why the sweep read other
            // semantics is #11842. A gap that no complete dispatch answers is
            // an unanswered gap: fail closed and name it, as a Blocked gap is
            // named.
            GapOpenness::Blocked | GapOpenness::Irrelevant | GapOpenness::Discharged => {
                blocked.push((*gap_id, gap.base.capability))
            }
        }
    }
    if residual.is_empty() && blocked.is_empty() && relation.is_none() && !foreign_gap {
        return Ok(Openness::Closed);
    }
    // Durable call keys include workspace identity. Keep the explanatory text
    // independent of the mount while the typed fields retain the exact sites.
    let reason = if foreign_gap {
        "the workspace gap sweep named a gap this procedure interpretation lacks"
    } else {
        "unproven local relations, residual calls or blocked gaps keep the procedure open"
    };
    // A blocked gap decides the diagnostic even when residual calls
    // remain: the ICFG engine's plan returns its blocked gap whenever one
    // exists in the procedure (`classify_snapshot_openness`).
    let blocked = blocked.first().map(|(gap, capability)| BlockedGap {
        gap: handle
            .logical_gap_handle(*gap)
            .expect("a blocked gap is a gap of its procedure"),
        capability: *capability,
    });
    let status = match relation {
        Some((status, _)) => status,
        None => snapshot_status(discovery, &handle, request)?,
    };
    let relation_cause = relation.map(|(_, cause)| cause);
    let cause = if relation_cause
        .iter()
        .chain(residual_causes.iter())
        .any(|cause| matches!(cause, IncompleteCause::Operational(_)))
    {
        relation_cause
            .iter()
            .chain(residual_causes.iter())
            .copied()
            .find(|cause| matches!(cause, IncompleteCause::Operational(_)))
            .expect("checked operational residual")
    } else {
        status_cause(status)
    };
    Ok(Openness::Open {
        residual: residual.into_boxed_slice(),
        residual_causes: residual_causes.into_boxed_slice(),
        relation_cause,
        cause,
        blocked,
        status,
        reason: reason.into(),
    })
}

/// The cause of an incomplete-relation promotion. Both the relations and the
/// status come from the file-local derivation of the head, which has constant
/// hooks and no nested queries, so a budget stop is the only operational
/// cause besides a cancellation or a provider error: the less stable of the
/// head's and the projection's causes wins (a cancellation, then a provider
/// error, then a budget stop, a truncated candidate set or a lowering budget
/// gap), and anything else is the procedure's content. Neither execution
/// marker is an input: the projection sets its own for a content reason on
/// every procedure with a member call.
fn file_local_promotion_cause(
    head: PartialFlowOutcome,
    status: SemanticInputStatus,
    budget_limited: bool,
) -> IncompleteCause {
    let budget = IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic));
    let projection = match status {
        SemanticInputStatus::ExceededBudget { .. } => budget,
        SemanticInputStatus::Cancelled => IncompleteCause::Operational(OperationalCause::Cancelled),
        _ if budget_limited => budget,
        _ => IncompleteCause::Content,
    };
    let head = match head {
        PartialFlowOutcome::ExceededBudget | PartialFlowOutcome::Truncated => Some(budget),
        PartialFlowOutcome::Error => Some(IncompleteCause::Operational(OperationalCause::Provider)),
        PartialFlowOutcome::Complete => None,
    };
    let causes = head.into_iter().chain([projection]);
    // Whether the promotion depends on execution is the reuse-verdict join.
    // Its two execution causes do not yet rank provider errors above budget
    // stops, so the less stable operational stop is chosen here.
    let verdict = causes
        .clone()
        .fold(ReuseVerdict::Content, |verdict, cause| {
            verdict.join(cause.reuse_verdict())
        });
    if verdict.is_content() {
        return IncompleteCause::Content;
    }
    let instability = |stop: &OperationalCause| match stop {
        OperationalCause::Budget(_) => 0,
        OperationalCause::Provider => 1,
        OperationalCause::Cancelled => 2,
    };
    causes
        .filter_map(|cause| match cause {
            IncompleteCause::Operational(stop) => Some(stop),
            IncompleteCause::Content => None,
        })
        .max_by_key(instability)
        .map(IncompleteCause::Operational)
        .expect("an execution-dependent verdict has an operational cause")
}

// Preserve the existing classification outside incomplete-relation promotion.
fn status_cause(status: SemanticInputStatus) -> IncompleteCause {
    match status {
        SemanticInputStatus::ExceededBudget { .. } => {
            IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic))
        }
        SemanticInputStatus::Cancelled => IncompleteCause::Operational(OperationalCause::Cancelled),
        _ => IncompleteCause::Content,
    }
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
        // A gap this handle lacks is reported by `decide_openness`, which
        // reads the same sweep; there is no call to prefetch for it.
        let Some(gap) = handle.semantics().logical_gap(*gap_id) else {
            continue;
        };
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

/// Project one raw workspace call answer into value ports and model decisions.
/// The raw answer remains available to the client for arm-level evidence.
pub fn dispatch_from_structure<D, M>(
    discovery: &D,
    models: &M,
    raw: CallStructureDispatch,
    request: &mut SemanticRequest<'_>,
) -> Result<LocalDispatch<M::Function>, D::Error>
where
    D: LocalTransferDiscovery,
    M: CallModelSource<Error = D::Error>,
{
    let CallStructureDispatch {
        handle: call_handle,
        answer,
    } = raw;
    let call = call_handle.durable_key();
    discovery.locator_procedure(&call.0, request)?;
    // Keep the exact selected caller that owns the raw dispatch's oracle arena.
    let handle = call_handle.procedure().clone();
    let result = answer.available_value();
    let status = SemanticInputStatus::from_outcome(&answer);
    let mut coverage = result.map_or_else(
        || CallSiteCoverage::unavailable(status),
        |result| CallSiteCoverage::from_dispatch(status, result),
    );
    let boundaries = result
        .map(|result| result.boundaries().into())
        .unwrap_or_default();
    let conversion = discovery.call_conversion_may_run_user_code(&call_handle, &answer, request)?;
    discovery.require_outcome(&conversion, "argument conversion effects")?;
    let conversion_open = conversion.available_value().copied().unwrap_or(true);
    let output = discovery.payload_constructor_output(&call_handle, request)?;
    let mut decision = models.dispatch_model(&call_handle, &answer)?;
    if let Some(Some(endpoint)) = output.available_value()
        && let Some(model) = decision.model.as_mut()
    {
        let output = crate::analyzer::semantic::partial_flow::ports::port_of_endpoint(endpoint)
            .expect("a constructor payload is a call-result member");
        model.endpoint_projections = true;
        for transfer in &mut model.transfers {
            transfer.output = output.clone();
            transfer.preserves_member_contents = true;
        }
    }
    let continuation = if conversion_open {
        HopQuality::new(decision.continuation.proven, false)
    } else {
        decision.continuation
    };
    let mut retained_model = None;
    if let Some(mut model) = decision.model {
        if conversion_open {
            model.completeness = Completeness::content("an argument conversion or receiver deref without a selected complete Identity summary may run user code")
                .preserving_operational_cause(&model.completeness);
        }
        if model.transfers.iter().any(|transfer| {
            matches!(
                transfer.output,
                PartialFlowPort::CallReceiver { .. } | PartialFlowPort::CallArgument { .. }
            ) || matches!(transfer.actual, PartialFlowPort::CallReceiver { .. })
                || (model.endpoint_projections && [&transfer.actual, &transfer.output].iter().any(|port|
                    matches!(port, PartialFlowPort::Heap { root, .. } if matches!(root.as_ref(),
                        PartialFlowPort::CallReceiver { .. } | PartialFlowPort::CallArgument { .. }))))
        }) {
            let snapshot =
                discovery.procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
            let index = snapshot
                .available_value()
                .map(CallStorageRelationIndex::new);
            let row = handle
                .semantics()
                .call_site(call.1)
                .expect("a modeled call belongs to its procedure");
            let mut writeback = Vec::new();
            for output in model.transfers.iter().map(|transfer| &transfer.output) {
                let output = match output {
                    PartialFlowPort::Heap { root, .. } if model.endpoint_projections => root.as_ref(),
                    output => output,
                };
                if writeback
                    .iter()
                    .any(|binding: &WritebackBinding| &binding.actual == output)
                {
                    continue;
                }
                let value = match output {
                    PartialFlowPort::CallReceiver { .. } => row.receiver,
                    PartialFlowPort::CallArgument { ordinal, .. } => row
                        .arguments
                        .get(*ordinal as usize)
                        .map(|argument| argument.value),
                    _ => continue,
                };
                let Some(actual) = value.and_then(|value| handle.value_handle(value)) else {
                    model.completeness =
                        Completeness::content("a model output has no caller storage value")
                            .preserving_operational_cause(&model.completeness);
                    continue;
                };
                let actual = CallArgumentEndpoint::Value(actual);
                let mode = match output {
                    PartialFlowPort::CallReceiver { .. } => {
                        crate::analyzer::semantic::CallPassingMode::MutableReference
                    }
                    PartialFlowPort::CallArgument { .. } => {
                        crate::analyzer::semantic::CallPassingMode::Value
                    }
                    _ => unreachable!("only receiver and argument outputs have storage"),
                };
                let sharing = snapshot.available_value().zip(index.as_ref()).map_or(
                    crate::analyzer::semantic::CallStorageSharing::Unknown,
                    |(snapshot, index)| {
                        crate::analyzer::semantic::argument_shares_storage_with_formal(
                            &actual,
                            mode,
                            crate::analyzer::semantic::CallWrittenMember::MayTraverseReferent,
                            snapshot,
                            index,
                        )
                    },
                );
                let storage = snapshot.available_value().map(|snapshot| {
                    caller_storage_locations(&actual, snapshot, ValueFlowPlanLimits::default())
                });
                let mut complete = storage.as_ref().is_some_and(|storage| storage.complete);
                let locations = storage
                    .into_iter()
                    .flat_map(|storage| storage.locations)
                    .filter(|location| location.proven_complete)
                    .map(|location| location.location)
                    .collect::<Vec<_>>();
                complete &= sharing == crate::analyzer::semantic::CallStorageSharing::Isolated
                    || !locations.is_empty();
                if sharing == crate::analyzer::semantic::CallStorageSharing::Unknown || !complete {
                    model.completeness = completeness_from_outcome(
                        &snapshot,
                        "a model output's target storage is not proven",
                    )
                    .preserving_operational_cause(&model.completeness);
                }
                writeback.push(WritebackBinding {
                    actual: output.clone(),
                    formal: output.clone(),
                    shares_storage: sharing,
                    direct_field_sharing: sharing,
                    direct_fields: Box::default(),
                    // The output is the caller's actual storage; this makes no
                    // claim that the model transfer preserves object identity.
                    conversion_preserves_identity: true,
                    proven: true,
                    complete,
                    storage: locations.into_boxed_slice(),
                });
            }
            model.writeback = writeback.into_boxed_slice();
            let mut read_ports = Vec::new();
            for transfer in &model.transfers {
                let port = match &transfer.actual {
                    port @ PartialFlowPort::CallReceiver { .. } => Some(port),
                    PartialFlowPort::Heap { root, .. }
                        if model.endpoint_projections
                            && matches!(
                                root.as_ref(),
                                PartialFlowPort::CallReceiver { .. }
                                    | PartialFlowPort::CallArgument { .. }
                            ) =>
                    {
                        Some(root.as_ref())
                    }
                    _ => None,
                };
                if let Some(port) = port
                    && !read_ports.contains(port)
                {
                    read_ports.push(port.clone());
                }
            }
            let mut receiver_reads = Vec::new();
            for port in read_ports {
                let actual =
                    call_input_value(row, &port).and_then(|value| handle.value_handle(value));
                if let Some(actual) = actual {
                    let actual = CallArgumentEndpoint::Value(actual);
                    let sharing = snapshot.available_value().zip(index.as_ref()).map_or(
                        crate::analyzer::semantic::CallStorageSharing::Unknown,
                        |(snapshot, index)| {
                            crate::analyzer::semantic::argument_shares_storage_with_formal(
                                &actual,
                                crate::analyzer::semantic::CallPassingMode::MutableReference,
                                crate::analyzer::semantic::CallWrittenMember::MayTraverseReferent,
                                snapshot,
                                index,
                            )
                        },
                    );
                    let storage = snapshot.available_value().map(|snapshot| {
                        if model.endpoint_projections {
                            caller_content_locations(actual.value(), snapshot, ValueFlowPlanLimits::default())
                        } else {
                            caller_storage_locations(&actual, snapshot, ValueFlowPlanLimits::default())
                        }
                    });
                    let complete = storage.as_ref().is_some_and(|storage| storage.complete);
                    let locations = storage
                        .into_iter()
                        .flat_map(|storage| storage.locations)
                        .filter(|location| location.proven_complete)
                        .map(|location| location.location)
                        .collect::<Vec<_>>();
                    if sharing == crate::analyzer::semantic::CallStorageSharing::Unknown
                        || !complete
                        || locations.is_empty()
                    {
                        model.completeness = completeness_from_outcome(
                            &snapshot,
                            "a model receiver input's storage is not proven",
                        )
                        .preserving_operational_cause(&model.completeness);
                    }
                    receiver_reads.push(WritebackBinding {
                        actual: port.clone(),
                        formal: port,
                        shares_storage: sharing,
                        direct_field_sharing: sharing,
                        direct_fields: Box::default(),
                        conversion_preserves_identity: true,
                        proven: true,
                        complete,
                        storage: locations.into_boxed_slice(),
                    });
                } else {
                    model.completeness =
                        Completeness::content("a model receiver input has no caller storage value")
                            .preserving_operational_cause(&model.completeness);
                }
            }
            model.receiver_reads = receiver_reads.into_boxed_slice();
        }
        if model.retains_dispatch {
            retained_model = Some(model);
        } else {
            return Ok(LocalDispatch {
                dispatch: Dispatch {
                    candidates: Vec::new(),
                    completeness: if conversion_open {
                        Completeness::content(
                            "an argument conversion or receiver deref without a selected complete Identity summary may run user code",
                        )
                    } else {
                        Completeness::Complete
                    },
                    continuation,
                    external_body_unavailable: None,
                },
                model: Some(model),
                handle: call_handle,
                status,
                coverage,
                boundaries,
            });
        }
    }
    let Some(result) = result else {
        return Ok(LocalDispatch {
            dispatch: Dispatch {
                candidates: Vec::new(),
                completeness: match answer {
                    SemanticOutcome::ExceededBudget { .. } => Completeness::operational(
                        OperationalCause::Budget(BudgetLane::Semantic),
                        "the dispatch of the call has no answer",
                    ),
                    SemanticOutcome::Cancelled { .. } => Completeness::operational(
                        OperationalCause::Cancelled,
                        "the dispatch of the call has no answer",
                    ),
                    _ => Completeness::content("the dispatch of the call has no answer"),
                },
                continuation,
                external_body_unavailable: None,
            },
            model: retained_model,
            handle: call_handle,
            status,
            coverage,
            boundaries,
        });
    };
    let mut completeness = dispatch_completeness(&answer, result);
    if conversion_open {
        completeness = Completeness::content("an argument conversion or receiver deref without a selected complete Identity summary may run user code")
            .preserving_operational_cause(&completeness);
    }
    let external_body_unavailable = match result.boundaries() {
        [boundary]
            if answer.is_complete()
                && result.coverage() == CandidateCoverage::Exhaustive
                && result.candidates().is_empty()
                && boundary.proof == ProofStatus::Proven
                && matches!(boundary.completeness, EvidenceCompleteness::Partial(_))
                && boundary.partial_cause
                    == Some(crate::analyzer::semantic::DispatchBoundaryPartialCause::ExternalBodyUnavailable) =>
        {
            boundary.unmaterialized_external_target().cloned().map(|target| {
                ExternalBodyUnavailableGap {
                    target,
                    raw_coverage: result.coverage(),
                }
            })
        }
        _ => None,
    };
    let external_body_unavailable = external_body_unavailable.filter(|_| !conversion_open);
    let mut candidates = Vec::new();
    let mut entered = Vec::new();
    let mut bindings = Vec::new();
    let snapshot_outcome =
        discovery.procedure_snapshot(&handle, &OracleCallContext::empty(), request)?;
    let snapshot_index = snapshot_outcome
        .available_value()
        .map(CallStorageRelationIndex::new);
    for candidate in result.candidates() {
        let selected = discovery.selected_procedure_handle(candidate.target(), request)?;
        let candidate = crate::analyzer::semantic::service::reseal_selected_candidate(
            candidate,
            &call_handle,
            &selected,
            crate::analyzer::semantic::OracleLimits::default(),
        )
        .map_err(|error| discovery.unavailable(error.to_string()))?;
        let candidate = &candidate;
        let callee_snapshot = discovery.procedure_snapshot(
            candidate.target(),
            &OracleCallContext::empty(),
            request,
        )?;
        let written_heap_ports = written_heap_ports(&callee_snapshot);
        let outcome = discovery.call_bindings(
            &call_handle,
            candidate,
            &OracleCallContext::empty(),
            request,
        )?;
        bindings.push(BindingCoverage::Answered {
            status: SemanticInputStatus::from_outcome(&outcome),
        });
        if candidate.target().semantics().properties().invocation
            == crate::analyzer::semantic::ProcedureInvocationKind::DeferredBody
        {
            // Construction names the body but cannot enter its formal, heap,
            // or return ports without an activation certificate. Keep the
            // native binding refusal visible even when it has no retained rows.
            completeness = completeness_from_outcome(
                &outcome,
                "async body caller effects remain deferred until activation",
            )
            .preserving_operational_cause(&completeness);
            continue;
        }
        // The mapping-quality check is intentionally unreachable for DeferredBody.
        // Each retained mapping becomes an actual/formal dependence edge.
        // Partial mapping or conversion evidence must travel with those
        // edges. Whole-binding openness from other evaluation/return gaps
        // belongs to the existing procedure-openness checks instead.
        if outcome.available_value().is_some_and(|bindings| {
            bindings.bindings().iter().any(|binding| match binding {
                CallBinding::ArgumentGroup(group) => group.mappings().iter().any(|mapping| {
                    mapping.completeness() != &EvidenceCompleteness::Complete
                        || matches!(mapping.value().conversion(), Some(Err(_)))
                }),
                _ => false,
            })
        }) {
            completeness = completeness_from_outcome(
                &outcome,
                "a selected argument mapping has incomplete conversion or binding evidence",
            )
            .preserving_operational_cause(&completeness);
        }
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
                    written_heap_ports,
                )
            });
        match composed {
            Ok(composed) => {
                // Boundary-member coverage only: the search asks `openness` for every visited
                // procedure afterwards, which decides the callee's undischarged gaps.
                if let (Some(callee_rows), Some(caller_rows)) = (
                    models.boundary_member_rows(&composed.procedure, request)?,
                    models.boundary_member_rows(&call_handle.procedure().durable_key(), request)?,
                ) && (!callee_rows.relations_proven()
                    || !returned_members_bound(
                        &callee_rows.ports,
                        &caller_rows,
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
                    completeness =
                        Completeness::content("a callee's boundary-member coverage is incomplete")
                            .preserving_operational_cause(&completeness);
                }
                entered.push(candidate.target().clone());
                candidates.push(composed);
            }
            Err(reason) => {
                completeness = completeness_from_outcome(&outcome, reason)
                    .preserving_operational_cause(&completeness)
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
            external_body_unavailable,
        },
        model: retained_model,
        handle: call_handle,
        status,
        coverage,
        boundaries,
    })
}

/// A whole-value boundary relation consumes every returned member. This includes
/// returns, arguments, heap stores and captures; unfamiliar destinations also
/// demand all members. Member-only reads are checked separately below.
/// Local aliases need no raw snapshot walk: an alias can affect the answer
/// through a retained boundary relation, or through an explicit member read
/// checked below. A local alias with neither use is not a demand. Unproven
/// caller relations cannot exclude whole uses and therefore demand all members.
fn caller_whole_value_demands(caller: &ProcedurePartialFlows) -> HashSet<&PartialFlowPort> {
    caller
        .flows
        .iter()
        .filter_map(|flow| {
            let source = caller
                .ports
                .get(flow.from.index())
                .expect("a relation source belongs to its port table");
            let target = caller
                .ports
                .get(flow.to.index())
                .expect("a relation target belongs to its port table");
            (source != target).then_some(source)
        })
        .collect()
}

fn returned_members_bound(
    callee_ports: &[PartialFlowPort],
    caller: &ProcedurePartialFlows,
    returns: &[(PartialFlowPort, PartialFlowPort)],
    mut canonical_field: impl FnMut(
        &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<crate::analyzer::semantic::SemanticLocator>,
) -> bool {
    let caller_ports = &caller.ports;
    let whole_demands = caller_whole_value_demands(caller);
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
                && ((caller.relations_proven() && !whole_demands.contains(result))
                    || caller_ports.iter().any(|caller| {
                        bound_return_member_matches(
                            caller,
                            port,
                            result,
                            returned,
                            &mut canonical_field,
                        )
                    }))
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
pub fn matching_calls<D: LocalTransferDiscovery>(
    discovery: &D,
    caller: &Arc<SemanticArtifact>,
    range: (usize, usize),
    request: &mut SemanticRequest<'_>,
) -> Result<Vec<(ProcedureHandle, CallSiteHandle)>, D::Error> {
    let mut matched = Vec::new();
    for procedure in caller.procedures() {
        // Enumerate structural procedure IDs, then inspect only the selected body.
        let base = caller
            .procedure_handle(procedure.id())
            .expect("enumerated procedure");
        let handle = discovery.selected_procedure_handle(&base, request)?;
        let procedure = handle.semantics();
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
    Ok(matched)
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
    written_heap_ports: Option<Box<[PartialFlowPort]>>,
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
            CallBinding::Receiver { actual, formal, .. } => {
                let actual_port = PartialFlowPort::CallReceiver { call: call_id };
                let formal_port = formal_port(formal)?;
                let receiver = CallArgumentEndpoint::Value(actual.clone());
                let preparation = bindings.candidate().member_receiver_preparation();
                // Direct calls can lack a member-selection preparation row.
                // An exact aggregate copy still supplies the receiver's
                // contents while isolating its storage from the caller.
                let copied_receiver = snapshot.is_some_and(|snapshot| {
                    let actual_endpoint = ValueFlowEndpoint::for_value(actual.clone());
                    snapshot.relations().iter().any(|relation| {
                        relation.target == actual_endpoint
                            && relation.transfer.is_some_and(|transfer| {
                                transfer.kind
                                    == crate::analyzer::semantic::TransferKind::AggregateCopy
                            })
                            && relation.proof == ProofStatus::Proven
                            && relation.completeness == EvidenceCompleteness::Complete
                    })
                });
                let preserves_identity = !copied_receiver
                    && !matches!(
                        preparation,
                        Some(
                            crate::analyzer::semantic::MemberReceiverPreparation::CopyValue
                                | crate::analyzer::semantic::MemberReceiverPreparation::CopyPointee
                        )
                    );
                let mode = crate::analyzer::semantic::CallPassingMode::MutableReference;
                let sharing = if preserves_identity {
                    snapshot.zip(snapshot_index).map_or(
                        crate::analyzer::semantic::CallStorageSharing::Unknown,
                        |(snapshot, index)| {
                            crate::analyzer::semantic::argument_shares_storage_with_formal(
                                &receiver,
                                mode,
                                crate::analyzer::semantic::CallWrittenMember::MayTraverseReferent,
                                snapshot,
                                index,
                            )
                        },
                    )
                } else {
                    crate::analyzer::semantic::CallStorageSharing::Isolated
                };
                let storage = snapshot.map(|snapshot| {
                    if copied_receiver
                        || preparation
                            == Some(crate::analyzer::semantic::MemberReceiverPreparation::CopyValue)
                    {
                        // A copied receiver reads the caller's fields, but its
                        // writes remain isolated by `sharing` below.
                        caller_content_locations(actual, snapshot, ValueFlowPlanLimits::default())
                    } else {
                        caller_storage_locations(
                            &receiver,
                            snapshot,
                            ValueFlowPlanLimits::default(),
                        )
                    }
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
                    shares_storage: sharing,
                    direct_field_sharing: sharing,
                    direct_fields: crate::analyzer::semantic::direct_formal_store_fields(
                        bindings.callee(),
                        &formal_port,
                    ),
                    conversion_preserves_identity: preserves_identity,
                    proven: *bindings.candidate().proof() == ProofStatus::Proven
                        && bindings.coverage() == CandidateCoverage::Exhaustive
                        && !bindings.context().was_truncated(),
                    complete: *bindings.candidate().completeness()
                        == EvidenceCompleteness::Complete
                        && bindings.coverage() == CandidateCoverage::Exhaustive
                        && storage_complete
                        && !bindings.context().was_truncated(),
                    storage: storage_locations.into_boxed_slice(),
                });
                arguments.push((actual_port, formal_port));
            }
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
        written_heap_ports,
        arguments: arguments.into_boxed_slice(),
        writeback: writeback.into_boxed_slice(),
        returns: returns.into_boxed_slice(),
    })
}

/// The ownership-transfer proof shared by call handoffs and object bypasses.
pub(crate) fn moved_into_call(
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
    value: ValueId,
) -> bool {
    procedure.semantics().move_outs().iter().any(|moved| {
        moved.point == call.point
            && moved.target_value == value
            && moved.state_after == crate::analyzer::semantic::MoveOutState::Uninitialized
    })
}

/// Project object-continuity evidence for a selected candidate only when a
/// stateful client asks. Each handoff indexes `candidate.arguments`, so the
/// taint candidate and its writeback path keep their existing shape.
pub fn project_call_handoffs(
    call: &CallSiteHandle,
    bindings: &CallBindings,
    candidate: &ComposeCandidate,
    reference_certified: &HashSet<ValueId>,
    receiver_continuity_certified: CallObjectContinuity,
) -> Result<Box<[CallHandoffBinding]>, String> {
    let row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .ok_or("the call is not a call of its procedure")?;
    if bindings.call() != call || candidate.procedure != bindings.callee().durable_key() {
        return Err("handoff candidate does not match its call binding".into());
    }
    let moved_into_call = |value: ValueId| moved_into_call(call.procedure(), row, value);
    let mut handoffs = Vec::new();
    let mut index = 0;
    for binding in bindings.bindings() {
        let entries: Vec<_> = match binding {
            CallBinding::Receiver {
                relation,
                actual,
                formal,
            } => {
                let continuity = if matches!(
                    bindings.candidate().receiver_owner_relation(),
                    crate::analyzer::semantic::ReceiverOwnerRelation::Promoted
                        | crate::analyzer::semantic::ReceiverOwnerRelation::Unknown
                ) {
                    CallObjectContinuity::Unknown
                } else if receiver_continuity_certified.is_exact() {
                    receiver_continuity_certified
                } else if bindings.candidate().receiver_owner_relation()
                    == crate::analyzer::semantic::ReceiverOwnerRelation::NotApplicable
                    && call
                        .procedure()
                        .semantics()
                        .value(actual.id())
                        .is_some_and(|value| {
                            value.kind == crate::analyzer::semantic::SemanticValueKind::Address
                        })
                {
                    CallObjectContinuity::Reference
                } else if !crate::analyzer::languages::language_support(
                    call.procedure().artifact().key().language().language(),
                )
                .is_some_and(|support| support.requires_selected_receiver_witness())
                    && moved_into_call(actual.id())
                {
                    CallObjectContinuity::Move
                } else {
                    CallObjectContinuity::Unknown
                };
                vec![(
                    PartialFlowPort::CallReceiver { call: call.id() },
                    formal_port(formal)?,
                    continuity,
                    HopQuality::new(
                        relation.record().is_proven(),
                        relation.record().is_complete(),
                    ),
                )]
            }
            CallBinding::ArgumentGroup(group) => group
                .mappings()
                .iter()
                .map(|mapping| {
                    let value = mapping.value();
                    let actual = value.actual().value().id();
                    let continuity =
                        match value.mode() {
                            crate::analyzer::semantic::CallPassingMode::SharedReference
                            | crate::analyzer::semantic::CallPassingMode::MutableReference
                            | crate::analyzer::semantic::CallPassingMode::InputOutputReference => {
                                CallObjectContinuity::Reference
                            }
                            crate::analyzer::semantic::CallPassingMode::Value
                                if reference_certified.contains(&actual) =>
                            {
                                CallObjectContinuity::Reference
                            }
                            crate::analyzer::semantic::CallPassingMode::Value
                                if moved_into_call(actual) =>
                            {
                                CallObjectContinuity::Move
                            }
                            crate::analyzer::semantic::CallPassingMode::Value
                                if candidate.writeback.iter().any(|writeback| {
                                    writeback.actual
                                        == actual_port(row, call.id(), actual)
                                            .expect("a bound actual has a call port")
                                        && writeback.formal
                                            == formal_port(value.formal())
                                                .expect("a bound formal has a port")
                                        && writeback.shares_storage
                                            == crate::analyzer::semantic::CallStorageSharing::Shares
                                        && writeback.conversion_preserves_identity
                                        && writeback.proven
                                        && writeback.complete
                                }) =>
                            {
                                CallObjectContinuity::Reference
                            }
                            crate::analyzer::semantic::CallPassingMode::Value
                                if call.procedure().semantics().value(actual).is_some_and(
                                    |row| {
                                        row.kind
                                            == crate::analyzer::semantic::SemanticValueKind::Address
                                    },
                                ) =>
                            {
                                CallObjectContinuity::Reference
                            }
                            _ => CallObjectContinuity::Unknown,
                        };
                    Ok((
                        actual_port(row, call.id(), actual)?,
                        formal_port(value.formal())?,
                        continuity,
                        HopQuality::new(
                            group.closure_relation().record().is_proven()
                                && mapping.proof() == &ProofStatus::Proven
                                && value.preserves_reference_identity(),
                            group.coverage().is_exhaustive()
                                && group.closure_relation().record().is_complete()
                                && mapping.completeness() == &EvidenceCompleteness::Complete,
                        ),
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?,
            _ => Vec::new(),
        };
        for (actual, formal, continuity, quality) in entries {
            if candidate
                .arguments
                .get(index)
                .is_none_or(|(bound_actual, bound_formal)| {
                    bound_actual != &actual || bound_formal != &formal
                })
            {
                return Err("handoff binding differs from the selected candidate".into());
            }
            let quality = quality.conjoin(HopQuality::from_uncertain(
                !bindings.coverage().is_exhaustive()
                    || bindings.context().was_truncated()
                    || candidate
                        .arguments
                        .iter()
                        .filter(|(_, bound)| bound == &formal)
                        .count()
                        != 1,
            ));
            let quality = quality.conjoin(HopQuality::new(
                matches!(bindings.candidate().proof(), ProofStatus::Proven),
                matches!(
                    bindings.candidate().completeness(),
                    EvidenceCompleteness::Complete
                ),
            ));
            for (exit, continuation) in [
                (CallHandoffExit::Normal, row.normal_continuation),
                (CallHandoffExit::Exceptional, row.exceptional_continuation),
            ] {
                if continuation.target().is_some() {
                    handoffs.push(CallHandoffBinding {
                        argument_index: index,
                        exit,
                        continuity,
                        quality,
                    });
                }
            }
            index += 1;
        }
    }
    if index != candidate.arguments.len() {
        return Err("handoff binding does not cover candidate arguments".into());
    }
    Ok(handoffs.into_boxed_slice())
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
    match answer {
        SemanticOutcome::ExceededBudget { .. } => {
            return Completeness::operational(
                OperationalCause::Budget(BudgetLane::Semantic),
                "the dispatch answer is not complete",
            );
        }
        SemanticOutcome::Cancelled { .. } => {
            return Completeness::operational(
                OperationalCause::Cancelled,
                "the dispatch answer is not complete",
            );
        }
        SemanticOutcome::Complete { .. } => {}
        _ => return content_incomplete("the dispatch answer is not complete".to_owned()),
    }
    match result.coverage() {
        CandidateCoverage::Exhaustive => {}
        // The provider reached a finite bound and omitted candidates: a larger
        // bound can change the answer, so this is a budget stop, not content.
        CandidateCoverage::Truncated => {
            return Completeness::operational(
                OperationalCause::Budget(BudgetLane::Semantic),
                "the dispatch candidates were truncated at a bound",
            );
        }
        CandidateCoverage::Open => {
            return content_incomplete("the dispatch coverage is Open".to_owned());
        }
    }
    if result.boundaries().iter().any(|boundary| {
        boundary.proof != ProofStatus::Proven
            || boundary.completeness != EvidenceCompleteness::Complete
    }) {
        return content_incomplete(
            "the dispatch leaves a boundary that is not proven and complete".to_owned(),
        );
    }
    Completeness::Complete
}

fn content_incomplete(reason: impl Into<Box<str>>) -> Completeness {
    Completeness::content(reason)
}

fn completeness_from_outcome<T>(
    answer: &SemanticOutcome<T>,
    reason: impl Into<Box<str>>,
) -> Completeness {
    match answer {
        SemanticOutcome::ExceededBudget { .. } => {
            Completeness::operational(OperationalCause::Budget(BudgetLane::Semantic), reason)
        }
        SemanticOutcome::Cancelled { .. } => {
            Completeness::operational(OperationalCause::Cancelled, reason)
        }
        _ => Completeness::content(reason),
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
    callers_with_coverage(
        discovery,
        |call, answer| CallModelSource::covers_caller_candidate(models, call, answer),
        procedure,
        max_callers_per_procedure,
        execution_budget,
        excluded_callers,
        request,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn callers_with_coverage<D, F>(
    discovery: &D,
    mut covers_candidate: F,
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
    F: FnMut(&CallSiteHandle, &SemanticOutcome<DispatchResult>) -> Result<bool, D::Error>,
{
    let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.callers");
    let handle = discovery.selected_procedure(procedure, request)?;
    let workspace = discovery.workspace();
    let analyzer = workspace.analyzer();
    let Some(file) = file_for_locator(workspace, handle.semantics().locator()) else {
        return Ok(Callers {
            calls: Vec::new(),
            completeness: content_incomplete("the procedure's file is not known"),
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
            completeness: content_incomplete(
                "the procedure's span does not identify one callable declaration",
            ),
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
    if sites.cancelled {
        completeness = Completeness::operational(
            OperationalCause::Cancelled,
            "the incoming-call enumeration was truncated or cancelled",
        );
    } else if sites.truncated {
        completeness = Completeness::operational(
            OperationalCause::Budget(BudgetLane::CallersPerProcedure),
            "the incoming-call enumeration was truncated or cancelled",
        );
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
        completeness =
            Completeness::operational(OperationalCause::Provider, "no certified reverse inventory");
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
            completeness =
                completeness_from_outcome(&outcome, "the caller's file has no semantic artifact")
                    .preserving_operational_cause(&completeness);
            continue;
        };
        let matched = matching_calls(
            discovery,
            &caller,
            (site.range.start_byte, site.range.end_byte),
            request,
        )?;
        if matched.is_empty() {
            completeness = content_incomplete("an incoming call site has no semantic call")
                .preserving_operational_cause(&completeness);
        }
        for (caller_handle, call_handle) in matched {
            let answer = discovery.resolve_call(&call_handle, request)?;
            let Some(result) = answer.available_value() else {
                completeness = completeness_from_outcome(
                    &answer,
                    "the dispatch of an incoming call has no answer",
                )
                .preserving_operational_cause(&completeness);
                continue;
            };
            let mut confirmed = false;
            for candidate in result.candidates() {
                let selected = discovery.selected_procedure_handle(candidate.target(), request)?;
                confirmed |= selected.durable_key() == target_key;
            }
            if confirmed {
                let key = (caller_handle.durable_key(), call_handle.id());
                if seen.insert(key.clone()) {
                    calls.push(key);
                }
            } else {
                if !covers_candidate(&call_handle, &answer)?
                    && !dispatch_completeness(&answer, result).is_complete()
                {
                    completeness = dispatch_completeness(&answer, result)
                        .preserving_operational_cause(&completeness);
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
        completeness: Completeness::operational(OperationalCause::Provider, reason.to_owned()),
    }
}

/// An interior run whose value-flow snapshot has no value. An exceeded budget
/// and a cancellation keep their cause, so the Output slice fallback sees a
/// budget stop as one (#9947). Any other missing snapshot is a provider failure.
pub fn unavailable_snapshot_interior(
    procedure: ProcedureHandle,
    status: SemanticInputStatus,
    reason: &str,
) -> InteriorFlows {
    let cause = match status_cause(status) {
        IncompleteCause::Operational(cause) => cause,
        IncompleteCause::Content => OperationalCause::Provider,
    };
    InteriorFlows {
        procedure,
        flows: Vec::new(),
        completeness: Completeness::operational(cause, reason.to_owned()),
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

#[cfg(test)]
mod activation_tests {
    use super::*;
    use crate::analyzer::semantic::{
        AbstractObject, CancellationToken, ObjectCardinality, SemanticBudget,
    };
    use crate::taint::compose::{CompositionProvider, Endpoint};
    use crate::typestate::{
        BoundTypestateSubjectSpec, ProtocolSpec, ProtocolStateKey, TypestateBindingContext,
        TypestateBindingMultiplicity, TypestateBindingPlan, TypestateBindingQuality,
        TypestateInitialSeedSpec, TypestateObjectRole, TypestateObservationSite,
        TypestateSubjectClassKey,
    };
    use crate::value_flow::ValueFlowCache;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn a_fully_modeled_call_retains_the_user_deref_obligation() {
        struct CompleteModel;
        impl CallModelSource for CompleteModel {
            type Error = SemanticProviderError;
            type Function = ();
            fn dispatch_model(
                &self,
                _call: &CallSiteHandle,
                _answer: &SemanticOutcome<DispatchResult>,
            ) -> Result<CallModelDecision<()>, Self::Error> {
                Ok(CallModelDecision {
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
                })
            }
            fn covers_caller_candidate(
                &self,
                _call: &CallSiteHandle,
                _answer: &SemanticOutcome<DispatchResult>,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Rust,
        )
        .file(
            "main.rs",
            r#"
struct W(String);
impl std::ops::Deref for W {
    type Target = str;
    fn deref(&self) -> &str { &self.0 }
}
fn sink(_text: &str) {}
pub fn run(w: &W) { sink(w); }
"#,
        )
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let file = crate::analyzer::ProjectFile::new(project.root(), "main.rs");
        let cancellation = CancellationToken::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .expect("semantics")
            .available_value()
            .cloned()
            .expect("artifact");
        let run = artifact
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
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("run");
        let [row] = run.semantics().call_sites() else {
            panic!("one sink call");
        };
        let call = run.call_site_handle(row.id).expect("call handle");
        let discovery = WorkspaceCompositionDiscovery::new(
            &workspace,
            WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let answer = discovery
            .resolve_call(&call, &mut request)
            .expect("dispatch");
        let projected = dispatch_from_structure(
            &discovery,
            &CompleteModel,
            CallStructureDispatch {
                handle: call,
                answer,
            },
            &mut request,
        )
        .expect("modeled projection");
        assert!(!projected.dispatch.continuation.complete);
        assert!(!matches!(
            projected.dispatch.completeness,
            Completeness::Complete
        ));
        assert!(!matches!(
            projected
                .model
                .expect("the model shortcut was used")
                .completeness,
            Completeness::Complete
        ));
    }

    /// A client whose workspace sweep names these gaps as relevant, as the
    /// panicking runs' sweeps did, while the head's relations are proven.
    struct SweepNamesGap(Vec<crate::analyzer::semantic::GapKey>);
    impl LocalOpennessClient<WorkspaceCompositionDiscovery<'_>> for SweepNamesGap {
        fn relations_head(
            &self,
            _procedure: &DurableProcedureKey,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<Arc<ProcedurePartialFlows>, SemanticProviderError> {
            Ok(Arc::new(ProcedurePartialFlows::new(
                PartialFlowOutcome::Complete,
                None,
                Vec::new(),
                Vec::new(),
                false,
                true,
                Vec::new(),
            )))
        }
        fn openness_sweep(
            &self,
            _handle: &ProcedureHandle,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<ProcedureOpenness, SemanticProviderError> {
            Ok(ProcedureOpenness {
                open: true,
                relevant_gaps: self.0.clone(),
            })
        }
        fn dispatch_completeness(
            &self,
            _call: &DurableCallSiteKey,
            _request: &mut SemanticRequest<'_>,
        ) -> Result<Completeness, SemanticProviderError> {
            unimplemented!("a gap with no refinement call needs no dispatch")
        }
    }

    #[test]
    #[hardwon(
        "#11826+#11842: a swept implicit-Drop gap the handle discards, or a swept gap it lacks, panicked"
    )]
    fn a_swept_implicit_drop_gap_leaves_the_procedure_open_without_panicking() {
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Rust,
        )
        .file(
            "main.rs",
            r#"
struct Guard(u32);
impl Drop for Guard {
    fn drop(&mut self) {}
}
fn sink(_text: &str) {}
pub fn scoped(password: &str) {
    let _guard = Guard(1);
    sink(password);
}
"#,
        )
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let artifact = workspace
            .materialize_program_semantics(&project.file("main.rs"), &mut request)
            .expect("semantics")
            .available_value()
            .cloned()
            .expect("artifact");
        let scoped = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("scoped")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("scoped");
        let drop_gap = scoped
            .semantics()
            .logical_gaps()
            .find(|gap| {
                gap.base.capability == SemanticCapability::Calls
                    && gap
                        .base
                        .detail
                        .contains("implicit Drop::drop invocations are not emitted")
            })
            .expect("the lowering emits the unmodeled-Drop Calls gap");
        assert!(
            !crate::analyzer::semantic::workspace_oracle::gap_impacts_value_flow(drop_gap.base),
            "the gap has no value-flow impact, so local classification leaves it out"
        );
        let discovery = WorkspaceCompositionDiscovery::new(
            &workspace,
            WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
        );
        // The procedure has no gap with this id, as in the log-injection run
        // whose sweep named a gap the handle lacked.
        let foreign = crate::analyzer::semantic::GapKey::Gap(
            crate::analyzer::semantic::SemanticGapId::new(1_000_000),
        );
        assert!(scoped.semantics().logical_gap(foreign).is_none());
        let mut decide = |gaps: Vec<crate::analyzer::semantic::GapKey>| {
            decide_openness(
                &discovery,
                &SweepNamesGap(gaps),
                &scoped.durable_key(),
                &mut request,
            )
            .expect("a swept gap the handle discards or lacks is not an error")
        };

        for gaps in [vec![drop_gap.key()], vec![drop_gap.key(), foreign]] {
            let openness = decide(gaps.clone());
            let Openness::Open {
                blocked: Some(blocked),
                ..
            } = &openness
            else {
                panic!("the procedure stays open and names the gap for {gaps:?}: {openness:?}");
            };
            assert_eq!(blocked.capability, SemanticCapability::Calls);
            assert_eq!(blocked.gap.id(), drop_gap.key());
        }
        let openness = decide(vec![foreign]);
        assert!(
            matches!(
                &openness,
                Openness::Open { blocked: None, reason, .. } if reason.contains("lacks")
            ),
            "a gap the handle lacks keeps the procedure open: {openness:?}"
        );
    }

    #[test]
    #[hardwon("#9378: composition seeded a result-contract source past its error guard")]
    fn activation_edge_confines_source_and_retains_open_binding_quality() {
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Rust,
        )
        .file(
            "main.rs",
            "pub fn make() -> bool { true }\npub fn root() { let result = make(); if result { let _success = 1; } else { let _failure = 2; } }\n",
        )
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("main.rs"),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .expect("Rust fixture materializes")
            .available_value()
            .cloned()
            .expect("Rust semantic IR is available");
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("root")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("root procedure");
        let [guard] = root.semantics().guard_facts() else {
            panic!("one Boolean guard: {:#?}", root.semantics().guard_facts())
        };
        let success_edge = root
            .control_edge_handle(guard.true_edge.expect("true edge"))
            .expect("success edge handle");
        let failure_edge = root
            .control_edge_handle(guard.false_edge.expect("false edge"))
            .expect("failure edge handle");
        let success_row = root
            .semantics()
            .control_edge(success_edge.id())
            .expect("success row");
        let success_evidence = root
            .semantics()
            .evidence_row(success_row.evidence)
            .expect("success edge evidence");
        assert!(matches!(success_evidence.proof, ProofStatus::Proven));
        assert!(matches!(
            success_evidence.completeness,
            EvidenceCompleteness::Complete
        ));
        let failure_row = root
            .semantics()
            .control_edge(failure_edge.id())
            .expect("failure row");
        assert_ne!(success_row.target_point, failure_row.target_point);
        let [call] = root.semantics().call_sites() else {
            panic!("one make call: {:#?}", root.semantics().call_sites())
        };
        let value = call.result.expect("make has a result");
        let object = AbstractObject::new(
            AccessPathRoot::Value(root.value_handle(value).expect("call result handle")),
            ObjectCardinality::Singleton,
        )
        .expect("one result object");
        let protocol = ProtocolSpec::from_json(br#"{
            "schema_version": 1, "states": ["ready"], "initial_state": "ready",
            "accepting_states": ["ready"], "error_states": [], "events": [],
            "transitions": [], "terminal_expectations": [],
            "semantics": {"analysis_mode": "may", "unmatched_event": "preserve_state",
                "uncertainty": {"ambiguous_dispatch": "abstain", "unknown_call": "abstain",
                    "external_call": "abstain", "escape": "abstain", "incomplete_analysis": "abstain"}}
        }"#).expect("small protocol parses").compile().expect("small protocol compiles");
        let context = TypestateBindingContext::root();
        let site = TypestateObservationSite::program_point(
            root.point_handle(
                call.normal_continuation
                    .target()
                    .expect("normal continuation"),
            )
            .expect("continuation handle"),
            context.clone(),
        );
        let class = TypestateSubjectClassKey::new("resource").expect("subject class");
        let definite = TypestateBindingQuality::proven_unique();
        let possible = TypestateBindingQuality::new(
            ProofStatus::Unproven("candidate success edge".into()),
            EvidenceCompleteness::Partial("open success-edge identity".into()),
            TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1)
                .expect("one candidate"),
        );
        // The control edge stays Proven/Complete; this loop varies binding quality.
        for quality in [definite, possible] {
            let subject =
                BoundTypestateSubjectSpec::new(class.clone(), object.clone(), quality.clone());
            let seed = TypestateInitialSeedSpec::new_on_control_edge(
                subject.key().clone(),
                ProtocolStateKey::new("ready").expect("state key"),
                site.clone(),
                success_edge.clone(),
                TypestateObjectRole::MatchedValue,
                quality.clone(),
            );
            let bindings =
                TypestateBindingPlan::try_new(&protocol, vec![subject], vec![seed], vec![], vec![])
                    .expect("conditional binding plan");
            let subject = &bindings.subjects()[0];
            let discovery = WorkspaceCompositionDiscovery::new(
                &workspace,
                WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
            );
            let provider = TypestateCompositionProvider::new(
                discovery,
                SemanticExecutionBudget::new(8),
                crate::taint::compose::CompositionBudget {
                    max_procedures: 8,
                    max_hops: 128,
                    max_callers_per_procedure: 8,
                },
                &protocol,
                &bindings,
                subject,
                context.clone(),
                usize::MAX,
            );
            let anchor = |point| {
                Endpoint::Object(Box::new(ObjectAnchor {
                    procedure: root.durable_key(),
                    site: ObjectAnchorSite::ProgramPoint(point),
                    role: ObjectAnchorRole::MatchedValue,
                    object: object.clone(),
                }))
            };
            let seed_anchor = anchor(success_row.source_point);
            let query = |at: &Endpoint| {
                provider
                    .object_relation(
                        &root.durable_key(),
                        at,
                        &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
                    )
                    .expect("production composition object relation")
            };
            let failure = query(&anchor(failure_row.target_point));
            assert!(
                failure
                    .predecessors
                    .iter()
                    .all(|edge| edge.from != seed_anchor),
                "the failure branch cannot receive the conditional seed: {failure:#?}"
            );
            let success = query(&anchor(success_row.target_point));
            assert!(
                success
                    .predecessors
                    .iter()
                    .any(|edge| edge.from == seed_anchor),
                "the success branch receives the selected edge: {success:#?}"
            );
            let source = query(&seed_anchor);
            let [source] = source.sources.as_slice() else {
                panic!("one initial source at the guard edge: {source:#?}")
            };
            assert_eq!(
                source
                    .fact
                    .proves_closed(&[protocol.initial_state()], HopQuality::CERTAIN, true),
                quality.is_definitive(),
                "an Open candidate cannot certify a clean composed outcome",
            );
        }
    }

    #[test]
    fn selected_fresh_origin_refuses_a_different_typed_boundary_target() {
        use crate::analyzer::semantic::{
            AbstractObjectIdentity, SemanticLanguage, UnmaterializedExternalTarget,
        };
        use crate::analyzer::semantic_model::{
            CatalogOptions, CompilerOptions, SemanticModelActivationControl,
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelControlAction, SemanticModelControlScope, SemanticModelPackSelector,
            SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
            SessionPackSource, SessionPackSourceKind, SourceFormat, acquire_active_semantic_models,
            compile_source,
        };

        let source = "import com.example.res.Handle; class App { static void run() { Handle h = new Handle(); } }";
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Java,
        )
        .file("App.java", source)
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let mut pack: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../tests/fixtures/9432-java-handle.json"))
                .expect("test-only Java model JSON");
        pack["schema_version"] = 11.into();
        pack["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("bifrost");
        let summary = &mut pack["shards"][1]["payload"]["summaries"][0];
        summary["ordinary_heap_unchanged"] = true.into();
        summary["no_concurrency_effects"] = true.into();
        let compiled = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&pack).unwrap(),
            &CompilerOptions::default(),
        )
        .expect("test-only Java model compiles");
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_session_pack(
                &compiled,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:9432-java-handle-origin".into(),
                },
            )
            .unwrap();
        let activation = SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: vec![SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: "test.9432.java-handle".into(),
                    version: None,
                    manifest_digest: None,
                },
            }],
            limits: SemanticModelRuntimeLimits::default(),
        };
        let cancellation = CancellationToken::default();
        let activated = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &activation,
            &cancellation,
        );
        assert!(
            matches!(activated, SemanticModelRuntimeOutcome::Ready { .. }),
            "{activated:?}"
        );
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("App.java"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .expect("Java semantic IR");
        let procedure = artifact
            .procedures()
            .iter()
            .filter_map(|row| artifact.procedure_handle(row.id()))
            .find(|procedure| {
                procedure.semantics().call_sites().iter().any(|row| {
                    procedure
                        .call_site_handle(row.id)
                        .and_then(|call| {
                            crate::analyzer::semantic::workspace_oracle::dispatch::exact_call_range(
                                &call,
                            )
                            .ok()
                        })
                        .and_then(|span| source.get(span.start_byte..span.end_byte))
                        == Some("new Handle()")
                })
            })
            .expect("constructor procedure");
        let call = procedure
            .semantics()
            .call_sites()
            .iter()
            .filter_map(|row| procedure.call_site_handle(row.id))
            .find(|call| {
                crate::analyzer::semantic::workspace_oracle::dispatch::exact_call_range(call)
                    .ok()
                    .and_then(|span| source.get(span.start_byte..span.end_byte))
                    == Some("new Handle()")
            })
            .expect("constructor call");
        let row = procedure.semantics().call_site(call.id()).unwrap();
        let result = procedure
            .value_handle(row.normal_result_values().next().expect("normal result"))
            .unwrap();
        let normal_point = row.normal_continuation.target().expect("normal arm");
        let object = AbstractObject::new(
            AbstractObjectIdentity::Value(result.clone()),
            ObjectCardinality::Unknown,
        )
        .expect("result object");
        let protocol = ProtocolSpec::from_json(br#"{
            "schema_version": 1, "states": ["open"], "initial_state": "open",
            "accepting_states": ["open"], "error_states": [], "events": [],
            "transitions": [], "terminal_expectations": [],
            "semantics": {"analysis_mode": "may", "unmatched_event": "preserve_state",
                "uncertainty": {"ambiguous_dispatch": "abstain", "unknown_call": "abstain",
                    "external_call": "abstain", "escape": "abstain", "incomplete_analysis": "abstain"}}
        }"#)
        .unwrap()
        .compile()
        .unwrap();
        let context = TypestateBindingContext::root();
        let subject = BoundTypestateSubjectSpec::new(
            TypestateSubjectClassKey::new("resource").unwrap(),
            object.clone(),
            TypestateBindingQuality::proven_unique(),
        );
        let seed = TypestateInitialSeedSpec::new_reviewed_fresh_result(
            subject.key().clone(),
            ProtocolStateKey::new("open").unwrap(),
            TypestateObservationSite::program_point(
                procedure.point_handle(normal_point).unwrap(),
                context.clone(),
            ),
            TypestateObjectRole::AllocationResult,
            TypestateBindingQuality::proven_unique(),
        );
        let bindings =
            TypestateBindingPlan::try_new(&protocol, vec![subject], vec![seed], vec![], vec![])
                .expect("one constructor subject");
        let discovery = WorkspaceCompositionDiscovery::new(
            &workspace,
            WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
        );
        let provider = TypestateCompositionProvider::new(
            discovery,
            SemanticExecutionBudget::new(8),
            crate::taint::compose::CompositionBudget {
                max_procedures: 8,
                max_hops: 128,
                max_callers_per_procedure: 8,
            },
            &protocol,
            &bindings,
            &bindings.subjects()[0],
            context,
            usize::MAX,
        );
        let call_key = (procedure.durable_key(), call.id());
        let (dispatch, _) = provider
            .dispatch(
                &call_key,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("constructor dispatch");
        let gap = dispatch.external_body_unavailable.expect("typed body gap");
        let anchor = ObjectAnchor {
            procedure: procedure.durable_key(),
            site: ObjectAnchorSite::ProgramPoint(normal_point),
            role: ObjectAnchorRole::AllocationResult,
            object,
        };
        let port = PartialFlowPort::CallResult {
            call: call.id(),
            ordinal: Some(0),
        };
        assert!(
            provider
                .certified_object_origin(
                    &anchor,
                    &call_key,
                    &port,
                    &gap,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap()
                .is_some()
        );
        let wrong_gap = ExternalBodyUnavailableGap {
            target: UnmaterializedExternalTarget::new_modeled(
                "com.example.res.Other",
                "<init>",
                SemanticLanguage::Standard(crate::analyzer::Language::Java),
                0,
                false,
            )
            .expect("other external target"),
            raw_coverage: gap.raw_coverage,
        };
        assert!(
            provider
                .certified_object_origin(
                    &anchor,
                    &call_key,
                    &port,
                    &wrong_gap,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
mod memo_receipt_tests {
    use super::*;
    use crate::analyzer::semantic::StableDigest;
    use crate::analyzer::workspace_authority::workspace_memo_attribution;
    use crate::analyzer::{AnalyzerConfig, Language, ReadKey, capture_query_reads};
    use crate::inline_project::InlineTestProject;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11234: composition memo hits lost typed incompleteness of an incomplete head"
    )]
    fn unit_partial_flow_memo_completion_conformance() {
        use crate::analyzer::semantic::ValueFlowOracle;
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget};
        use crate::analyzer::usages::common::{
            QueryMemoOwner, assert_memo_owner_conformance_for_test,
        };
        use crate::value_flow::{
            ValueFlowCache, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
            ValueFlowSinkSpec, ValueFlowSourceSpec,
        };
        for (source, incomplete) in [
            ("pub fn subject(input: u8) -> u8 { input }", false),
            (
                "pub unsafe fn subject(ptr: *mut u8, input: u8) -> u8 { unsafe { *ptr = input; } input }",
                true,
            ),
        ] {
            let project = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname=\"memo-head\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .file(
                    "src/lib.rs",
                    format!("{source}\npub fn plan_root(input: u8) -> u8 {{ input }}"),
                )
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let _scope = AnalyzerQueryScope::new(workspace.analyzer());
            let cancellation = CancellationToken::new();
            let mut budget = SemanticBudget::default();
            let artifact = workspace
                .materialize_program_semantics(
                    &project.file("src/lib.rs"),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap()
                .available_value()
                .cloned()
                .unwrap();
            let procedure = |name| {
                artifact
                    .procedures()
                    .iter()
                    .find(|procedure| {
                        procedure
                            .locator()
                            .declaration()
                            .segments()
                            .last()
                            .and_then(|segment| segment.name())
                            == Some(name)
                    })
                    .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                    .unwrap()
            };
            // Keep the endpoint plan representable while acquiring each head.
            let root = procedure("plan_root");
            let key = procedure("subject").durable_key();
            let outcome = workspace
                .semantic_oracle_provider()
                .procedure_relations(
                    &root,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .unwrap();
            let status = SemanticInputStatus::from_outcome(&outcome);
            let snapshot = outcome.available_value().cloned().unwrap();
            let relation = snapshot.relations().last().expect("return relation");
            let point = relation.point.clone();
            let source = ValueFlowSourceSpec::new(
                ValueFlowEventKey::at_point(&point, 0, ValueFlowEventKind::Source).unwrap(),
                point.clone(),
                ValueFlowObservationPhase::BeforeEffects,
                ValueFlowCarrier::from(&relation.source),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            );
            let sink = ValueFlowSinkSpec::new(
                ValueFlowEventKey::at_point(&point, 0, ValueFlowEventKind::Sink).unwrap(),
                point,
                ValueFlowObservationPhase::AfterEffects,
                ValueFlowCarrier::from(&relation.target),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            );
            let plan = ValueFlowPlan::try_new(
                root.clone(),
                vec![ValueFlowInput::new(snapshot, status)],
                Vec::new(),
                vec![source],
                vec![sink],
            )
            .unwrap();
            let make = |bytes| {
                UnitCompositionProvider::new(
                    &workspace,
                    WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
                    &plan,
                    SemanticExecutionBudget::new(8),
                    128,
                    bytes,
                )
            };
            let query = |provider: &mut UnitCompositionProvider<'_>| {
                let cancellation = CancellationToken::new();
                let mut budget = SemanticBudget::default();
                let head = <UnitCompositionProvider<'_> as crate::taint::compose::CompositionProvider>::partial_flows(
                    provider, &key, &mut SemanticRequest::new(&mut budget, &cancellation),
                ).unwrap();
                assert_eq!(head.may_omit_flows(), incomplete, "{head:?}");
                assert_eq!(head.outcome, PartialFlowOutcome::Complete, "{head:?}");
                head
            };
            let retained = |provider: &UnitCompositionProvider<'_>| {
                let retained = provider
                    .partial
                    .account(|entries| usize::from(!entries.borrow().is_empty()))
                    != 0;
                if !retained {
                    assert!(
                        provider
                            .discovery
                            .artifacts
                            .account(|artifacts| artifacts.borrow().len())
                            == 0,
                        "rejected fill retained local artifact refs"
                    );
                    assert_eq!(provider.memo_budget.remaining.get(), usize::MAX);
                }
                retained
            };
            assert_memo_owner_conformance_for_test(
                QueryMemoOwner::CompositionPartialFlow,
                workspace.analyzer(),
                || make(usize::MAX),
                query,
                retained,
            );
            let mut zero = make(0);
            let first = query(&mut zero);
            let second = query(&mut zero);
            assert!(
                !Arc::ptr_eq(&first, &second),
                "zero-quota retry must rebuild"
            );
            assert_eq!(*first, *second);
            assert_eq!(zero.partial.account(|entries| entries.borrow().len()), 0);
            assert_eq!(zero.memo_budget.remaining.get(), 0);
        }
    }

    #[test]
    fn durable_candidate_call_locators_refuse_cross_interpretation() {
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget};
        use crate::value_flow::ValueFlowCache;
        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname=\"locator-test\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n")
            .file("src/lib.rs", "fn sink(x:u32)->u32{x} fn emit(value:u32){log::info!(\"{}\",sink(value));} fn caller(){emit(1);}")
            .build();
        let filesystem = crate::analyzer::FilesystemProject::new(project.root()).unwrap();
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::new(filesystem), AnalyzerConfig::default())
                .unwrap();
        let _scope = AnalyzerQueryScope::new(workspace.analyzer());
        let live = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &live);
        let artifact = workspace
            .materialize_program_semantics(&project.file("src/lib.rs"), &mut request)
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let base = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("emit")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .unwrap();
        let discovery = WorkspaceCompositionDiscovery::new(
            &workspace,
            WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
        );
        let selected = discovery
            .selected_procedure(&base.durable_key(), &mut request)
            .unwrap();
        assert!(selected.is_candidate_alternate());
        let base_call = base
            .call_site_handle(base.semantics().call_sites()[0].id)
            .unwrap();
        let alternate_call = selected
            .call_site_handle(selected.semantics().call_sites()[0].id)
            .unwrap();
        for refusal in [
            alternate_call
                .durable_locator()
                .validate_owner(&base)
                .unwrap_err(),
            base_call
                .durable_locator()
                .validate_owner(&selected)
                .unwrap_err(),
        ] {
            assert!(matches!(refusal, crate::analyzer::semantic::ProcedureLocalLocatorError::CandidateAlternateLocatorUntranslated { .. }));
        }
        for refusal in [
            base.resolve_durable_call(&alternate_call.durable_key())
                .unwrap_err(),
            selected
                .resolve_durable_call(&base_call.durable_key())
                .unwrap_err(),
        ] {
            assert_eq!(refusal.label(), "candidate_alternate_locator_untranslated");
        }
        assert!(
            base.resolve_durable_call(&base_call.durable_key())
                .unwrap()
                .is_some()
        );
        assert!(
            selected
                .resolve_durable_call(&alternate_call.durable_key())
                .unwrap()
                .is_some()
        );
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
            .unwrap();
        let call = caller
            .call_site_handle(caller.semantics().call_sites()[0].id)
            .unwrap();
        let dispatch = discovery.resolve_call(&call, &mut request).unwrap();
        let candidate = &dispatch.available_value().unwrap().candidates()[0];
        let resealed = crate::analyzer::semantic::service::reseal_selected_candidate(
            candidate,
            &call,
            &selected,
            crate::analyzer::semantic::OracleLimits::default(),
        )
        .unwrap();
        let bindings = discovery
            .call_bindings(&call, &resealed, &OracleCallContext::empty(), &mut request)
            .unwrap();
        let bindings = bindings.available_value().unwrap();
        assert_eq!(bindings.callee(), &selected);
        assert!(bindings.callee().is_candidate_alternate());
        assert!(!bindings.bindings().is_empty());
    }

    #[test]
    fn selected_caller_and_callee_keep_executable_identities() {
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget};
        use crate::value_flow::ValueFlowCache;
        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname=\"locator-test\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n")
            .file("src/lib.rs", "fn sink(x:u32)->u32{x} fn emit(value:u32){log::info!(\"{}\",sink(value));} fn caller(){log::info!(\"{}\",{emit(1);1});}")
            .build();
        let filesystem = crate::analyzer::FilesystemProject::new(project.root()).unwrap();
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::new(filesystem), AnalyzerConfig::default())
                .unwrap();
        let _scope = AnalyzerQueryScope::new(workspace.analyzer());
        let live = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &live);
        let artifact = workspace
            .materialize_program_semantics(&project.file("src/lib.rs"), &mut request)
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let base = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("emit")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .unwrap();
        let discovery = WorkspaceCompositionDiscovery::new(
            &workspace,
            WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
        );
        let selected = discovery
            .selected_procedure(&base.durable_key(), &mut request)
            .unwrap();
        assert!(selected.is_candidate_alternate());
        let base_call = base
            .call_site_handle(base.semantics().call_sites()[0].id)
            .unwrap();
        let alternate_call = selected
            .call_site_handle(selected.semantics().call_sites()[0].id)
            .unwrap();
        for refusal in [
            alternate_call
                .durable_locator()
                .validate_owner(&base)
                .unwrap_err(),
            base_call
                .durable_locator()
                .validate_owner(&selected)
                .unwrap_err(),
        ] {
            assert!(matches!(refusal, crate::analyzer::semantic::ProcedureLocalLocatorError::CandidateAlternateLocatorUntranslated { .. }));
        }
        for refusal in [
            base.resolve_durable_call(&alternate_call.durable_key())
                .unwrap_err(),
            selected
                .resolve_durable_call(&base_call.durable_key())
                .unwrap_err(),
        ] {
            assert_eq!(refusal.label(), "candidate_alternate_locator_untranslated");
        }
        assert!(
            base.resolve_durable_call(&base_call.durable_key())
                .unwrap()
                .is_some()
        );
        assert!(
            selected
                .resolve_durable_call(&alternate_call.durable_key())
                .unwrap()
                .is_some()
        );
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
            .unwrap();
        let selected_caller = discovery
            .selected_procedure(&caller.durable_key(), &mut request)
            .unwrap();
        assert!(selected_caller.is_candidate_alternate());
        let row = selected_caller
            .semantics()
            .call_sites()
            .iter()
            .find(|row| {
                let call = selected_caller.call_site_handle(row.id).unwrap();
                let outcome = discovery.resolve_call(&call, &mut request).unwrap();
                outcome.available_value().is_some_and(|dispatch| {
                    dispatch
                        .candidates()
                        .iter()
                        .any(|candidate| candidate.target().id() == base.id())
                })
            })
            .unwrap();
        let span = selected_caller
            .semantics()
            .source_mapping(row.source)
            .unwrap()
            .locator
            .anchor()
            .span();
        let matched = matching_calls(
            &discovery,
            &artifact,
            (span.start_byte() as usize, span.end_byte() as usize),
            &mut request,
        )
        .unwrap();
        let (matched_owner, call) = matched
            .into_iter()
            .find(|(_, call)| call.id() == row.id)
            .unwrap();
        assert_eq!(matched_owner.durable_key(), selected_caller.durable_key());
        assert!(call.procedure().is_candidate_alternate());
        let refusal = call_structure::resolve_call_structure(
            &discovery,
            &caller
                .call_site_handle(caller.semantics().call_sites()[0].id)
                .unwrap()
                .durable_key(),
            &mut request,
        )
        .err()
        .unwrap();
        assert!(
            refusal
                .to_string()
                .contains("candidate_alternate_locator_untranslated")
        );
        let raw =
            call_structure::resolve_call_structure(&discovery, &call.durable_key(), &mut request)
                .unwrap();
        let projected = dispatch_from_structure(
            &discovery,
            &UnitCallModels::new(&workspace),
            raw,
            &mut request,
        )
        .unwrap();
        assert!(projected.handle.procedure().is_candidate_alternate());
        assert!(
            projected
                .dispatch
                .candidates
                .iter()
                .any(|candidate| candidate.procedure == selected.durable_key())
        );
        let dispatch = discovery.resolve_call(&call, &mut request).unwrap();
        let candidate = &dispatch.available_value().unwrap().candidates()[0];
        let resealed = crate::analyzer::semantic::service::reseal_selected_candidate(
            candidate,
            &call,
            &selected,
            crate::analyzer::semantic::OracleLimits::default(),
        )
        .unwrap();
        let bindings = discovery
            .call_bindings(&call, &resealed, &OracleCallContext::empty(), &mut request)
            .unwrap();
        let bindings = bindings.available_value().unwrap();
        assert_eq!(bindings.callee(), &selected);
        assert!(bindings.callee().is_candidate_alternate());
        assert!(!bindings.bindings().is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10972+#11826+#11842: composition paired base flows or memoized gaps with another interpretation"
    )]
    fn composition_candidate_pair_and_receipt() {
        use crate::analyzer::i_analyzer::QueryReadReceipt;
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticEffect};
        use crate::value_flow::ValueFlowCache;
        for (prefix, dependency, alternate, handle_first) in [
            ("", "log=\"0.4\"", true, true),
            ("", "log=\"0.4\"", true, false),
            ("", "log={package=\"other\",version=\"0.4\"}", false, true),
            ("mod fake {}", "log=\"0.4\"", false, true),
        ] {
            let source = format!(
                "{prefix}\nfn sink(x:u32)->u32 {{x}}\nfn emit(mut target:u32, value:u32) {{ log::info!(\"{{}}\", sink(log::debug!(\"{{}}\", {{target=value;value}}))); }}"
            );
            let source = if prefix.is_empty() {
                source
            } else {
                format!(
                    "{prefix}\nfn sink(x:u32)->u32 {{x}}\nfn emit(mut target:u32, value:u32) {{ use crate::fake as log; log::info!(\"{{}}\", sink({{ log::debug!(\"{{}}\", {{target=value;value}}) }})); }}"
                )
            };
            let project = InlineTestProject::with_language(Language::Rust)
                .file("Cargo.toml", format!("[package]\nname=\"pair-test\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\n{dependency}\n"))
                .file("src/lib.rs", &source).build();
            let filesystem = crate::analyzer::FilesystemProject::new(project.root()).unwrap();
            let workspace =
                WorkspaceAnalyzer::build_persisted(Arc::new(filesystem), AnalyzerConfig::default())
                    .unwrap();
            let _scope = AnalyzerQueryScope::new(workspace.analyzer());
            let live = CancellationToken::default();
            let artifact = workspace
                .materialize_program_semantics(
                    &project.file("src/lib.rs"),
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
                )
                .unwrap()
                .available_value()
                .cloned()
                .unwrap();
            let id = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("emit")
                })
                .unwrap()
                .id();
            let base = artifact.procedure_handle(id).unwrap();
            let discovery = WorkspaceCompositionDiscovery::new(
                &workspace,
                WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
            );
            let base_flows = workspace.stored_partial_flows(&base).unwrap().unwrap();
            let assignment_count = |handle: &ProcedureHandle| {
                handle
                    .semantics()
                    .points()
                    .iter()
                    .flat_map(|point| &point.events)
                    .filter(|event| matches!(event.effect, SemanticEffect::Assignment { .. }))
                    .count()
            };
            let acquire_handle = || {
                workspace
                    .selected_procedure_handle(
                        &base,
                        &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
                    )
                    .unwrap()
                    .available_value()
                    .cloned()
                    .unwrap()
            };
            let mut handle = handle_first.then(acquire_handle);
            let mut first = None;
            for alternate_entry in [false, true] {
                let entry = if alternate_entry {
                    handle
                        .as_ref()
                        .expect("the first pair selected a handle")
                        .handle
                        .clone()
                } else {
                    base.clone()
                };
                let (pair, reads) = QueryReadReceipt::capture(workspace.analyzer(), || {
                    discovery
                        .selected_procedure_and_flows(
                            &entry.durable_key(),
                            &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
                        )
                        .unwrap()
                });
                let handle = handle.get_or_insert_with(acquire_handle);
                assert_eq!(handle.handle, pair.procedure);
                assert_eq!(handle.side, pair.side);
                assert_eq!(
                    pair.procedure.is_candidate_alternate(),
                    alternate,
                    "{prefix} {dependency}"
                );
                assert_eq!(
                    pair.procedure.semantics().call_sites().len()
                        > base.semantics().call_sites().len(),
                    alternate
                );
                assert_eq!(
                    assignment_count(&pair.procedure) > assignment_count(&base),
                    alternate
                );
                if alternate {
                    assert!(pair.flows.ports.len() > base_flows.ports.len());
                } else {
                    assert_eq!(pair.flows, base_flows);
                }
                // Dense call IDs in flow ports must belong to this interpretation.
                for port in &pair.flows.ports {
                    if let PartialFlowPort::CallReceiver { call }
                    | PartialFlowPort::CallArgument { call, .. }
                    | PartialFlowPort::CallResult { call, .. }
                    | PartialFlowPort::CallThrown { call } = port
                    {
                        assert!(pair.procedure.semantics().call_site(*call).is_some());
                    }
                }
                let (_, replay) = QueryReadReceipt::capture(workspace.analyzer(), || {
                    pair.admissions.replay(workspace.analyzer())
                });
                assert_eq!(reads.digest(), replay.digest());
                if alternate {
                    let execution = SemanticExecutionBudget::new(8);
                    let sweep = |h: &ProcedureHandle| {
                        openness_sweep(
                            &discovery,
                            h,
                            &execution,
                            &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
                        )
                        .unwrap()
                    };
                    let expected = [sweep(&base), sweep(&pair.procedure)];
                    assert_ne!(expected[0], expected[1]);
                    assert_ne!(base.durable_key(), pair.procedure.durable_key());
                    let plan = ValueFlowPlan::try_new(
                        base.clone(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    )
                    .unwrap();
                    let mut classifications = None;
                    for order in [[0, 1], [1, 0]] {
                        // Prefetch each interpretation before classification through either alias.
                        let provider = UnitCompositionProvider {
                            discovery: WorkspaceCompositionDiscovery::new(
                                &workspace,
                                WorkspaceValueFlowProvider::new(
                                    &workspace,
                                    ValueFlowCache::default(),
                                ),
                            ),
                            models: UnitCallModels::new(&workspace),
                            plan: &plan,
                            execution_budget: SemanticExecutionBudget::new(8),
                            max_callers: 128,
                            attribution: workspace_memo_attribution(&workspace),
                            memo_budget: Rc::new(CompositionMemoBudget::new(usize::MAX)),
                            partial: ReplayingMemo::new(RefCell::new(HashMap::new())),
                            dispatches: ReplayingMemo::new(RefCell::new(HashMap::new())),
                            sweeps: ReplayingMemo::new(RefCell::new(HashMap::new())),
                            openness: ReplayingMemo::new(RefCell::new(HashMap::new())),
                            excluded_callers: RefCell::new(Vec::new()),
                        };
                        for index in order {
                            let handle = [&base, &pair.procedure][index];
                            assert_eq!(
                                provider
                                    .openness_sweep(
                                        handle,
                                        &mut SemanticRequest::new(
                                            &mut SemanticBudget::default(),
                                            &live
                                        )
                                    )
                                    .unwrap(),
                                expected[index]
                            );
                        }
                        let answers = [&base, &pair.procedure].map(|entry| {
                            let (answer, receipt) =
                                QueryReadReceipt::capture(workspace.analyzer(), || {
                                    decide_openness(
                                        &provider.discovery,
                                        &provider,
                                        &entry.durable_key(),
                                        &mut SemanticRequest::new(
                                            &mut SemanticBudget::default(),
                                            &live,
                                        ),
                                    )
                                    .unwrap()
                                });
                            (format!("{answer:?}"), receipt.digest())
                        });
                        assert_eq!(answers[0], answers[1]);
                        if let Some(previous) = &classifications {
                            assert_eq!(previous, &answers);
                        }
                        classifications = Some(answers);
                        let stopped = CancellationToken::default();
                        stopped.cancel();
                        assert!(
                            decide_openness(
                                &provider.discovery,
                                &provider,
                                &entry.durable_key(),
                                &mut SemanticRequest::new(&mut SemanticBudget::default(), &stopped)
                            )
                            .is_err()
                        );
                    }
                }
                let signature = (
                    pair.procedure.is_candidate_alternate(),
                    pair.flows,
                    pair.admissions.digest(),
                );
                if let Some(first) = &first {
                    assert_eq!(first, &signature);
                }
                first = Some(signature);
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11935: a cancelled admission left a stale Complete(Base) for a later live request"
    )]
    fn cancelled_candidate_admission_is_not_retained_in_root_query() {
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget};

        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname=\"pair-test\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n")
            .file("src/lib.rs", "fn sink(x:u32)->u32 {x}\nfn emit(mut target:u32, value:u32) { log::info!(\"{}\", sink(log::debug!(\"{}\", {target=value;value}))); }\n")
            .build();
        let filesystem = crate::analyzer::FilesystemProject::new(project.root()).unwrap();
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::new(filesystem), AnalyzerConfig::default())
                .unwrap();
        let _scope = AnalyzerQueryScope::new(workspace.analyzer());
        let live = CancellationToken::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("src/lib.rs"),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let base = artifact
            .procedures()
            .iter()
            .find(|p| {
                p.locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|s| s.name())
                    == Some("emit")
            })
            .map(|p| artifact.procedure_handle(p.id()).unwrap())
            .unwrap();
        // Warm the retained arena in a separate root; admission must still run
        // in the fresh root below.
        workspace
            .selected_procedure_handle(
                &base,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
            )
            .unwrap();
        drop(_scope);
        let _scope = AnalyzerQueryScope::new(workspace.analyzer());
        // Wrapper entry and the two publication checks pass, then the
        // selection entry check passes; the first candidate check cancels.
        let cancelled = CancellationToken::cancel_after_checks_for_test(5);
        let result = workspace
            .selected_procedure_handle(
                &base,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancelled),
            )
            .unwrap();
        assert!(matches!(
            result,
            crate::analyzer::semantic::SemanticOutcome::Cancelled { .. }
        ));
        let _live_answer =
            AnalyzerQueryScope::independent_answer(workspace.analyzer(), Some(&live));
        let outcome = workspace
            .selected_procedure_handle(
                &base,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
            )
            .unwrap();
        let selected = outcome.available_value().unwrap();
        assert!(selected.handle.is_candidate_alternate());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11910: a selected alternate handle passed back in missed its base's pinned selection"
    )]
    fn selected_alternate_handle_finds_its_pinned_selection() {
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget};

        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname=\"pair-test\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n")
            .file("src/lib.rs", "fn sink(x:u32)->u32 {x}\nfn emit(mut target:u32, value:u32) { log::info!(\"{}\", sink(log::debug!(\"{}\", {target=value;value}))); }\n")
            .build();
        let filesystem = crate::analyzer::FilesystemProject::new(project.root()).unwrap();
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::new(filesystem), AnalyzerConfig::default())
                .unwrap();
        let _scope = AnalyzerQueryScope::new(workspace.analyzer());
        let live = CancellationToken::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("src/lib.rs"),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let base = artifact
            .procedures()
            .iter()
            .find(|p| {
                p.locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|s| s.name())
                    == Some("emit")
            })
            .map(|p| artifact.procedure_handle(p.id()).unwrap())
            .unwrap();
        let first = workspace
            .selected_procedure_handle(
                &base,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
            )
            .unwrap();
        let alternate = first.available_value().unwrap().handle.clone();
        assert!(alternate.is_candidate_alternate());
        // Wrapper entry, publication and selection entry checks pass; a rerun
        // of admission would cancel at its first candidate check. The pinned
        // selection must be found instead.
        let _answer = AnalyzerQueryScope::independent_answer(workspace.analyzer(), Some(&live));
        let cancelling = CancellationToken::cancel_after_checks_for_test(5);
        let again = workspace
            .selected_procedure_handle(
                &alternate,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancelling),
            )
            .unwrap();
        let again = again.available_value().expect("the pinned selection");
        assert_eq!(again.handle, alternate);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11910: a budget-stopped selection was retained for the rest of the root query"
    )]
    fn budget_stopped_candidate_selection_is_not_retained_in_root_query() {
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticWork};

        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname=\"pair-test\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n")
            .file("src/lib.rs", "fn sink(x:u32)->u32 {x}\nfn emit(mut target:u32, value:u32) { log::info!(\"{}\", sink(log::debug!(\"{}\", {target=value;value}))); }\n")
            .build();
        let filesystem = crate::analyzer::FilesystemProject::new(project.root()).unwrap();
        let workspace =
            WorkspaceAnalyzer::build_persisted(Arc::new(filesystem), AnalyzerConfig::default())
                .unwrap();
        let live = CancellationToken::default();
        let base = {
            let _scope = AnalyzerQueryScope::new(workspace.analyzer());
            let artifact = workspace
                .materialize_program_semantics(
                    &project.file("src/lib.rs"),
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
                )
                .unwrap()
                .available_value()
                .cloned()
                .unwrap();
            artifact
                .procedures()
                .iter()
                .find(|p| {
                    p.locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|s| s.name())
                        == Some("emit")
                })
                .map(|p| artifact.procedure_handle(p.id()).unwrap())
                .unwrap()
        };
        let starved = |call_sites: usize| {
            SemanticBudget::new(SemanticWork {
                call_sites,
                ..SemanticWork::default_limits()
            })
            .unwrap()
        };
        // The largest call-site limit that still stops the acquisition is the
        // last budget check before a selection exists: candidate admission.
        // Each probe runs in its own root, so no probe sees another's table.
        let stops = |call_sites: usize| {
            let _probe = AnalyzerQueryScope::new(workspace.analyzer());
            matches!(
                workspace
                    .selected_procedure_handle(
                        &base,
                        &mut SemanticRequest::new(&mut starved(call_sites), &live),
                    )
                    .unwrap(),
                crate::analyzer::semantic::SemanticOutcome::ExceededBudget { .. }
            )
        };
        let (mut stopping, mut selecting) = (1, SemanticWork::default_limits().call_sites);
        assert!(stops(stopping) && !stops(selecting));
        while selecting - stopping > 1 {
            let middle = stopping + (selecting - stopping) / 2;
            if stops(middle) {
                stopping = middle;
            } else {
                selecting = middle;
            }
        }
        // One root query: the admission-stopped acquisition, then a
        // default-budget one, which must run admission and select.
        let _scope = AnalyzerQueryScope::new(workspace.analyzer());
        let mut starved = starved(stopping);
        let stopped = workspace
            .selected_procedure_handle(&base, &mut SemanticRequest::new(&mut starved, &live))
            .unwrap();
        assert!(
            matches!(
                stopped,
                crate::analyzer::semantic::SemanticOutcome::ExceededBudget { .. }
            ),
            "{stopped:?}"
        );
        let _answer = AnalyzerQueryScope::independent_answer(workspace.analyzer(), Some(&live));
        let outcome = workspace
            .selected_procedure_handle(
                &base,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
            )
            .unwrap();
        let selected = outcome.available_value().unwrap();
        assert!(selected.handle.is_candidate_alternate());
    }

    #[test]
    fn composition_memo_hits_replay_reads_for_each_answer_shape() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("main.rs", "pub fn caller() { leaf(); } fn leaf() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let attribution = workspace_memo_attribution(&workspace);
        // The answer shapes include an empty result and an ordered result.
        for (class, answer) in [
            ("summary", vec![1]),
            ("local", vec![2]),
            ("dispatch", vec![3]),
            ("openness", vec![4]),
            ("sweep", Vec::new()),
            ("ordered", vec![5, 6]),
        ] {
            let memo = ReplayingMemo::new(RefCell::new(HashMap::new()));
            let key = ReadKey::Models(StableDigest::sha256(class.as_bytes()));
            let mut built = 0;
            let mut access = || {
                memo.read(&attribution.capability(), |entries, capture| {
                    if let Some(entry) = entries.borrow().get(&0).cloned() {
                        return Ok::<_, ()>(entry);
                    }
                    built += 1;
                    let entry = Arc::new(capture.build(|| {
                        workspace.analyzer().record_read(key.clone());
                        answer.clone()
                    }));
                    entries.borrow_mut().insert(0, Arc::clone(&entry));
                    Ok(entry)
                })
                .expect("memo access")
                .to_vec()
            };
            let (first, first_reads) = capture_query_reads(workspace.analyzer(), &mut access);
            let (second, second_reads) = capture_query_reads(workspace.analyzer(), &mut access);
            assert_eq!(first, second, "{class}");
            assert_eq!(built, 1, "{class} must hit");
            assert_eq!(first_reads.keys(), second_reads.keys(), "{class}");
            assert!(second_reads.keys().contains(&key), "{class}");
        }
    }

    #[test]
    fn zero_composition_budget_never_retains_an_answer_or_loses_its_reads() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("main.rs", "pub fn caller() { leaf(); } fn leaf() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let attribution = workspace_memo_attribution(&workspace);
        let memo = ReplayingMemo::new(RefCell::new(HashMap::new()));
        let budget = CompositionMemoBudget::new(0);
        let key = ReadKey::Models(StableDigest::sha256(b"zero budget"));
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(workspace.analyzer(), || {
                memo.read(&attribution.capability(), |entries, capture| {
                    assert!(entries.borrow().is_empty());
                    let entry = capture.build_weighted(|| {
                        workspace.analyzer().record_read(key.clone());
                        ((), 1)
                    });
                    Ok::<_, ()>(admit_composition_entry(entries, &0, entry, &budget, false))
                })
                .expect("zero budget access");
            });
            assert!(reads.keys().contains(&key));
        }
        assert_eq!(memo.account(|entries| entries.borrow().len()), 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9746: review found the ordered memo charged only outer vectors of retained procedure rows"
    )]
    fn ordered_parts_nested_rows_exceed_memo_budget() {
        use crate::analyzer::semantic::{
            CallReceiverTypeFact, CallSiteId, EvidenceId, ProcedureId, ProcedureKind,
            ProcedureSemanticsParts, SourceMappingId, SourcePosition, SourceSpan,
            procedure_parts_retained_bytes,
        };
        let position = SourcePosition::new(0, 0, 0);
        let span = SourceSpan::new(position, position).unwrap();
        let locator = crate::test_support::function_locator(
            "memo",
            "main.rs",
            Language::Rust,
            crate::analyzer::semantic::SemanticRole::Procedure,
            "caller",
            span,
        );
        let mut parts = ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            locator,
            ProcedureKind::Function,
            SourceMappingId::new(0),
            EvidenceId::new(0),
        );
        parts.receiver_type_facts.push(CallReceiverTypeFact {
            call_site: CallSiteId::new(0),
            receiver_type: vec!["segment".into(); 2_000].into_boxed_slice(),
            member: "call".into(),
        });
        let outer_bytes = std::mem::size_of::<Option<ProcedureSemanticsParts>>()
            + parts.receiver_type_facts.capacity() * std::mem::size_of::<CallReceiverTypeFact>();
        let retained_bytes = std::mem::size_of::<Option<ProcedureSemanticsParts>>()
            + procedure_parts_retained_bytes(&parts);
        assert!(retained_bytes > outer_bytes);
        let budget = CompositionMemoBudget::new(outer_bytes + 1);
        let memo = RefCell::new(HashMap::new());
        let project = InlineTestProject::with_language(Language::Rust)
            .file("main.rs", "pub fn caller() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let attribution = workspace_memo_attribution(&workspace);
        let memo = ReplayingMemo::new(memo);
        memo.read(&attribution.capability(), |entries, capture| {
            let entry = capture.build_weighted(|| (parts, retained_bytes));
            Ok::<_, ()>(admit_composition_entry(entries, &0, entry, &budget, false))
        })
        .unwrap();
        assert_eq!(memo.account(|entries| entries.borrow().len()), 0);
    }

    #[test]
    fn retained_composition_memo_hit_replays_refusal() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("main.rs", "pub fn caller() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let attribution = workspace_memo_attribution(&workspace);
        let memo = ReplayingMemo::new(RefCell::new(HashMap::new()));
        let access = || {
            memo.read(&attribution.capability(), |entries, capture| {
                if let Some(entry) = entries.borrow().get(&0).cloned() {
                    return Ok::<_, ()>(entry);
                }
                let entry = Arc::new(capture.build(|| {
                    workspace.analyzer().refuse_read_reuse();
                    7
                }));
                entries.borrow_mut().insert(0, Arc::clone(&entry));
                Ok(entry)
            })
            .expect("refused memo access")
            .to_owned()
        };
        let (first, first_reads) = capture_query_reads(workspace.analyzer(), access);
        let (second, second_reads) = capture_query_reads(workspace.analyzer(), access);
        assert_eq!((first, second), (7, 7));
        assert!(first_reads.reuse_refused());
        assert!(second_reads.reuse_refused());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11953: a warm composition artifact hit dropped its fill's semantic-model read"
    )]
    fn warm_procedure_lookup_keeps_the_artifact_fill_reads() {
        use crate::analyzer::semantic::{CancellationToken, SemanticBudget};
        use crate::analyzer::{
            ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
            verify_read_set,
        };
        use crate::value_flow::ValueFlowCache;
        let project = InlineTestProject::with_language(Language::Rust)
            .file("main.rs", "pub fn caller() { leaf(); } fn leaf() {}\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let live = CancellationToken::default();
        let key = {
            let artifact = workspace
                .materialize_program_semantics(
                    &project.file("main.rs"),
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
                )
                .unwrap()
                .available_value()
                .cloned()
                .unwrap();
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
                .unwrap()
                .id();
            artifact.procedure_handle(caller).unwrap().durable_key()
        };
        // Both lookups run in one root query, so the second hits the memo.
        let _scope = AnalyzerQueryScope::new(workspace.analyzer());
        let discovery = WorkspaceCompositionDiscovery::new(
            &workspace,
            WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default()),
        );
        let lookup = || {
            capture_query_reads(workspace.analyzer(), || {
                discovery
                    .procedure(
                        &key,
                        &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
                    )
                    .unwrap()
            })
            .1
            .keys()
        };
        let cold = lookup();
        let warm = lookup();
        assert_eq!(discovery.artifacts.account(|memo| memo.borrow().len()), 1);
        let models = cold
            .iter()
            .find_map(|key| match key {
                ReadKey::Models(models) => Some(*models),
                _ => None,
            })
            .unwrap_or_else(|| panic!("the fill reads the active model set: {cold:#?}"));
        assert_eq!(cold, warm);

        // A product validated from the warm receipt sees a model-set change.
        let placeholder = StableDigest::sha256(b"inputs this lookup does not read");
        let verify = |models| {
            verify_read_set(
                &workspace,
                &ChangedFacts::between(&workspace, &workspace),
                &HeadInputs {
                    models,
                    policy_semantic_hash: placeholder,
                    policy_source: placeholder,
                    configuration: placeholder,
                    epoch: placeholder,
                },
                &warm,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        };
        assert!(verify(models).is_unchanged(), "{:?}", verify(models));
        let activated = verify(StableDigest::sha256(b"a pack was activated"));
        assert_eq!(
            activated.changed().map(|changed| &changed.key),
            Some(&ReadKey::Models(models)),
            "{activated:?}"
        );
    }
}

#[cfg(test)]
mod promotion_cause_tests {
    use super::*;

    #[test]
    fn only_a_request_stop_or_truncation_keeps_the_promotion_operational() {
        let budget = IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic));
        let exceeded = SemanticInputStatus::ExceededBudget {
            exceeded: crate::analyzer::semantic::SemanticBudgetExceeded::new(
                crate::analyzer::semantic::SemanticBudgetDimension::Procedures,
                1,
                2,
            ),
        };
        let cause = file_local_promotion_cause;
        // The head's own derivation is content whatever its status reads.
        for status in [
            SemanticInputStatus::Complete,
            SemanticInputStatus::Ambiguous,
            SemanticInputStatus::Unknown,
            SemanticInputStatus::Unproven,
            SemanticInputStatus::Unsupported {
                capability: SemanticCapability::Values,
            },
        ] {
            assert_eq!(
                cause(PartialFlowOutcome::Complete, status, false),
                IncompleteCause::Content
            );
        }
        assert_eq!(cause(PartialFlowOutcome::Complete, exceeded, false), budget);
        // A truncated candidate set or a lowering budget gap.
        assert_eq!(
            cause(
                PartialFlowOutcome::Complete,
                SemanticInputStatus::Unproven,
                true
            ),
            budget
        );
        assert_eq!(
            cause(
                PartialFlowOutcome::Complete,
                SemanticInputStatus::Cancelled,
                false
            ),
            IncompleteCause::Operational(OperationalCause::Cancelled)
        );
        // The less stable of the head and the projection wins.
        assert_eq!(
            cause(
                PartialFlowOutcome::ExceededBudget,
                SemanticInputStatus::Unknown,
                false
            ),
            budget
        );
        assert_eq!(
            cause(
                PartialFlowOutcome::Truncated,
                SemanticInputStatus::Unknown,
                false
            ),
            budget
        );
        assert_eq!(
            cause(PartialFlowOutcome::Error, exceeded, false),
            IncompleteCause::Operational(OperationalCause::Provider)
        );
        assert_eq!(
            cause(
                PartialFlowOutcome::Error,
                SemanticInputStatus::Cancelled,
                false
            ),
            IncompleteCause::Operational(OperationalCause::Cancelled)
        );
    }
}

#[cfg(test)]
mod return_demand_tests {
    use super::*;
    use crate::analyzer::semantic::AccessPathTail;
    use crate::analyzer::semantic::partial_flow::ports::{HeapSelector, PortId};
    use crate::analyzer::semantic::partial_flow::{PartialFlow, PartialFlowOutcome};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#11268: unused callee tuple members incorrectly opened caller coverage")]
    fn returned_members_follow_caller_consumption() {
        let result = PartialFlowPort::CallResult {
            call: CallSiteId::new(0),
            ordinal: None,
        };
        let member = |root: PartialFlowPort, name: &str| PartialFlowPort::Heap {
            root: Box::new(root),
            selectors: vec![HeapSelector::Property(name.into())].into_boxed_slice(),
            tail: AccessPathTail::Exact,
        };
        let callee = vec![
            member(PartialFlowPort::NormalReturn, "a"),
            member(PartialFlowPort::NormalReturn, "b"),
        ];
        let returns = vec![(PartialFlowPort::NormalReturn, result.clone())];
        let make_rows = |ports, flows| {
            ProcedurePartialFlows::new(
                PartialFlowOutcome::Complete,
                None,
                ports,
                flows,
                false,
                true,
                Vec::new(),
            )
        };
        let mut caller = make_rows(vec![result.clone(), member(result.clone(), "a")], vec![]);
        assert!(returned_members_bound(&callee, &caller, &returns, |_| None));
        // Each boundary use of the whole value demands both members. Unknown
        // destinations obey the same rule, without a destination allowlist.
        for destination in [
            PartialFlowPort::CallArgument {
                call: CallSiteId::new(1),
                ordinal: 0,
            },
            member(PartialFlowPort::Parameter { ordinal: 0 }, "stored"),
            PartialFlowPort::NormalReturn,
            PartialFlowPort::Capture {
                slot: crate::analyzer::semantic::MemoryLocationId::new(0),
            },
        ] {
            caller.ports.push(destination);
            caller.flows.push(PartialFlow {
                from: PortId::new(0),
                to: PortId::new(2),
                uncertain: false,
                crossed: vec![Box::default()].into_boxed_slice(),
            });
            assert!(!returned_members_bound(&callee, &caller, &returns, |_| {
                None
            }));
            caller.ports.push(member(result.clone(), "b"));
            assert!(returned_members_bound(&callee, &caller, &returns, |_| None));
            caller.ports.truncate(2);
            caller.flows.clear();
        }
        caller.ports.push(member(result, "unmatched"));
        assert!(!returned_members_bound(&callee, &caller, &returns, |_| {
            None
        }));
    }
}
