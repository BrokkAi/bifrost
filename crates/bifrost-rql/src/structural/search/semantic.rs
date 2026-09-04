use std::mem::{align_of, size_of};
use std::sync::Arc;

use super::concurrency::{ConcurrentAccessConflictValue, WorkspaceConcurrencyProvider};
use super::taint::{SemanticTaintFindingValue, TaintQueryState};
use super::typestate::{SemanticTypestateFindingValue, TypestateQueryState};
use super::value_flow::{SemanticFlowEndpointValue, SemanticFlowWitnessValue, ValueFlowQueryState};
use super::{
    CodeQueryCallResult, CodeQueryControlEdge, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryProcedure, CodeQueryProgramPoint,
    CodeQueryProgramPointBoundary, CodeQueryProgramPointRef, CodeQueryRange,
    CodeQuerySemanticCompleteness, CodeQuerySemanticEvidence, CodeQuerySemanticLimits,
    CodeQuerySemanticProof, CodeQuerySemanticReceipt, CodeQuerySemanticRowLimits,
    CodeQuerySemanticWork, DeclarationValue, SeedMatch, seed_range,
};
use crate::analyzer::semantic::service::semantic_artifact_retained_bytes;
use crate::analyzer::semantic::workspace_oracle::{
    PreparedSourceDispatchSession, ProcedureRangeLookupStatus,
    procedures_for_definition_with_limits, procedures_for_source_ranges,
};
use crate::analyzer::semantic::{
    AllocationSite, BasicBlock, CallSiteHandle, CapabilitySupport, CaptureBinding, ContentIdentity,
    ControlEdge, ControlEdgeHandle, ControlEdgeId, DeclarationSegmentKind, DispatchBoundaryKind,
    Evidence, EvidenceCompleteness, ExecutionTiming, HeapOracle, LengthDelimitedDigest,
    MemoryLocation, ObservationPhase, OracleCallContext, ProcedureHandle, ProcedureSemantics,
    ProgramPoint, ProgramPointHandle, ProgramPointId, ProofStatus, SemanticArtifact,
    SemanticArtifactLeaseChild, SemanticArtifactLeaseError, SemanticArtifactLeaseLiveReservation,
    SemanticArtifactLeaseSet, SemanticArtifactLeaseSnapshot, SemanticArtifactLeaseWindow,
    SemanticBudget, SemanticBudgetDimension, SemanticBudgetScopeSnapshot, SemanticCallSite,
    SemanticCapability, SemanticEvent, SemanticExecutionBudget, SemanticExecutionBudgetSnapshot,
    SemanticGap, SemanticLocator, SemanticOutcome, SemanticRequest, SemanticValue, SemanticWork,
    SourceMapping, ValueAtPoint, ValueHandle, ValueId, WorkspaceIcfgProvider,
};
use crate::analyzer::semantic_model::{ActiveSemanticModelSnapshot, SemanticModelOverlay};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::structural::analysis_context::{
    ProtocolRef, QueryAnalysisContext, TaintResultRef, ValueFlowPlanRef,
};
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use brokk_bifrost_rql::WitnessTraversal;

#[derive(Debug, Clone)]
struct SemanticSourceSnapshot {
    source: Arc<str>,
    line_starts: Arc<[usize]>,
}

impl SemanticSourceSnapshot {
    fn new(source: String) -> Self {
        let line_starts = compute_line_starts(&source).into();
        Self {
            source: Arc::from(source),
            line_starts,
        }
    }

    fn retained_bytes(&self) -> usize {
        const ARC_HEADER_BYTES: usize = 2 * size_of::<usize>();
        const ALLOCATION_HEADER_BYTES: usize = 2 * size_of::<usize>();
        const ARC_ALLOCATION_PADDING_BYTES: usize = align_of::<usize>() - 1;
        size_of::<Self>()
            .saturating_add(2 * ARC_HEADER_BYTES)
            .saturating_add(2 * ALLOCATION_HEADER_BYTES)
            .saturating_add(2 * ARC_ALLOCATION_PADDING_BYTES)
            .saturating_add(self.source.len())
            .saturating_add(self.line_starts.len().saturating_mul(size_of::<usize>()))
    }
}

#[derive(Debug, Clone, Default)]
struct SemanticQueryQuality {
    proof_reason: Option<Arc<str>>,
    completeness_reason: Option<Arc<str>>,
}

impl SemanticQueryQuality {
    fn unproven_partial(reason: impl Into<Arc<str>>) -> Self {
        let reason = reason.into();
        Self {
            proof_reason: Some(Arc::clone(&reason)),
            completeness_reason: Some(reason),
        }
    }

    fn partial(reason: impl Into<Arc<str>>) -> Self {
        Self {
            proof_reason: None,
            completeness_reason: Some(reason.into()),
        }
    }

    fn combine(&self, other: &Self) -> Self {
        Self {
            proof_reason: self
                .proof_reason
                .clone()
                .or_else(|| other.proof_reason.clone()),
            completeness_reason: self
                .completeness_reason
                .clone()
                .or_else(|| other.completeness_reason.clone()),
        }
    }

    fn is_complete(&self) -> bool {
        self.proof_reason.is_none() && self.completeness_reason.is_none()
    }
}

#[derive(Debug, Clone)]
pub(super) struct SemanticProcedureValue {
    pub(super) handle: ProcedureHandle,
    file: ProjectFile,
    source: SemanticSourceSnapshot,
    quality: SemanticQueryQuality,
}

#[derive(Debug, Clone)]
pub(super) struct SemanticProgramPointValue {
    pub(super) handle: ProgramPointHandle,
    file: ProjectFile,
    source: SemanticSourceSnapshot,
    quality: SemanticQueryQuality,
}

#[derive(Debug, Clone)]
pub(super) struct SemanticControlEdgeValue {
    pub(super) handle: ControlEdgeHandle,
    file: ProjectFile,
    source: SemanticSourceSnapshot,
    quality: SemanticQueryQuality,
}

#[derive(Debug, Clone)]
pub(super) struct SemanticCallResultValue {
    pub(super) handle: CallSiteHandle,
    pub(super) ordinal: usize,
    pub(super) value: ValueId,
    pub(super) site_id: String,
    pub(super) site_ast_id: String,
    file: ProjectFile,
    source: SemanticSourceSnapshot,
    quality: SemanticQueryQuality,
}

#[derive(Debug, Clone)]
pub(super) struct ExactObjectIdentity {
    pub(super) id: String,
    pub(super) cardinality: &'static str,
}

#[derive(Debug, Clone)]
struct SemanticSourceCallCandidate {
    span: std::ops::Range<usize>,
    procedure: ProcedureHandle,
    call: CallSiteHandle,
}

#[derive(Debug, Default)]
struct SemanticSourceCallIndex {
    candidates: Box<[SemanticSourceCallCandidate]>,
}

impl SemanticSourceCallIndex {
    const ALLOCATION_HEADER_BYTES: usize = 2 * size_of::<usize>();
    const HASH_BUCKET_SLACK_BYTES: usize = 4 * size_of::<usize>();
    const ALLOCATION_PADDING_BYTES: usize = align_of::<SemanticSourceCallCandidate>() - 1;
    // Hashbrown's bucket/control layout is private. The outer cache retains at
    // most one entry for each charged index, so four bucket-widths per entry is
    // the same conservative sparse-table allowance used by semantic leases.
    const OUTER_BUCKET_SLOP: usize = 4;

    fn outer_entry_retained_bytes() -> Result<usize, SemanticArtifactLeaseError> {
        let bucket = size_of::<ProjectFile>()
            .checked_add(size_of::<Option<Self>>())
            .and_then(|bytes| bytes.checked_add(size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(Self::HASH_BUCKET_SLACK_BYTES))
            .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)?;
        Self::ALLOCATION_HEADER_BYTES
            .checked_add(
                bucket
                    .checked_mul(Self::OUTER_BUCKET_SLOP)
                    .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)?,
            )
            .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)
    }

    fn candidate_storage_retained_bytes(
        call_sites: usize,
    ) -> Result<usize, SemanticArtifactLeaseError> {
        if call_sites == 0 {
            return Ok(0);
        }
        call_sites
            .checked_mul(size_of::<SemanticSourceCallCandidate>())
            .and_then(|bytes| bytes.checked_add(Self::ALLOCATION_HEADER_BYTES))
            .and_then(|bytes| bytes.checked_add(Self::ALLOCATION_PADDING_BYTES))
            .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)
    }

    /// Exact structural-call storage plus conservative outer-map metadata,
    /// reserved before either allocation is made.
    fn reservation_bytes(call_sites: usize) -> Result<usize, SemanticArtifactLeaseError> {
        Self::outer_entry_retained_bytes()?
            .checked_add(Self::candidate_storage_retained_bytes(call_sites)?)
            .ok_or(SemanticArtifactLeaseError::RetainedBytesOverflow)
    }

    /// Physical metadata retained after this index enters the query cache.
    /// Artifact allocations reached through the handles are accounted by the
    /// exact lease set and are intentionally not charged again here.
    fn retained_bytes(&self) -> Result<usize, SemanticArtifactLeaseError> {
        Self::reservation_bytes(self.candidates.len())
    }

    fn absent_entry_retained_bytes() -> Result<usize, SemanticArtifactLeaseError> {
        Self::outer_entry_retained_bytes()
    }
}

#[derive(Debug, Clone)]
enum CachedSemanticMaterialization {
    Outcome {
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        source: Option<SemanticSourceSnapshot>,
    },
    ProviderFailed(Arc<str>),
    FileBudgetExhausted,
    RetainedBudgetExhausted,
}

struct PreparedSourceDispatchCache<'a> {
    file: ProjectFile,
    session: PreparedSourceDispatchSession<'a>,
    retained_bytes: usize,
}

pub(super) struct SemanticQueryContext<'a> {
    workspace: &'a WorkspaceAnalyzer,
    cancellation: Option<&'a CancellationToken>,
    uncancelled: CancellationToken,
    limits: CodeQuerySemanticLimits,
    typestate_limits: super::CodeQueryTypestateLimits,
    value_flow_limits: super::CodeQueryValueFlowLimits,
    taint_limits: super::CodeQueryTaintLimits,
    workspace_generation: u64,
    analysis_context: Option<&'a QueryAnalysisContext>,
    /// The activation snapshot shared by every semantic row family in this
    /// query, including each ICFG provider created on a cache miss.
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    semantic_summaries: Arc<brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository>,
    budget: SemanticBudget,
    cache: HashMap<ProjectFile, CachedSemanticMaterialization>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    reported: HashSet<(CodeQueryDiagnosticCode, ProjectFile, String)>,
    attempts: usize,
    receipt_execution: Option<(SemanticExecutionBudgetSnapshot, SemanticExecutionBudget)>,
    artifact_leases: SemanticArtifactLeaseChild,
    artifact_window: Option<SemanticArtifactLeaseWindow>,
    artifact_window_file: Option<ProjectFile>,
    initial_artifact_lease_error: Option<crate::analyzer::semantic::SemanticArtifactLeaseError>,
    promote_artifact_windows: bool,
    execution_budget_exhausted: bool,
    materialized_files: HashSet<ProjectFile>,
    cache_hits: usize,
    active_retained_bytes: usize,
    peak_retained_bytes: usize,
    traversal_steps: usize,
    indexed_source_identities: HashMap<ProjectFile, Option<ContentIdentity>>,
    source_call_indexes: HashMap<ProjectFile, Option<SemanticSourceCallIndex>>,
    prepared_source_dispatch: Option<PreparedSourceDispatchCache<'a>>,
    budget_exhausted: bool,
    typestate: TypestateQueryState,
    value_flow: ValueFlowQueryState,
    taint: TaintQueryState,
    type_flow: super::type_flow::TypeFlowQueryState,
}

impl<'a> SemanticQueryContext<'a> {
    #[cfg(test)]
    pub(super) fn new(
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
        limits: CodeQuerySemanticLimits,
    ) -> Self {
        let active_semantic_model_snapshot = workspace.analyzer().active_semantic_model_snapshot();
        Self::new_with_analysis(
            workspace,
            cancellation,
            limits,
            super::CodeQueryTypestateLimits::default(),
            super::CodeQueryValueFlowLimits::default(),
            super::CodeQueryTaintLimits::default(),
            0,
            None,
            active_semantic_model_snapshot,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_with_analysis(
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
        limits: CodeQuerySemanticLimits,
        typestate_limits: super::CodeQueryTypestateLimits,
        value_flow_limits: super::CodeQueryValueFlowLimits,
        taint_limits: super::CodeQueryTaintLimits,
        workspace_generation: u64,
        analysis_context: Option<&'a QueryAnalysisContext>,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        semantic_summaries: Option<
            Arc<brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository>,
        >,
    ) -> Self {
        debug_assert!(limits.all_positive());
        let budget = SemanticBudget::new(semantic_budget_limits(limits))
            .expect("CodeQuery semantic limits are positive");
        Self::new_with_budget(
            workspace,
            cancellation,
            limits,
            typestate_limits,
            value_flow_limits,
            taint_limits,
            workspace_generation,
            analysis_context,
            active_semantic_model_snapshot,
            semantic_summaries,
            budget,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_with_parent_scope(
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
        limits: CodeQuerySemanticLimits,
        typestate_limits: super::CodeQueryTypestateLimits,
        value_flow_limits: super::CodeQueryValueFlowLimits,
        taint_limits: super::CodeQueryTaintLimits,
        workspace_generation: u64,
        analysis_context: Option<&'a QueryAnalysisContext>,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        semantic_summaries: Option<
            Arc<brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository>,
        >,
        parent_scope: &SemanticBudgetScopeSnapshot,
        child_semantic_limits: SemanticWork,
        execution_before: SemanticExecutionBudgetSnapshot,
        execution_child: SemanticExecutionBudget,
        artifact_leases: SemanticArtifactLeaseSnapshot,
    ) -> Self {
        let budget = SemanticBudget::new_child(child_semantic_limits, parent_scope);
        Self::new_with_budget(
            workspace,
            cancellation,
            limits,
            typestate_limits,
            value_flow_limits,
            taint_limits,
            workspace_generation,
            analysis_context,
            active_semantic_model_snapshot,
            semantic_summaries,
            budget,
            Some((execution_before, execution_child)),
            Some(artifact_leases),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_budget(
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
        limits: CodeQuerySemanticLimits,
        typestate_limits: super::CodeQueryTypestateLimits,
        value_flow_limits: super::CodeQueryValueFlowLimits,
        taint_limits: super::CodeQueryTaintLimits,
        workspace_generation: u64,
        analysis_context: Option<&'a QueryAnalysisContext>,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        semantic_summaries: Option<
            Arc<brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository>,
        >,
        budget: SemanticBudget,
        receipt_execution: Option<(SemanticExecutionBudgetSnapshot, SemanticExecutionBudget)>,
        artifact_leases: Option<SemanticArtifactLeaseSnapshot>,
    ) -> Self {
        let promote_artifact_windows = artifact_leases.is_some();
        let artifact_leases = artifact_leases
            .unwrap_or_else(|| SemanticArtifactLeaseSet::new(limits.max_retained_bytes).snapshot());
        let mut artifact_leases = artifact_leases
            .restrict_to(limits.max_retained_bytes)
            .into_child();
        let artifact_lease_bytes = artifact_leases.retained_bytes();
        let initial_artifact_lease_error = {
            let preflight = artifact_leases.begin_window(0);
            let error = preflight.overflow();
            preflight.discard();
            error
        };
        Self {
            workspace,
            cancellation,
            uncancelled: CancellationToken::default(),
            limits,
            typestate_limits,
            value_flow_limits,
            taint_limits,
            workspace_generation,
            analysis_context,
            active_semantic_model_snapshot,
            semantic_summaries: semantic_summaries.unwrap_or_else(|| {
                Arc::new(brokk_bifrost_flow::dataflow::ProductionSemanticSummaryRepository::new())
            }),
            budget,
            cache: HashMap::default(),
            diagnostics: Vec::new(),
            reported: HashSet::default(),
            attempts: 0,
            receipt_execution,
            artifact_leases,
            artifact_window: None,
            artifact_window_file: None,
            initial_artifact_lease_error,
            promote_artifact_windows,
            execution_budget_exhausted: false,
            materialized_files: HashSet::default(),
            cache_hits: 0,
            active_retained_bytes: 0,
            peak_retained_bytes: artifact_lease_bytes,
            traversal_steps: 0,
            indexed_source_identities: HashMap::default(),
            source_call_indexes: HashMap::default(),
            prepared_source_dispatch: None,
            budget_exhausted: false,
            typestate: TypestateQueryState::default(),
            value_flow: ValueFlowQueryState::default(),
            taint: TaintQueryState::default(),
            type_flow: super::type_flow::TypeFlowQueryState::default(),
        }
    }

    pub(super) fn cfg(&mut self) -> CfgQueryAdapter<'_, 'a> {
        CfgQueryAdapter { context: self }
    }

    /// The declaration overlay paired with the procedure-summary activation
    /// snapshot used by this query. Returning the owned `Arc` lets a caller
    /// retain the exact activation while continuing to materialize semantic
    /// rows through this mutable context.
    pub(super) fn semantic_model_overlay(&self) -> Option<Arc<SemanticModelOverlay>> {
        self.active_semantic_model_snapshot
            .as_ref()?
            .semantic_model_overlay()
            .cloned()
    }

    pub(super) fn exact_object_identity(
        &mut self,
        value: ValueHandle,
        point: ProgramPointHandle,
    ) -> Result<ExactObjectIdentity, &'static str> {
        let query = ValueAtPoint::new(
            value,
            point,
            ObservationPhase::BeforeEffects,
            OracleCallContext::empty(),
        )
        .expect("detached transfer value and call point share one procedure");
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        let artifact_collector = self
            .artifact_window
            .as_ref()
            .map(SemanticArtifactLeaseWindow::collector);
        let mut request = SemanticRequest::new(&mut self.budget, cancellation);
        if let Some(collector) = &artifact_collector {
            request = request.with_artifact_collector(collector);
        }
        let outcome = self
            .workspace
            .semantic_oracle_provider()
            .pointees(&query, &mut request)
            .map_err(|_| "heap_provider_failed")?;
        let Some(result) = outcome.available_value() else {
            return Err("heap_result_unavailable");
        };
        if !outcome.is_complete() || !result.objects().coverage().is_exhaustive() {
            return Err("object_set_open");
        }
        let [candidate] = result.objects().candidates() else {
            return Err(if result.objects().candidates().is_empty() {
                "object_identity_absent"
            } else {
                "object_identity_ambiguous"
            });
        };
        if !candidate.is_proven_complete() {
            return Err("object_identity_unproven");
        }
        let object = candidate.value();
        Ok(ExactObjectIdentity {
            id: brokk_bifrost_flow::typestate::TypestateObjectKey::for_object(object)
                .public_canonical_rendering(),
            cardinality: match object.cardinality() {
                crate::analyzer::semantic::ObjectCardinality::Singleton => "singleton",
                crate::analyzer::semantic::ObjectCardinality::Summary => "summary",
                crate::analyzer::semantic::ObjectCardinality::Unknown => "unknown",
            },
        })
    }

    fn take_prepared_source_dispatch(&mut self) -> Option<PreparedSourceDispatchCache<'a>> {
        let prepared = self.prepared_source_dispatch.take()?;
        assert!(
            prepared.retained_bytes > 0,
            "only an initialized dispatch session enters the retained cache"
        );
        assert_eq!(
            prepared.session.retained_bytes(),
            prepared.retained_bytes,
            "a retained dispatch session keeps one exact syntax footprint"
        );
        self.active_retained_bytes = self
            .active_retained_bytes
            .checked_sub(prepared.retained_bytes)
            .expect("prepared dispatch bytes are included in active retention");
        Some(prepared)
    }

    fn evict_prepared_source_dispatch(&mut self) {
        drop(self.take_prepared_source_dispatch());
    }

    fn try_retain_prepared_source_dispatch(
        &mut self,
        file: ProjectFile,
        session: PreparedSourceDispatchSession<'a>,
        expected_retained_bytes: Option<usize>,
    ) {
        let retained_bytes = session.retained_bytes();
        if let Some(expected) = expected_retained_bytes {
            assert_eq!(
                retained_bytes, expected,
                "serial dispatch does not replace its frozen syntax snapshot"
            );
        }
        if retained_bytes == 0
            || self
                .artifact_window
                .as_ref()
                .is_some_and(|window| window.overflow().is_some())
            || retained_bytes
                > self
                    .limits
                    .max_retained_bytes
                    .saturating_sub(self.physical_retained_bytes())
        {
            return;
        }
        debug_assert_eq!(self.artifact_window_file.as_ref(), Some(&file));
        self.record_active_retained_bytes(retained_bytes);
        self.prepared_source_dispatch = Some(PreparedSourceDispatchCache {
            file,
            session,
            retained_bytes,
        });
    }

    fn prepared_dispatch_at_source(
        &mut self,
        file: &ProjectFile,
        range: crate::analyzer::Range,
    ) -> Option<
        Result<
            SemanticOutcome<crate::analyzer::semantic::workspace_oracle::SourceDispatchResult>,
            crate::analyzer::semantic::SemanticProviderError,
        >,
    > {
        if &self.prepared_source_dispatch.as_ref()?.file != file {
            return None;
        }
        let cached = self
            .take_prepared_source_dispatch()
            .expect("matching prepared dispatch cache remains available");
        let PreparedSourceDispatchCache {
            file: prepared_file,
            mut session,
            retained_bytes,
        } = cached;
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        let artifact_collector = self
            .artifact_window
            .as_ref()
            .map(SemanticArtifactLeaseWindow::collector);
        let mut request = SemanticRequest::new(&mut self.budget, cancellation);
        if let Some(collector) = &artifact_collector {
            request = request.with_artifact_collector(collector);
        }
        let outcome = session.resolve_at_source(range, &mut request);
        drop(request);
        self.try_retain_prepared_source_dispatch(prepared_file, session, Some(retained_bytes));
        Some(outcome)
    }

    fn one_shot_dispatch_at_source(
        &mut self,
        materialized: SemanticOutcome<Arc<SemanticArtifact>>,
        range: crate::analyzer::Range,
    ) -> Result<
        SemanticOutcome<crate::analyzer::semantic::workspace_oracle::SourceDispatchResult>,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        let oracle = self.workspace.semantic_oracle_provider();
        let artifact_collector = self
            .artifact_window
            .as_ref()
            .map(SemanticArtifactLeaseWindow::collector);
        let mut request = SemanticRequest::new(&mut self.budget, cancellation);
        if let Some(collector) = &artifact_collector {
            request = request.with_artifact_collector(collector);
        }
        oracle.dispatch_at_source_in_artifact(materialized, range, &mut request)
    }

    /// Try the retained source/tree optimization for the first real dispatch
    /// cache miss in an active file window. Construction is transient; only
    /// exact syntax bytes left after mandatory target dependencies are known
    /// may enter the optional query-local cache.
    fn begin_prepared_dispatch_at_source(
        &mut self,
        file: &ProjectFile,
        materialized: SemanticOutcome<Arc<SemanticArtifact>>,
        range: crate::analyzer::Range,
    ) -> Option<
        Result<
            SemanticOutcome<crate::analyzer::semantic::workspace_oracle::SourceDispatchResult>,
            crate::analyzer::semantic::SemanticProviderError,
        >,
    > {
        if self.artifact_window_file.as_ref() != Some(file) || self.artifact_window.is_none() {
            return None;
        }
        let oracle = self.workspace.semantic_oracle_provider();
        let mut prepared = oracle.prepare_source_dispatch_session_in_artifact(materialized);
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        let artifact_collector = self
            .artifact_window
            .as_ref()
            .map(SemanticArtifactLeaseWindow::collector);
        let mut request = SemanticRequest::new(&mut self.budget, cancellation);
        if let Some(collector) = &artifact_collector {
            request = request.with_artifact_collector(collector);
        }
        let outcome = prepared.resolve_at_source(range, &mut request);
        drop(request);
        self.try_retain_prepared_source_dispatch(file.clone(), prepared, None);
        Some(outcome)
    }

    /// Bounded dispatch for one exact source position.
    ///
    /// The answer is the workspace oracle's own, projected into the row
    /// vocabulary without re-deriving anything. Materialization runs through
    /// this context first so the query's file and retained-byte budgets stay
    /// authoritative and one file reports one diagnostic. The exact cached
    /// materialization is then passed to the oracle, which shares this
    /// context's semantic budget and cancellation token without charging the
    /// artifact again.
    ///
    /// The result is total: a gate, a provider failure, or an interrupted
    /// dispatch still returns a typed answer, because the mandatory outcome
    /// row must exist for every input site.
    pub(super) fn dispatch_at_source(
        &mut self,
        file: &ProjectFile,
        range: crate::analyzer::Range,
    ) -> super::dispatch::DispatchSiteAnswer {
        use super::dispatch::{DispatchArm, DispatchSiteAnswer};

        let outcome = match self.prepared_dispatch_at_source(file, range) {
            Some(outcome) => outcome,
            None => {
                if self
                    .cancellation
                    .is_some_and(crate::cancellation::CancellationToken::is_cancelled)
                {
                    return DispatchSiteAnswer::interrupted("cancelled", None, None);
                }
                if !self.initial_artifact_leases_fit(file) {
                    return DispatchSiteAnswer::interrupted("exceeded_budget", None, None);
                }
                if self.materialize(file).is_none() {
                    let (outcome, unsupported) = self.materialization_gate(file);
                    return DispatchSiteAnswer::interrupted(outcome, unsupported, None);
                }
                let materialized = match self.cache.get(file) {
                    Some(CachedSemanticMaterialization::Outcome { outcome, .. }) => outcome.clone(),
                    _ => {
                        unreachable!("successful semantic materialization is cached as an outcome")
                    }
                };

                match self.begin_prepared_dispatch_at_source(file, materialized.clone(), range) {
                    Some(outcome) => outcome,
                    None => self.one_shot_dispatch_at_source(materialized, range),
                }
            }
        };
        let artifact_window_fits = self.artifact_window_fits(file);
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if !artifact_window_fits {
                    return DispatchSiteAnswer::interrupted("exceeded_budget", None, None);
                }
                let reason = error.to_string();
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::SemanticProviderFailed,
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    &reason,
                );
                return DispatchSiteAnswer::interrupted("unknown", None, None);
            }
        };
        if !artifact_window_fits {
            return DispatchSiteAnswer::interrupted("exceeded_budget", None, None);
        }

        let label = match &outcome {
            SemanticOutcome::Complete { .. } => "resolved",
            SemanticOutcome::Ambiguous { .. } => "ambiguous",
            SemanticOutcome::Unknown { .. } => "unknown",
            SemanticOutcome::Unsupported { .. } => "unsupported",
            SemanticOutcome::Unproven { .. } => "unproven",
            SemanticOutcome::ExceededBudget { .. } => "exceeded_budget",
            SemanticOutcome::Cancelled { .. } => "cancelled",
        };
        let semantic_unsupported = match &outcome {
            SemanticOutcome::Unsupported { capability, .. } => Some(capability.label()),
            _ => None,
        };
        let exceeded_limit = outcome
            .budget_exceeded()
            .map(|exceeded| exceeded.dimension().label());
        if let Some(exceeded) = outcome.budget_exceeded() {
            self.budget_exhausted = true;
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &exceeded.to_string(),
            );
        }
        let Some(result) = outcome.available_value() else {
            return DispatchSiteAnswer::interrupted(label, semantic_unsupported, exceeded_limit);
        };

        let coverage = result.coverage();
        let mut arms = Vec::new();
        let mut call_contexts = Vec::with_capacity(result.observations().len());
        let mut unnamed_boundaries = Vec::new();
        for observation in result.observations() {
            let call = observation.call();
            let semantic_call = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("source dispatch retains a valid semantic call-site handle");
            let caller_locator = call.procedure().semantics().locator();
            let caller = self.definition_for_locator(caller_locator);
            let caller_is_exact = caller
                .as_ref()
                .is_some_and(|unit| self.locator_exactly_names_unit(caller_locator, unit));
            let call_context = call_contexts.len();
            call_contexts.push(super::dispatch::DispatchCallContext {
                caller,
                caller_is_exact,
            });
            for candidate in observation.dispatch().candidates() {
                let target = candidate.target();
                let locator = target.semantics().locator();
                arms.push(DispatchArm {
                    call_context,
                    execution_timing: dispatch_arm_execution_timing(
                        semantic_call.execution_timing,
                        None,
                    ),
                    target_id: super::dispatch::target_identity(
                        Some(target.artifact().key().public_fingerprint().to_string()).as_deref(),
                        locator,
                    ),
                    target_path: locator.path().as_str().to_string(),
                    target_unit: self
                        .definition_for_locator(locator)
                        .filter(|unit| self.locator_exactly_names_unit(locator, unit)),
                    exact_external_target: None,
                    // A dispatch candidate names a materialized procedure, so
                    // it never carries an unmaterialized identity.
                    unmaterialized_target: None,
                    proof: candidate.proof().label(),
                    completeness: candidate.completeness().label(),
                    boundary_kind: None,
                });
            }
            for boundary in observation.dispatch().boundaries() {
                // An unresolved or truncated residual arm names no target. It
                // is already reflected in the site's coverage; inventing a row
                // for it would claim a target that does not exist. It is
                // counted, though: a consumer reasoning over the arm set has no
                // other way to learn the set is not the whole answer.
                let Some(locator) = boundary.kind.target_locator() else {
                    unnamed_boundaries.push(boundary.kind.label());
                    continue;
                };
                let fingerprint = boundary
                    .exact_external_target()
                    .map(|target| target.artifact().public_fingerprint().to_string());
                arms.push(DispatchArm {
                    call_context,
                    execution_timing: dispatch_arm_execution_timing(
                        semantic_call.execution_timing,
                        Some(&boundary.kind),
                    ),
                    target_id: super::dispatch::target_identity(fingerprint.as_deref(), locator),
                    target_path: locator.path().as_str().to_string(),
                    target_unit: self
                        .definition_for_locator(locator)
                        .filter(|unit| self.locator_exactly_names_unit(locator, unit)),
                    exact_external_target: boundary.exact_external_target().cloned(),
                    // #1978: a fully-qualified callee the workspace never
                    // materializes still has a canonical member identity. It
                    // is the only way a consumer can key an activated pack
                    // lookup for this arm, so it is retained rather than
                    // dropped with the rest of the boundary.
                    unmaterialized_target: boundary.unmaterialized_external_target().cloned(),
                    proof: boundary.proof.label(),
                    completeness: boundary.completeness.label(),
                    boundary_kind: Some(boundary.kind.label()),
                });
            }
        }
        DispatchSiteAnswer {
            outcome: label,
            coverage,
            call_site_count: result.observations().len(),
            semantic_unsupported,
            exceeded_limit,
            arms,
            call_contexts,
            unnamed_boundaries,
        }
    }

    /// Project the ordered normal results of the semantic call represented by
    /// one exact structural call shape.
    pub(super) fn call_results_at_source(
        &mut self,
        file: &ProjectFile,
        range: crate::analyzer::Range,
        site_id: &str,
        site_ast_id: &str,
    ) -> Vec<SemanticCallResultValue> {
        let Some((artifact, source, quality)) = self.materialize(file) else {
            return Vec::new();
        };
        let Some(index) = self.source_call_index(file, &artifact) else {
            return Vec::new();
        };
        let exact_key = (range.start_byte, range.end_byte);
        let exact_start = index
            .candidates
            .partition_point(|candidate| (candidate.span.start, candidate.span.end) < exact_key);
        let exact_end = index
            .candidates
            .partition_point(|candidate| (candidate.span.start, candidate.span.end) <= exact_key);
        let exact = &index.candidates[exact_start..exact_end];
        let mut candidates = if !exact.is_empty() {
            exact
                .iter()
                .cloned()
                .map(|candidate| (false, candidate))
                .collect::<Vec<_>>()
        } else {
            index
                .candidates
                .iter()
                .filter(|candidate| {
                    candidate.span.start <= range.start_byte && candidate.span.end >= range.end_byte
                })
                .cloned()
                .map(|candidate| (true, candidate))
                .collect::<Vec<_>>()
        };
        candidates.sort_by(|(left_inexact, left), (right_inexact, right)| {
            (
                left_inexact,
                left.span.len(),
                left.span.start,
                left.procedure.semantics().locator(),
                left.call.id(),
            )
                .cmp(&(
                    right_inexact,
                    right.span.len(),
                    right.span.start,
                    right.procedure.semantics().locator(),
                    right.call.id(),
                ))
        });
        let Some((best_inexact, best)) = candidates.first() else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                "structural call shape does not identify a semantic call site",
            );
            return Vec::new();
        };
        let rank = (*best_inexact, best.span.len());
        candidates.retain(|(inexact, candidate)| (*inexact, candidate.span.len()) == rank);
        let first_span = candidates[0].1.span.clone();
        let first_procedure = candidates[0].1.procedure.semantics().locator().clone();
        if candidates.iter().any(|(_, candidate)| {
            candidate.span != first_span
                || candidate.procedure.semantics().locator() != &first_procedure
        }) {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                "structural call shape identifies multiple distinct semantic source calls",
            );
            return Vec::new();
        }

        candidates
            .into_iter()
            .flat_map(|(_, candidate)| {
                let call = candidate
                    .procedure
                    .semantics()
                    .call_site(candidate.call.id())
                    .expect("validated semantic call handle resolves");
                call.normal_result_values()
                    .enumerate()
                    .map(|(ordinal, value)| SemanticCallResultValue {
                        handle: candidate.call.clone(),
                        ordinal,
                        value,
                        site_id: site_id.to_owned(),
                        site_ast_id: site_ast_id.to_owned(),
                        file: file.clone(),
                        source: source.clone(),
                        quality: quality.clone(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The exact artifact outcome already retained for this file.
    ///
    /// Flow-state consumers that join back to the handles projected above
    /// must derive from this allocation, not independently materialize an
    /// artifact with the same durable key. Handle identity intentionally
    /// distinguishes those allocations when a complete artifact was evicted
    /// or the provider returned a partial outcome.
    pub(super) fn materialized_outcome(
        &mut self,
        file: &ProjectFile,
    ) -> Option<SemanticOutcome<Arc<SemanticArtifact>>> {
        if !self.cache.contains_key(file) {
            self.materialize(file)?;
        }
        match self.cache.get(file) {
            Some(CachedSemanticMaterialization::Outcome { outcome, .. })
                if outcome.available_value().is_some() =>
            {
                Some(outcome.clone())
            }
            _ => None,
        }
    }

    /// Build one source-call index per materialized file. Exact structural
    /// call shapes are the common case and use a binary-search slice; the
    /// enclosing fallback scans the cached index only when an adapter anchors
    /// its structural row inside the semantic call expression.
    fn source_call_index(
        &mut self,
        file: &ProjectFile,
        artifact: &Arc<SemanticArtifact>,
    ) -> Option<&SemanticSourceCallIndex> {
        if self.source_call_indexes.contains_key(file) {
            return self.source_call_indexes.get(file).and_then(Option::as_ref);
        }
        if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::Cancelled,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                "semantic call-result lookup was cancelled",
            );
            return None;
        }
        let reservation_bytes =
            match SemanticSourceCallIndex::reservation_bytes(artifact.work().call_sites) {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.reject_retained_bytes_error(file, error);
                    return None;
                }
            };
        if self.artifact_window.is_some() {
            // Index metadata is mandatory for this row family. An idle parsed
            // dispatch cache is optional and must not participate in (or
            // poison) the lease window's reservation decision.
            self.evict_prepared_source_dispatch();
        }
        let live_reservation = if let Some(window) = self.artifact_window.as_ref() {
            match window.reserve_other_live_bytes(reservation_bytes) {
                Ok(reservation) => Some(reservation),
                Err(_) => {
                    let artifact_window_fits = self.artifact_window_fits(file);
                    assert!(
                        !artifact_window_fits,
                        "a refused index reservation latches its lease-window error"
                    );
                    return None;
                }
            }
        } else {
            if !self.active_retained_bytes_fit(file, reservation_bytes) {
                return None;
            }
            None
        };
        let mut candidates = Vec::with_capacity(artifact.work().call_sites);
        let candidate_storage_bytes =
            SemanticSourceCallIndex::candidate_storage_retained_bytes(artifact.work().call_sites)
                .expect("a successful total reservation includes candidate storage");
        self.observe_transient_active_retained_bytes(candidate_storage_bytes);
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        for procedure in artifact.procedures() {
            if cancellation.is_cancelled() {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::Cancelled,
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    "semantic call-result lookup was cancelled",
                );
                drop(candidates);
                if let Err(error) = self.retain_source_call_index_entry(
                    file,
                    None,
                    live_reservation,
                    reservation_bytes,
                ) {
                    self.reject_retained_bytes_error(file, error);
                }
                return None;
            }
            self.traversal_steps = self.traversal_steps.saturating_add(1);
            if self.traversal_steps > self.limits.max_traversal_steps {
                self.exhaust_traversal_budget(file, "call-shape-to-result lookup");
                drop(candidates);
                if let Err(error) = self.retain_source_call_index_entry(
                    file,
                    None,
                    live_reservation,
                    reservation_bytes,
                ) {
                    self.reject_retained_bytes_error(file, error);
                }
                return None;
            }
            let Some(procedure_handle) = artifact.procedure_handle(procedure.id()) else {
                continue;
            };
            for call in procedure.call_sites() {
                self.traversal_steps = self.traversal_steps.saturating_add(1);
                if self.traversal_steps > self.limits.max_traversal_steps {
                    self.exhaust_traversal_budget(file, "call-shape-to-result lookup");
                    drop(candidates);
                    if let Err(error) = self.retain_source_call_index_entry(
                        file,
                        None,
                        live_reservation,
                        reservation_bytes,
                    ) {
                        self.reject_retained_bytes_error(file, error);
                    }
                    return None;
                }
                let mapping = procedure
                    .source_mapping(call.source)
                    .expect("validated semantic call has a source mapping");
                let candidate = SemanticSourceCallCandidate {
                    span: byte_span(mapping),
                    procedure: procedure_handle.clone(),
                    call: procedure_handle
                        .call_site_handle(call.id)
                        .expect("validated semantic call has a scoped handle"),
                };
                candidates.push(candidate);
            }
        }
        assert_eq!(
            candidates.len(),
            artifact.work().call_sites,
            "complete artifact call census matches its source-call index"
        );
        candidates.sort_unstable_by(|left, right| {
            (
                left.span.start,
                left.span.end,
                left.procedure.semantics().locator(),
                left.call.id(),
            )
                .cmp(&(
                    right.span.start,
                    right.span.end,
                    right.procedure.semantics().locator(),
                    right.call.id(),
                ))
        });
        let index = SemanticSourceCallIndex {
            candidates: candidates.into_boxed_slice(),
        };
        if let Err(error) = self.retain_source_call_index_entry(
            file,
            Some(index),
            live_reservation,
            reservation_bytes,
        ) {
            self.reject_retained_bytes_error(file, error);
            return None;
        }
        self.source_call_indexes.get(file).and_then(Option::as_ref)
    }

    fn retain_source_call_index_entry(
        &mut self,
        file: &ProjectFile,
        index: Option<SemanticSourceCallIndex>,
        live_reservation: Option<SemanticArtifactLeaseLiveReservation>,
        reservation_bytes: usize,
    ) -> Result<(), SemanticArtifactLeaseError> {
        let retained_bytes = index.as_ref().map_or_else(
            SemanticSourceCallIndex::absent_entry_retained_bytes,
            SemanticSourceCallIndex::retained_bytes,
        )?;
        assert!(
            retained_bytes <= reservation_bytes,
            "semantic source-call index exceeded its pre-allocation reservation"
        );
        assert!(
            self.source_call_indexes
                .insert(file.clone(), index)
                .is_none(),
            "one semantic source-call index is retained per file"
        );
        if let Some(reservation) = live_reservation {
            reservation.retain_exact(retained_bytes);
            self.record_active_retained_bytes(retained_bytes);
        } else {
            assert!(
                self.admit_active_retained_bytes(file, retained_bytes),
                "a source-call index cannot exceed its successful upper preflight"
            );
        }
        Ok(())
    }

    /// The typed reason [`Self::materialize`] refused, so a mandatory row can
    /// state it instead of reporting a bare unknown.
    fn materialization_gate(&self, file: &ProjectFile) -> (&'static str, Option<&'static str>) {
        match self.cache.get(file) {
            Some(CachedSemanticMaterialization::FileBudgetExhausted)
            | Some(CachedSemanticMaterialization::RetainedBudgetExhausted) => {
                ("exceeded_budget", None)
            }
            Some(CachedSemanticMaterialization::Outcome { outcome, .. }) => match outcome {
                SemanticOutcome::Cancelled { .. } => ("cancelled", None),
                SemanticOutcome::Unsupported { capability, .. } => {
                    ("unsupported", Some(capability.label()))
                }
                SemanticOutcome::ExceededBudget { .. } => ("exceeded_budget", None),
                _ => ("unknown", None),
            },
            Some(CachedSemanticMaterialization::ProviderFailed(_)) | None => ("unknown", None),
        }
    }

    /// The workspace declaration for one semantic procedure locator, or `None`
    /// when the workspace no longer indexes a callable declaration that the
    /// locator's own span aligns with.
    ///
    /// The lookup is span-structural, never name-based: an exactly aligned
    /// declaration wins, and otherwise the smallest declaration whose own
    /// range contains the procedure's anchor span does.
    fn definition_for_locator(
        &self,
        locator: &SemanticLocator,
    ) -> Option<crate::analyzer::CodeUnit> {
        let file = super::witness_projection::locator_file(self.workspace, locator);
        super::dispatch::declaration_at_locator(self.workspace.analyzer(), locator, &file)
    }

    /// Whether a semantic procedure locator names this declaration itself,
    /// rather than only a nested callable structurally contained by it.
    ///
    /// Exact source ranges are sufficient. Language extractors may instead
    /// retain a declaration wrapper (for example, TypeScript's `export`
    /// statement) around the callable node. In that case the locator's named
    /// declaration path must match the declaration's structured FQ-name suffix.
    /// An anonymous locator never borrows the enclosing named declaration.
    fn locator_exactly_names_unit(
        &self,
        locator: &SemanticLocator,
        unit: &crate::analyzer::CodeUnit,
    ) -> bool {
        let span = locator.anchor().span();
        let ranges = self.workspace.analyzer().ranges_of(unit);
        if ranges.iter().any(|range| {
            range.start_byte == span.start_byte() as usize
                && range.end_byte == span.end_byte() as usize
        }) {
            return true;
        }
        if !ranges.iter().any(|range| {
            range.start_byte <= span.start_byte() as usize
                && range.end_byte >= span.end_byte() as usize
        }) {
            return false;
        }

        let mut locator_names = Vec::new();
        for segment in locator.declaration().segments() {
            if segment.kind() == DeclarationSegmentKind::File {
                continue;
            }
            let Some(name) = segment.name() else {
                return false;
            };
            locator_names.push(name);
        }
        if locator_names.is_empty() {
            return false;
        }
        let unit_names = unit.fq_segment_texts();
        locator_names.len() <= unit_names.len()
            && unit_names[unit_names.len() - locator_names.len()..]
                .iter()
                .zip(locator_names)
                .all(|(unit_name, locator_name)| unit_name == locator_name)
    }

    pub(super) fn procedure_of_match(&mut self, seed: &SeedMatch) -> Vec<SemanticProcedureValue> {
        let ranges = [seed_range(seed)];
        let Some((artifact, source, quality)) = self.materialize(&seed.file) else {
            return Vec::new();
        };
        if seed.facts.source_identity() != artifact.key().revision().content() {
            self.push_source_generation_changed(&seed.file);
            return Vec::new();
        }
        let quality = quality.combine(&self.capability_quality(
            &seed.file,
            artifact.as_ref(),
            &[SemanticCapability::Procedures],
        ));
        let lookup = procedures_for_source_ranges(
            &artifact,
            &ranges,
            self.limits
                .max_traversal_steps
                .saturating_sub(self.traversal_steps),
            self.cancellation.unwrap_or(&self.uncancelled),
        );
        self.traversal_steps = self.traversal_steps.saturating_add(lookup.examined);
        match lookup.status {
            ProcedureRangeLookupStatus::Complete => {
                self.finish_procedure_lookup(&seed.file, source, lookup.handles, quality)
            }
            ProcedureRangeLookupStatus::BudgetExhausted => {
                self.exhaust_traversal_budget(&seed.file, "enclosing-procedure lookup");
                Vec::new()
            }
            ProcedureRangeLookupStatus::Cancelled => {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::Cancelled,
                    CodeQueryDiagnosticImpact::Incomplete,
                    &seed.file,
                    "enclosing-procedure lookup was cancelled",
                );
                Vec::new()
            }
            ProcedureRangeLookupStatus::SourceChanged => {
                self.push_source_generation_changed(&seed.file);
                Vec::new()
            }
        }
    }

    pub(super) fn seed_generation_is_current(&mut self, seed: &SeedMatch) -> bool {
        let current = *self
            .indexed_source_identities
            .entry(seed.file.clone())
            .or_insert_with(|| {
                self.workspace
                    .analyzer()
                    .indexed_source(&seed.file)
                    .map(|source| ContentIdentity::hash_bytes(source.as_bytes()))
            });
        if current == Some(seed.facts.source_identity()) {
            return true;
        }
        self.push_source_generation_changed(&seed.file);
        false
    }

    fn procedure_of_declaration(
        &mut self,
        declaration: &DeclarationValue,
    ) -> Vec<SemanticProcedureValue> {
        let file = declaration.unit.source();
        let Some((artifact, source, quality)) = self.materialize(file) else {
            return Vec::new();
        };
        let quality = quality.combine(&self.capability_quality(
            file,
            artifact.as_ref(),
            &[SemanticCapability::Procedures],
        ));
        let lookup = procedures_for_definition_with_limits(
            self.workspace.analyzer(),
            &declaration.unit,
            &artifact,
            self.limits
                .max_traversal_steps
                .saturating_sub(self.traversal_steps),
            self.cancellation.unwrap_or(&self.uncancelled),
        );
        self.traversal_steps = self.traversal_steps.saturating_add(lookup.examined);
        match lookup.status {
            ProcedureRangeLookupStatus::Complete => {
                self.finish_procedure_lookup(file, source, lookup.handles, quality)
            }
            ProcedureRangeLookupStatus::BudgetExhausted => {
                self.exhaust_traversal_budget(file, "declaration-to-procedure lookup");
                Vec::new()
            }
            ProcedureRangeLookupStatus::Cancelled => {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::Cancelled,
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    "declaration-to-procedure lookup was cancelled",
                );
                Vec::new()
            }
            ProcedureRangeLookupStatus::SourceChanged => {
                self.push_source_generation_changed(file);
                Vec::new()
            }
        }
    }

    /// Resolve one workspace declaration to one exact request-retained
    /// procedure handle. Consumers that prove an interprocedural identity must
    /// not pick one body when an enclosing/declaration lookup remains
    /// ambiguous.
    pub(super) fn unique_procedure_of_declaration(
        &mut self,
        declaration: &DeclarationValue,
    ) -> Option<ProcedureHandle> {
        let mut procedures = self.procedure_of_declaration(declaration);
        if procedures.len() != 1 || !procedures[0].quality.is_complete() {
            return None;
        }
        Some(procedures.remove(0).handle)
    }

    /// Charge a bounded consumer walk over rows in an already retained
    /// artifact. Materialization pays for the rows themselves; this ledger is
    /// the independent per-query bound on how many of them consumers inspect.
    pub(super) fn charge_consumer_traversal(
        &mut self,
        file: &ProjectFile,
        steps: usize,
        operation: &str,
    ) -> bool {
        if self.budget_exhausted {
            return false;
        }
        if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::Cancelled,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &format!("semantic traversal was cancelled during {operation}"),
            );
            return false;
        }
        if steps
            > self
                .limits
                .max_traversal_steps
                .saturating_sub(self.traversal_steps)
        {
            self.exhaust_traversal_budget(file, operation);
            return false;
        }
        self.traversal_steps = self.traversal_steps.saturating_add(steps);
        true
    }

    fn cfg_entry(
        &mut self,
        procedure: &SemanticProcedureValue,
    ) -> Option<SemanticProgramPointValue> {
        let quality = procedure.quality.combine(&self.capability_quality(
            &procedure.file,
            procedure.handle.artifact().as_ref(),
            &[
                SemanticCapability::ProgramPoints,
                SemanticCapability::EntryBoundary,
            ],
        ));
        procedure
            .handle
            .point_handle(procedure.handle.semantics().entry_point())
            .map(|handle| SemanticProgramPointValue {
                handle,
                file: procedure.file.clone(),
                source: procedure.source.clone(),
                quality,
            })
    }

    fn cfg_exits(&mut self, procedure: &SemanticProcedureValue) -> Vec<SemanticProgramPointValue> {
        let quality = procedure.quality.combine(&self.capability_quality(
            &procedure.file,
            procedure.handle.artifact().as_ref(),
            &[
                SemanticCapability::ProgramPoints,
                SemanticCapability::NormalExitBoundary,
                SemanticCapability::ExceptionalExitBoundary,
            ],
        ));
        let semantics = procedure.handle.semantics();
        let ids = [
            semantics.normal_exit_point(),
            semantics.exceptional_exit_point(),
        ];
        let mut seen = HashSet::default();
        ids.into_iter()
            .filter(|id| seen.insert(*id))
            .filter_map(|id| procedure.handle.point_handle(id))
            .map(|handle| SemanticProgramPointValue {
                handle,
                file: procedure.file.clone(),
                source: procedure.source.clone(),
                quality: quality.clone(),
            })
            .collect()
    }

    fn cfg_successor_edges(
        &mut self,
        point: &SemanticProgramPointValue,
        max_outputs: usize,
    ) -> Vec<SemanticControlEdgeValue> {
        self.cfg_edges(point, true, max_outputs)
    }

    fn cfg_predecessor_edges(
        &mut self,
        point: &SemanticProgramPointValue,
        max_outputs: usize,
    ) -> Vec<SemanticControlEdgeValue> {
        self.cfg_edges(point, false, max_outputs)
    }

    fn cfg_edge_source(
        &mut self,
        edge: &SemanticControlEdgeValue,
    ) -> Option<SemanticProgramPointValue> {
        self.cfg_edge_endpoint(edge, true)
    }

    fn cfg_edge_target(
        &mut self,
        edge: &SemanticControlEdgeValue,
    ) -> Option<SemanticProgramPointValue> {
        self.cfg_edge_endpoint(edge, false)
    }

    pub(super) fn take_diagnostics(&mut self) -> Vec<CodeQueryDiagnostic> {
        self.reported.clear();
        let mut diagnostics = std::mem::take(&mut self.diagnostics);
        diagnostics.extend(self.typestate.take_diagnostics());
        diagnostics.extend(self.value_flow.take_diagnostics());
        diagnostics.extend(self.taint.take_diagnostics());
        diagnostics.extend(self.type_flow.take_diagnostics());
        diagnostics
    }

    pub(super) fn work(&self) -> CodeQuerySemanticWork {
        let used = self.budget.used();
        CodeQuerySemanticWork {
            materialization_attempts: saturating_u64(self.attempts),
            unique_materialized_files: saturating_u64(self.materialized_files.len()),
            request_cache_hits: saturating_u64(self.cache_hits),
            source_bytes: saturating_u64(used.source_bytes),
            procedures: saturating_u64(used.procedures),
            blocks: saturating_u64(used.blocks),
            program_points: saturating_u64(used.program_points),
            values: saturating_u64(used.values),
            allocations: saturating_u64(used.allocations),
            call_sites: saturating_u64(used.call_sites),
            memory_locations: saturating_u64(used.memory_locations),
            captures: saturating_u64(used.captures),
            source_mappings: saturating_u64(used.source_mappings),
            evidence: saturating_u64(used.evidence),
            gaps: saturating_u64(used.gaps),
            events: saturating_u64(used.events),
            control_edges: saturating_u64(used.control_edges),
            nested_entries: saturating_u64(used.nested_entries),
            retained_bytes: saturating_u64(self.peak_retained_bytes),
            traversal_steps: saturating_u64(self.traversal_steps),
            budget_exhausted: self.budget_exhausted
                || self.typestate.semantic_budget_exhausted()
                || self.value_flow.semantic_budget_exhausted()
                || self.value_flow.query_budget_exhausted()
                || self.type_flow.semantic_budget_exhausted(),
            typestate: self.typestate.work(),
            value_flow: self.value_flow.work(),
            type_flow: self.type_flow.work(),
        }
    }

    pub(super) fn typestate_findings(
        &mut self,
        procedure: &SemanticProcedureValue,
        protocol_ref: &ProtocolRef,
    ) -> Vec<SemanticTypestateFindingValue> {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        self.typestate.findings(
            self.workspace,
            self.workspace_generation,
            self.analysis_context,
            procedure,
            protocol_ref,
            &mut self.budget,
            self.typestate_limits,
            cancellation,
            self.active_semantic_model_snapshot.clone(),
        )
    }

    pub(super) fn concurrent_access_conflicts(
        &mut self,
        procedure: &SemanticProcedureValue,
    ) -> Vec<ConcurrentAccessConflictValue> {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        let artifact_collector = self
            .artifact_window
            .as_ref()
            .map(SemanticArtifactLeaseWindow::collector);
        let mut request = SemanticRequest::new(&mut self.budget, cancellation);
        if let Some(collector) = &artifact_collector {
            request = request.with_artifact_collector(collector);
        }
        let icfg = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            self.workspace,
            self.active_semantic_model_snapshot.clone(),
        );
        let summaries = match brokk_bifrost_flow::typestate::project_production_semantic_summaries(
            std::slice::from_ref(&procedure.handle),
            &icfg,
            &mut request,
        ) {
            Ok(summaries) => {
                if let Err(error) = self
                    .semantic_summaries
                    .publish_components(summaries.summaries(), summaries.components())
                {
                    self.diagnostics.push(CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: "workspace",
                        message: format!(
                            "complete concurrency summaries exceeded workspace retention: {error}"
                        ),
                    });
                }
                Some(summaries)
            }
            Err(error) => {
                self.diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!("concurrency summary projection was incomplete: {error}"),
                });
                None
            }
        };
        let provider = WorkspaceConcurrencyProvider::new(
            self.workspace,
            self.active_semantic_model_snapshot.clone(),
            summaries,
        );
        match brokk_bifrost_flow::concurrency::concurrent_access_conflicts(
            &provider,
            &procedure.handle,
            &mut request,
        ) {
            Ok(report) => {
                if !report.reasons.is_empty() {
                    let code = if report.reasons.contains(
                        &brokk_bifrost_flow::concurrency::ConcurrencyOpenReason::BudgetExhausted,
                    ) {
                        CodeQueryDiagnosticCode::SemanticBudgetExhausted
                    } else {
                        CodeQueryDiagnosticCode::SemanticAnalysisPartial
                    };
                    self.diagnostics.push(CodeQueryDiagnostic {
                        code,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: "go",
                        message: format!(
                            "concurrent access analysis retained incomplete task slices: {:?}",
                            report.reasons
                        ),
                    });
                }
                report
                    .conflicts
                    .into_iter()
                    .map(|conflict| {
                        super::concurrency::project_conflict(self.workspace, procedure, conflict)
                    })
                    .collect()
            }
            Err(error) => {
                self.diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::SemanticProviderFailed,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!("concurrent access analysis failed: {error}"),
                });
                Vec::new()
            }
        }
    }

    pub(super) fn typestate_witness_truncated(&mut self, count: usize) {
        self.typestate.witness_truncated(count);
    }

    pub(super) fn value_flow_endpoints(
        &mut self,
        procedure: &SemanticProcedureValue,
        plan_ref: &ValueFlowPlanRef,
        max_endpoints: usize,
    ) -> Vec<SemanticFlowEndpointValue> {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        self.value_flow.endpoints(
            self.workspace,
            self.workspace_generation,
            self.analysis_context,
            procedure,
            plan_ref,
            &mut self.budget,
            self.value_flow_limits,
            max_endpoints,
            cancellation,
            self.active_semantic_model_snapshot.clone(),
        )
    }

    pub(super) fn value_flow_witnesses(
        &mut self,
        endpoint: &SemanticFlowEndpointValue,
        traversal: &WitnessTraversal,
    ) -> Vec<SemanticFlowWitnessValue> {
        self.value_flow
            .witnesses(self.workspace, endpoint, traversal, self.value_flow_limits)
    }

    pub(super) fn class_set_rows(
        &mut self,
        procedure: &SemanticProcedureValue,
    ) -> Vec<super::type_flow::ClassSetRowValue> {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        self.type_flow.class_sets(
            self.workspace,
            procedure,
            &mut self.budget,
            self.value_flow_limits,
            cancellation,
            self.active_semantic_model_snapshot.clone(),
        )
    }

    pub(super) fn absent_member_findings(
        &mut self,
        procedure: &SemanticProcedureValue,
    ) -> Vec<super::type_flow::AbsentMemberFindingValue> {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        self.type_flow.absent_member_findings(
            self.workspace,
            procedure,
            &mut self.budget,
            self.value_flow_limits,
            cancellation,
            self.active_semantic_model_snapshot.clone(),
        )
    }

    pub(super) fn taint_findings(
        &mut self,
        procedure: &SemanticProcedureValue,
        taint_ref: &TaintResultRef,
        max_findings: usize,
    ) -> Vec<SemanticTaintFindingValue> {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        self.taint.findings(
            self.workspace,
            self.workspace_generation,
            self.analysis_context,
            procedure,
            taint_ref,
            self.taint_limits,
            max_findings,
            cancellation,
        )
    }

    fn finish_procedure_lookup(
        &mut self,
        file: &ProjectFile,
        source: SemanticSourceSnapshot,
        mut candidates: Vec<ProcedureHandle>,
        mut quality: SemanticQueryQuality,
    ) -> Vec<SemanticProcedureValue> {
        let smallest_span = candidates
            .iter()
            .map(|candidate| {
                let span = candidate.semantics().locator().anchor().span();
                span.end_byte().saturating_sub(span.start_byte())
            })
            .min();
        if let Some(smallest_span) = smallest_span {
            candidates.retain(|candidate| {
                let span = candidate.semantics().locator().anchor().span();
                span.end_byte().saturating_sub(span.start_byte()) == smallest_span
            });
        }
        if candidates.len() > 1 {
            let reason: Arc<str> = "multiple equally specific enclosing procedures".into();
            quality = quality.combine(&SemanticQueryQuality::unproven_partial(Arc::clone(&reason)));
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                reason.as_ref(),
            );
        } else if candidates.is_empty() && quality.is_complete() {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::NoEnclosingProcedure,
                CodeQueryDiagnosticImpact::Advisory,
                file,
                "no source-backed executable procedure encloses the query input",
            );
        }
        candidates
            .into_iter()
            .map(|handle| SemanticProcedureValue {
                handle,
                file: file.clone(),
                source: source.clone(),
                quality: quality.clone(),
            })
            .collect()
    }

    fn cfg_edges(
        &mut self,
        point: &SemanticProgramPointValue,
        successors: bool,
        max_outputs: usize,
    ) -> Vec<SemanticControlEdgeValue> {
        let quality = point.quality.combine(&self.capability_quality(
            &point.file,
            point.handle.procedure().artifact().as_ref(),
            &[
                SemanticCapability::ProgramPoints,
                SemanticCapability::NormalControlFlow,
                SemanticCapability::ExceptionalControlFlow,
                SemanticCapability::CleanupControlFlow,
            ],
        ));
        let procedure = point.handle.procedure();
        let semantics = procedure.semantics();
        if successors {
            self.collect_cfg_edges(
                point,
                quality,
                semantics.successor_edges(point.handle.id()),
                max_outputs,
            )
        } else {
            self.collect_cfg_edges(
                point,
                quality,
                semantics.predecessor_edges(point.handle.id()),
                max_outputs,
            )
        }
    }

    fn collect_cfg_edges<'edge>(
        &mut self,
        point: &SemanticProgramPointValue,
        quality: SemanticQueryQuality,
        edges: impl ExactSizeIterator<
            Item = (crate::analyzer::semantic::ControlEdgeId, &'edge ControlEdge),
        >,
        max_outputs: usize,
    ) -> Vec<SemanticControlEdgeValue> {
        let edge_count = edges.len();
        let remaining_traversal = self
            .limits
            .max_traversal_steps
            .saturating_sub(self.traversal_steps);
        let admitted = edge_count.min(max_outputs).min(remaining_traversal);
        let mut output = Vec::with_capacity(admitted);
        let procedure = point.handle.procedure();
        for (id, _) in edges.take(admitted) {
            if self
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::Cancelled,
                    CodeQueryDiagnosticImpact::Incomplete,
                    &point.file,
                    "control-edge traversal was cancelled",
                );
                break;
            }
            self.traversal_steps = self.traversal_steps.saturating_add(1);
            let Some(handle) = procedure.control_edge_handle(id) else {
                continue;
            };
            output.push(SemanticControlEdgeValue {
                handle,
                file: point.file.clone(),
                source: point.source.clone(),
                quality: quality.clone(),
            });
        }
        if edge_count > remaining_traversal && admitted == remaining_traversal {
            self.exhaust_traversal_budget(&point.file, "control-edge traversal");
        }
        output
    }

    fn cfg_edge_endpoint(
        &mut self,
        edge: &SemanticControlEdgeValue,
        source: bool,
    ) -> Option<SemanticProgramPointValue> {
        let procedure = edge.handle.procedure();
        let quality = edge.quality.combine(&self.capability_quality(
            &edge.file,
            procedure.artifact().as_ref(),
            &[SemanticCapability::ProgramPoints],
        ));
        let edge_row = procedure
            .semantics()
            .control_edge(edge.handle.id())
            .expect("validated control-edge handle resolves in its procedure");
        let id = if source {
            edge_row.source_point
        } else {
            edge_row.target_point
        };
        procedure
            .point_handle(id)
            .map(|handle| SemanticProgramPointValue {
                handle,
                file: edge.file.clone(),
                source: edge.source.clone(),
                quality,
            })
    }

    fn physical_retained_bytes(&self) -> usize {
        let lease_bytes = self.artifact_window.as_ref().map_or_else(
            || self.artifact_leases.retained_bytes(),
            SemanticArtifactLeaseWindow::retained_bytes,
        );
        lease_bytes.saturating_add(self.active_retained_bytes)
    }

    fn initial_artifact_leases_fit(&mut self, file: &ProjectFile) -> bool {
        let Some(error) = self.initial_artifact_lease_error else {
            return true;
        };
        self.budget_exhausted = true;
        self.push_diagnostic(
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
            CodeQueryDiagnosticImpact::Incomplete,
            file,
            &error.to_string(),
        );
        false
    }

    fn artifact_window_fits(&mut self, file: &ProjectFile) -> bool {
        let mut physical_retained_bytes = self.physical_retained_bytes();
        self.peak_retained_bytes = self.peak_retained_bytes.max(physical_retained_bytes);
        if let Some(error) = self
            .artifact_window
            .as_ref()
            .and_then(SemanticArtifactLeaseWindow::overflow)
        {
            self.evict_prepared_source_dispatch();
            self.budget_exhausted = true;
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &error.to_string(),
            );
            return false;
        }

        if physical_retained_bytes > self.limits.max_retained_bytes {
            self.evict_prepared_source_dispatch();
            physical_retained_bytes = self.physical_retained_bytes();
        }
        if physical_retained_bytes <= self.limits.max_retained_bytes {
            return true;
        }
        self.reject_retained_bytes_error(file, SemanticArtifactLeaseError::RetainedBytesOverflow);
        false
    }

    fn active_retained_bytes_fit(&mut self, file: &ProjectFile, bytes: usize) -> bool {
        // Mandatory retained rows always displace the optional parsed dispatch
        // cache before admission is decided.
        self.evict_prepared_source_dispatch();
        if bytes
            > self
                .limits
                .max_retained_bytes
                .saturating_sub(self.physical_retained_bytes())
        {
            self.budget_exhausted = true;
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                "semantic retained-artifact byte budget exhausted",
            );
            return false;
        }
        true
    }

    fn reject_retained_bytes_error(
        &mut self,
        file: &ProjectFile,
        error: SemanticArtifactLeaseError,
    ) {
        debug_assert_eq!(
            error,
            SemanticArtifactLeaseError::RetainedBytesOverflow,
            "retained-byte invariant fallback only reports arithmetic overflow"
        );
        self.budget_exhausted = true;
        self.push_diagnostic(
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
            CodeQueryDiagnosticImpact::Incomplete,
            file,
            &error.to_string(),
        );
    }

    fn record_active_retained_bytes(&mut self, bytes: usize) {
        self.active_retained_bytes = self.active_retained_bytes.saturating_add(bytes);
        self.peak_retained_bytes = self.peak_retained_bytes.max(self.physical_retained_bytes());
    }

    fn observe_transient_active_retained_bytes(&mut self, bytes: usize) {
        self.peak_retained_bytes = self
            .peak_retained_bytes
            .max(self.physical_retained_bytes().saturating_add(bytes));
    }

    fn admit_active_retained_bytes(&mut self, file: &ProjectFile, bytes: usize) -> bool {
        if !self.active_retained_bytes_fit(file, bytes) {
            return false;
        }
        self.record_active_retained_bytes(bytes);
        true
    }

    fn retained_artifact_bytes_if_unleased(&self, artifact: &Arc<SemanticArtifact>) -> usize {
        if self.artifact_leases.contains_exact(artifact) {
            0
        } else {
            usize::try_from(semantic_artifact_retained_bytes(artifact)).unwrap_or(usize::MAX)
        }
    }

    /// Capture the exact indexed source before a windowed provider
    /// call and reserve its physical headroom in the current file window. The
    /// same snapshot is used for post-provider key freshness, so opening a
    /// stable continuation never adds a second source read or a transient
    /// unaccounted source allocation.
    fn prepare_artifact_window_source(
        &mut self,
        file: &ProjectFile,
    ) -> Result<Option<SemanticSourceSnapshot>, Box<CachedSemanticMaterialization>> {
        if self.artifact_window_file.as_ref() != Some(file) {
            return Ok(None);
        }
        assert!(
            self.artifact_window.is_none(),
            "an uncached artifact-window materialization opens one file window"
        );
        let Some(source) = self.workspace.analyzer().indexed_source(file) else {
            let reason: Arc<str> =
                "semantic artifact source is unavailable for public range conversion".into();
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticProviderFailed,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                reason.as_ref(),
            );
            return Err(Box::new(CachedSemanticMaterialization::ProviderFailed(
                reason,
            )));
        };
        let source = SemanticSourceSnapshot::new(source);
        self.active_retained_bytes = self
            .active_retained_bytes
            .saturating_add(source.retained_bytes());
        let other_live_bytes = self.active_retained_bytes;
        let window = self.artifact_leases.begin_window(other_live_bytes);
        self.artifact_window = Some(window);
        if !self.artifact_window_fits(file) {
            return Err(Box::new(
                CachedSemanticMaterialization::RetainedBudgetExhausted,
            ));
        }
        Ok(Some(source))
    }

    fn materialize(
        &mut self,
        file: &ProjectFile,
    ) -> Option<(
        Arc<SemanticArtifact>,
        SemanticSourceSnapshot,
        SemanticQueryQuality,
    )> {
        if !self.initial_artifact_leases_fit(file) {
            self.cache.insert(
                file.clone(),
                CachedSemanticMaterialization::RetainedBudgetExhausted,
            );
            return None;
        }
        if let Some(cached) = self.cache.get(file).cloned() {
            self.cache_hits = self.cache_hits.saturating_add(1);
            return self.cached_value(file, cached);
        }
        let admitted = match &self.receipt_execution {
            Some((_, execution)) => execution.admit_materialization(file),
            None => self.attempts < self.limits.max_materialized_files,
        };
        if !admitted {
            self.budget_exhausted = true;
            self.execution_budget_exhausted = true;
            self.cache.insert(
                file.clone(),
                CachedSemanticMaterialization::FileBudgetExhausted,
            );
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                "semantic materialization file budget exhausted",
            );
            return None;
        }

        self.attempts = self.attempts.saturating_add(1);
        let window_source = match self.prepare_artifact_window_source(file) {
            Ok(source) => source,
            Err(cached) => {
                self.cache.insert(file.clone(), *cached);
                return None;
            }
        };
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        let mut request = SemanticRequest::new(&mut self.budget, cancellation);
        let artifact_collector = self
            .artifact_window
            .as_ref()
            .map(SemanticArtifactLeaseWindow::collector);
        if let Some(collector) = &artifact_collector {
            request = request.with_artifact_collector(collector);
        }
        let outcome = self
            .workspace
            .materialize_program_semantics(file, &mut request);
        drop(request);
        let artifact_window_fits = self.artifact_window_fits(file);
        match outcome {
            Ok(outcome) => {
                if !artifact_window_fits {
                    self.cache.insert(
                        file.clone(),
                        CachedSemanticMaterialization::RetainedBudgetExhausted,
                    );
                    return None;
                }
                let complete = outcome.is_complete();
                let source = match outcome.available_value() {
                    Some(artifact) => match window_source.clone() {
                        Some(source) => self.exact_source_snapshot(file, artifact, source),
                        None => self.exact_source(file, artifact),
                    },
                    None => None,
                };
                if let (Some(artifact), Some(source)) = (outcome.available_value(), source.as_ref())
                {
                    if self.artifact_window.is_some() && !complete {
                        self.artifact_window
                            .take()
                            .expect("partial artifact retains its open file window")
                            .discard();
                    }
                    let active_bytes = if window_source.is_some() {
                        if complete {
                            0
                        } else {
                            self.retained_artifact_bytes_if_unleased(artifact)
                        }
                    } else {
                        self.retained_artifact_bytes_if_unleased(artifact)
                            .saturating_add(source.retained_bytes())
                    };
                    if !self.admit_active_retained_bytes(file, active_bytes) {
                        self.cache.insert(
                            file.clone(),
                            CachedSemanticMaterialization::RetainedBudgetExhausted,
                        );
                        return None;
                    }
                    self.materialized_files.insert(file.clone());
                } else if let Some(artifact) = outcome.available_value() {
                    if window_source.is_some() && !complete {
                        self.artifact_window
                            .take()
                            .expect("partial artifact retains its open file window")
                            .discard();
                    }
                    let active_artifact_bytes = self.retained_artifact_bytes_if_unleased(artifact);
                    if self.artifact_window.is_none()
                        && !self.admit_active_retained_bytes(file, active_artifact_bytes)
                    {
                        self.cache.insert(
                            file.clone(),
                            CachedSemanticMaterialization::RetainedBudgetExhausted,
                        );
                        return None;
                    }
                }
                let cached = CachedSemanticMaterialization::Outcome { outcome, source };
                self.cache.insert(file.clone(), cached.clone());
                self.cached_value(file, cached)
            }
            Err(error) => {
                if !artifact_window_fits {
                    self.cache.insert(
                        file.clone(),
                        CachedSemanticMaterialization::RetainedBudgetExhausted,
                    );
                    return None;
                }
                let reason: Arc<str> = error.to_string().into();
                self.cache.insert(
                    file.clone(),
                    CachedSemanticMaterialization::ProviderFailed(Arc::clone(&reason)),
                );
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::SemanticProviderFailed,
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    reason.as_ref(),
                );
                None
            }
        }
    }

    /// Whether an artifact-independent pipeline step may bound its semantic
    /// retention in file windows without releasing an artifact already used by
    /// an earlier semantic row family.
    pub(super) fn can_start_artifact_windows(&self) -> bool {
        self.cache.is_empty()
            && self.indexed_source_identities.is_empty()
            && self.source_call_indexes.is_empty()
            && self.prepared_source_dispatch.is_none()
            && self.active_retained_bytes == 0
            && self.artifact_window.is_none()
            && self.artifact_window_file.is_none()
    }

    /// Designate the next result-contract file as the only semantic lease
    /// window that may open. Source capture stays lazy until a surviving row
    /// actually asks the provider to materialize this file.
    pub(super) fn start_artifact_window(&mut self, file: ProjectFile) {
        assert!(
            self.can_start_artifact_windows(),
            "result-contract file windows are sequential and artifact-independent"
        );
        self.artifact_window_file = Some(file);
    }

    /// Finish one successful result-contract file window.
    ///
    /// The bounded collector stages nested workspace-oracle materializations
    /// as well as the window's source file. Receipt mode promotes that exact
    /// dependency set into its child; an ordinary query discards it here. A
    /// window that emits no usable contract row instead reaches
    /// [`Self::release_artifact_window`] and is also discarded.
    pub(super) fn retain_artifact_window_dependencies(&mut self) {
        self.evict_prepared_source_dispatch();
        let Some(window) = self.artifact_window.take() else {
            return;
        };
        if !self.promote_artifact_windows {
            window.discard();
            return;
        }
        let result = window.commit(&mut self.artifact_leases);
        if let Err(error) = result {
            self.budget_exhausted = true;
            let file = self
                .artifact_window_file
                .clone()
                .expect("an artifact window retains its designated file");
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                CodeQueryDiagnosticImpact::Incomplete,
                &file,
                &error.to_string(),
            );
        }
    }

    /// Drop one artifact-independent step's completed file window while
    /// retaining cumulative request work, diagnostics, and the peak live byte
    /// charge. Callers must ensure no emitted pipeline value or trace owns a
    /// handle into these artifacts.
    pub(super) fn release_artifact_window(&mut self) {
        self.evict_prepared_source_dispatch();
        if let Some(window) = self.artifact_window.take() {
            window.discard();
        }
        self.cache.clear();
        self.indexed_source_identities.clear();
        drop(std::mem::take(&mut self.source_call_indexes));
        self.active_retained_bytes = 0;
        self.artifact_window_file = None;
        debug_assert_eq!(
            self.physical_retained_bytes(),
            self.artifact_leases.retained_bytes(),
            "releasing a window retains only parent-pinned and promoted dependencies"
        );
    }

    pub(super) fn into_receipt(mut self) -> Option<CodeQuerySemanticReceipt> {
        let (execution_before, execution_child) = self.receipt_execution.take()?;
        assert!(
            execution_child.charge_traversal(self.traversal_steps),
            "RQL traversal delta must fit the forked execution budget"
        );
        if self.execution_budget_exhausted && !execution_child.work().exhausted {
            assert!(
                !execution_child.charge_traversal(1),
                "a traversal refusal must leave the forked execution budget exhausted"
            );
        }
        let execution_charge = execution_child
            .charge_since(&execution_before)
            .expect("a forked execution child extends its exact starting state");
        assert!(
            self.artifact_window.is_none()
                && self.artifact_window_file.is_none()
                && self.prepared_source_dispatch.is_none(),
            "the pipeline releases its final result-contract file window"
        );
        let artifact_charge = self.artifact_leases.into_charge();
        Some(CodeQuerySemanticReceipt::new(
            self.budget.into_child_charge(),
            execution_before,
            execution_charge,
            artifact_charge,
        ))
    }

    fn cached_value(
        &mut self,
        file: &ProjectFile,
        cached: CachedSemanticMaterialization,
    ) -> Option<(
        Arc<SemanticArtifact>,
        SemanticSourceSnapshot,
        SemanticQueryQuality,
    )> {
        match cached {
            CachedSemanticMaterialization::Outcome { outcome, source } => {
                let value = outcome.available_value().cloned();
                let quality = match &outcome {
                    SemanticOutcome::Complete { .. } => SemanticQueryQuality::default(),
                    SemanticOutcome::Ambiguous { .. } => {
                        let reason = "semantic provider returned an ambiguous artifact";
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            reason,
                        );
                        SemanticQueryQuality::unproven_partial(reason)
                    }
                    SemanticOutcome::Unknown { .. } => {
                        let reason = "semantic provider returned an unknown partial artifact";
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            reason,
                        );
                        SemanticQueryQuality::unproven_partial(reason)
                    }
                    SemanticOutcome::Unsupported { capability, .. } => {
                        let reason = format!(
                            "semantic capability `{}` is unsupported",
                            capability.label()
                        );
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::SemanticCapabilityUnsupported,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            &reason,
                        );
                        SemanticQueryQuality::unproven_partial(reason)
                    }
                    SemanticOutcome::Unproven { .. } => {
                        let reason = "semantic provider returned an unproven partial artifact";
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            reason,
                        );
                        SemanticQueryQuality::unproven_partial(reason)
                    }
                    SemanticOutcome::ExceededBudget { exceeded, .. } => {
                        self.budget_exhausted = true;
                        let reason = exceeded.to_string();
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            &reason,
                        );
                        SemanticQueryQuality::unproven_partial(reason)
                    }
                    SemanticOutcome::Cancelled { .. } => {
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::Cancelled,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            "semantic materialization was cancelled",
                        );
                        return None;
                    }
                };
                value
                    .zip(source)
                    .map(|(value, source)| (value, source, quality))
            }
            CachedSemanticMaterialization::ProviderFailed(reason) => {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::SemanticProviderFailed,
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    reason.as_ref(),
                );
                None
            }
            CachedSemanticMaterialization::FileBudgetExhausted => {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    "semantic materialization file budget exhausted",
                );
                None
            }
            CachedSemanticMaterialization::RetainedBudgetExhausted => {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    "semantic retained-artifact byte budget exhausted",
                );
                None
            }
        }
    }

    fn exact_source(
        &mut self,
        file: &ProjectFile,
        artifact: &SemanticArtifact,
    ) -> Option<SemanticSourceSnapshot> {
        let Some(source) = self.workspace.analyzer().indexed_source(file) else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticProviderFailed,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                "semantic artifact source is unavailable for public range conversion",
            );
            return None;
        };
        self.exact_source_snapshot(file, artifact, SemanticSourceSnapshot::new(source))
    }

    fn exact_source_snapshot(
        &mut self,
        file: &ProjectFile,
        artifact: &SemanticArtifact,
        source: SemanticSourceSnapshot,
    ) -> Option<SemanticSourceSnapshot> {
        if ContentIdentity::hash_bytes(source.source.as_bytes())
            != artifact.key().revision().content()
        {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticResultsOmitted,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                "source generation changed before semantic result projection; retry the query for a coherent snapshot",
            );
            return None;
        }
        Some(source)
    }

    fn push_source_generation_changed(&mut self, file: &ProjectFile) {
        self.push_diagnostic(
            CodeQueryDiagnosticCode::SemanticResultsOmitted,
            CodeQueryDiagnosticImpact::Incomplete,
            file,
            "source generation changed between structural matching and semantic projection; retry the query for a coherent snapshot",
        );
    }

    fn exhaust_traversal_budget(&mut self, file: &ProjectFile, operation: &str) {
        self.traversal_steps = self.limits.max_traversal_steps;
        self.budget_exhausted = true;
        self.execution_budget_exhausted = true;
        self.push_diagnostic(
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
            CodeQueryDiagnosticImpact::Incomplete,
            file,
            &format!("semantic traversal-step budget exhausted during {operation}"),
        );
    }

    fn capability_quality(
        &mut self,
        file: &ProjectFile,
        artifact: &SemanticArtifact,
        required: &[SemanticCapability],
    ) -> SemanticQueryQuality {
        let mut quality = SemanticQueryQuality::default();
        for &capability in required {
            match artifact.capabilities().support(capability) {
                CapabilitySupport::Complete => {}
                CapabilitySupport::Partial => {
                    let reason = format!("semantic capability `{}` is partial", capability.label());
                    self.push_diagnostic(
                        CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                        CodeQueryDiagnosticImpact::Incomplete,
                        file,
                        &reason,
                    );
                    quality = quality.combine(&SemanticQueryQuality::partial(reason));
                }
                CapabilitySupport::Unsupported => {
                    let reason = format!(
                        "semantic capability `{}` is unsupported",
                        capability.label()
                    );
                    self.push_diagnostic(
                        CodeQueryDiagnosticCode::SemanticCapabilityUnsupported,
                        CodeQueryDiagnosticImpact::Incomplete,
                        file,
                        &reason,
                    );
                    quality = quality.combine(&SemanticQueryQuality::partial(reason));
                }
            }
        }
        quality
    }

    fn push_diagnostic(
        &mut self,
        code: CodeQueryDiagnosticCode,
        impact: CodeQueryDiagnosticImpact,
        file: &ProjectFile,
        message: &str,
    ) {
        let key = (code, file.clone(), message.to_string());
        if !self.reported.insert(key) {
            return;
        }
        self.diagnostics.push(CodeQueryDiagnostic {
            code,
            impact,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(file).config_label(),
            message: message.to_string(),
        });
    }
}

/// Refine source-call timing with facts that apply only to one dispatch arm.
///
/// A deferred target boundary says the target body does not execute as an
/// ordinary invocation of this source call. Until async/generator resumption
/// has an exact schedule model, that arm is unknown. An explicit Go spawn has
/// already established that all work reached through the call is in a
/// different task, so a deferred target cannot weaken that fact.
fn dispatch_arm_execution_timing(
    source: ExecutionTiming,
    boundary: Option<&DispatchBoundaryKind>,
) -> ExecutionTiming {
    match boundary {
        Some(DispatchBoundaryKind::Deferred { .. }) if source != ExecutionTiming::DifferentTask => {
            ExecutionTiming::Unknown
        }
        _ => source,
    }
}

/// CFG-specific projection over the reusable request-local semantic context.
///
/// Later flow or typestate adapters can share the same coherent
/// materialization cache, diagnostics, cancellation, and work ledger without
/// depending on the CFG operation surface.
pub(super) struct CfgQueryAdapter<'context, 'workspace> {
    context: &'context mut SemanticQueryContext<'workspace>,
}

impl CfgQueryAdapter<'_, '_> {
    pub(super) fn procedure_of_match(&mut self, seed: &SeedMatch) -> Vec<SemanticProcedureValue> {
        self.context.procedure_of_match(seed)
    }

    pub(super) fn procedure_of_declaration(
        &mut self,
        declaration: &DeclarationValue,
    ) -> Vec<SemanticProcedureValue> {
        self.context.procedure_of_declaration(declaration)
    }

    pub(super) fn entry(
        &mut self,
        procedure: &SemanticProcedureValue,
    ) -> Option<SemanticProgramPointValue> {
        self.context.cfg_entry(procedure)
    }

    pub(super) fn exits(
        &mut self,
        procedure: &SemanticProcedureValue,
    ) -> Vec<SemanticProgramPointValue> {
        self.context.cfg_exits(procedure)
    }

    pub(super) fn successor_edges(
        &mut self,
        point: &SemanticProgramPointValue,
        max_outputs: usize,
    ) -> Vec<SemanticControlEdgeValue> {
        self.context.cfg_successor_edges(point, max_outputs)
    }

    pub(super) fn predecessor_edges(
        &mut self,
        point: &SemanticProgramPointValue,
        max_outputs: usize,
    ) -> Vec<SemanticControlEdgeValue> {
        self.context.cfg_predecessor_edges(point, max_outputs)
    }

    pub(super) fn edge_source(
        &mut self,
        edge: &SemanticControlEdgeValue,
    ) -> Option<SemanticProgramPointValue> {
        self.context.cfg_edge_source(edge)
    }

    pub(super) fn edge_target(
        &mut self,
        edge: &SemanticControlEdgeValue,
    ) -> Option<SemanticProgramPointValue> {
        self.context.cfg_edge_target(edge)
    }
}

impl SemanticProcedureValue {
    /// Why this procedure cannot support a complete exact downstream
    /// selection, if materialization or enclosing-procedure discovery was
    /// partial. Local row families may still expose proven facts, but must not
    /// promote them to a complete selection while this quality is open.
    pub(super) fn exact_selection_incomplete_reason(&self) -> Option<String> {
        if self.quality.is_complete() {
            return None;
        }
        let mut reasons = Vec::new();
        if let Some(reason) = &self.quality.proof_reason {
            reasons.push(format!("proof: {reason}"));
        }
        if let Some(reason) = &self.quality.completeness_reason {
            reasons.push(format!("coverage: {reason}"));
        }
        Some(reasons.join("; "))
    }

    /// The procedure's public wire identity, so a derived row family can name
    /// the same procedure a `procedure` row does.
    pub(super) fn wire_id(&self) -> String {
        procedure_wire_id(&self.handle)
    }

    pub(super) fn public(&self) -> CodeQueryProcedure {
        let procedure = self.handle.semantics();
        let mapping = procedure_source_mapping(&self.handle);
        CodeQueryProcedure {
            id: procedure_wire_id(&self.handle),
            artifact_id: self
                .handle
                .artifact()
                .key()
                .public_fingerprint()
                .to_string(),
            path: mapping.locator.path().as_str().to_string(),
            language: mapping.locator.language().config_label(),
            procedure_kind: procedure.kind().label(),
            range: public_range(mapping, &self.source),
            evidence: public_evidence(procedure_evidence(&self.handle), &self.quality),
        }
    }

    pub(super) fn public_ref(&self) -> super::CodeQueryResultRef {
        let public = self.public();
        super::CodeQueryResultRef::Procedure {
            id: public.id,
            path: public.path,
            procedure_kind: public.procedure_kind,
            range: public.range,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn byte_span(&self) -> std::ops::Range<usize> {
        byte_span(procedure_source_mapping(&self.handle))
    }

    /// One of the procedure's own program points as a pipeline value.
    ///
    /// A derived row family that names a point by its dense id needs the point
    /// row's public projection -- its wire id, its range, its boundary -- and
    /// that projection is only mintable from the artifact the procedure came
    /// from. Sharing the seed's file, source snapshot and quality is what makes
    /// the two rows agree about the same point (#2443).
    pub(super) fn point_value(&self, id: ProgramPointId) -> Option<SemanticProgramPointValue> {
        Some(SemanticProgramPointValue {
            handle: self.handle.point_handle(id)?,
            file: self.file.clone(),
            source: self.source.clone(),
            quality: self.quality.clone(),
        })
    }

    /// One of the procedure's own control edges as a pipeline value.
    pub(super) fn edge_value(&self, id: ControlEdgeId) -> Option<SemanticControlEdgeValue> {
        Some(SemanticControlEdgeValue {
            handle: self.handle.control_edge_handle(id)?,
            file: self.file.clone(),
            source: self.source.clone(),
            quality: self.quality.clone(),
        })
    }
}

impl SemanticProgramPointValue {
    pub(super) fn public(&self) -> CodeQueryProgramPoint {
        let procedure = self.handle.procedure();
        let point = procedure
            .semantics()
            .point(self.handle.id())
            .expect("validated program-point handle resolves in its procedure");
        let mapping = procedure
            .semantics()
            .source_mapping(point.source)
            .expect("validated program point has a source mapping");
        CodeQueryProgramPoint {
            id: program_point_wire_id(&self.handle),
            procedure_id: procedure_wire_id(procedure),
            path: mapping.locator.path().as_str().to_string(),
            language: mapping.locator.language().config_label(),
            range: public_range(mapping, &self.source),
            boundary: point_boundary(&self.handle),
            event_count: point.events.len(),
            evidence: public_evidence(
                procedure
                    .semantics()
                    .evidence_row(point.evidence)
                    .expect("validated program point has evidence"),
                &self.quality,
            ),
        }
    }

    pub(super) fn public_ref(&self) -> super::CodeQueryResultRef {
        let public = self.public();
        super::CodeQueryResultRef::ProgramPoint {
            id: public.id,
            procedure_id: public.procedure_id,
            path: public.path,
            range: public.range,
            boundary: public.boundary,
        }
    }

    pub(super) fn point_ref(&self) -> CodeQueryProgramPointRef {
        let public = self.public();
        CodeQueryProgramPointRef {
            id: public.id,
            procedure_id: public.procedure_id,
            path: public.path,
            range: public.range,
            boundary: public.boundary,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    /// The point's own source region as an analyzer range, for a derived row
    /// family that anchors its evidence on a program point rather than on a
    /// rendered row of its own (#2443).
    pub(super) fn source_range(&self) -> crate::analyzer::Range {
        let point = self
            .handle
            .procedure()
            .semantics()
            .point(self.handle.id())
            .expect("validated program-point handle resolves in its procedure");
        let mapping = self
            .handle
            .procedure()
            .semantics()
            .source_mapping(point.source)
            .expect("validated program point has a source mapping");
        let span = mapping.locator.anchor().span();
        crate::analyzer::Range {
            start_byte: span.start_byte() as usize,
            end_byte: span.end_byte() as usize,
            start_line: span.start().line() as usize + 1,
            end_line: span.end().line() as usize + 1,
        }
    }

    pub(super) fn byte_span(&self) -> std::ops::Range<usize> {
        let point = self
            .handle
            .procedure()
            .semantics()
            .point(self.handle.id())
            .expect("validated program-point handle resolves in its procedure");
        byte_span(
            self.handle
                .procedure()
                .semantics()
                .source_mapping(point.source)
                .expect("validated program point has a source mapping"),
        )
    }
}

impl SemanticControlEdgeValue {
    pub(super) fn public(&self) -> CodeQueryControlEdge {
        let procedure = self.handle.procedure();
        let edge = procedure
            .semantics()
            .control_edge(self.handle.id())
            .expect("validated control-edge handle resolves in its procedure");
        let mapping = procedure
            .semantics()
            .source_mapping(edge.source)
            .expect("validated control edge has a source mapping");
        let source = SemanticProgramPointValue {
            handle: procedure
                .point_handle(edge.source_point)
                .expect("validated control edge source resolves"),
            file: self.file.clone(),
            source: self.source.clone(),
            quality: self.quality.clone(),
        };
        let target = SemanticProgramPointValue {
            handle: procedure
                .point_handle(edge.target_point)
                .expect("validated control edge target resolves"),
            file: self.file.clone(),
            source: self.source.clone(),
            quality: self.quality.clone(),
        };
        CodeQueryControlEdge {
            id: control_edge_wire_id(&self.handle),
            procedure_id: procedure_wire_id(procedure),
            path: mapping.locator.path().as_str().to_string(),
            language: mapping.locator.language().config_label(),
            range: public_range(mapping, &self.source),
            edge_kind: edge.kind.label(),
            source: source.point_ref(),
            target: target.point_ref(),
            evidence: public_evidence(
                procedure
                    .semantics()
                    .evidence_row(edge.evidence)
                    .expect("validated control edge has evidence"),
                &self.quality,
            ),
        }
    }

    pub(super) fn public_ref(&self) -> super::CodeQueryResultRef {
        let public = self.public();
        super::CodeQueryResultRef::ControlEdge {
            id: public.id,
            procedure_id: public.procedure_id,
            path: public.path,
            range: public.range,
            edge_kind: public.edge_kind,
            source_id: public.source.id,
            target_id: public.target.id,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn byte_span(&self) -> std::ops::Range<usize> {
        let edge = self
            .handle
            .procedure()
            .semantics()
            .control_edge(self.handle.id())
            .expect("validated control-edge handle resolves in its procedure");
        byte_span(
            self.handle
                .procedure()
                .semantics()
                .source_mapping(edge.source)
                .expect("validated control edge has a source mapping"),
        )
    }
}

impl SemanticCallResultValue {
    pub(super) fn public(&self) -> CodeQueryCallResult {
        let procedure = self.handle.procedure();
        let call = procedure
            .semantics()
            .call_site(self.handle.id())
            .expect("validated semantic call-result handle resolves");
        let mapping = procedure
            .semantics()
            .source_mapping(call.source)
            .expect("validated semantic call result has a source mapping");
        let point = procedure
            .point_handle(call.point)
            .expect("validated semantic call result has a point");
        let evidence = public_evidence(
            procedure
                .semantics()
                .evidence_row(call.evidence)
                .expect("validated semantic call result has evidence"),
            &self.quality,
        );
        let call_id = call_site_wire_id(&self.handle);
        let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.call_result.v1");
        digest.push(call_id.as_bytes());
        digest.push(&self.ordinal.to_le_bytes());
        digest.push(&self.value.get().to_le_bytes());
        CodeQueryCallResult {
            id: digest.finish().to_string(),
            site_id: self.site_id.clone(),
            site_ast_id: self.site_ast_id.clone(),
            call_id,
            procedure_id: procedure_wire_id(procedure),
            point_id: program_point_wire_id(&point),
            path: mapping.locator.path().as_str().to_string(),
            language: mapping.locator.language().config_label(),
            range: public_range(mapping, &self.source),
            ordinal: u64::try_from(self.ordinal)
                .expect("a semantic result ordinal fits the public integer domain"),
            value_id: u64::from(self.value.get()),
            proof: match evidence.proof {
                CodeQuerySemanticProof::Proven => "proven",
                CodeQuerySemanticProof::Unproven => "unproven",
            },
            completeness: match evidence.completeness {
                CodeQuerySemanticCompleteness::Complete => "complete",
                CodeQuerySemanticCompleteness::Partial => "partial",
            },
        }
    }

    pub(super) fn public_ref(&self) -> super::CodeQueryResultRef {
        let public = self.public();
        super::CodeQueryResultRef::CallResult {
            id: public.id,
            site_id: public.site_id,
            path: public.path,
            range: public.range,
            ordinal: public.ordinal,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn byte_span(&self) -> std::ops::Range<usize> {
        let procedure = self.handle.procedure();
        let call = procedure
            .semantics()
            .call_site(self.handle.id())
            .expect("validated semantic call-result handle resolves");
        byte_span(
            procedure
                .semantics()
                .source_mapping(call.source)
                .expect("validated semantic call result has a source mapping"),
        )
    }
}

/// This query's semantic ledger limits, one per dimension.
///
/// A caller that publishes `rows_per_dimension` has priced every row lane
/// against its own ledger, so its entries are used exactly as given. A caller
/// that supplies only the uniform `max_rows_per_dimension` has priced none of
/// the homogeneous retained rows, so each of those lanes is additionally held
/// to a memory-shaped estimate: the half of `max_retained_bytes` that is not
/// owned text, split across the row dimensions and priced at each one's row
/// size.
///
/// `nested_entries` keeps the authored row limit. It combines compact CFG
/// offsets, IDs, arguments, evidence handles, and locator segments with
/// bounded adapter and dispatch traversal that is not retained at all. Pricing
/// every unit as a `SemanticLocator` made that work lane a 49,932-entry limit
/// under the defaults, even when there was no retained-byte exhaustion. The
/// estimates guard individual retained-row lanes; the real
/// memory bound is measured in `SemanticQueryState::materialize`, which charges
/// each artifact's own retained bytes against `max_retained_bytes` (#2523).
pub(super) fn semantic_budget_limits(limits: CodeQuerySemanticLimits) -> SemanticWork {
    fn rows_for<T>(limits: CodeQuerySemanticLimits, dimension: SemanticBudgetDimension) -> usize {
        const ALLOCATION_OVERHEAD_FACTOR: usize = 2;
        let rows = limits.rows(dimension);
        if limits.rows_per_dimension.is_some() {
            return rows;
        }
        let retained_row_bytes = limits.max_retained_bytes / 2;
        let per_dimension_bytes =
            retained_row_bytes / CodeQuerySemanticRowLimits::ROW_DIMENSIONS.len();
        let conservative_row_bytes = size_of::<T>()
            .max(1)
            .saturating_mul(ALLOCATION_OVERHEAD_FACTOR);
        rows.min((per_dimension_bytes / conservative_row_bytes).max(1))
    }
    use SemanticBudgetDimension as Dimension;
    let retained_text_bytes = if limits.max_retained_bytes == 0 {
        0
    } else {
        (limits.max_retained_bytes / 2).max(1)
    };
    SemanticWork {
        source_bytes: limits.max_source_bytes.min(retained_text_bytes),
        procedures: rows_for::<ProcedureSemantics>(limits, Dimension::Procedures),
        blocks: rows_for::<BasicBlock>(limits, Dimension::Blocks),
        program_points: rows_for::<ProgramPoint>(limits, Dimension::ProgramPoints),
        values: rows_for::<SemanticValue>(limits, Dimension::Values),
        allocations: rows_for::<AllocationSite>(limits, Dimension::Allocations),
        call_sites: rows_for::<SemanticCallSite>(limits, Dimension::CallSites),
        memory_locations: rows_for::<MemoryLocation>(limits, Dimension::MemoryLocations),
        captures: rows_for::<CaptureBinding>(limits, Dimension::Captures),
        source_mappings: rows_for::<SourceMapping>(limits, Dimension::SourceMappings),
        evidence: rows_for::<Evidence>(limits, Dimension::Evidence),
        gaps: rows_for::<SemanticGap>(limits, Dimension::Gaps),
        events: rows_for::<SemanticEvent>(limits, Dimension::Events),
        control_edges: rows_for::<ControlEdge>(limits, Dimension::ControlEdges),
        nested_entries: limits.rows(Dimension::NestedEntries),
        // Owned semantic strings can exceed source volume because stable
        // identities, evidence, and nested locators intentionally duplicate
        // selected spellings. They consume the retained-text lane, not the
        // input source-byte lane.
        owned_text_bytes: retained_text_bytes,
    }
}

fn public_evidence(
    evidence: &Evidence,
    quality: &SemanticQueryQuality,
) -> CodeQuerySemanticEvidence {
    let (proof, proof_reason) = match (&quality.proof_reason, &evidence.proof) {
        (Some(reason), _) => (
            CodeQuerySemanticProof::Unproven,
            Some(bounded_reason(reason)),
        ),
        (None, ProofStatus::Proven) => (CodeQuerySemanticProof::Proven, None),
        (None, ProofStatus::Unproven(reason)) => (
            CodeQuerySemanticProof::Unproven,
            Some(bounded_reason(reason)),
        ),
    };
    let (completeness, completeness_reason) =
        match (&quality.completeness_reason, &evidence.completeness) {
            (Some(reason), _) => (
                CodeQuerySemanticCompleteness::Partial,
                Some(bounded_reason(reason)),
            ),
            (None, EvidenceCompleteness::Complete) => {
                (CodeQuerySemanticCompleteness::Complete, None)
            }
            (None, EvidenceCompleteness::Partial(reason)) => (
                CodeQuerySemanticCompleteness::Partial,
                Some(bounded_reason(reason)),
            ),
        };
    CodeQuerySemanticEvidence {
        proof,
        proof_reason,
        completeness,
        completeness_reason,
    }
}

fn bounded_reason(reason: &str) -> String {
    const MAX_REASON_CHARS: usize = 256;
    let mut chars = reason.chars();
    let mut bounded = chars.by_ref().take(MAX_REASON_CHARS).collect::<String>();
    if chars.next().is_some() {
        bounded.push('…');
    }
    bounded
}

fn procedure_source_mapping(handle: &ProcedureHandle) -> &SourceMapping {
    handle
        .semantics()
        .source_mapping(handle.semantics().source())
        .expect("validated procedure has a source mapping")
}

fn procedure_evidence(handle: &ProcedureHandle) -> &Evidence {
    handle
        .semantics()
        .evidence_row(handle.semantics().evidence())
        .expect("validated procedure has evidence")
}

fn public_range(mapping: &SourceMapping, source: &SemanticSourceSnapshot) -> CodeQueryRange {
    let span = mapping.locator.anchor().span();
    let (start_line, start_column) = line_column_for_offset(
        &source.source,
        &source.line_starts,
        span.start_byte() as usize,
    );
    let (end_line, end_column) = line_column_for_offset(
        &source.source,
        &source.line_starts,
        span.end_byte() as usize,
    );
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

fn byte_span(mapping: &SourceMapping) -> std::ops::Range<usize> {
    let span = mapping.locator.anchor().span();
    span.start_byte() as usize..span.end_byte() as usize
}

fn point_boundary(handle: &ProgramPointHandle) -> Option<CodeQueryProgramPointBoundary> {
    let procedure = handle.procedure().semantics();
    let id = handle.id();
    if id == procedure.entry_point() {
        Some(CodeQueryProgramPointBoundary::Entry)
    } else if id == procedure.normal_exit_point() {
        Some(CodeQueryProgramPointBoundary::NormalExit)
    } else if id == procedure.exceptional_exit_point() {
        Some(CodeQueryProgramPointBoundary::ExceptionalExit)
    } else {
        None
    }
}

pub(crate) fn procedure_wire_id(handle: &ProcedureHandle) -> String {
    brokk_bifrost_flow::flow_state::procedure_wire_id(handle)
}

pub(crate) fn program_point_wire_id(handle: &ProgramPointHandle) -> String {
    brokk_bifrost_flow::flow_state::program_point_wire_id(handle)
}

pub(crate) fn semantic_value_wire_id(value: &ValueHandle) -> String {
    let identity = crate::analyzer::semantic::DurableValueIdentity::of(value)
        .expect("validated semantic value has a durable source identity");
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.semantic_value.v1");
    digest.push(
        value
            .procedure()
            .artifact()
            .key()
            .public_fingerprint()
            .as_bytes(),
    );
    identity.locator.push_stable_identity(&mut digest);
    digest.push(identity.role.as_bytes());
    if let Some(ordinal) = identity.ordinal {
        digest.push(&ordinal.to_le_bytes());
    }
    digest.finish().to_string()
}

pub(crate) fn control_edge_wire_id(handle: &ControlEdgeHandle) -> String {
    let procedure = handle.procedure();
    let edge = procedure
        .semantics()
        .control_edge(handle.id())
        .expect("validated control-edge handle resolves in its procedure");
    let mapping = procedure
        .semantics()
        .source_mapping(edge.source)
        .expect("validated control edge has a source mapping");
    let source = procedure
        .point_handle(edge.source_point)
        .expect("validated control edge source resolves");
    let target = procedure
        .point_handle(edge.target_point)
        .expect("validated control edge target resolves");
    let evidence = procedure
        .semantics()
        .evidence_row(edge.evidence)
        .expect("validated control edge has evidence");
    let mut digest = semantic_wire_digest(procedure.artifact().as_ref(), b"control_edge");
    push_locator(&mut digest, procedure.semantics().locator());
    // Source and evidence rows are allowed to carry distinct provenance even
    // when their public content is otherwise identical. Keep their local IDs
    // private, but include them in the artifact-scoped digest: validation
    // rejects an otherwise-identical edge with the same pair, making this
    // injective without tying the wire identity to control-edge storage order.
    digest.push(&edge.source.get().to_le_bytes());
    digest.push(&edge.evidence.get().to_le_bytes());
    push_locator(&mut digest, &mapping.locator);
    digest.push(edge.kind.label().as_bytes());
    digest.push(program_point_wire_id(&source).as_bytes());
    digest.push(program_point_wire_id(&target).as_bytes());
    push_evidence(&mut digest, procedure.semantics(), evidence);
    digest.finish().to_string()
}

pub(crate) fn call_site_wire_id(handle: &CallSiteHandle) -> String {
    let procedure = handle.procedure();
    let call = procedure
        .semantics()
        .call_site(handle.id())
        .expect("validated semantic call-site handle resolves");
    let mapping = procedure
        .semantics()
        .source_mapping(call.source)
        .expect("validated semantic call site has a source mapping");
    let mut digest = semantic_wire_digest(procedure.artifact().as_ref(), b"call_site");
    push_locator(&mut digest, procedure.semantics().locator());
    push_locator(&mut digest, &mapping.locator);
    digest.push(&call.id.get().to_le_bytes());
    digest.finish().to_string()
}

fn semantic_wire_digest(artifact: &SemanticArtifact, domain: &[u8]) -> LengthDelimitedDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-code-query-semantic-wire-id-v2");
    digest.push(artifact.key().public_fingerprint().as_bytes());
    digest.push(domain);
    digest
}

/// The shared locator digest recipe, exposed for row families outside this
/// module that identify a semantic target by its locator.
pub(super) fn push_locator_bytes(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    push_locator(digest, locator);
}

fn push_locator(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    locator.push_stable_identity(digest);
}

fn push_evidence(
    digest: &mut LengthDelimitedDigest,
    procedure: &ProcedureSemantics,
    evidence: &Evidence,
) {
    match &evidence.proof {
        ProofStatus::Proven => digest.push(b"proven"),
        ProofStatus::Unproven(reason) => {
            digest.push(b"unproven");
            digest.push(reason.as_bytes());
        }
    }
    match &evidence.completeness {
        EvidenceCompleteness::Complete => digest.push(b"complete"),
        EvidenceCompleteness::Partial(reason) => {
            digest.push(b"partial");
            digest.push(reason.as_bytes());
        }
    }
    for source in evidence
        .sources
        .iter()
        .filter_map(|id| procedure.source_mapping(*id))
    {
        push_locator(digest, &source.locator);
    }
}

fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::duplicate_mod)]
#[path = "../../../../../test-support/inline_project.rs"]
mod inline_project;

#[cfg(test)]
mod tests {
    use super::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use super::*;
    use crate::analyzer::AnalyzerConfig;
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        AdapterSemanticsVersion, BasicBlock, BlockId, CandidateCoverage, ConfigurationFingerprint,
        ContentIdentity, ControlEdgeId, ControlEdgeKind, DeclarationLocator, DeclarationSegment,
        DeclarationSegmentKind, DeferredInvocationKind, DependencyFingerprint, EvidenceId,
        ProcedureId, ProcedureKind, ProcedureSemanticsParts, ProgramPointId, SemanticArtifactKey,
        SemanticArtifactLeaseSet, SemanticCapabilities, SemanticEvent, SemanticIrVersion,
        SemanticLanguage, SemanticRole, SourceAnchor, SourceMappingId, SourceMappingKind,
        SourcePosition, SourceRevision, SourceSpan, WorkspaceMountId, WorkspaceRelativePath,
    };

    #[test]
    fn semantic_source_snapshot_retained_bytes_include_both_arc_allocations() {
        let short = SemanticSourceSnapshot::new("one line\n".to_owned());
        let source = (0..4_096)
            .map(|line| format!("line {line}: {}\n", "source".repeat(8)))
            .collect::<String>();
        let many_lines = SemanticSourceSnapshot::new(source.clone());
        let minimum = size_of::<SemanticSourceSnapshot>()
            .saturating_add(4 * size_of::<usize>())
            .saturating_add(4 * size_of::<usize>())
            .saturating_add(2 * (align_of::<usize>() - 1))
            .saturating_add(source.len())
            .saturating_add(
                many_lines
                    .line_starts
                    .len()
                    .saturating_mul(size_of::<usize>()),
            );

        assert!(many_lines.retained_bytes() >= minimum);
        assert!(
            many_lines.retained_bytes()
                >= short
                    .retained_bytes()
                    .saturating_add(source.len().saturating_sub(short.source.len())),
            "long sources and their line indexes must increase physical headroom"
        );
    }

    #[test]
    fn semantic_source_snapshot_consumes_exact_lease_window_headroom() {
        let source = (0..4_096)
            .map(|line| format!("line {line}: {}\n", "source".repeat(8)))
            .collect::<String>();
        let source = SemanticSourceSnapshot::new(source);
        let source_bytes = source.retained_bytes();
        let leases = SemanticArtifactLeaseSet::new(source_bytes - 1);
        let mut child = leases.snapshot().into_child();
        let window = child.begin_window(source_bytes);

        let Some(SemanticArtifactLeaseError::Capacity(exceeded)) = window.overflow() else {
            panic!("source-only over-cap window must report typed capacity exhaustion")
        };
        assert_eq!(exceeded.limit(), source_bytes - 1);
        assert_eq!(exceeded.attempted(), source_bytes);
        window.discard();
        assert_eq!(
            child.into_charge().len(),
            0,
            "an initially over-cap source window must not retain any lease"
        );
    }

    fn receipt_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        let project = InlineTestProject::with_language(Language::Go)
            .file("subject.go", "package subject\n\nfunc subject() {}\n")
            .file("first.unsupported", "first\n")
            .file("second.unsupported", "second\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        (project, workspace)
    }

    fn source_call_index_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        let calls = (0..32).map(|_| "    sink()\n").collect::<String>();
        let source =
            format!("package subject\n\nfunc sink() {{}}\n\nfunc subject() {{\n{calls}}}\n");
        let project = InlineTestProject::with_language(Language::Go)
            .file("subject.go", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        (project, workspace)
    }

    const PREPARED_DISPATCH_SOURCE: &str =
        "package subject\n\nfunc target() {}\nfunc caller() { target() }\n";

    fn prepared_dispatch_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        let project = InlineTestProject::with_language(Language::Go)
            .file("subject.go", PREPARED_DISPATCH_SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        (project, workspace)
    }

    fn prepared_dispatch_call_range() -> crate::analyzer::Range {
        let start = PREPARED_DISPATCH_SOURCE
            .rfind("target()")
            .expect("fixture caller contains its target invocation");
        crate::analyzer::Range {
            start_byte: start,
            end_byte: start + "target()".len(),
            start_line: 3,
            end_line: 3,
        }
    }

    const CROSS_FILE_DISPATCH_CALLER: &str = "package subject\n\nfunc caller() { target() }\n";
    const CROSS_FILE_DISPATCH_TARGET: &str = "package subject\n\nfunc target() {}\n";

    fn cross_file_dispatch_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        let project = InlineTestProject::with_language(Language::Go)
            .file("caller.go", CROSS_FILE_DISPATCH_CALLER)
            .file("target.go", CROSS_FILE_DISPATCH_TARGET)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        (project, workspace)
    }

    fn cross_file_dispatch_call_range() -> crate::analyzer::Range {
        let start = CROSS_FILE_DISPATCH_CALLER
            .rfind("target()")
            .expect("fixture caller contains its cross-file invocation");
        crate::analyzer::Range {
            start_byte: start,
            end_byte: start + "target()".len(),
            start_line: 2,
            end_line: 2,
        }
    }

    fn continuation_context<'a>(
        workspace: &'a WorkspaceAnalyzer,
        parent_semantic: &SemanticBudget,
        parent_execution: &SemanticExecutionBudget,
        limits: CodeQuerySemanticLimits,
    ) -> SemanticQueryContext<'a> {
        let leases = SemanticArtifactLeaseSet::new(limits.max_retained_bytes);
        continuation_context_with_leases(
            workspace,
            parent_semantic,
            parent_execution,
            limits,
            &leases,
        )
    }

    fn continuation_context_with_leases<'a>(
        workspace: &'a WorkspaceAnalyzer,
        parent_semantic: &SemanticBudget,
        parent_execution: &SemanticExecutionBudget,
        limits: CodeQuerySemanticLimits,
        leases: &SemanticArtifactLeaseSet,
    ) -> SemanticQueryContext<'a> {
        let parent_scope = parent_semantic.scope_snapshot();
        let (execution_before, execution_child) = parent_execution
            .fork_with_additional_limits(limits.max_materialized_files, limits.max_traversal_steps);
        SemanticQueryContext::new_with_parent_scope(
            workspace,
            None,
            limits,
            super::super::CodeQueryTypestateLimits::default(),
            super::super::CodeQueryValueFlowLimits::default(),
            super::super::CodeQueryTaintLimits::default(),
            0,
            None,
            workspace.analyzer().active_semantic_model_snapshot(),
            None,
            &parent_scope,
            parent_semantic.remaining(),
            execution_before,
            execution_child,
            leases.snapshot(),
        )
    }

    #[test]
    fn ordinary_result_contract_windows_discard_complete_artifacts_between_windows() {
        let (project, workspace) = receipt_workspace();
        let file = project.file("subject.go");
        let mut context =
            SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
        assert!(!context.promote_artifact_windows);

        for _ in 0..2 {
            assert!(context.can_start_artifact_windows());
            context.start_artifact_window(file.clone());
            let materialized = context
                .materialize(&file)
                .expect("ordinary result-contract window materializes");
            drop(materialized);
            context.retain_artifact_window_dependencies();
            context.release_artifact_window();
            assert_eq!(
                context.artifact_leases.retained_bytes(),
                0,
                "ordinary queries discard even policy-relevant window leases"
            );
        }
        assert!(context.into_receipt().is_none());
    }

    #[test]
    fn prepared_dispatch_retention_fits_refuses_and_rolls_back_without_semantic_failure() {
        let (project, workspace) = prepared_dispatch_workspace();
        let file = project.file("subject.go");
        let call_range = prepared_dispatch_call_range();

        let mut calibration =
            SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
        calibration.start_artifact_window(file.clone());
        let calibration_answer = calibration.dispatch_at_source(&file, call_range);
        assert_eq!(
            calibration_answer.outcome, "resolved",
            "{calibration_answer:#?}"
        );
        let prepared_bytes = calibration
            .prepared_source_dispatch
            .as_ref()
            .expect("the default cap retains calibrated dispatch syntax")
            .retained_bytes;
        let mandatory_bytes = calibration
            .physical_retained_bytes()
            .checked_sub(prepared_bytes)
            .expect("prepared syntax is part of the calibrated total");
        assert!(mandatory_bytes > 0);
        assert!(prepared_bytes > 0);
        calibration.release_artifact_window();
        assert_eq!(calibration.physical_retained_bytes(), 0);

        // These cases calibrate physical retention only. A standalone context
        // derives its semantic row and source limits from max_retained_bytes,
        // so tightening that cap would also change the provider answer under
        // test. Keep full semantic authority while independently narrowing the
        // child lease window, as production continuations do.
        let parent_semantic = SemanticBudget::default();
        let parent_execution = SemanticExecutionBudget::new(
            CodeQuerySemanticLimits::default().max_materialized_files,
            CodeQuerySemanticLimits::default().max_traversal_steps,
        );

        let fitting_limits = CodeQuerySemanticLimits {
            max_retained_bytes: mandatory_bytes + prepared_bytes,
            ..CodeQuerySemanticLimits::default()
        };
        let mut fitting = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            fitting_limits,
        );
        fitting.start_artifact_window(file.clone());
        let fitting_answer = fitting.dispatch_at_source(&file, call_range);
        assert_eq!(fitting_answer.outcome, "resolved", "{fitting_answer:#?}");
        assert_eq!(fitting_answer.call_site_count, 1);
        assert!(!fitting_answer.arms.is_empty());
        let fitting_targets = fitting_answer
            .arms
            .iter()
            .map(|arm| arm.target_id.clone())
            .collect::<Vec<_>>();
        let prepared = fitting
            .prepared_source_dispatch
            .as_ref()
            .expect("an exactly fitting window retains its parsed dispatch session");
        assert_eq!(prepared.retained_bytes, prepared_bytes);
        assert_eq!(prepared.session.retained_bytes(), prepared.retained_bytes);
        assert_eq!(
            fitting.physical_retained_bytes(),
            mandatory_bytes + prepared_bytes
        );
        assert!(
            fitting
                .artifact_window
                .as_ref()
                .expect("dispatch keeps its file window open")
                .overflow()
                .is_none()
        );
        fitting.release_artifact_window();
        assert_eq!(fitting.physical_retained_bytes(), 0);

        let refusing_limits = CodeQuerySemanticLimits {
            max_retained_bytes: mandatory_bytes + prepared_bytes - 1,
            ..CodeQuerySemanticLimits::default()
        };
        let mut refusing = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            refusing_limits,
        );
        refusing.start_artifact_window(file.clone());
        let refusing_answer = refusing.dispatch_at_source(&file, call_range);
        assert_eq!(refusing_answer.outcome, fitting_answer.outcome);
        assert_eq!(refusing_answer.coverage, fitting_answer.coverage);
        assert_eq!(
            refusing_answer.call_site_count,
            fitting_answer.call_site_count
        );
        assert_eq!(
            refusing_answer
                .arms
                .iter()
                .map(|arm| arm.target_id.clone())
                .collect::<Vec<_>>(),
            fitting_targets,
            "the optional-retention refusal falls back to the same one-shot answer"
        );
        assert!(refusing.prepared_source_dispatch.is_none());
        assert_eq!(
            refusing.physical_retained_bytes(),
            mandatory_bytes,
            "a refused accelerator retains no syntax allocation"
        );
        assert!(
            refusing
                .artifact_window
                .as_ref()
                .expect("optional-cache refusal keeps its ordinary file window")
                .overflow()
                .is_none(),
            "optional reservation refusal must not poison the semantic window"
        );
        assert!(refusing.take_diagnostics().is_empty());
        refusing.release_artifact_window();
        assert_eq!(refusing.physical_retained_bytes(), 0);

        let mut no_call =
            SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
        no_call.start_artifact_window(file.clone());
        let no_call_answer = no_call.dispatch_at_source(
            &file,
            crate::analyzer::Range {
                start_byte: 0,
                end_byte: "package".len(),
                start_line: 0,
                end_line: 0,
            },
        );
        assert_eq!(no_call_answer.outcome, "unknown", "{no_call_answer:#?}");
        assert!(no_call.prepared_source_dispatch.is_none());
        assert_eq!(
            no_call.physical_retained_bytes(),
            mandatory_bytes,
            "a non-call range drops its transient syntax session"
        );
        assert!(
            no_call
                .artifact_window
                .as_ref()
                .expect("non-call lookup retains the ordinary artifact window")
                .overflow()
                .is_none()
        );
        no_call.release_artifact_window();
        assert_eq!(no_call.physical_retained_bytes(), 0);
    }

    #[test]
    fn optional_dispatch_syntax_yields_to_mandatory_cross_file_target_leases() {
        let (project, workspace) = cross_file_dispatch_workspace();
        let caller = project.file("caller.go");
        let call_range = cross_file_dispatch_call_range();

        let mut root_calibration =
            SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
        root_calibration.start_artifact_window(caller.clone());
        root_calibration
            .materialize(&caller)
            .expect("caller artifact calibrates the mandatory root footprint");
        let root_bytes = root_calibration.physical_retained_bytes();
        root_calibration.release_artifact_window();

        let mut calibration =
            SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
        calibration.start_artifact_window(caller.clone());
        let answer = calibration.dispatch_at_source(&caller, call_range);
        assert_eq!(answer.outcome, "resolved", "{answer:#?}");
        let expected_coverage = answer.coverage;
        let expected_targets = answer
            .arms
            .iter()
            .map(|arm| (arm.target_id.clone(), arm.boundary_kind))
            .collect::<Vec<_>>();
        assert!(!expected_targets.is_empty());
        let expected_unnamed_boundaries = answer.unnamed_boundaries.clone();
        let prepared = calibration
            .prepared_source_dispatch
            .as_ref()
            .expect("the default cap retains the cross-file caller syntax");
        let prepared_bytes = prepared.retained_bytes;
        assert_eq!(prepared.session.retained_bytes(), prepared_bytes);
        let mandatory_bytes = calibration
            .physical_retained_bytes()
            .checked_sub(prepared_bytes)
            .expect("prepared syntax is part of the calibrated total");
        assert!(
            mandatory_bytes > root_bytes,
            "cross-file dispatch adds a mandatory target artifact lease"
        );
        calibration.release_artifact_window();

        let fitting_cap = mandatory_bytes.max(root_bytes.saturating_add(prepared_bytes));
        assert!(
            root_bytes.saturating_add(prepared_bytes) <= fitting_cap,
            "the old eager syntax reservation would have fit before target dispatch"
        );
        assert!(
            fitting_cap < mandatory_bytes.saturating_add(prepared_bytes),
            "the complete mandatory dependency set leaves no room for retained syntax"
        );
        // The replay varies only the physical lease cap. Do not let the
        // standalone-context heuristic derive smaller semantic work lanes from
        // that same number and confound target resolution with lease admission.
        let parent_semantic = SemanticBudget::default();
        let parent_execution = SemanticExecutionBudget::new(
            CodeQuerySemanticLimits::default().max_materialized_files,
            CodeQuerySemanticLimits::default().max_traversal_steps,
        );
        let fitting_limits = CodeQuerySemanticLimits {
            max_retained_bytes: fitting_cap,
            ..CodeQuerySemanticLimits::default()
        };
        let mut fitting = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            fitting_limits,
        );
        fitting.start_artifact_window(caller.clone());
        let fitting_answer = fitting.dispatch_at_source(&caller, call_range);
        assert_eq!(fitting_answer.outcome, "resolved", "{fitting_answer:#?}");
        assert_eq!(fitting_answer.coverage, expected_coverage);
        assert_eq!(fitting_answer.coverage, CandidateCoverage::Exhaustive);
        assert_eq!(
            fitting_answer
                .arms
                .iter()
                .map(|arm| (arm.target_id.clone(), arm.boundary_kind))
                .collect::<Vec<_>>(),
            expected_targets
        );
        assert_eq!(
            fitting_answer.unnamed_boundaries,
            expected_unnamed_boundaries
        );
        assert!(
            fitting_answer
                .arms
                .iter()
                .all(|arm| arm.proof == "proven" && arm.completeness == "complete"),
            "the optional-cache refusal leaves the complete target answer unchanged"
        );
        assert!(fitting.prepared_source_dispatch.is_none());
        assert_eq!(fitting.physical_retained_bytes(), mandatory_bytes);
        assert!(
            fitting
                .artifact_window
                .as_ref()
                .expect("cross-file dispatch retains its mandatory window")
                .overflow()
                .is_none()
        );
        assert!(
            fitting
                .take_diagnostics()
                .iter()
                .all(|diagnostic| diagnostic.code
                    != CodeQueryDiagnosticCode::SemanticBudgetExhausted)
        );
        fitting.release_artifact_window();

        let overflow_limit = mandatory_bytes
            .checked_sub(1)
            .expect("the mandatory cross-file footprint is nonzero");
        assert!(overflow_limit >= root_bytes);
        let overflow_limits = CodeQuerySemanticLimits {
            max_retained_bytes: overflow_limit,
            ..CodeQuerySemanticLimits::default()
        };
        let mut overflowing = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            overflow_limits,
        );
        overflowing.start_artifact_window(caller.clone());
        let overflow_answer = overflowing.dispatch_at_source(&caller, call_range);
        assert_eq!(
            overflow_answer.outcome, "exceeded_budget",
            "one byte below the mandatory footprint is a real semantic failure"
        );
        let Some(SemanticArtifactLeaseError::Capacity(exceeded)) = overflowing
            .artifact_window
            .as_ref()
            .and_then(SemanticArtifactLeaseWindow::overflow)
        else {
            panic!("mandatory cross-file target admission must report typed capacity")
        };
        assert_eq!(exceeded.limit(), overflow_limit);
        assert_eq!(exceeded.attempted(), mandatory_bytes);
        let diagnostics = overflowing.take_diagnostics();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted
                && diagnostic
                    .message
                    .contains("semantic artifact leases attempted")
        }));
        assert!(!diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("retained-byte arithmetic overflowed")
        }));
        overflowing.release_artifact_window();
    }

    #[test]
    fn source_call_index_reserves_window_headroom_before_retaining_handle_metadata() {
        assert_eq!(
            SemanticSourceCallIndex::reservation_bytes(usize::MAX),
            Err(SemanticArtifactLeaseError::RetainedBytesOverflow),
            "admission arithmetic overflows before allocating source-call storage"
        );
        let (project, workspace) = source_call_index_workspace();
        let file = project.file("subject.go");
        let mut calibration =
            SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
        calibration.start_artifact_window(file.clone());
        let (artifact, _, _) = calibration
            .materialize(&file)
            .expect("calibration materializes the call-bearing artifact");
        assert!(artifact.work().call_sites >= 32);
        let artifact_and_source_bytes = calibration.physical_retained_bytes();
        let reservation_bytes =
            SemanticSourceCallIndex::reservation_bytes(artifact.work().call_sites)
                .expect("fixture index byte arithmetic fits");
        let index = calibration
            .source_call_index(&file, &artifact)
            .expect("the calibrated source-call index fits");
        let retained_index_bytes = index
            .retained_bytes()
            .expect("fixture retained index byte arithmetic fits");
        assert!(retained_index_bytes <= reservation_bytes);
        assert_eq!(
            calibration.physical_retained_bytes(),
            artifact_and_source_bytes + retained_index_bytes
        );
        drop(artifact);
        calibration.release_artifact_window();

        let parent_semantic = SemanticBudget::default();
        let parent_execution = SemanticExecutionBudget::new(
            CodeQuerySemanticLimits::default().max_materialized_files,
            CodeQuerySemanticLimits::default().max_traversal_steps,
        );

        let fitting_limits = CodeQuerySemanticLimits {
            max_retained_bytes: artifact_and_source_bytes + reservation_bytes,
            ..CodeQuerySemanticLimits::default()
        };
        let mut fitting = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            fitting_limits,
        );
        fitting.start_artifact_window(file.clone());
        let (artifact, _, _) = fitting
            .materialize(&file)
            .expect("the artifact and source fit before index construction");
        assert_eq!(fitting.physical_retained_bytes(), artifact_and_source_bytes);
        assert!(fitting.source_call_index(&file, &artifact).is_some());
        assert_eq!(
            fitting.physical_retained_bytes(),
            artifact_and_source_bytes + retained_index_bytes,
            "the successful reservation becomes retained index metadata"
        );
        drop(artifact);
        fitting.release_artifact_window();
        assert_eq!(fitting.source_call_indexes.capacity(), 0);
        assert_eq!(fitting.active_retained_bytes, 0);

        let refusing_limit = artifact_and_source_bytes + reservation_bytes - 1;
        let refusing_limits = CodeQuerySemanticLimits {
            max_retained_bytes: refusing_limit,
            ..CodeQuerySemanticLimits::default()
        };
        let mut refusing = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            refusing_limits,
        );
        refusing.start_artifact_window(file.clone());
        let (artifact, _, _) = refusing
            .materialize(&file)
            .expect("the tight window still admits its artifact and source");
        assert!(refusing.source_call_index(&file, &artifact).is_none());
        let Some(SemanticArtifactLeaseError::Capacity(exceeded)) = refusing
            .artifact_window
            .as_ref()
            .and_then(SemanticArtifactLeaseWindow::overflow)
        else {
            panic!("source-call index headroom reports typed capacity exhaustion")
        };
        assert_eq!(exceeded.limit(), refusing_limit);
        assert_eq!(
            exceeded.attempted(),
            artifact_and_source_bytes + reservation_bytes
        );
        assert_eq!(
            refusing.work().retained_bytes,
            saturating_u64(artifact_and_source_bytes),
            "a refused reservation is not reported as live retained memory"
        );
        assert!(refusing.take_diagnostics().iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted
        }));
        drop(artifact);
        refusing.release_artifact_window();

        let mut interrupted = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            CodeQuerySemanticLimits::default(),
        );
        interrupted.start_artifact_window(file.clone());
        let (artifact, _, _) = interrupted
            .materialize(&file)
            .expect("the interrupted index materializes its artifact first");
        let artifact_and_source_bytes = interrupted.physical_retained_bytes();
        interrupted.limits.max_traversal_steps = interrupted.traversal_steps.saturating_add(1);
        assert!(interrupted.source_call_index(&file, &artifact).is_none());
        assert_eq!(
            interrupted.physical_retained_bytes(),
            artifact_and_source_bytes
                + SemanticSourceCallIndex::absent_entry_retained_bytes()
                    .expect("fixture absent-entry byte arithmetic fits"),
            "an interrupted build drops candidate storage before retaining its absent entry"
        );
        assert_eq!(
            interrupted.work().retained_bytes,
            saturating_u64(
                artifact_and_source_bytes
                    + SemanticSourceCallIndex::candidate_storage_retained_bytes(
                        artifact.work().call_sites,
                    )
                    .expect("fixture candidate byte arithmetic fits")
            ),
            "the high-water mark includes candidate scratch that was genuinely allocated"
        );
        let retained_after_interruption = interrupted.physical_retained_bytes();
        assert!(interrupted.source_call_index(&file, &artifact).is_none());
        assert_eq!(
            interrupted.physical_retained_bytes(),
            retained_after_interruption,
            "an absent entry prevents rebuilding and recharging the interrupted index"
        );
        drop(artifact);
        interrupted.release_artifact_window();
        assert_eq!(interrupted.source_call_indexes.capacity(), 0);
        assert_eq!(interrupted.active_retained_bytes, 0);
    }

    #[test]
    fn continuation_snapshot_is_restricted_before_provider_observation() {
        let (project, workspace) = receipt_workspace();
        let file = project.file("subject.go");
        let parent_semantic = SemanticBudget::default();
        let parent_execution = SemanticExecutionBudget::new(1, 16);
        let parent_leases =
            SemanticArtifactLeaseSet::new(CodeQuerySemanticLimits::default().max_retained_bytes);
        let limits = CodeQuerySemanticLimits {
            max_retained_bytes: 1,
            ..CodeQuerySemanticLimits::default()
        };
        let mut context = continuation_context_with_leases(
            &workspace,
            &parent_semantic,
            &parent_execution,
            limits,
            &parent_leases,
        );
        assert_eq!(context.artifact_leases.retained_bytes(), 0);
        context.start_artifact_window(file.clone());
        assert!(context.materialize(&file).is_none());
        assert_eq!(
            context.budget.used(),
            SemanticWork::default(),
            "the restricted source window refuses before the provider performs semantic work"
        );
        assert!(context.take_diagnostics().iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted
        }));
        context.release_artifact_window();
        let receipt = context
            .into_receipt()
            .expect("continuation returns work receipt");
        let (_, _, _, artifact_charge) = receipt.into_parts();
        assert!(artifact_charge.is_empty());
    }

    #[test]
    fn narrowed_nonwindowed_continuation_refuses_retained_base_before_provider_work() {
        let (project, workspace) = receipt_workspace();
        let file = project.file("subject.go");
        let mut parent_semantic = SemanticBudget::default();
        let parent_execution = SemanticExecutionBudget::new(1, 16);
        let mut parent_leases =
            SemanticArtifactLeaseSet::new(CodeQuerySemanticLimits::default().max_retained_bytes);

        let mut seed = continuation_context_with_leases(
            &workspace,
            &parent_semantic,
            &parent_execution,
            CodeQuerySemanticLimits::default(),
            &parent_leases,
        );
        seed.start_artifact_window(file.clone());
        let materialized = seed
            .materialize(&file)
            .expect("seed window materializes one complete artifact");
        drop(materialized);
        seed.retain_artifact_window_dependencies();
        seed.release_artifact_window();
        let seed_receipt = seed.into_receipt().expect("seed receipt");
        parent_semantic
            .check_child_charge(SemanticWork::default(), seed_receipt.budget_charge())
            .expect("seed work fits the parent");
        let (semantic_charge, execution_before, execution_charge, artifact_charge) =
            seed_receipt.into_parts();
        assert!(parent_execution.can_replay_charge(&execution_before, &execution_charge));
        assert!(parent_execution.replay_charge(&execution_before, &execution_charge));
        parent_semantic
            .apply_child_charge(SemanticWork::default(), semantic_charge)
            .expect("preflighted seed semantic work applies");
        parent_leases
            .try_apply_charge(artifact_charge, 0)
            .expect("seed artifact enters the parent lease set");
        let retained_bytes = parent_leases.retained_bytes();
        assert!(retained_bytes > 1);

        let semantic_before = parent_semantic.used();
        let execution_before = parent_execution.work();
        let narrowed_limits = CodeQuerySemanticLimits {
            max_retained_bytes: retained_bytes - 1,
            ..CodeQuerySemanticLimits::default()
        };
        let mut narrowed = continuation_context_with_leases(
            &workspace,
            &parent_semantic,
            &parent_execution,
            narrowed_limits,
            &parent_leases,
        );
        assert!(
            narrowed.materialize(&file).is_none(),
            "a nonwindowed request refuses an already-over-cap retained base"
        );
        assert_eq!(narrowed.work().materialization_attempts, 0);
        assert_eq!(narrowed.budget.used(), SemanticWork::default());
        assert!(narrowed.take_diagnostics().iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted
                && diagnostic
                    .message
                    .contains("semantic artifact leases attempted")
        }));

        let narrowed_receipt = narrowed.into_receipt().expect("narrowed receipt");
        let (semantic_charge, execution_snapshot, execution_charge, artifact_charge) =
            narrowed_receipt.into_parts();
        assert!(artifact_charge.is_empty());
        assert!(parent_execution.can_replay_charge(&execution_snapshot, &execution_charge));
        assert!(parent_execution.replay_charge(&execution_snapshot, &execution_charge));
        parent_semantic
            .apply_child_charge(SemanticWork::default(), semantic_charge)
            .expect("zero provider work imports cleanly");
        assert_eq!(parent_semantic.used(), semantic_before);
        assert_eq!(parent_execution.work(), execution_before);
    }

    fn import_context_charge(
        parent_semantic: &mut SemanticBudget,
        parent_execution: &SemanticExecutionBudget,
        context: SemanticQueryContext<'_>,
    ) {
        let receipt = context
            .into_receipt()
            .expect("continuation context returns a one-shot charge");
        parent_semantic
            .check_child_charge(SemanticWork::default(), receipt.budget_charge())
            .expect("exact child work fits the parent");
        let (semantic_charge, execution_before, execution_charge, artifact_charge) =
            receipt.into_parts();
        assert!(artifact_charge.is_empty());
        assert!(parent_execution.replay_charge(&execution_before, &execution_charge));
        parent_semantic
            .apply_child_charge(SemanticWork::default(), semantic_charge)
            .expect("preflighted semantic charge commits");
    }

    #[test]
    fn unsupported_attempts_import_entered_file_identity_and_zero_new_file_refusal() {
        let (project, workspace) = receipt_workspace();
        let first = project.file("first.unsupported");
        let second = project.file("second.unsupported");
        let mut parent_semantic = SemanticBudget::default();
        let parent_execution = SemanticExecutionBudget::new(1, 16);

        let mut first_context = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            CodeQuerySemanticLimits::default(),
        );
        assert!(first_context.materialize(&first).is_none());
        let first_work = first_context.work();
        assert_eq!(first_work.materialization_attempts, 1);
        assert_eq!(first_work.unique_materialized_files, 0);
        import_context_charge(&mut parent_semantic, &parent_execution, first_context);
        assert_eq!(parent_execution.work().materialized_files, 1);

        let zero_new_limits = CodeQuerySemanticLimits {
            max_materialized_files: 0,
            ..CodeQuerySemanticLimits::default()
        };
        let mut revisit_context = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            zero_new_limits,
        );
        assert!(revisit_context.materialize(&first).is_none());
        assert_eq!(revisit_context.work().materialization_attempts, 1);
        import_context_charge(&mut parent_semantic, &parent_execution, revisit_context);
        assert_eq!(parent_execution.work().materialized_files, 1);

        let mut refused_context = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            zero_new_limits,
        );
        assert!(refused_context.materialize(&second).is_none());
        let refused_work = refused_context.work();
        assert_eq!(refused_work.materialization_attempts, 0);
        assert!(refused_work.budget_exhausted);
        assert!(refused_context.take_diagnostics().iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted
                && diagnostic.message.contains("file budget")
        }));
        import_context_charge(&mut parent_semantic, &parent_execution, refused_context);
        assert_eq!(parent_execution.work().materialized_files, 1);
        assert!(parent_execution.work().exhausted);
    }

    #[test]
    fn retained_rejection_imports_paid_work_and_identity_without_a_result() {
        let (project, workspace) = receipt_workspace();
        let file = project.file("subject.go");
        let mut parent_semantic = SemanticBudget::default();
        let parent_execution = SemanticExecutionBudget::new(1, 16);
        let retained_rejecting_limits = CodeQuerySemanticLimits {
            max_retained_bytes: 1,
            ..CodeQuerySemanticLimits::default()
        };

        let mut rejected_context = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            retained_rejecting_limits,
        );
        assert!(rejected_context.materialize(&file).is_none());
        let rejected_work = rejected_context.work();
        assert_eq!(rejected_work.materialization_attempts, 1);
        assert_eq!(rejected_work.unique_materialized_files, 0);
        assert!(rejected_work.procedures > 0);
        assert!(
            rejected_context
                .take_diagnostics()
                .iter()
                .any(|diagnostic| {
                    diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted
                        && diagnostic.message.contains("retained-artifact byte budget")
                })
        );
        import_context_charge(&mut parent_semantic, &parent_execution, rejected_context);
        assert!(parent_semantic.used().procedures > 0);
        assert_eq!(parent_execution.work().materialized_files, 1);

        let revisit_limits = CodeQuerySemanticLimits {
            max_materialized_files: 0,
            ..CodeQuerySemanticLimits::default()
        };
        let mut revisit_context = continuation_context(
            &workspace,
            &parent_semantic,
            &parent_execution,
            revisit_limits,
        );
        assert!(revisit_context.materialize(&file).is_some());
        let revisit_work = revisit_context.work();
        assert_eq!(revisit_work.procedures, 0);
        assert_eq!(revisit_work.nested_entries, 1);
        import_context_charge(&mut parent_semantic, &parent_execution, revisit_context);
        assert_eq!(parent_execution.work().materialized_files, 1);
    }

    #[test]
    fn promoted_artifact_is_a_physical_parent_lease_not_an_additive_window_charge() {
        let (project, workspace) = receipt_workspace();
        let file = project.file("subject.go");
        let mut parent_semantic = SemanticBudget::default();
        let parent_execution = SemanticExecutionBudget::new(1, 16);

        let calibration_leases =
            SemanticArtifactLeaseSet::new(CodeQuerySemanticLimits::default().max_retained_bytes);
        let mut calibration = continuation_context_with_leases(
            &workspace,
            &parent_semantic,
            &parent_execution,
            CodeQuerySemanticLimits::default(),
            &calibration_leases,
        );
        calibration.start_artifact_window(file.clone());
        let calibration_artifact = calibration
            .materialize(&file)
            .expect("calibration selector materializes its semantic artifact")
            .0;
        let retained_cap = usize::try_from(calibration.work().retained_bytes)
            .expect("fixture retained bytes fit usize");
        assert!(retained_cap > 0);
        calibration.retain_artifact_window_dependencies();
        calibration.release_artifact_window();
        let calibration_receipt = calibration.into_receipt().expect("calibration receipt");
        let (_, _, _, calibration_charge) = calibration_receipt.into_parts();
        assert_eq!(calibration_charge.len(), 1);
        drop(calibration_charge);
        drop(calibration_artifact);

        let limits = CodeQuerySemanticLimits {
            max_retained_bytes: retained_cap,
            ..CodeQuerySemanticLimits::default()
        };
        let mut parent_leases = SemanticArtifactLeaseSet::new(retained_cap);
        let mut first = continuation_context_with_leases(
            &workspace,
            &parent_semantic,
            &parent_execution,
            limits,
            &parent_leases,
        );
        first.start_artifact_window(file.clone());
        let first_artifact = first
            .materialize(&file)
            .expect("first selector fits the calibrated physical cap")
            .0;
        assert_eq!(
            first.work().retained_bytes,
            u64::try_from(retained_cap).expect("fixture retained bytes fit u64")
        );
        first.retain_artifact_window_dependencies();
        first.release_artifact_window();
        let receipt = first.into_receipt().expect("first selector receipt");
        parent_semantic
            .check_child_charge(SemanticWork::default(), receipt.budget_charge())
            .expect("first selector work fits");
        let (semantic_charge, execution_before, execution_charge, artifact_charge) =
            receipt.into_parts();
        assert_eq!(artifact_charge.len(), 1);
        assert!(parent_execution.can_replay_charge(&execution_before, &execution_charge));
        assert!(parent_execution.replay_charge(&execution_before, &execution_charge));
        parent_semantic
            .apply_child_charge(SemanticWork::default(), semantic_charge)
            .expect("first selector charge was preflighted");
        parent_leases
            .try_apply_charge(artifact_charge, 0)
            .expect("first selector leases fit their calibrated physical cap");
        {
            let snapshot = parent_leases.snapshot();
            assert!(snapshot.contains_exact(&first_artifact));
        }

        let revisit_limits = CodeQuerySemanticLimits {
            max_materialized_files: 0,
            max_retained_bytes: retained_cap,
            ..CodeQuerySemanticLimits::default()
        };
        for ordinal in 0..2 {
            let before = parent_semantic.used();
            let mut revisit = continuation_context_with_leases(
                &workspace,
                &parent_semantic,
                &parent_execution,
                revisit_limits,
                &parent_leases,
            );
            revisit.start_artifact_window(file.clone());
            let revisited_artifact = revisit
                .materialize(&file)
                .unwrap_or_else(|| panic!("overlapping selector {ordinal} fits one physical cap"))
                .0;
            assert!(Arc::ptr_eq(&revisited_artifact, &first_artifact));
            assert_eq!(
                revisit.work().retained_bytes,
                u64::try_from(retained_cap).expect("fixture retained bytes fit u64")
            );
            revisit.retain_artifact_window_dependencies();
            revisit.release_artifact_window();
            let receipt = revisit.into_receipt().expect("revisit receipt");
            let (semantic_charge, execution_before, execution_charge, new_charge) =
                receipt.into_parts();
            assert!(
                new_charge.is_empty(),
                "the pinned Arc is not promoted twice"
            );
            assert!(parent_execution.can_replay_charge(&execution_before, &execution_charge));
            assert!(parent_execution.replay_charge(&execution_before, &execution_charge));
            parent_semantic
                .apply_child_charge(SemanticWork::default(), semantic_charge)
                .expect("repeat work remains additively bounded");
            let after = parent_semantic.used();
            for dimension in SemanticBudgetDimension::ALL {
                let expected = before.get(dimension).saturating_add(usize::from(
                    dimension == SemanticBudgetDimension::NestedEntries,
                ));
                assert_eq!(after.get(dimension), expected, "{dimension:?}");
            }
            assert_eq!(parent_execution.work().materialized_files, 1);
        }
    }

    #[test]
    fn traversal_refusal_replays_the_full_delta_and_exhaustion() {
        let (project, workspace) = receipt_workspace();
        let file = project.file("subject.go");
        let mut parent_semantic = SemanticBudget::default();
        let parent_execution = SemanticExecutionBudget::new(1, 3);
        assert!(parent_execution.charge_traversal(1));
        let limits = CodeQuerySemanticLimits {
            max_materialized_files: 0,
            max_traversal_steps: 1,
            ..CodeQuerySemanticLimits::default()
        };
        let mut context =
            continuation_context(&workspace, &parent_semantic, &parent_execution, limits);

        context.exhaust_traversal_budget(&file, "receipt regression");
        assert_eq!(context.work().traversal_steps, 1);
        assert!(context.work().budget_exhausted);
        import_context_charge(&mut parent_semantic, &parent_execution, context);

        assert_eq!(parent_execution.work().traversal_steps, 2);
        assert!(parent_execution.work().exhausted);
    }

    fn test_anchor(offset: u32) -> SourceAnchor {
        SourceAnchor::new(
            SourceSpan::new(
                SourcePosition::new(offset, 0, offset),
                SourcePosition::new(offset + 1, 0, offset + 1),
            )
            .expect("ordered test span"),
            0,
        )
    }

    fn parallel_edge_artifact(reverse_edges: bool) -> Arc<SemanticArtifact> {
        let key = SemanticArtifactKey::new(
            WorkspaceMountId::hash_bytes(b"test mount"),
            WorkspaceRelativePath::new("src/Test.java").expect("valid test path"),
            SemanticLanguage::Standard(Language::Java),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(b"class Test {}"),
            },
            AdapterSemanticsVersion::hash_bytes("test-java", b"adapter")
                .expect("non-empty adapter version"),
            SemanticIrVersion::hash_bytes(b"semantic-ir-test"),
            ConfigurationFingerprint::hash_bytes(b"configuration"),
            DependencyFingerprint::hash_bytes(b"dependencies"),
        );
        let procedure_anchor = test_anchor(1);
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::File, "Test.java", test_anchor(0), 0)
                .expect("valid file segment"),
            DeclarationSegment::named(
                DeclarationSegmentKind::Function,
                "target",
                procedure_anchor,
                0,
            )
            .expect("valid procedure segment"),
        ])
        .expect("non-empty declaration");
        let locator = SemanticLocator::new(
            key.mount(),
            key.path().clone(),
            key.language(),
            declaration,
            SemanticRole::Procedure,
            procedure_anchor,
        );
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let mut procedure = ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            locator.clone(),
            ProcedureKind::Function,
            source,
            evidence,
        );
        procedure.source_mappings.extend([
            SourceMapping {
                id: source,
                locator: locator.clone(),
                kind: SourceMappingKind::Exact,
                ast_identity: None,
            },
            SourceMapping {
                id: SourceMappingId::new(1),
                locator,
                kind: SourceMappingKind::Exact,
                ast_identity: None,
            },
        ]);
        procedure.evidence_rows.extend([
            Evidence {
                id: evidence,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                sources: Box::new([source]),
            },
            Evidence {
                id: EvidenceId::new(1),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                sources: Box::new([SourceMappingId::new(1)]),
            },
        ]);

        let entry = ProgramPointId::new(0);
        let normal_exit = ProgramPointId::new(1);
        let exceptional_exit = ProgramPointId::new(2);
        let ordinary_first = ProgramPointId::new(3);
        let ordinary_second = ProgramPointId::new(4);
        procedure.blocks.push(BasicBlock {
            id: BlockId::new(0),
            points: Box::new([
                entry,
                ordinary_first,
                ordinary_second,
                normal_exit,
                exceptional_exit,
            ]),
            source,
            evidence,
        });
        procedure.points.extend([
            ProgramPoint {
                id: entry,
                block: BlockId::new(0),
                events: Box::new([SemanticEvent::new(
                    crate::analyzer::semantic::SemanticEffect::Entry,
                    source,
                    evidence,
                )]),
                source,
                evidence,
            },
            ProgramPoint {
                id: normal_exit,
                block: BlockId::new(0),
                events: Box::new([SemanticEvent::new(
                    crate::analyzer::semantic::SemanticEffect::NormalExit,
                    source,
                    evidence,
                )]),
                source,
                evidence,
            },
            ProgramPoint {
                id: exceptional_exit,
                block: BlockId::new(0),
                events: Box::new([SemanticEvent::new(
                    crate::analyzer::semantic::SemanticEffect::ExceptionalExit,
                    source,
                    evidence,
                )]),
                source,
                evidence,
            },
            ProgramPoint {
                id: ordinary_first,
                block: BlockId::new(0),
                events: Box::new([]),
                source,
                evidence,
            },
            ProgramPoint {
                id: ordinary_second,
                block: BlockId::new(0),
                events: Box::new([]),
                source,
                evidence,
            },
        ]);
        procedure.control_edges.extend([
            ControlEdge {
                source_point: entry,
                target_point: ordinary_first,
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            },
            ControlEdge {
                source_point: entry,
                target_point: ordinary_first,
                kind: ControlEdgeKind::Normal,
                source: SourceMappingId::new(1),
                evidence: EvidenceId::new(1),
            },
            ControlEdge {
                source_point: entry,
                target_point: exceptional_exit,
                kind: ControlEdgeKind::Exceptional,
                source,
                evidence,
            },
            ControlEdge {
                source_point: ordinary_first,
                target_point: ordinary_second,
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            },
            ControlEdge {
                source_point: ordinary_second,
                target_point: normal_exit,
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            },
        ]);
        if reverse_edges {
            procedure.control_edges.reverse();
        }

        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Procedures)
            .complete(SemanticCapability::EntryBoundary)
            .complete(SemanticCapability::NormalExitBoundary)
            .complete(SemanticCapability::ExceptionalExitBoundary)
            .complete(SemanticCapability::BasicBlocks)
            .complete(SemanticCapability::ProgramPoints)
            .complete(SemanticCapability::NormalControlFlow)
            .complete(SemanticCapability::ExceptionalControlFlow)
            .build();
        Arc::new(
            SemanticArtifact::try_new(key, capabilities, vec![procedure])
                .expect("parallel edges with distinct provenance are valid"),
        )
    }

    #[test]
    fn parallel_control_edges_have_distinct_public_wire_ids() {
        let artifact = parallel_edge_artifact(false);
        let procedure = artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("test procedure exists");
        let first = procedure
            .control_edge_handle(ControlEdgeId::new(0))
            .expect("first parallel edge exists");
        let second = procedure
            .control_edge_handle(ControlEdgeId::new(1))
            .expect("second parallel edge exists");

        assert_ne!(
            control_edge_wire_id(&first),
            control_edge_wire_id(&second),
            "valid parallel edges must not collide on the public wire"
        );

        let reversed = parallel_edge_artifact(true);
        let reversed_procedure = reversed
            .procedure_handle(ProcedureId::new(0))
            .expect("reordered test procedure exists");
        let mut original_ids = (0..5)
            .map(|id| {
                control_edge_wire_id(
                    &procedure
                        .control_edge_handle(ControlEdgeId::new(id))
                        .expect("original edge exists"),
                )
            })
            .collect::<Vec<_>>();
        let mut reordered_ids = (0..5)
            .map(|id| {
                control_edge_wire_id(
                    &reversed_procedure
                        .control_edge_handle(ControlEdgeId::new(id))
                        .expect("reordered edge exists"),
                )
            })
            .collect::<Vec<_>>();
        original_ids.sort_unstable();
        reordered_ids.sort_unstable();
        assert_eq!(
            original_ids, reordered_ids,
            "edge storage order must not affect public identities"
        );
    }

    #[test]
    fn ordinary_points_with_identical_public_metadata_have_distinct_wire_ids() {
        let artifact = parallel_edge_artifact(false);
        let procedure = artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("test procedure exists");
        let first = procedure
            .point_handle(ProgramPointId::new(3))
            .expect("first ordinary point exists");
        let second = procedure
            .point_handle(ProgramPointId::new(4))
            .expect("second ordinary point exists");

        assert_ne!(
            program_point_wire_id(&first),
            program_point_wire_id(&second),
            "valid ordinary points that share source and evidence rows must not collide"
        );
    }

    #[test]
    fn deferred_dispatch_boundary_weakens_only_unestablished_arm_timing() {
        let artifact = parallel_edge_artifact(false);
        let target = artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("test procedure exists")
            .semantics()
            .locator()
            .clone();
        let deferred = DispatchBoundaryKind::Deferred {
            target,
            kind: DeferredInvocationKind::Async,
        };

        assert_eq!(
            dispatch_arm_execution_timing(ExecutionTiming::SameEvaluation, Some(&deferred)),
            ExecutionTiming::Unknown,
            "an ordinary call does not establish when a deferred target body runs"
        );
        assert_eq!(
            dispatch_arm_execution_timing(ExecutionTiming::DifferentTask, Some(&deferred)),
            ExecutionTiming::DifferentTask,
            "an explicit spawn independently establishes a different task"
        );
        assert_eq!(
            dispatch_arm_execution_timing(ExecutionTiming::SameEvaluation, None),
            ExecutionTiming::SameEvaluation,
            "an ordinary materialized arm retains the source call timing"
        );
    }
}
