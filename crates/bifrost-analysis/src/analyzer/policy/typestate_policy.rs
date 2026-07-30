//! Production lowering and execution for resolved typestate policies.
//!
//! Policy loading owns authoring/composition semantics; this module starts at
//! the closed [`ResolvedTypestatePolicySpec`] boundary and lowers only typed,
//! source-backed values into the diagnostic-neutral typestate engine.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::ops::Range as ByteRange;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::CancellationToken;
use crate::analyzer::common::language_for_file;
use crate::analyzer::dataflow::{
    DataflowRequest, SolverBudget, SolverTermination, SummaryWitnessStepKind,
    WitnessReconstructionLimits,
};
use crate::analyzer::lexical_definitions::formal_parameter_slots;
use crate::analyzer::policy::budget::PolicyBudget;
use crate::analyzer::policy::composition::PrecedenceGraph;
use crate::analyzer::policy::definition::{
    EndpointObservationPhase, MayMode, PolicyEndpointBinding, PolicyReportOptions,
    PolicySelectorPath, PolicySemanticEvent, TypestateCallBinding,
    TypestateEventId as PolicyTypestateEventId,
    TypestateExpectationId as PolicyTypestateExpectationId,
    TypestateStateId as PolicyTypestateStateId,
};
use crate::analyzer::policy::evaluator::{
    PolicyEvaluationContext, TypestateCompilationFailure, TypestatePolicyEvaluator,
};
use crate::analyzer::policy::finding::{
    BoundedWitness, CertaintyReason, FindingCertainty, FindingCompleteness,
    FindingIncompleteReason, PolicyByteSpan, PolicyDiagnostic, PolicyDiagnosticCode,
    PolicyDiagnosticImpact, PolicyDiagnosticSeverity, PolicyDisplayRegion, PolicyFailureReason,
    PolicyIncompleteReason, PolicyLocationRelationship, PolicyRunCompletion, PolicySourceLocation,
    PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit, ProofMetadata, ProofReason, ProofState,
    RelatedPolicyLocation, WitnessStep, WitnessStepKind,
};
use crate::analyzer::policy::finding_identity::{
    AnalysisFindingId, AnalysisSubjectRef, StableSemanticIdentity, TypestateScenarioId, WitnessId,
};
use crate::analyzer::policy::future_evidence::{
    ResolvedTypestateTerminal, TypestateFindingAnchor, TypestatePolicyProjectionFacts,
    TypestateViolationEvidence,
};
use crate::analyzer::policy::projection::{
    ProjectedFindingReport, TypestateCompilationHashes, TypestateProjectedFinding,
    TypestateProjectionAuthority, TypestateProjectionPayload,
};
use crate::analyzer::policy::resolved::{
    LoadedPolicy, ResolvedEndpointIdentity, ResolvedPolicySelector, ResolvedPrecedenceEdge,
    ResolvedTypestateBinding, ResolvedTypestateEventTrigger, ResolvedTypestatePolicySpec,
    ResolvedTypestateTerminalTrigger,
};
use crate::analyzer::semantic::workspace_oracle::{
    ProcedureRangeLookupStatus, procedures_for_source_ranges,
};
use crate::analyzer::semantic::{
    AbstractObject, CallBinding, CallSiteHandle, CallSiteId, CallTransferSet, CandidateCoverage,
    DispatchOracle, DispatchResult, EvidenceCompleteness, HeapOracle, IcfgExitProfile,
    IcfgProvider, IcfgSnapshot, IcfgSnapshotLimits, ObservationPhase, OracleCallContext,
    ProcedureHandle, ProcedurePortHandle, ProcedurePortKind, ProgramPointHandle, ProofStatus,
    SemanticArtifact, SemanticBudget, SemanticBudgetDimension, SemanticExecutionBudget,
    SemanticExecutionWork, SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticWork,
    ValueAtPoint, ValueFlowOracle, ValueHandle, WorkspaceIcfgProvider,
};
use crate::analyzer::structural::search::{DetailedCodeQueryDomain, execute_code_query_detailed};
use crate::analyzer::structural::{
    CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, CodeQueryExecutionWork,
    CodeQuerySemanticLimits, CodeQuerySemanticWork,
};
use crate::analyzer::typestate::{
    BoundTypestateSubjectSpec, CompiledProtocol, PROTOCOL_SCHEMA_VERSION,
    ProductionSummaryLifecycleCounters, ProductionTypestateExecutionContext,
    ProductionTypestateSummaryRepository, ProtocolAnalysisMode, ProtocolEventKey,
    ProtocolEventOccurrence, ProtocolEventSpec, ProtocolExpectationKey, ProtocolGuardSpec,
    ProtocolObservationPhase, ProtocolObservationSpec, ProtocolProcedureExitKind,
    ProtocolSemantics, ProtocolSpec, ProtocolStateKey, ProtocolTerminalExpectationSpec,
    ProtocolTerminalObservationSpec, ProtocolTransitionSpec, ProtocolUncertaintyBehavior,
    ProtocolUncertaintySemantics, ProtocolUnmatchedEventBehavior, TypestateBindingContext,
    TypestateBindingMultiplicity, TypestateBindingPlan, TypestateBindingQuality,
    TypestateEventBindingId, TypestateEventBindingSpec, TypestateFinding,
    TypestateFindingCertainty, TypestateFindingKind, TypestateFindingLimits,
    TypestateFlowProblemError, TypestateInitialSeedSpec, TypestateObjectRole,
    TypestateObservationSite, TypestateSubjectClassKey, TypestateSubjectKey,
    TypestateTerminalBindingId, TypestateTerminalBindingSpec, TypestateUncertainty,
    collect_summary_findings_with_limits, solve_typestate_with_production_summaries,
};
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use crate::text_utils::{compute_line_starts, line_column_for_offset};

#[derive(Debug)]
pub(crate) enum TypestatePolicyCompileError {
    Protocol(crate::analyzer::typestate::ProtocolCompileError),
    MissingWorkspace,
    MissingSelector(String),
    QueryIncomplete {
        completion: CodeQueryCompletion,
        detail: String,
    },
    SemanticProvider(SemanticProviderError),
    SemanticUnavailable(String),
    AmbiguousSemanticSite(String),
    EndpointDominanceUndecidable(String),
    UnsupportedBinding(String),
    BindingPlan(crate::analyzer::typestate::TypestateBindingPlanError),
}

pub(crate) struct TypestatePolicyCompileFailure {
    error: TypestatePolicyCompileError,
    work: PolicyWorkReport,
}

impl fmt::Display for TypestatePolicyCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => {
                write!(formatter, "typestate protocol compilation failed: {error}")
            }
            Self::MissingWorkspace => formatter
                .write_str("typestate policy compilation requires a workspace semantic snapshot"),
            Self::MissingSelector(path) => {
                write!(formatter, "typestate selector `{path}` is missing")
            }
            Self::QueryIncomplete { detail, .. } => write!(
                formatter,
                "typestate selector did not execute completely: {detail}"
            ),
            Self::SemanticProvider(message) => {
                write!(formatter, "typestate semantic provider failed: {message}")
            }
            Self::SemanticUnavailable(message) => {
                write!(
                    formatter,
                    "typestate semantic binding is unavailable: {message}"
                )
            }
            Self::AmbiguousSemanticSite(message) => {
                write!(
                    formatter,
                    "typestate semantic binding is ambiguous: {message}"
                )
            }
            Self::EndpointDominanceUndecidable(message) => {
                write!(
                    formatter,
                    "typestate endpoint dominance is undecidable: {message}"
                )
            }
            Self::UnsupportedBinding(message) => {
                write!(formatter, "typestate binding is unsupported: {message}")
            }
            Self::BindingPlan(error) => {
                write!(
                    formatter,
                    "typestate binding-plan compilation failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for TypestatePolicyCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::BindingPlan(error) => Some(error),
            Self::SemanticProvider(error) => Some(error),
            Self::MissingWorkspace
            | Self::MissingSelector(_)
            | Self::QueryIncomplete { .. }
            | Self::SemanticUnavailable(_)
            | Self::AmbiguousSemanticSite(_)
            | Self::EndpointDominanceUndecidable(_)
            | Self::UnsupportedBinding(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledTypestateSubject {
    pub(crate) key: TypestateSubjectKey,
    pub(crate) endpoint: ResolvedEndpointIdentity,
    pub(crate) root: ProcedureHandle,
}

#[derive(Debug)]
pub(crate) struct CompiledTypestatePolicy {
    pub(crate) protocol: Arc<CompiledProtocol>,
    pub(crate) bindings: Arc<TypestateBindingPlan>,
    pub(crate) roots: Box<[ProcedureHandle]>,
    pub(crate) subjects: Box<[CompiledTypestateSubject]>,
    event_endpoints: Box<[Option<ResolvedEndpointIdentity>]>,
    terminal_endpoints: Box<[Option<ResolvedEndpointIdentity>]>,
    query_work: CodeQueryExecutionWork,
    semantic_compile_work: SemanticWork,
    semantic_remaining: SemanticWork,
    semantic_compile_execution_work: SemanticExecutionWork,
    semantic_execution_budget: SemanticExecutionBudget,
}

pub(crate) struct TypestatePolicyCompiler<'a> {
    workspace: &'a WorkspaceAnalyzer,
    query_limits: CodeQueryExecutionLimits,
    cancellation: &'a CancellationToken,
    semantic_budget: SemanticBudget,
    semantic_execution_budget: SemanticExecutionBudget,
    query_work: CodeQueryExecutionWork,
    artifacts: HashMap<ProjectFile, Arc<SemanticArtifact>>,
    syntax_trees: HashMap<ProjectFile, tree_sitter::Tree>,
    formal_names: HashMap<ProcedurePortHandle, Box<[String]>>,
}

struct PolicyIcfgProvider<'a> {
    inner: WorkspaceIcfgProvider<'a>,
    execution_budget: SemanticExecutionBudget,
    initial_work: SemanticExecutionWork,
}

impl<'a> PolicyIcfgProvider<'a> {
    fn new(workspace: &'a WorkspaceAnalyzer, compiled: &CompiledTypestatePolicy) -> Self {
        let execution_budget = compiled.semantic_execution_budget.clone();
        let initial_work = execution_budget.work();
        Self {
            inner: workspace.icfg_provider(),
            execution_budget,
            initial_work,
        }
    }

    fn work(&self) -> (usize, usize, bool) {
        let current = self.execution_budget.work();
        (
            current
                .materialized_files
                .saturating_sub(self.initial_work.materialized_files),
            current
                .traversal_steps
                .saturating_sub(self.initial_work.traversal_steps),
            current.exhausted,
        )
    }
}

impl DispatchOracle for PolicyIcfgProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.inner.resolve_call(
            call,
            &mut SemanticRequest::with_execution_budget(
                &mut *request.budget,
                request.cancellation,
                &self.execution_budget,
            ),
        )
    }
}

impl IcfgProvider for PolicyIcfgProvider<'_> {
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        self.inner.call_transfers(
            caller,
            call,
            &mut SemanticRequest::with_execution_budget(
                &mut *request.budget,
                request.cancellation,
                &self.execution_budget,
            ),
        )
    }

    fn snapshot(
        &self,
        root: &ProcedureHandle,
        limits: IcfgSnapshotLimits,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError> {
        self.inner.snapshot(
            root,
            limits,
            &mut SemanticRequest::with_execution_budget(
                &mut *request.budget,
                request.cancellation,
                &self.execution_budget,
            ),
        )
    }

    fn exit_profile(
        &self,
        callee_entry: &ProgramPointHandle,
        callee_exit: &ProgramPointHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
        self.inner.exit_profile(
            callee_entry,
            callee_exit,
            &mut SemanticRequest::with_execution_budget(
                &mut *request.budget,
                request.cancellation,
                &self.execution_budget,
            ),
        )
    }
}

#[derive(Default)]
pub(crate) struct ProductionTypestatePolicyEvaluator {
    prepared: RefCell<Option<CompiledTypestatePolicy>>,
    summaries: Arc<ProductionTypestateSummaryRepository>,
}

impl super::projection::sealed::TypestateAdapter for ProductionTypestatePolicyEvaluator {}

impl TypestatePolicyEvaluator for ProductionTypestatePolicyEvaluator {
    fn compilation_hashes(
        &self,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
    ) -> Result<TypestateCompilationHashes, TypestateCompilationFailure> {
        let workspace = context.workspace.ok_or_else(|| {
            TypestateCompilationFailure::failed(
                PolicyFailureReason::InternalInvariant,
                TypestatePolicyCompileError::MissingWorkspace.to_string(),
            )
        })?;
        let uncancelled = CancellationToken::default();
        let cancellation = context.cancellation.unwrap_or(&uncancelled);
        let compiled = TypestatePolicyCompiler::new(workspace, budget.query_limits(), cancellation)
            .compile(policy, spec)
            .map_err(|failure| compile_failure(*failure))?;
        let hashes =
            TypestateCompilationHashes::new(compiled.protocol.hash(), compiled.bindings.hash());
        self.prepared.replace(Some(compiled));
        Ok(hashes)
    }

    fn evaluate_typestate(
        &self,
        authority: &TypestateProjectionAuthority,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
    ) -> TypestateProjectionPayload {
        let compiled = self
            .prepared
            .borrow_mut()
            .take()
            .expect("typestate compilation and evaluation are one evaluator transaction");
        let Some(workspace) = context.workspace else {
            return failed_projection_payload(
                "typestate policy evaluation lost its workspace semantic snapshot",
            );
        };
        let summary_lease = match self.summaries.lease(0) {
            Ok(summary_lease) => summary_lease,
            Err(error) => return failed_projection_payload(&error.to_string()),
        };
        match evaluate_compiled_typestate(
            authority,
            policy,
            spec,
            workspace,
            context.cancellation,
            budget,
            &compiled,
            &summary_lease,
        ) {
            Ok(payload) => payload,
            Err(error) => failed_projection_payload(&error),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_compiled_typestate(
    authority: &TypestateProjectionAuthority<'_>,
    policy: &LoadedPolicy,
    spec: &ResolvedTypestatePolicySpec,
    workspace: &WorkspaceAnalyzer,
    cancellation: Option<&CancellationToken>,
    budget: &PolicyBudget,
    compiled: &CompiledTypestatePolicy,
    summary_lease: &crate::analyzer::typestate::ProductionTypestateSummaryLease,
) -> Result<TypestateProjectionPayload, String> {
    let mut cache_work = ProductionSummaryLifecycleCounters::default();
    let uncancelled = CancellationToken::default();
    let cancellation = cancellation.unwrap_or(&uncancelled);
    let limits = budget.query_limits().typestate;
    let mut solver_budget = SolverBudget::new(limits.solver_work);
    let mut semantic_budget = if compiled.roots.is_empty() {
        None
    } else {
        Some(SemanticBudget::new(compiled.semantic_remaining).map_err(|error| error.to_string())?)
    };
    let icfg_provider = PolicyIcfgProvider::new(workspace, compiled);
    let mut projections = Vec::new();
    let mut incomplete_reasons = Vec::new();
    let mut reached_rows = 0_u64;
    let mut subject_rows = 0_u64;
    let mut terminal_rows = 0_u64;
    let mut retained_analysis_findings = 0_u64;
    let mut omitted_analysis_findings = 0_u64;
    let mut remaining_finding_reached_rows = limits.max_reached_rows;
    let mut remaining_finding_candidates = limits.max_candidates;
    let mut remaining_finding_witness_expansions = limits.max_total_witness_expansions;
    let mut remaining_finding_witness_bytes = limits.max_witness_bytes;

    for root in &compiled.roots {
        let mut request = DataflowRequest::new(&mut solver_budget, cancellation);
        let production = solve_typestate_with_production_summaries(
            summary_lease,
            root,
            &[],
            &icfg_provider,
            &icfg_provider.inner,
            ProductionTypestateExecutionContext::Policy(&icfg_provider.execution_budget),
            &compiled.protocol,
            &compiled.bindings,
            semantic_budget
                .as_mut()
                .expect("nonempty roots retain a semantic budget"),
            &mut request,
        )
        .map_err(|error| error.to_string())?;
        cache_work.saturating_add_assign(production.lifecycle());
        let solved = production.result();
        let fixed_point = match solved.result().termination() {
            SolverTermination::FixedPoint => true,
            SolverTermination::Cancelled => {
                incomplete_reasons.push(PolicyIncompleteReason::Cancelled);
                false
            }
            SolverTermination::ExceededBudget(_) => {
                incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
                false
            }
        };
        reached_rows = reached_rows
            .saturating_add(u64::try_from(solved.result().reached().len()).unwrap_or(u64::MAX));
        for reached in solved.result().reached() {
            let fact = solved
                .result()
                .fact(reached.fact())
                .ok_or_else(|| "typestate solve retained an invalid fact row".to_owned())?;
            if fact.subject().is_some() {
                subject_rows = subject_rows.saturating_add(1);
            }
            if fact.terminal_observation().is_some() {
                terminal_rows = terminal_rows.saturating_add(1);
            }
        }
        if !fixed_point {
            continue;
        }
        if remaining_finding_reached_rows == 0
            || remaining_finding_candidates == 0
            || remaining_finding_witness_expansions == 0
            || remaining_finding_witness_bytes == 0
        {
            incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
            omitted_analysis_findings = omitted_analysis_findings.saturating_add(1);
            break;
        }
        let finding_limits = TypestateFindingLimits::with_witness_limits(
            remaining_finding_reached_rows,
            remaining_finding_candidates,
            WitnessReconstructionLimits::new(
                limits.max_witness_steps,
                limits
                    .max_witness_expansions
                    .min(remaining_finding_witness_expansions),
            )
            .map_err(|error| error.to_string())?,
            remaining_finding_witness_expansions,
            remaining_finding_witness_bytes,
        )
        .map_err(|error| error.to_string())?;
        let findings = match collect_summary_findings_with_limits(
            &compiled.protocol,
            &compiled.bindings,
            solved,
            finding_limits,
            cancellation,
        ) {
            Ok(findings) => findings,
            Err(TypestateFlowProblemError::FindingCancelled) => {
                incomplete_reasons.push(PolicyIncompleteReason::Cancelled);
                break;
            }
            Err(TypestateFlowProblemError::FindingBudgetExceeded) => {
                incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
                omitted_analysis_findings = omitted_analysis_findings.saturating_add(1);
                break;
            }
            Err(error) => return Err(error.to_string()),
        };
        if !findings.analysis_complete() || findings.omitted() > 0 {
            incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
        }
        let finding_work = findings.work();
        remaining_finding_reached_rows =
            remaining_finding_reached_rows.saturating_sub(finding_work.reached_rows());
        remaining_finding_candidates =
            remaining_finding_candidates.saturating_sub(finding_work.candidates());
        remaining_finding_witness_expansions =
            remaining_finding_witness_expansions.saturating_sub(finding_work.witness_expansions());
        remaining_finding_witness_bytes =
            remaining_finding_witness_bytes.saturating_sub(finding_work.witness_bytes());
        retained_analysis_findings = retained_analysis_findings
            .saturating_add(u64::try_from(findings.findings().len()).unwrap_or(u64::MAX));
        omitted_analysis_findings = omitted_analysis_findings
            .saturating_add(u64::try_from(findings.omitted()).unwrap_or(u64::MAX));
        for finding in findings.findings() {
            projections.extend(project_finding(
                authority, policy, spec, workspace, budget, compiled, root, finding,
            )?);
        }
    }

    let (evaluation_materialized_files, evaluation_traversal_steps, evaluation_budget_exhausted) =
        icfg_provider.work();
    if evaluation_budget_exhausted {
        incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
    }
    incomplete_reasons.sort();
    incomplete_reasons.dedup();
    let completion = if incomplete_reasons.is_empty() {
        PolicyRunCompletion::Complete
    } else {
        PolicyRunCompletion::inconclusive(incomplete_reasons).map_err(|error| error.to_string())?
    };
    let semantic_evaluation_work = semantic_budget
        .as_ref()
        .map_or_else(SemanticWork::default, SemanticBudget::used);
    let metrics = [
        ("typestate.roots", compiled.roots.len()),
        ("typestate.subjects", compiled.bindings.subjects().len()),
        (
            "typestate.initial_seeds",
            compiled.bindings.initial_seeds().len(),
        ),
        (
            "typestate.event_bindings",
            compiled.bindings.event_bindings().len(),
        ),
        (
            "typestate.terminal_bindings",
            compiled.bindings.terminal_bindings().len(),
        ),
    ]
    .into_iter()
    .map(|(name, value)| {
        PolicyWorkMetric::try_new(
            name,
            PolicyWorkUnit::Count,
            u64::try_from(value).unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string())
    })
    .chain([
        PolicyWorkMetric::try_new("typestate.reached_rows", PolicyWorkUnit::Rows, reached_rows)
            .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new("typestate.subject_rows", PolicyWorkUnit::Rows, subject_rows)
            .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.terminal_rows",
            PolicyWorkUnit::Rows,
            terminal_rows,
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.analysis_findings",
            PolicyWorkUnit::Count,
            retained_analysis_findings,
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.summary_hits",
            PolicyWorkUnit::Count,
            u64::try_from(cache_work.hits).unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.summary_misses",
            PolicyWorkUnit::Count,
            u64::try_from(cache_work.misses).unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.summary_rejections",
            PolicyWorkUnit::Count,
            u64::try_from(cache_work.rejections).unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.summary_evictions",
            PolicyWorkUnit::Count,
            u64::try_from(cache_work.evictions).unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.summary_recomputations",
            PolicyWorkUnit::Count,
            u64::try_from(cache_work.recomputations).unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.semantic_traversal_steps",
            PolicyWorkUnit::Count,
            u64::try_from(compiled.semantic_compile_execution_work.traversal_steps)
                .unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.selector_semantic_materializations",
            PolicyWorkUnit::Count,
            compiled.query_work.semantic.materialization_attempts,
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.selector_semantic_traversal_steps",
            PolicyWorkUnit::Count,
            compiled.query_work.semantic.traversal_steps,
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.evaluation_semantic_materialized_files",
            PolicyWorkUnit::Count,
            u64::try_from(evaluation_materialized_files).unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.evaluation_semantic_traversal_steps",
            PolicyWorkUnit::Count,
            u64::try_from(evaluation_traversal_steps).unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.semantic_source_bytes",
            PolicyWorkUnit::Bytes,
            u64::try_from(
                compiled
                    .semantic_compile_work
                    .source_bytes
                    .saturating_add(semantic_evaluation_work.source_bytes),
            )
            .unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.semantic_procedures",
            PolicyWorkUnit::Rows,
            u64::try_from(
                compiled
                    .semantic_compile_work
                    .procedures
                    .saturating_add(semantic_evaluation_work.procedures),
            )
            .unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.semantic_program_points",
            PolicyWorkUnit::Rows,
            u64::try_from(
                compiled
                    .semantic_compile_work
                    .program_points
                    .saturating_add(semantic_evaluation_work.program_points),
            )
            .unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
        PolicyWorkMetric::try_new(
            "typestate.semantic_control_edges",
            PolicyWorkUnit::Rows,
            u64::try_from(
                compiled
                    .semantic_compile_work
                    .control_edges
                    .saturating_add(semantic_evaluation_work.control_edges),
            )
            .unwrap_or(u64::MAX),
        )
        .map_err(|error| error.to_string()),
    ])
    .collect::<Result<Vec<_>, _>>()?;
    let work = PolicyWorkReport::try_new(
        compiled.query_work.scanned_files,
        compiled.query_work.scanned_source_bytes,
        compiled.query_work.fact_nodes.saturating_add(reached_rows),
        compiled
            .query_work
            .pipeline_rows
            .saturating_add(reached_rows),
        compiled.query_work.examined_references,
        u64::try_from(projections.len()).unwrap_or(u64::MAX),
        omitted_analysis_findings,
        0,
        metrics,
    )
    .map_err(|error| error.to_string())?;
    Ok(TypestateProjectionPayload {
        projections,
        completion,
        diagnostics: Vec::new(),
        diagnostics_truncated: false,
        work,
    })
}

#[allow(clippy::too_many_arguments)]
fn project_finding(
    authority: &TypestateProjectionAuthority<'_>,
    policy: &LoadedPolicy,
    spec: &ResolvedTypestatePolicySpec,
    workspace: &WorkspaceAnalyzer,
    budget: &PolicyBudget,
    compiled: &CompiledTypestatePolicy,
    root: &ProcedureHandle,
    finding: &TypestateFinding,
) -> Result<Vec<TypestateProjectedFinding>, String> {
    let bound_subject = compiled
        .bindings
        .subject(finding.subject())
        .ok_or_else(|| "typestate finding refers to an unknown bound subject".to_owned())?;
    let subject = compiled
        .subjects
        .iter()
        .find(|subject| subject.key == *bound_subject.key())
        .ok_or_else(|| "typestate finding has no policy subject projection".to_owned())?;
    let resolved_subject = spec
        .subjects
        .iter()
        .find(|candidate| candidate.identity == subject.endpoint)
        .ok_or_else(|| "typestate finding subject is absent from the loaded policy".to_owned())?;
    let dependency = spec
        .endpoint_dependencies
        .iter()
        .find(|dependency| dependency.identity() == &subject.endpoint)
        .ok_or_else(|| "typestate finding subject endpoint metadata is absent".to_owned())?;
    let site = finding.site();
    let mut acquisitions = compiled
        .bindings
        .initial_seeds()
        .iter()
        .filter(|seed| seed.subject() == finding.subject())
        .map(|seed| seed.site().identity())
        .collect::<Vec<_>>();
    acquisitions.sort_unstable();
    acquisitions.dedup();
    let subject_locator = acquisitions
        .first()
        .copied()
        .ok_or_else(|| "typestate finding subject has no acquisition observation".to_owned())?;
    let subject_path = subject_locator.path().clone();
    let subject_namespace = subject_locator.language().config_label();
    let site_path = site.path().clone();
    let site_namespace = site.language().config_label();
    let scenario_key = semantic_root_key(root);
    let scenario = TypestateScenarioId::try_new("bifrost", &scenario_key)
        .map_err(|error| error.to_string())?;
    let site_key = semantic_site_key(workspace, site);
    let site_identity =
        StableSemanticIdentity::protocol_violation_site(site_namespace, site_path, &site_key)
            .map_err(|error| error.to_string())?;
    let subject_key = stable_hex(bound_subject.key().public_canonical_rendering().as_bytes());
    let subject_identity =
        StableSemanticIdentity::protocol_subject(subject_namespace, subject_path, &subject_key)
            .map_err(|error| error.to_string())?;

    let violations = policy_violations(spec, compiled, finding)?;
    let mut projected = Vec::with_capacity(violations.len());
    for violation in violations {
        let facts = TypestatePolicyProjectionFacts::try_new(
            spec.authoring_projection_hash,
            authority.protocol_hash(),
            authority.binding_plan_hash(),
            subject.endpoint.clone(),
            resolved_subject.semantic_hash,
            resolved_subject.analysis_projection_hash,
            dependency.model().categories.clone(),
            dependency.model().display_name.clone(),
            Some(site_identity.clone()),
            violation.clone(),
            vec![scenario.clone()],
            budget,
        )
        .map_err(|error| error.to_string())?;
        let anchor = TypestateFindingAnchor::strong(
            authority.protocol_hash(),
            authority.binding_plan_hash(),
            subject_identity.clone(),
            site_identity.clone(),
            facts.scenario_set_hash,
            &violation,
        )
        .map_err(|error| error.to_string())?;
        let finding_key =
            stable_hex(format!("{}:{}:{}", subject_key, site_key, facts.semantic_hash).as_bytes());
        let (report, witness_refs) = projected_report(
            workspace,
            finding,
            &acquisitions,
            &finding_key,
            &policy.definition().report,
            budget,
        )?;
        let witnesses_truncated = report.witnesses_truncated;
        projected.push(TypestateProjectedFinding {
            facts,
            analysis_finding_id: AnalysisFindingId::try_new("bifrost", &finding_key)
                .map_err(|error| error.to_string())?,
            anchor,
            subject: AnalysisSubjectRef::try_new("bifrost", &subject_key)
                .map_err(|error| error.to_string())?,
            witness_refs,
            witness_refs_truncated: witnesses_truncated,
            report,
        });
    }
    Ok(projected)
}

fn policy_violations(
    spec: &ResolvedTypestatePolicySpec,
    compiled: &CompiledTypestatePolicy,
    finding: &TypestateFinding,
) -> Result<Vec<TypestateViolationEvidence>, String> {
    let protocol = &compiled.protocol;
    match finding.kind() {
        TypestateFindingKind::ErrorTransition {
            binding,
            event,
            from,
            to,
        } => {
            let event_key = protocol
                .event(*event)
                .ok_or_else(|| "typestate finding event is absent from the protocol".to_owned())?
                .key();
            let _resolved = spec
                .automaton
                .events
                .iter()
                .find(|candidate| candidate.id.as_str() == event_key.as_str())
                .ok_or_else(|| "typestate finding event is absent from the policy".to_owned())?;
            let endpoint = event_endpoint(compiled, *binding)?;
            Ok(vec![TypestateViolationEvidence::error_transition(
                PolicyTypestateEventId::new(event_key.as_str())
                    .map_err(|error| error.to_string())?,
                endpoint,
                policy_state(protocol, *from)?,
                policy_state(protocol, *to)?,
            )])
        }
        TypestateFindingKind::TerminalExpectation {
            binding,
            expectation,
            actual_states,
        } => {
            let key = protocol
                .terminal_expectation(*expectation)
                .ok_or_else(|| {
                    "typestate finding expectation is absent from the protocol".to_owned()
                })?
                .key();
            let resolved = spec
                .automaton
                .terminal_expectations
                .iter()
                .find(|candidate| candidate.id.as_str() == key.as_str())
                .ok_or_else(|| {
                    "typestate finding expectation is absent from the policy".to_owned()
                })?;
            let terminal = match &resolved.trigger {
                ResolvedTypestateTerminalTrigger::SemanticEvent { event } => {
                    ResolvedTypestateTerminal::SemanticEvent { event: *event }
                }
                ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, phase } => {
                    ResolvedTypestateTerminal::Endpoint {
                        endpoint: terminal_endpoint(compiled, *binding)?.ok_or_else(|| {
                            format!(
                                "typestate terminal trigger has no exact endpoint provenance among {} candidates",
                                endpoints.len()
                            )
                        })?,
                        phase: *phase,
                    }
                }
            };
            let expected = resolved.expected_states.clone();
            let mut violations = Vec::with_capacity(actual_states.len());
            for state in actual_states {
                let actual = policy_state(protocol, *state)?;
                if expected.contains(&actual) {
                    continue;
                }
                violations.push(
                    TypestateViolationEvidence::try_terminal_expectation(
                        PolicyTypestateExpectationId::new(key.as_str())
                            .map_err(|error| error.to_string())?,
                        terminal.clone(),
                        actual,
                        expected.clone(),
                    )
                    .map_err(|error| error.to_string())?,
                );
            }
            if violations.is_empty() {
                return Err(
                    "typestate terminal finding contains no state outside the expectation"
                        .to_owned(),
                );
            }
            Ok(violations)
        }
    }
}

fn event_endpoint(
    compiled: &CompiledTypestatePolicy,
    binding: TypestateEventBindingId,
) -> Result<Option<ResolvedEndpointIdentity>, String> {
    compiled
        .event_endpoints
        .get(binding.get() as usize)
        .cloned()
        .ok_or_else(|| "typestate event binding has no policy provenance slot".to_owned())
}

fn terminal_endpoint(
    compiled: &CompiledTypestatePolicy,
    binding: TypestateTerminalBindingId,
) -> Result<Option<ResolvedEndpointIdentity>, String> {
    compiled
        .terminal_endpoints
        .get(binding.get() as usize)
        .cloned()
        .ok_or_else(|| "typestate terminal binding has no policy provenance slot".to_owned())
}

fn policy_state(
    protocol: &CompiledProtocol,
    state: crate::analyzer::typestate::ProtocolStateId,
) -> Result<PolicyTypestateStateId, String> {
    let key = protocol
        .state_key(state)
        .ok_or_else(|| "typestate finding state is absent from the protocol".to_owned())?;
    PolicyTypestateStateId::new(key.as_str()).map_err(|error| error.to_string())
}

fn projected_report(
    workspace: &WorkspaceAnalyzer,
    finding: &TypestateFinding,
    acquisitions: &[&crate::analyzer::semantic::SemanticLocator],
    finding_key: &str,
    report_options: &PolicyReportOptions,
    budget: &PolicyBudget,
) -> Result<(ProjectedFindingReport, Vec<WitnessId>), String> {
    let primary = policy_location(workspace, finding.site())?;
    let certainty = match finding.certainty() {
        TypestateFindingCertainty::Must => FindingCertainty::Definite,
        TypestateFindingCertainty::May | TypestateFindingCertainty::Inconclusive => {
            FindingCertainty::possible(certainty_reasons(finding)?)
                .map_err(|error| error.to_string())?
        }
    };
    let evidence = finding.evidence();
    let proof = ProofMetadata::try_new(
        if evidence.path_proven() {
            ProofState::Proven
        } else {
            ProofState::Unproven
        },
        vec![ProofReason::TypestateWitness],
        Vec::new(),
    )
    .map_err(|error| error.to_string())?;
    let mut witnesses = Vec::new();
    let mut witness_refs = Vec::new();
    let retained_witness_limit = budget
        .max_witnesses_per_finding()
        .min(report_options.witnesses_per_finding)
        .min(finding.witnesses().len());
    let retained_step_limit = budget
        .max_witness_steps()
        .min(report_options.witness.max_steps);
    let retained_byte_limit = budget
        .max_witness_bytes()
        .min(report_options.witness.max_bytes);
    let mut omitted_witnesses = finding.omitted_witnesses().saturating_add(
        finding
            .witnesses()
            .len()
            .saturating_sub(retained_witness_limit),
    );
    for (index, finding_witness) in finding
        .witnesses()
        .iter()
        .take(retained_witness_limit)
        .enumerate()
    {
        let witness = finding_witness.witness();
        let id_key = stable_hex(format!("{finding_key}:{index}").as_bytes());
        let id = WitnessId::try_new("bifrost", &id_key).map_err(|error| error.to_string())?;
        let mut steps = Vec::new();
        for step in witness.steps().take(retained_step_limit) {
            let (kind, label) = match step.kind() {
                SummaryWitnessStepKind::Seed => (WitnessStepKind::Source, "typestate seed"),
                SummaryWitnessStepKind::Edge(_) => {
                    (WitnessStepKind::Propagation, "typestate propagation")
                }
                SummaryWitnessStepKind::EndSummaryGap(_) => {
                    (WitnessStepKind::Return, "typestate summary boundary")
                }
            };
            let source = program_point_locator(step.source());
            let step = WitnessStep::try_new(
                kind,
                Some(policy_location(workspace, source)?),
                label,
                Vec::new(),
            )
            .map_err(|error| error.to_string())?;
            steps.push(step);
            let candidate = BoundedWitness::try_new(id.clone(), steps.clone(), true, 1)
                .map_err(|error| error.to_string())?;
            if usize::try_from(candidate.retained_bytes()).unwrap_or(usize::MAX)
                > retained_byte_limit
            {
                steps.pop();
                break;
            }
        }
        if steps.is_empty() {
            omitted_witnesses = omitted_witnesses.saturating_add(1);
            continue;
        }
        let mut omitted = witness
            .omitted_steps_lower_bound()
            .saturating_add(witness.step_count().saturating_sub(steps.len()));
        if witness.truncated() && omitted == 0 {
            omitted = 1;
        }
        let truncated = omitted > 0;
        witnesses.push(
            BoundedWitness::try_new(
                id.clone(),
                steps,
                truncated,
                u64::try_from(omitted).unwrap_or(u64::MAX),
            )
            .map_err(|error| error.to_string())?,
        );
        witness_refs.push(id);
    }
    let witnesses_truncated = omitted_witnesses > 0;
    let mut incomplete = Vec::new();
    if !evidence.path_proven() || !evidence.path_complete() || !evidence.analysis_complete() {
        incomplete.push(FindingIncompleteReason::ProofPartial);
    }
    if witnesses_truncated || witnesses.iter().any(BoundedWitness::truncated) {
        incomplete.push(FindingIncompleteReason::WitnessTruncated);
    }
    let completeness = if incomplete.is_empty() {
        FindingCompleteness::Complete
    } else {
        FindingCompleteness::partial(incomplete).map_err(|error| error.to_string())?
    };
    let mut related = Vec::new();
    let mut omitted_related_locations = 0_u64;
    let related_limit = budget
        .max_related_locations_per_finding()
        .min(report_options.origins_per_finding);
    for acquisition in acquisitions {
        let location = policy_location(workspace, acquisition)?;
        if location == primary
            || related
                .iter()
                .any(|retained: &RelatedPolicyLocation| retained.location() == &location)
        {
            continue;
        }
        if related.len() >= related_limit {
            omitted_related_locations = omitted_related_locations.saturating_add(1);
            continue;
        }
        related.push(
            RelatedPolicyLocation::try_new(
                PolicyLocationRelationship::Source,
                location,
                Vec::new(),
            )
            .map_err(|error| error.to_string())?,
        );
    }
    Ok((
        ProjectedFindingReport {
            primary,
            certainty,
            completeness,
            related,
            related_truncated: omitted_related_locations > 0,
            omitted_related_locations_lower_bound: omitted_related_locations,
            evidence_refs_truncated: false,
            omitted_evidence_refs_lower_bound: 0,
            proof,
            witnesses,
            witnesses_truncated,
            omitted_witnesses_lower_bound: u64::try_from(omitted_witnesses).unwrap_or(u64::MAX),
        },
        witness_refs,
    ))
}

fn certainty_reasons(finding: &TypestateFinding) -> Result<Vec<CertaintyReason>, String> {
    let uncertainty = finding.evidence().uncertainty();
    let mut reasons = Vec::new();
    if uncertainty.contains(TypestateUncertainty::AmbiguousDispatch) {
        reasons.push(CertaintyReason::AmbiguousDispatch);
    }
    for (cause, code) in [
        (TypestateUncertainty::UnknownCall, "typestate-unknown-call"),
        (
            TypestateUncertainty::ExternalCall,
            "typestate-external-call",
        ),
        (TypestateUncertainty::Escape, "typestate-escape"),
        (
            TypestateUncertainty::IncompleteAnalysis,
            "typestate-incomplete-analysis",
        ),
        (
            TypestateUncertainty::UnmatchedEvent,
            "typestate-unmatched-event",
        ),
    ] {
        if uncertainty.contains(cause) {
            reasons.push(
                CertaintyReason::analyzer_ambiguity(code).map_err(|error| error.to_string())?,
            );
        }
    }
    if reasons.is_empty() {
        let code = match finding.certainty() {
            TypestateFindingCertainty::May => "typestate-may-path",
            TypestateFindingCertainty::Inconclusive => "typestate-inconclusive-path",
            TypestateFindingCertainty::Must => return Ok(reasons),
        };
        reasons.push(CertaintyReason::analyzer_ambiguity(code).map_err(|error| error.to_string())?);
    }
    Ok(reasons)
}

pub(super) fn policy_location(
    workspace: &WorkspaceAnalyzer,
    locator: &crate::analyzer::semantic::SemanticLocator,
) -> Result<PolicySourceLocation, String> {
    let span = locator.anchor().span();
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    );
    let (start_line, start_column, end_line, end_column) = workspace
        .analyzer()
        .indexed_source(&file)
        .map(|source| {
            let starts = compute_line_starts(&source);
            let (start_line, start_column) =
                line_column_for_offset(&source, &starts, span.start_byte() as usize);
            let (end_line, end_column) =
                line_column_for_offset(&source, &starts, span.end_byte() as usize);
            (start_line, start_column, end_line, end_column)
        })
        .unwrap_or_else(|| {
            (
                span.start().line() as usize + 1,
                span.start().byte_column() as usize + 1,
                span.end().line() as usize + 1,
                span.end().byte_column() as usize + 1,
            )
        });
    Ok(PolicySourceLocation::span(
        locator.path().clone(),
        PolicyByteSpan::new(u64::from(span.start_byte()), u64::from(span.end_byte()))
            .map_err(|error| error.to_string())?,
        PolicyDisplayRegion::new(
            start_line as u64,
            start_column as u64,
            end_line as u64,
            end_column as u64,
        )
        .map_err(|error| error.to_string())?,
    ))
}

pub(super) fn program_point_locator(
    point: &ProgramPointHandle,
) -> &crate::analyzer::semantic::SemanticLocator {
    let row = point
        .procedure()
        .semantics()
        .point(point.id())
        .expect("validated typestate witness point resolves");
    &point
        .procedure()
        .semantics()
        .source_mapping(row.source)
        .expect("validated typestate witness point has a source mapping")
        .locator
}

pub(super) fn semantic_root_key(root: &ProcedureHandle) -> String {
    let mut bytes = Vec::new();
    let locator = root.semantics().locator();
    bytes.extend_from_slice(locator.path().as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(locator.language().config_label().as_bytes());
    bytes.push(0);
    for segment in locator.declaration().segments() {
        bytes.extend_from_slice(segment.kind().stable_label().as_bytes());
        bytes.push(0);
        if let Some(name) = segment.name() {
            bytes.extend_from_slice(name.as_bytes());
        }
        bytes.extend_from_slice(&segment.sibling_ordinal().to_le_bytes());
    }
    stable_hex(&bytes)
}

pub(super) fn semantic_site_key(
    workspace: &WorkspaceAnalyzer,
    locator: &crate::analyzer::semantic::SemanticLocator,
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(semantic_root_key_from_locator(locator).as_bytes());
    bytes.extend_from_slice(locator.role().stable_label().as_bytes());
    let span = locator.anchor().span();
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    );
    if let Some(source) = workspace.analyzer().indexed_source(&file)
        && let Some(slice) = source.get(span.start_byte() as usize..span.end_byte() as usize)
    {
        bytes.extend_from_slice(slice.as_bytes());
    }
    bytes.extend_from_slice(&locator.anchor().occurrence().to_le_bytes());
    stable_hex(&bytes)
}

fn semantic_root_key_from_locator(locator: &crate::analyzer::semantic::SemanticLocator) -> String {
    let mut bytes = Vec::new();
    for segment in locator.declaration().segments() {
        bytes.extend_from_slice(segment.kind().stable_label().as_bytes());
        bytes.push(0);
        if let Some(name) = segment.name() {
            bytes.extend_from_slice(name.as_bytes());
        }
        bytes.extend_from_slice(&segment.sibling_ordinal().to_le_bytes());
    }
    stable_hex(&bytes)
}

pub(super) fn stable_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    encoded
}

fn failed_projection_payload(message: &str) -> TypestateProjectionPayload {
    let completion = PolicyRunCompletion::failed(vec![PolicyFailureReason::InternalInvariant])
        .expect("one failure reason is canonical");
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Error,
        PolicyDiagnosticImpact::RunFailed,
        message,
        None,
        Vec::new(),
    )
    .ok();
    TypestateProjectionPayload {
        projections: Vec::new(),
        completion,
        diagnostics: diagnostic.into_iter().collect(),
        diagnostics_truncated: false,
        work: PolicyWorkReport::default(),
    }
}

fn compile_failure(failure: TypestatePolicyCompileFailure) -> TypestateCompilationFailure {
    let TypestatePolicyCompileFailure { error, work } = failure;
    let message = error.to_string();
    match error {
        TypestatePolicyCompileError::QueryIncomplete {
            completion: CodeQueryCompletion::Cancelled,
            ..
        } => TypestateCompilationFailure::incomplete_many_with_work(
            vec![PolicyIncompleteReason::Cancelled],
            message,
            work,
        ),
        TypestatePolicyCompileError::QueryIncomplete {
            completion: completion @ CodeQueryCompletion::Incomplete { .. },
            ..
        }
        | TypestatePolicyCompileError::QueryIncomplete {
            completion: completion @ CodeQueryCompletion::ProvenSubset { .. },
            ..
        } => {
            let mut reasons = super::evaluator::incomplete_reasons(&completion, false);
            if reasons.is_empty() {
                reasons.push(PolicyIncompleteReason::PartialDiscovery);
            }
            TypestateCompilationFailure::incomplete_many_with_work(reasons, message, work)
        }
        TypestatePolicyCompileError::SemanticUnavailable(_)
        | TypestatePolicyCompileError::AmbiguousSemanticSite(_) => {
            TypestateCompilationFailure::incomplete_many_with_work(
                vec![PolicyIncompleteReason::CapabilityIncomplete],
                message,
                work,
            )
        }
        TypestatePolicyCompileError::EndpointDominanceUndecidable(_) => {
            TypestateCompilationFailure::incomplete_many_with_work(
                vec![PolicyIncompleteReason::EndpointDominanceUndecidable],
                message,
                work,
            )
        }
        TypestatePolicyCompileError::QueryIncomplete {
            completion: CodeQueryCompletion::Invalid { .. },
            ..
        }
        | TypestatePolicyCompileError::Protocol(_)
        | TypestatePolicyCompileError::MissingSelector(_)
        | TypestatePolicyCompileError::UnsupportedBinding(_)
        | TypestatePolicyCompileError::BindingPlan(_) => {
            TypestateCompilationFailure::failed_with_work(
                PolicyFailureReason::InvalidExecutionPlan,
                message,
                work,
            )
        }
        TypestatePolicyCompileError::MissingWorkspace
        | TypestatePolicyCompileError::SemanticProvider(_) => {
            TypestateCompilationFailure::failed_with_work(
                PolicyFailureReason::InternalInvariant,
                message,
                work,
            )
        }
        TypestatePolicyCompileError::QueryIncomplete {
            completion: CodeQueryCompletion::Complete,
            ..
        } => TypestateCompilationFailure::failed_with_work(
            PolicyFailureReason::InternalInvariant,
            message,
            work,
        ),
    }
}

fn query_budget_error(
    code: CodeQueryDiagnosticCode,
    detail: impl Into<String>,
) -> TypestatePolicyCompileError {
    TypestatePolicyCompileError::QueryIncomplete {
        completion: CodeQueryCompletion::Incomplete { codes: vec![code] },
        detail: detail.into(),
    }
}

fn require_uninterrupted_semantic_outcome<T>(
    outcome: &SemanticOutcome<T>,
    operation: &str,
) -> Result<(), TypestatePolicyCompileError> {
    match outcome {
        SemanticOutcome::Cancelled { .. } => Err(TypestatePolicyCompileError::QueryIncomplete {
            completion: CodeQueryCompletion::Cancelled,
            detail: format!("{operation} was cancelled"),
        }),
        SemanticOutcome::ExceededBudget { exceeded, .. } => Err(query_budget_error(
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
            format!("{operation} exceeded the shared semantic budget: {exceeded}"),
        )),
        SemanticOutcome::Complete { .. }
        | SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unknown { .. }
        | SemanticOutcome::Unsupported { .. }
        | SemanticOutcome::Unproven { .. } => Ok(()),
    }
}

impl<'a> TypestatePolicyCompiler<'a> {
    pub(crate) fn new(
        workspace: &'a WorkspaceAnalyzer,
        query_limits: CodeQueryExecutionLimits,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            workspace,
            query_limits,
            cancellation,
            semantic_budget: SemanticBudget::new(super::selector_compiler::semantic_work_limits(
                query_limits.semantic,
            ))
            .expect("validated CodeQuery semantic limits are positive"),
            semantic_execution_budget: SemanticExecutionBudget::new(
                query_limits.semantic.max_materialized_files,
                query_limits.semantic.max_traversal_steps,
            ),
            query_work: CodeQueryExecutionWork::default(),
            artifacts: HashMap::new(),
            syntax_trees: HashMap::new(),
            formal_names: HashMap::new(),
        }
    }

    pub(crate) fn compile(
        mut self,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
    ) -> Result<CompiledTypestatePolicy, Box<TypestatePolicyCompileFailure>> {
        match self.compile_inner(policy, spec) {
            Ok(compiled) => Ok(compiled),
            Err(error) => Err(Box::new(TypestatePolicyCompileFailure {
                error,
                work: self.compilation_work_report(),
            })),
        }
    }

    fn compile_inner(
        &mut self,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
    ) -> Result<CompiledTypestatePolicy, TypestatePolicyCompileError> {
        let protocol = Arc::new(compile_protocol(spec)?);
        let selectors = policy
            .resolved_selectors()
            .iter()
            .map(|selector| (&selector.path, selector))
            .collect::<HashMap<_, _>>();
        let endpoint_precedence = endpoint_precedence_graph(policy, spec)?;
        let event_precedence = event_precedence_graph(policy, spec)?;
        let expectation_precedence = expectation_precedence_graph(policy, spec)?;

        let mut subjects = Vec::new();
        let mut subject_specs = Vec::new();
        let mut seeds = Vec::new();
        let mut roots = Vec::new();
        let mut pending_subjects = Vec::new();
        for subject in &spec.subjects {
            let selector = selector(&selectors, &subject.selector_path)?;
            let binding = SelectorBinding::from_subject(&subject.binding);
            let selections = self.select(selector, &binding)?;
            let class =
                TypestateSubjectClassKey::new(format!("endpoint.{}", subject.semantic_hash))
                    .map_err(|error| {
                        TypestatePolicyCompileError::UnsupportedBinding(error.to_string())
                    })?;
            for selection in selections {
                let resolved = self.resolve_selection(selection, &binding, None)?;
                let seed_site = TypestateObservationSite::program_point(
                    resolved.observation_point.clone(),
                    TypestateBindingContext::root(),
                );
                for object in resolved.objects {
                    pending_subjects.push(PendingSubjectBinding {
                        class: class.clone(),
                        endpoint: subject.identity.clone(),
                        root: resolved.procedure.clone(),
                        site: seed_site.clone(),
                        role: resolved.role,
                        object: object.object,
                        quality: object.quality,
                    });
                }
            }
        }
        let initial_state = ProtocolStateKey::new(spec.automaton.initial.as_str())
            .map_err(|error| TypestatePolicyCompileError::UnsupportedBinding(error.to_string()))?;
        for subject in reduce_subject_bindings(pending_subjects, &endpoint_precedence)? {
            let key = TypestateSubjectKey::for_object(subject.class.clone(), &subject.object);
            subject_specs.push(BoundTypestateSubjectSpec::new(
                subject.class,
                subject.object,
                subject.quality.clone(),
            ));
            seeds.push(TypestateInitialSeedSpec::new(
                key.clone(),
                initial_state.clone(),
                subject.site,
                subject.role,
                subject.quality,
            ));
            roots.push(subject.root.clone());
            subjects.push(CompiledTypestateSubject {
                key,
                endpoint: subject.endpoint,
                root: subject.root,
            });
        }

        let mut events = Vec::new();
        for (event_order, event) in spec.automaton.events.iter().enumerate() {
            let order = u32::try_from(event_order).map_err(|_| {
                TypestatePolicyCompileError::UnsupportedBinding(
                    "too many ordered typestate events".to_owned(),
                )
            })?;
            let event_key = ProtocolEventKey::new(event.id.as_str()).map_err(|error| {
                TypestatePolicyCompileError::UnsupportedBinding(error.to_string())
            })?;
            if let ResolvedTypestateEventTrigger::SemanticEvent {
                event: semantic_event,
            } = &event.trigger
            {
                let exit_kind = procedure_exit_kind(*semantic_event);
                for subject in subjects
                    .iter()
                    .filter(|subject| event.applies_to_subjects.contains(&subject.endpoint))
                {
                    let root = &subject.root;
                    let exit = match exit_kind {
                        ProtocolProcedureExitKind::Normal => {
                            root.point_handle(root.semantics().normal_exit_point())
                        }
                        ProtocolProcedureExitKind::Exceptional => {
                            root.point_handle(root.semantics().exceptional_exit_point())
                        }
                    }
                    .ok_or_else(|| {
                        TypestatePolicyCompileError::SemanticUnavailable(
                            "analysis root has no requested exit point".to_owned(),
                        )
                    })?;
                    events.push(PendingEventBinding {
                        event: event_key.clone(),
                        policy_event: event.id.clone(),
                        subject: subject.key.clone(),
                        site: TypestateObservationSite::program_point(
                            exit,
                            TypestateBindingContext::root(),
                        ),
                        phase: EventObservationPhase::AnalysisRoot(*semantic_event),
                        order,
                        role: TypestateObjectRole::CurrentObject,
                        quality: TypestateBindingQuality::proven_unique(),
                        endpoint: None,
                    });
                }
                continue;
            }
            for trigger in self.event_selections(policy, &selectors, &event.trigger)? {
                let endpoint = trigger.endpoint.clone();
                let resolved = self.resolve_selection(
                    trigger.selection,
                    &trigger.binding,
                    Some(trigger.phase),
                )?;
                for object in &resolved.objects {
                    for subject in subjects.iter().filter(|subject| {
                        event.applies_to_subjects.contains(&subject.endpoint)
                            && subject.key.object()
                                == TypestateSubjectKey::for_object(
                                    subject.key.class().clone(),
                                    &object.object,
                                )
                                .object()
                    }) {
                        let (site, role) = event_site(&resolved, trigger.phase)?;
                        events.push(PendingEventBinding {
                            event: event_key.clone(),
                            policy_event: event.id.clone(),
                            subject: subject.key.clone(),
                            site,
                            phase: EventObservationPhase::Endpoint(trigger.phase),
                            order,
                            role,
                            quality: object.quality.clone(),
                            endpoint: endpoint.clone(),
                        });
                    }
                }
            }
        }

        let mut terminals = Vec::new();
        for expectation in &spec.automaton.terminal_expectations {
            let expectation_key =
                ProtocolExpectationKey::new(expectation.id.as_str()).map_err(|error| {
                    TypestatePolicyCompileError::UnsupportedBinding(error.to_string())
                })?;
            match &expectation.trigger {
                ResolvedTypestateTerminalTrigger::SemanticEvent { event } => {
                    let exit_kind = procedure_exit_kind(*event);
                    for subject in subjects.iter().filter(|subject| {
                        expectation.applies_to_subjects.contains(&subject.endpoint)
                    }) {
                        let root = &subject.root;
                        let exit = match exit_kind {
                            ProtocolProcedureExitKind::Normal => {
                                root.point_handle(root.semantics().normal_exit_point())
                            }
                            ProtocolProcedureExitKind::Exceptional => {
                                root.point_handle(root.semantics().exceptional_exit_point())
                            }
                        }
                        .ok_or_else(|| {
                            TypestatePolicyCompileError::SemanticUnavailable(
                                "analysis root has no requested exit point".to_owned(),
                            )
                        })?;
                        terminals.push(PendingTerminalBinding {
                            expectation: expectation_key.clone(),
                            policy_expectation: expectation.id.clone(),
                            subject: subject.key.clone(),
                            site: TypestateObservationSite::program_point(
                                exit,
                                TypestateBindingContext::root(),
                            ),
                            phase: TerminalObservationPhase::AnalysisRoot(*event),
                            role: TypestateObjectRole::CurrentObject,
                            quality: TypestateBindingQuality::proven_unique(),
                            endpoint: None,
                        });
                    }
                }
                ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, phase } => {
                    for endpoint in endpoints {
                        let dependency = spec
                            .endpoint_dependencies
                            .iter()
                            .find(|dependency| dependency.identity() == endpoint)
                            .ok_or_else(|| {
                                TypestatePolicyCompileError::SemanticUnavailable(
                                    "terminal endpoint dependency is missing".to_owned(),
                                )
                            })?;
                        let selector = selector(&selectors, dependency.selector_path())?;
                        let binding = SelectorBinding::from_endpoint(&dependency.model().binding);
                        for selection in self.select(selector, &binding)? {
                            let resolved =
                                self.resolve_selection(selection, &binding, Some(*phase))?;
                            for object in &resolved.objects {
                                for subject in subjects.iter().filter(|subject| {
                                    expectation.applies_to_subjects.contains(&subject.endpoint)
                                        && subject.key.object()
                                            == TypestateSubjectKey::for_object(
                                                subject.key.class().clone(),
                                                &object.object,
                                            )
                                            .object()
                                }) {
                                    let (site, role) = event_site(&resolved, *phase)?;
                                    terminals.push(PendingTerminalBinding {
                                        expectation: expectation_key.clone(),
                                        policy_expectation: expectation.id.clone(),
                                        subject: subject.key.clone(),
                                        site,
                                        phase: TerminalObservationPhase::Endpoint(*phase),
                                        role,
                                        quality: object.quality.clone(),
                                        endpoint: Some(endpoint.clone()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        roots.sort_by(|left, right| left.semantics().locator().cmp(right.semantics().locator()));
        roots.dedup_by(|left, right| left == right);
        subjects.sort_by(|left, right| left.key.cmp(&right.key));
        let events = reduce_event_bindings(events, &endpoint_precedence, &event_precedence)?;
        let terminals =
            reduce_terminal_bindings(terminals, &endpoint_precedence, &expectation_precedence)?;
        let event_provenance = events
            .iter()
            .map(|binding| {
                (
                    EventProvenanceKey {
                        event: binding.event.clone(),
                        subject: binding.subject.clone(),
                        site: binding.site.clone(),
                        order: binding.order,
                        role: binding.role,
                    },
                    binding.endpoint.clone(),
                )
            })
            .collect::<HashMap<_, _>>();
        let terminal_provenance = terminals
            .iter()
            .map(|binding| {
                (
                    TerminalProvenanceKey {
                        expectation: binding.expectation.clone(),
                        subject: binding.subject.clone(),
                        site: binding.site.clone(),
                        role: binding.role,
                    },
                    binding.endpoint.clone(),
                )
            })
            .collect::<HashMap<_, _>>();
        let event_specs = events
            .into_iter()
            .map(|binding| {
                TypestateEventBindingSpec::new(
                    binding.event,
                    binding.subject,
                    binding.site,
                    binding.order,
                    binding.role,
                    binding.quality,
                )
            })
            .collect();
        let terminal_specs = terminals
            .into_iter()
            .map(|binding| {
                TypestateTerminalBindingSpec::new(
                    binding.expectation,
                    binding.subject,
                    binding.site,
                    binding.role,
                    binding.quality,
                )
            })
            .collect();
        let bindings = Arc::new(
            TypestateBindingPlan::try_new(
                &protocol,
                subject_specs,
                seeds,
                event_specs,
                terminal_specs,
            )
            .map_err(TypestatePolicyCompileError::BindingPlan)?,
        );
        let event_endpoints = bindings
            .event_bindings()
            .iter()
            .map(|binding| {
                let event = protocol
                    .event(binding.event())
                    .expect("binding-plan event ID resolves")
                    .key()
                    .clone();
                let subject = bindings
                    .subject(binding.subject())
                    .expect("binding-plan subject ID resolves")
                    .key()
                    .clone();
                event_provenance
                    .get(&EventProvenanceKey {
                        event,
                        subject,
                        site: binding.site().clone(),
                        order: binding.order(),
                        role: binding.role(),
                    })
                    .cloned()
                    .ok_or_else(|| {
                        TypestatePolicyCompileError::SemanticUnavailable(
                            "typestate event lost its endpoint provenance".to_owned(),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let terminal_endpoints = bindings
            .terminal_bindings()
            .iter()
            .map(|binding| {
                let expectation = protocol
                    .terminal_expectation(binding.expectation())
                    .expect("binding-plan expectation ID resolves")
                    .key()
                    .clone();
                let subject = bindings
                    .subject(binding.subject())
                    .expect("binding-plan subject ID resolves")
                    .key()
                    .clone();
                terminal_provenance
                    .get(&TerminalProvenanceKey {
                        expectation,
                        subject,
                        site: binding.site().clone(),
                        role: binding.role(),
                    })
                    .cloned()
                    .ok_or_else(|| {
                        TypestatePolicyCompileError::SemanticUnavailable(
                            "typestate terminal lost its endpoint provenance".to_owned(),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let semantic_compile_work = self.semantic_budget.used();
        let semantic_remaining = self.semantic_budget.remaining();
        let semantic_compile_execution_work = self.semantic_execution_budget.work();
        if !roots.is_empty()
            && (SemanticBudgetDimension::ALL
                .into_iter()
                .any(|dimension| semantic_remaining.get(dimension) == 0))
        {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "typestate semantic preparation exhausted the shared policy budget",
            ));
        }
        Ok(CompiledTypestatePolicy {
            protocol,
            bindings,
            roots: roots.into_boxed_slice(),
            subjects: subjects.into_boxed_slice(),
            event_endpoints: event_endpoints.into_boxed_slice(),
            terminal_endpoints: terminal_endpoints.into_boxed_slice(),
            query_work: self.query_work,
            semantic_compile_work,
            semantic_remaining,
            semantic_compile_execution_work,
            semantic_execution_budget: self.semantic_execution_budget.clone(),
        })
    }

    fn event_selections(
        &mut self,
        _policy: &LoadedPolicy,
        selectors: &HashMap<&PolicySelectorPath, &ResolvedPolicySelector>,
        trigger: &ResolvedTypestateEventTrigger,
    ) -> Result<Vec<EventSelection>, TypestatePolicyCompileError> {
        let mut selected = Vec::new();
        match trigger {
            ResolvedTypestateEventTrigger::Calls {
                selector_path,
                subject,
                phase,
            } => {
                let binding = SelectorBinding::from_call(subject);
                for selection in self.select(selector(selectors, selector_path)?, &binding)? {
                    selected.push(EventSelection {
                        selection,
                        binding: binding.clone(),
                        phase: *phase,
                        endpoint: None,
                    });
                }
            }
            ResolvedTypestateEventTrigger::MatchEndpoints { endpoints, phase } => {
                // The caller resolves endpoint identities from the same closed
                // dependency set retained by the loaded specification.
                for endpoint in endpoints {
                    let dependency = _policy
                        .endpoint_dependencies()
                        .iter()
                        .find(|dependency| dependency.identity() == endpoint)
                        .ok_or_else(|| {
                            TypestatePolicyCompileError::SemanticUnavailable(
                                "event endpoint dependency is missing".to_owned(),
                            )
                        })?;
                    let binding = SelectorBinding::from_endpoint(&dependency.model().binding);
                    for selection in
                        self.select(selector(selectors, dependency.selector_path())?, &binding)?
                    {
                        selected.push(EventSelection {
                            selection,
                            binding: binding.clone(),
                            phase: *phase,
                            endpoint: Some(endpoint.clone()),
                        });
                    }
                }
            }
            ResolvedTypestateEventTrigger::SemanticEvent { .. } => {}
        }
        Ok(selected)
    }

    fn select(
        &mut self,
        selector: &ResolvedPolicySelector,
        binding: &SelectorBinding,
    ) -> Result<Vec<SelectedSite>, TypestatePolicyCompileError> {
        let limits = self.remaining_query_limits()?;
        let detailed = execute_code_query_detailed(
            self.workspace.analyzer(),
            &selector.query,
            limits,
            Some(self.cancellation),
        );
        self.query_work = self.query_work.saturating_add(detailed.work);
        self.charge_query_semantic_work(detailed.work.semantic)?;
        if !matches!(detailed.result.completion(), CodeQueryCompletion::Complete) {
            let diagnostics = detailed
                .result
                .diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {}", diagnostic.code.as_str(), diagnostic.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(TypestatePolicyCompileError::QueryIncomplete {
                completion: detailed.result.completion(),
                detail: format!("`{}` ({diagnostics})", selector.path),
            });
        }
        let mut sites = Vec::new();
        for evidence in detailed.evidence {
            if matches!(evidence.domain, DetailedCodeQueryDomain::File) {
                continue;
            }
            let result_item = detailed
                .result
                .results
                .get(evidence.result_index)
                .ok_or_else(|| {
                    TypestatePolicyCompileError::SemanticUnavailable(format!(
                        "selector `{}` evidence refers to an absent result row",
                        selector.path
                    ))
                })?;
            let (proof, completeness) =
                super::selector_compiler::selected_site_quality(result_item);
            let Some(span) = evidence.byte_span else {
                return Err(TypestatePolicyCompileError::SemanticUnavailable(format!(
                    "selector `{}` produced a row without a source span",
                    selector.path
                )));
            };
            sites.push(SelectedSite {
                file: evidence.file,
                span,
                require_exact_call: matches!(binding, SelectorBinding::MatchedValue),
                proof,
                completeness,
            });
        }
        Ok(sites)
    }

    fn remaining_query_limits(
        &self,
    ) -> Result<CodeQueryExecutionLimits, TypestatePolicyCompileError> {
        let remaining = |limit: usize, used: u64| {
            limit.saturating_sub(usize::try_from(used).unwrap_or(usize::MAX))
        };
        let max_scanned_files = remaining(
            self.query_limits.max_scanned_files,
            self.query_work.scanned_files,
        );
        let max_scanned_source_bytes = remaining(
            self.query_limits.max_scanned_source_bytes,
            self.query_work.scanned_source_bytes,
        );
        let max_fact_nodes =
            remaining(self.query_limits.max_fact_nodes, self.query_work.fact_nodes);
        let max_pipeline_rows = remaining(
            self.query_limits.max_pipeline_rows,
            self.query_work.pipeline_rows,
        );
        if [
            max_scanned_files,
            max_scanned_source_bytes,
            max_fact_nodes,
            max_pipeline_rows,
        ]
        .contains(&0)
        {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
                "typestate selectors exhausted the shared structural query budget",
            ));
        }

        let semantic_remaining = self.semantic_budget.remaining();
        let max_materialized_files = self
            .semantic_execution_budget
            .remaining_materialized_files();
        let max_source_bytes = semantic_remaining.source_bytes;
        let max_rows_per_dimension = SemanticBudgetDimension::ALL
            .into_iter()
            .filter(|dimension| {
                !matches!(
                    dimension,
                    SemanticBudgetDimension::SourceBytes | SemanticBudgetDimension::OwnedTextBytes
                )
            })
            .map(|dimension| semantic_remaining.get(dimension))
            .min()
            .unwrap_or(0);
        let max_retained_bytes = semantic_remaining.owned_text_bytes;
        let max_traversal_steps = self.remaining_semantic_traversal_steps()?;
        let semantic = CodeQuerySemanticLimits {
            max_materialized_files,
            max_source_bytes,
            max_rows_per_dimension,
            max_retained_bytes,
            max_traversal_steps,
        };
        if !semantic.all_positive() {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "typestate selectors exhausted the shared semantic query budget",
            ));
        }
        Ok(CodeQueryExecutionLimits {
            max_scanned_files,
            max_scanned_source_bytes,
            max_fact_nodes,
            max_pipeline_rows,
            semantic,
            typestate: self.query_limits.typestate,
            value_flow: self.query_limits.value_flow,
        })
    }

    fn remaining_semantic_traversal_steps(&self) -> Result<usize, TypestatePolicyCompileError> {
        let remaining = self.semantic_execution_budget.remaining_traversal_steps();
        if remaining == 0 {
            Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "typestate semantic lookup exhausted the shared traversal budget",
            ))
        } else {
            Ok(remaining)
        }
    }

    fn charge_query_semantic_work(
        &mut self,
        work: CodeQuerySemanticWork,
    ) -> Result<(), TypestatePolicyCompileError> {
        let usize_work = |value| usize::try_from(value).unwrap_or(usize::MAX);
        if !self.semantic_execution_budget.charge_external_query_work(
            usize_work(work.unique_materialized_files),
            usize_work(work.traversal_steps),
        ) {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "typestate selectors exhausted the shared semantic execution budget",
            ));
        }
        self.semantic_budget
            .charge(SemanticWork {
                source_bytes: usize_work(work.source_bytes),
                procedures: usize_work(work.procedures),
                blocks: usize_work(work.blocks),
                program_points: usize_work(work.program_points),
                values: usize_work(work.values),
                allocations: usize_work(work.allocations),
                call_sites: usize_work(work.call_sites),
                memory_locations: usize_work(work.memory_locations),
                captures: usize_work(work.captures),
                source_mappings: usize_work(work.source_mappings),
                evidence: usize_work(work.evidence),
                gaps: usize_work(work.gaps),
                events: usize_work(work.events),
                control_edges: usize_work(work.control_edges),
                nested_entries: usize_work(work.nested_entries),
                owned_text_bytes: usize_work(work.retained_bytes),
            })
            .map_err(|_| {
                query_budget_error(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    "typestate selectors exhausted the shared semantic materialization budget",
                )
            })
    }

    fn resolve_selection(
        &mut self,
        selection: SelectedSite,
        binding: &SelectorBinding,
        phase: Option<EndpointObservationPhase>,
    ) -> Result<ResolvedSelection, TypestatePolicyCompileError> {
        if matches!(binding, SelectorBinding::MatchedValue)
            && matches!(phase, None | Some(EndpointObservationPhase::AtMatch))
        {
            return self.resolve_matched_selection(selection);
        }
        let artifact = self.materialize(&selection.file)?;
        let range = super::selector_compiler::source_range(&selection.span);
        let lookup = procedures_for_source_ranges(
            &artifact,
            &[range],
            self.remaining_semantic_traversal_steps()?,
            self.cancellation,
        );
        if !self
            .semantic_execution_budget
            .charge_traversal(lookup.examined)
        {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "enclosing-procedure lookup exhausted the shared traversal budget",
            ));
        }
        match lookup.status {
            ProcedureRangeLookupStatus::Complete => {}
            ProcedureRangeLookupStatus::Cancelled => {
                return Err(TypestatePolicyCompileError::QueryIncomplete {
                    completion: CodeQueryCompletion::Cancelled,
                    detail: "enclosing-procedure lookup was cancelled".to_owned(),
                });
            }
            ProcedureRangeLookupStatus::BudgetExhausted => {
                return Err(query_budget_error(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    "enclosing-procedure lookup exhausted the shared traversal budget",
                ));
            }
            ProcedureRangeLookupStatus::SourceChanged => {
                return Err(TypestatePolicyCompileError::SemanticUnavailable(
                    "enclosing-procedure lookup observed a changed source snapshot".to_owned(),
                ));
            }
        }
        let (procedure, call) = select_call(&lookup.handles, &selection)?;
        let named_argument;
        let effective_binding = if let SelectorBinding::ArgumentName(name) = binding {
            named_argument =
                SelectorBinding::ArgumentIndex(self.resolve_named_argument_index(&call, name)?);
            &named_argument
        } else {
            binding
        };
        let (value, observation_point, role) =
            select_value(&procedure, &call, &selection.span, effective_binding, phase)?;
        let oracle = self.workspace.semantic_oracle_provider();
        let at_point = ValueAtPoint::new(
            value,
            observation_point.clone(),
            oracle_observation_phase(phase),
            OracleCallContext::empty(),
        )
        .map_err(|error| {
            TypestatePolicyCompileError::SemanticProvider(SemanticProviderError::internal(
                error.to_string(),
            ))
        })?;
        let mut request = SemanticRequest::with_execution_budget(
            &mut self.semantic_budget,
            self.cancellation,
            &self.semantic_execution_budget,
        );
        let outcome = oracle
            .pointees(&at_point, &mut request)
            .map_err(TypestatePolicyCompileError::SemanticProvider)?;
        require_uninterrupted_semantic_outcome(&outcome, "heap analysis")?;
        self.require_execution_budget("heap analysis")?;
        let result = outcome.available_value().ok_or_else(|| {
            TypestatePolicyCompileError::SemanticUnavailable(
                "heap analysis produced no object candidates".to_owned(),
            )
        })?;
        if result.objects().candidates().is_empty() {
            return Err(TypestatePolicyCompileError::SemanticUnavailable(
                "selected value has no structured abstract object".to_owned(),
            ));
        }
        let multiplicity = TypestateBindingMultiplicity::new(
            result.objects().coverage(),
            result.objects().candidates().len(),
        )
        .map_err(TypestatePolicyCompileError::BindingPlan)?;
        let objects = result
            .objects()
            .candidates()
            .iter()
            .map(|candidate| ResolvedObject {
                object: candidate.value().clone(),
                quality: TypestateBindingQuality::new(
                    conjoin_proof(&selection.proof, candidate.proof()),
                    conjoin_completeness(&selection.completeness, candidate.completeness()),
                    multiplicity,
                ),
            })
            .collect();
        Ok(ResolvedSelection {
            procedure,
            call: Some(call),
            observation_point,
            role,
            objects,
        })
    }

    fn resolve_matched_selection(
        &mut self,
        selection: SelectedSite,
    ) -> Result<ResolvedSelection, TypestatePolicyCompileError> {
        let oracle = self.workspace.semantic_oracle_provider();
        let outcome = {
            let mut request = SemanticRequest::with_execution_budget(
                &mut self.semantic_budget,
                self.cancellation,
                &self.semantic_execution_budget,
            );
            oracle
                .pointees_at_source(
                    &selection.file,
                    super::selector_compiler::source_range(&selection.span),
                    &mut request,
                )
                .map_err(TypestatePolicyCompileError::SemanticProvider)?
        };
        require_uninterrupted_semantic_outcome(&outcome, "matched source heap analysis")?;
        self.require_execution_budget("matched source heap analysis")?;
        let result = outcome.available_value().ok_or_else(|| {
            TypestatePolicyCompileError::SemanticUnavailable(
                "matched source row produced no point-sensitive value observation".to_owned(),
            )
        })?;
        if result.observations().len() != 1 {
            return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                "matched-value binding identifies {} point-sensitive observations",
                result.observations().len()
            )));
        }
        let observation = &result.observations()[0];
        if observation.objects().candidates().is_empty() {
            return Err(TypestatePolicyCompileError::SemanticUnavailable(
                "matched source value has no structured abstract object".to_owned(),
            ));
        }
        let multiplicity = TypestateBindingMultiplicity::new(
            observation.objects().coverage(),
            observation.objects().candidates().len(),
        )
        .map_err(TypestatePolicyCompileError::BindingPlan)?;
        let objects = observation
            .objects()
            .candidates()
            .iter()
            .map(|candidate| ResolvedObject {
                object: candidate.value().clone(),
                quality: TypestateBindingQuality::new(
                    conjoin_proof(&selection.proof, candidate.proof()),
                    conjoin_completeness(&selection.completeness, candidate.completeness()),
                    multiplicity,
                ),
            })
            .collect();
        Ok(ResolvedSelection {
            procedure: observation.query().point().procedure().clone(),
            call: None,
            observation_point: observation.query().point().clone(),
            role: TypestateObjectRole::MatchedValue,
            objects,
        })
    }

    fn resolve_named_argument_index(
        &mut self,
        call: &CallSiteHandle,
        expected_name: &str,
    ) -> Result<u32, TypestatePolicyCompileError> {
        let oracle = self.workspace.semantic_oracle_provider();
        let dispatch = {
            let mut request = SemanticRequest::with_execution_budget(
                &mut self.semantic_budget,
                self.cancellation,
                &self.semantic_execution_budget,
            );
            oracle
                .resolve_call(call, &mut request)
                .map_err(TypestatePolicyCompileError::SemanticProvider)?
        };
        require_uninterrupted_semantic_outcome(&dispatch, "formal-name dispatch")?;
        self.require_execution_budget("formal-name dispatch")?;
        if !dispatch.is_complete() {
            return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                "formal-name binding `{expected_name}` requires complete dispatch"
            )));
        }
        let dispatch = dispatch.available_value().ok_or_else(|| {
            TypestatePolicyCompileError::SemanticUnavailable(
                "formal-name binding has no dispatch result".to_owned(),
            )
        })?;
        if dispatch.coverage() != CandidateCoverage::Exhaustive || dispatch.candidates().is_empty()
        {
            return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                "formal-name binding `{expected_name}` has incomplete dispatch coverage"
            )));
        }

        let mut common_index = None;
        for candidate in dispatch.candidates() {
            if !matches!(candidate.proof(), ProofStatus::Proven) {
                return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                    "formal-name binding `{expected_name}` has an unproven dispatch target"
                )));
            }
            let bindings = {
                let mut request = SemanticRequest::with_execution_budget(
                    &mut self.semantic_budget,
                    self.cancellation,
                    &self.semantic_execution_budget,
                );
                oracle
                    .call_bindings(call, candidate, &OracleCallContext::empty(), &mut request)
                    .map_err(TypestatePolicyCompileError::SemanticProvider)?
            };
            require_uninterrupted_semantic_outcome(&bindings, "formal-name argument binding")?;
            self.require_execution_budget("formal-name argument binding")?;
            if !bindings.is_complete() {
                return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                    "formal-name binding `{expected_name}` requires complete argument binding"
                )));
            }
            let bindings = bindings.available_value().ok_or_else(|| {
                TypestatePolicyCompileError::SemanticUnavailable(
                    "formal-name binding has no argument relation".to_owned(),
                )
            })?;
            if bindings.coverage() != CandidateCoverage::Exhaustive {
                return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                    "formal-name binding `{expected_name}` has incomplete argument coverage"
                )));
            }
            let mut target_indices = Vec::new();
            for binding in bindings.bindings() {
                let CallBinding::ArgumentGroup(group) = binding else {
                    continue;
                };
                if group.coverage() != CandidateCoverage::Exhaustive {
                    return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                        "formal-name binding `{expected_name}` crosses an open argument group"
                    )));
                }
                for mapping in group.mappings() {
                    if matches!(mapping.proof(), ProofStatus::Proven)
                        && self
                            .formal_parameter_has_name(mapping.value().formal(), expected_name)?
                    {
                        target_indices.push(mapping.value().source_index());
                    }
                }
            }
            target_indices.sort_unstable();
            target_indices.dedup();
            if target_indices.len() != 1 {
                return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                    "formal-name binding `{expected_name}` does not identify exactly one argument"
                )));
            }
            match common_index {
                None => common_index = target_indices.first().copied(),
                Some(index) if target_indices == [index] => {}
                Some(_) => {
                    return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                        "formal-name binding `{expected_name}` maps to different arguments across dispatch targets"
                    )));
                }
            }
        }
        common_index.ok_or_else(|| {
            TypestatePolicyCompileError::SemanticUnavailable(format!(
                "formal-name binding `{expected_name}` has no mapped argument"
            ))
        })
    }

    fn formal_parameter_has_name(
        &mut self,
        formal: &ProcedurePortHandle,
        expected_name: &str,
    ) -> Result<bool, TypestatePolicyCompileError> {
        let ProcedurePortKind::Parameter { ordinal } = formal.kind() else {
            return Ok(false);
        };
        if let Some(names) = self.formal_names.get(formal) {
            return Ok(parameter_names_match(names, expected_name));
        }
        if self.cancellation.is_cancelled() {
            return Err(TypestatePolicyCompileError::QueryIncomplete {
                completion: CodeQueryCompletion::Cancelled,
                detail: "formal-parameter layout resolution was cancelled".to_owned(),
            });
        }
        self.remaining_semantic_traversal_steps()?;
        if !self.semantic_execution_budget.charge_traversal(1) {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "formal-parameter layout resolution exhausted the shared traversal budget",
            ));
        }
        let semantics = formal.procedure().semantics();
        let Some(locator) = semantics
            .source_mapping(semantics.source())
            .map(|mapping| &mapping.locator)
        else {
            return Ok(false);
        };
        let span = locator.anchor().span();
        let file = ProjectFile::new(
            self.workspace.analyzer().project().root().to_path_buf(),
            locator.path().as_path(),
        );
        let Some(source) = self.workspace.analyzer().indexed_source(&file) else {
            return Ok(false);
        };
        let language = language_for_file(&file);
        if !self.syntax_trees.contains_key(&file) {
            let Some(tree) = parse_tree_for_language(&file, language, &source) else {
                return Ok(false);
            };
            self.syntax_trees.insert(file.clone(), tree);
        }
        let tree = self
            .syntax_trees
            .get(&file)
            .expect("cached parameter syntax tree is retained");
        let declaration_range = Range {
            start_byte: span.start_byte() as usize,
            end_byte: span.end_byte() as usize,
            start_line: 0,
            end_line: 0,
        };
        let Some(layout) =
            formal_parameter_slots(language, tree.root_node(), &source, &declaration_range)
        else {
            return Ok(false);
        };
        let names = layout
            .slots
            .iter()
            .filter(|slot| !slot.receiver)
            .nth(ordinal as usize)
            .map_or_else(
                || Vec::<String>::new().into_boxed_slice(),
                |slot| slot.names.clone().into_boxed_slice(),
            );
        let matches = parameter_names_match(&names, expected_name);
        self.formal_names.insert(formal.clone(), names);
        Ok(matches)
    }

    fn materialize(
        &mut self,
        file: &ProjectFile,
    ) -> Result<Arc<SemanticArtifact>, TypestatePolicyCompileError> {
        if let Some(artifact) = self.artifacts.get(file) {
            return Ok(Arc::clone(artifact));
        }
        let mut request = SemanticRequest::with_execution_budget(
            &mut self.semantic_budget,
            self.cancellation,
            &self.semantic_execution_budget,
        );
        let outcome = self
            .workspace
            .materialize_program_semantics(file, &mut request)
            .map_err(TypestatePolicyCompileError::SemanticProvider)?;
        require_uninterrupted_semantic_outcome(&outcome, "program semantics materialization")?;
        self.require_execution_budget("program semantics materialization")?;
        let artifact = outcome.available_value().cloned().ok_or_else(|| {
            TypestatePolicyCompileError::SemanticUnavailable(format!(
                "program semantics are unavailable for {}",
                file.abs_path().display()
            ))
        })?;
        self.artifacts.insert(file.clone(), Arc::clone(&artifact));
        Ok(artifact)
    }

    fn require_execution_budget(&self, operation: &str) -> Result<(), TypestatePolicyCompileError> {
        if self.semantic_execution_budget.work().exhausted {
            Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                format!("{operation} exhausted the shared semantic file or traversal budget"),
            ))
        } else {
            Ok(())
        }
    }

    fn compilation_work_report(&self) -> PolicyWorkReport {
        let semantic = self.semantic_budget.used();
        let execution = self.semantic_execution_budget.work();
        let metrics = [
            PolicyWorkMetric::try_new(
                "typestate.semantic_materialized_files",
                PolicyWorkUnit::Count,
                u64::try_from(execution.materialized_files).unwrap_or(u64::MAX),
            ),
            PolicyWorkMetric::try_new(
                "typestate.semantic_traversal_steps",
                PolicyWorkUnit::Count,
                u64::try_from(execution.traversal_steps).unwrap_or(u64::MAX),
            ),
            PolicyWorkMetric::try_new(
                "typestate.semantic_source_bytes",
                PolicyWorkUnit::Bytes,
                u64::try_from(semantic.source_bytes).unwrap_or(u64::MAX),
            ),
            PolicyWorkMetric::try_new(
                "typestate.semantic_program_points",
                PolicyWorkUnit::Rows,
                u64::try_from(semantic.program_points).unwrap_or(u64::MAX),
            ),
        ]
        .into_iter()
        .filter_map(Result::ok)
        .collect();
        PolicyWorkReport::try_new(
            self.query_work.scanned_files,
            self.query_work.scanned_source_bytes,
            self.query_work.fact_nodes,
            self.query_work.pipeline_rows,
            self.query_work.examined_references,
            0,
            0,
            0,
            metrics,
        )
        .unwrap_or_default()
    }
}

#[derive(Clone)]
enum SelectorBinding {
    MatchedValue,
    Receiver,
    ReturnValue,
    ArgumentIndex(u32),
    ArgumentName(String),
}

fn parameter_names_match(names: &[String], expected_name: &str) -> bool {
    names.iter().any(|name| {
        name == expected_name
            || name.strip_prefix('$') == Some(expected_name)
            || expected_name.strip_prefix('$') == Some(name)
    })
}

impl SelectorBinding {
    fn from_subject(binding: &ResolvedTypestateBinding) -> Self {
        match binding {
            ResolvedTypestateBinding::MatchedValue => Self::MatchedValue,
            ResolvedTypestateBinding::Receiver => Self::Receiver,
            ResolvedTypestateBinding::ReturnValue => Self::ReturnValue,
            ResolvedTypestateBinding::ArgumentIndex { index } => Self::ArgumentIndex(*index),
            ResolvedTypestateBinding::ArgumentName { name } => Self::ArgumentName(name.clone()),
        }
    }

    fn from_call(binding: &TypestateCallBinding) -> Self {
        match binding {
            TypestateCallBinding::Receiver => Self::Receiver,
            TypestateCallBinding::ReturnValue => Self::ReturnValue,
            TypestateCallBinding::ArgumentIndex { index } => Self::ArgumentIndex(*index),
            TypestateCallBinding::ArgumentName { name } => Self::ArgumentName(name.clone()),
        }
    }

    fn from_endpoint(binding: &PolicyEndpointBinding) -> Self {
        match binding {
            PolicyEndpointBinding::MatchedValue => Self::MatchedValue,
            PolicyEndpointBinding::Receiver => Self::Receiver,
            PolicyEndpointBinding::ReturnValue => Self::ReturnValue,
            PolicyEndpointBinding::ArgumentIndex { index } => Self::ArgumentIndex(*index),
            PolicyEndpointBinding::ArgumentName { name } => Self::ArgumentName(name.clone()),
        }
    }
}

#[derive(Clone)]
struct SelectedSite {
    file: ProjectFile,
    span: ByteRange<usize>,
    require_exact_call: bool,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

fn conjoin_proof(left: &ProofStatus, right: &ProofStatus) -> ProofStatus {
    if matches!((left, right), (ProofStatus::Proven, ProofStatus::Proven)) {
        ProofStatus::Proven
    } else {
        ProofStatus::Unproven("selector or heap evidence is unproven".into())
    }
}

fn conjoin_completeness(
    left: &EvidenceCompleteness,
    right: &EvidenceCompleteness,
) -> EvidenceCompleteness {
    if matches!(
        (left, right),
        (
            EvidenceCompleteness::Complete,
            EvidenceCompleteness::Complete
        )
    ) {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial("selector or heap evidence is partial".into())
    }
}

struct EventSelection {
    selection: SelectedSite,
    binding: SelectorBinding,
    phase: EndpointObservationPhase,
    endpoint: Option<ResolvedEndpointIdentity>,
}

struct PendingSubjectBinding {
    class: TypestateSubjectClassKey,
    endpoint: ResolvedEndpointIdentity,
    root: ProcedureHandle,
    site: TypestateObservationSite,
    role: TypestateObjectRole,
    object: AbstractObject,
    quality: TypestateBindingQuality,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SubjectObservationGroupKey {
    site: TypestateObservationSite,
    role: TypestateObjectRole,
    object: AbstractObject,
}

fn reduce_subject_bindings(
    candidates: Vec<PendingSubjectBinding>,
    endpoint_precedence: &PrecedenceGraph<ResolvedEndpointIdentity>,
) -> Result<Vec<PendingSubjectBinding>, TypestatePolicyCompileError> {
    let mut groups = HashMap::<SubjectObservationGroupKey, Vec<PendingSubjectBinding>>::new();
    for candidate in candidates {
        groups
            .entry(SubjectObservationGroupKey {
                site: candidate.site.clone(),
                role: candidate.role,
                object: candidate.object.clone(),
            })
            .or_default()
            .push(candidate);
    }
    let mut reduced = Vec::with_capacity(groups.len());
    for mut candidates in groups.into_values() {
        let endpoints = candidates
            .iter()
            .map(|candidate| Some(candidate.endpoint.clone()))
            .collect::<Vec<_>>();
        let winner = endpoint_winner_index(&endpoints, endpoint_precedence)?;
        reduced.push(candidates.swap_remove(winner));
    }
    Ok(reduced)
}

struct PendingEventBinding {
    event: ProtocolEventKey,
    policy_event: PolicyTypestateEventId,
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
    phase: EventObservationPhase,
    order: u32,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
    endpoint: Option<ResolvedEndpointIdentity>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum EventObservationPhase {
    AnalysisRoot(PolicySemanticEvent),
    Endpoint(EndpointObservationPhase),
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct EventObservationGroupKey {
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
    phase: EventObservationPhase,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct EventProvenanceKey {
    event: ProtocolEventKey,
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
    order: u32,
    role: TypestateObjectRole,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum TerminalObservationPhase {
    AnalysisRoot(PolicySemanticEvent),
    Endpoint(EndpointObservationPhase),
}

struct PendingTerminalBinding {
    expectation: ProtocolExpectationKey,
    policy_expectation: PolicyTypestateExpectationId,
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
    phase: TerminalObservationPhase,
    role: TypestateObjectRole,
    quality: TypestateBindingQuality,
    endpoint: Option<ResolvedEndpointIdentity>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct TerminalObservationGroupKey {
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
    phase: TerminalObservationPhase,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct TerminalProvenanceKey {
    expectation: ProtocolExpectationKey,
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
    role: TypestateObjectRole,
}

fn endpoint_precedence_graph(
    policy: &LoadedPolicy,
    spec: &ResolvedTypestatePolicySpec,
) -> Result<PrecedenceGraph<ResolvedEndpointIdentity>, TypestatePolicyCompileError> {
    PrecedenceGraph::try_new(
        spec.endpoint_dependencies
            .iter()
            .map(|dependency| dependency.identity().clone()),
        policy
            .precedence_manifest()
            .edges
            .iter()
            .filter_map(|edge| match edge {
                ResolvedPrecedenceEdge::Endpoint {
                    dominant,
                    dominated,
                } => Some((dominant.clone(), dominated.clone())),
                _ => None,
            }),
    )
    .map_err(|error| {
        TypestatePolicyCompileError::EndpointDominanceUndecidable(format!(
            "invalid endpoint precedence graph: {error}"
        ))
    })
}

fn event_precedence_graph(
    policy: &LoadedPolicy,
    spec: &ResolvedTypestatePolicySpec,
) -> Result<PrecedenceGraph<PolicyTypestateEventId>, TypestatePolicyCompileError> {
    PrecedenceGraph::try_new(
        spec.automaton.events.iter().map(|event| event.id.clone()),
        policy
            .precedence_manifest()
            .edges
            .iter()
            .filter_map(|edge| match edge {
                ResolvedPrecedenceEdge::TypestateEvent {
                    dominant,
                    dominated,
                } => Some((dominant.clone(), dominated.clone())),
                _ => None,
            }),
    )
    .map_err(|error| {
        TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
            "invalid typestate-event precedence graph: {error}"
        ))
    })
}

fn expectation_precedence_graph(
    policy: &LoadedPolicy,
    spec: &ResolvedTypestatePolicySpec,
) -> Result<PrecedenceGraph<PolicyTypestateExpectationId>, TypestatePolicyCompileError> {
    PrecedenceGraph::try_new(
        spec.automaton
            .terminal_expectations
            .iter()
            .map(|expectation| expectation.id.clone()),
        policy
            .precedence_manifest()
            .edges
            .iter()
            .filter_map(|edge| match edge {
                ResolvedPrecedenceEdge::TypestateExpectation {
                    dominant,
                    dominated,
                } => Some((dominant.clone(), dominated.clone())),
                _ => None,
            }),
    )
    .map_err(|error| {
        TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
            "invalid typestate-expectation precedence graph: {error}"
        ))
    })
}

fn endpoint_winner_index(
    endpoints: &[Option<ResolvedEndpointIdentity>],
    precedence: &PrecedenceGraph<ResolvedEndpointIdentity>,
) -> Result<usize, TypestatePolicyCompileError> {
    let candidates = endpoints.iter().flatten().cloned().collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(0);
    }
    if candidates.len() != endpoints.len() {
        return Err(TypestatePolicyCompileError::EndpointDominanceUndecidable(
            "one typestate observation mixes endpoint and non-endpoint meanings".to_owned(),
        ));
    }
    let winner = precedence
        .unique_winner(candidates)
        .map_err(|error| {
            TypestatePolicyCompileError::EndpointDominanceUndecidable(format!(
                "same-site endpoint precedence is undecidable: {error}"
            ))
        })?
        .ok_or_else(|| {
            TypestatePolicyCompileError::EndpointDominanceUndecidable(
                "same-site endpoint candidate set is empty".to_owned(),
            )
        })?;
    endpoints
        .iter()
        .position(|candidate| candidate.as_ref() == Some(&winner))
        .ok_or_else(|| {
            TypestatePolicyCompileError::SemanticUnavailable(
                "endpoint precedence winner is absent from its candidate group".to_owned(),
            )
        })
}

fn reduce_event_bindings(
    candidates: Vec<PendingEventBinding>,
    endpoint_precedence: &PrecedenceGraph<ResolvedEndpointIdentity>,
    event_precedence: &PrecedenceGraph<PolicyTypestateEventId>,
) -> Result<Vec<PendingEventBinding>, TypestatePolicyCompileError> {
    let mut groups = HashMap::<EventObservationGroupKey, Vec<PendingEventBinding>>::new();
    for candidate in candidates {
        groups
            .entry(EventObservationGroupKey {
                subject: candidate.subject.clone(),
                site: candidate.site.clone(),
                phase: candidate.phase,
            })
            .or_default()
            .push(candidate);
    }
    let mut reduced = Vec::new();
    for group in groups.into_values() {
        let mut by_event = HashMap::<PolicyTypestateEventId, Vec<PendingEventBinding>>::new();
        for candidate in group {
            by_event
                .entry(candidate.policy_event.clone())
                .or_default()
                .push(candidate);
        }
        let mut event_candidates = Vec::with_capacity(by_event.len());
        for mut candidates in by_event.into_values() {
            let endpoints = candidates
                .iter()
                .map(|candidate| candidate.endpoint.clone())
                .collect::<Vec<_>>();
            let winner = endpoint_winner_index(&endpoints, endpoint_precedence)?;
            event_candidates.push(candidates.swap_remove(winner));
        }
        let winner = event_precedence
            .unique_winner(
                event_candidates
                    .iter()
                    .map(|candidate| candidate.policy_event.clone()),
            )
            .map_err(|error| {
                TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                    "same-site typestate event precedence is undecidable: {error}"
                ))
            })?
            .ok_or_else(|| {
                TypestatePolicyCompileError::SemanticUnavailable(
                    "same-site typestate event candidate set is empty".to_owned(),
                )
            })?;
        reduced.push(
            event_candidates
                .into_iter()
                .find(|candidate| candidate.policy_event == winner)
                .expect("precedence winner belongs to the reduced event candidates"),
        );
    }
    Ok(reduced)
}

fn reduce_terminal_bindings(
    candidates: Vec<PendingTerminalBinding>,
    endpoint_precedence: &PrecedenceGraph<ResolvedEndpointIdentity>,
    expectation_precedence: &PrecedenceGraph<PolicyTypestateExpectationId>,
) -> Result<Vec<PendingTerminalBinding>, TypestatePolicyCompileError> {
    let mut groups = HashMap::<TerminalObservationGroupKey, Vec<PendingTerminalBinding>>::new();
    for candidate in candidates {
        groups
            .entry(TerminalObservationGroupKey {
                subject: candidate.subject.clone(),
                site: candidate.site.clone(),
                phase: candidate.phase,
            })
            .or_default()
            .push(candidate);
    }
    let mut reduced = Vec::new();
    for group in groups.into_values() {
        let mut by_expectation =
            HashMap::<PolicyTypestateExpectationId, Vec<PendingTerminalBinding>>::new();
        for candidate in group {
            by_expectation
                .entry(candidate.policy_expectation.clone())
                .or_default()
                .push(candidate);
        }
        let mut expectation_candidates = Vec::with_capacity(by_expectation.len());
        for mut candidates in by_expectation.into_values() {
            let endpoints = candidates
                .iter()
                .map(|candidate| candidate.endpoint.clone())
                .collect::<Vec<_>>();
            let winner = endpoint_winner_index(&endpoints, endpoint_precedence)?;
            expectation_candidates.push(candidates.swap_remove(winner));
        }
        let winner = expectation_precedence
            .unique_winner(
                expectation_candidates
                    .iter()
                    .map(|candidate| candidate.policy_expectation.clone()),
            )
            .map_err(|error| {
                TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                    "same-site typestate expectation precedence is undecidable: {error}"
                ))
            })?
            .ok_or_else(|| {
                TypestatePolicyCompileError::SemanticUnavailable(
                    "same-site typestate expectation candidate set is empty".to_owned(),
                )
            })?;
        reduced.push(
            expectation_candidates
                .into_iter()
                .find(|candidate| candidate.policy_expectation == winner)
                .expect("precedence winner belongs to the reduced expectation candidates"),
        );
    }
    Ok(reduced)
}

struct ResolvedObject {
    object: AbstractObject,
    quality: TypestateBindingQuality,
}

struct ResolvedSelection {
    procedure: ProcedureHandle,
    call: Option<CallSiteHandle>,
    observation_point: ProgramPointHandle,
    role: TypestateObjectRole,
    objects: Vec<ResolvedObject>,
}

fn selector<'a>(
    selectors: &HashMap<&PolicySelectorPath, &'a ResolvedPolicySelector>,
    path: &PolicySelectorPath,
) -> Result<&'a ResolvedPolicySelector, TypestatePolicyCompileError> {
    selectors
        .get(path)
        .copied()
        .ok_or_else(|| TypestatePolicyCompileError::MissingSelector(path.as_str().to_owned()))
}

fn select_call(
    procedures: &[ProcedureHandle],
    selection: &SelectedSite,
) -> Result<(ProcedureHandle, CallSiteHandle), TypestatePolicyCompileError> {
    let mut candidates = Vec::new();
    for procedure in procedures {
        for call in procedure.semantics().call_sites() {
            let mapping = procedure
                .semantics()
                .source_mapping(call.source)
                .expect("validated semantic call has a source mapping");
            let span = mapping.locator.anchor().span();
            let call_range = span.start_byte() as usize..span.end_byte() as usize;
            let exact = call_range == selection.span;
            let enclosing =
                call_range.start <= selection.span.start && call_range.end >= selection.span.end;
            if exact || (!selection.require_exact_call && enclosing) {
                let handle = procedure
                    .call_site_handle(call.id)
                    .expect("validated semantic call has a scoped handle");
                candidates.push((!exact, call_range.len(), procedure.clone(), handle));
            }
        }
    }
    candidates.sort_by(|left, right| {
        (left.0, left.1, left.2.semantics().locator()).cmp(&(
            right.0,
            right.1,
            right.2.semantics().locator(),
        ))
    });
    let Some(best) = candidates.first() else {
        return Err(TypestatePolicyCompileError::SemanticUnavailable(
            "selected source row does not identify a semantic call site".to_owned(),
        ));
    };
    if candidates
        .get(1)
        .is_some_and(|next| (next.0, next.1) == (best.0, best.1))
    {
        return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(
            "selected source row identifies multiple equal semantic call sites".to_owned(),
        ));
    }
    Ok((best.2.clone(), best.3.clone()))
}

fn select_value(
    procedure: &ProcedureHandle,
    call_handle: &CallSiteHandle,
    selected_span: &ByteRange<usize>,
    binding: &SelectorBinding,
    phase: Option<EndpointObservationPhase>,
) -> Result<(ValueHandle, ProgramPointHandle, TypestateObjectRole), TypestatePolicyCompileError> {
    let call = procedure
        .semantics()
        .call_site(call_handle.id())
        .expect("validated call handle resolves");
    let (value_id, role) = match binding {
        SelectorBinding::MatchedValue => {
            let matching = procedure
                .semantics()
                .values()
                .iter()
                .filter(|value| {
                    let mapping = procedure
                        .semantics()
                        .source_mapping(value.source)
                        .expect("validated semantic value has a source mapping");
                    let span = mapping.locator.anchor().span();
                    span.start_byte() as usize == selected_span.start
                        && span.end_byte() as usize == selected_span.end
                })
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(
                    "matched-value binding does not identify exactly one semantic value".to_owned(),
                ));
            }
            (matching[0].id, TypestateObjectRole::MatchedValue)
        }
        SelectorBinding::Receiver => (
            call.receiver.ok_or_else(|| {
                TypestatePolicyCompileError::SemanticUnavailable(
                    "receiver binding selected a call without a receiver".to_owned(),
                )
            })?,
            TypestateObjectRole::Receiver,
        ),
        SelectorBinding::ReturnValue => (
            call.result.ok_or_else(|| {
                TypestatePolicyCompileError::SemanticUnavailable(
                    "return-value binding selected a call without a normal result".to_owned(),
                )
            })?,
            TypestateObjectRole::NormalReturn,
        ),
        SelectorBinding::ArgumentIndex(index) => (
            call.arguments
                .get(usize::try_from(*index).map_err(|_| {
                    TypestatePolicyCompileError::UnsupportedBinding(
                        "argument index does not fit this platform".to_owned(),
                    )
                })?)
                .ok_or_else(|| {
                    TypestatePolicyCompileError::SemanticUnavailable(format!(
                        "selected call has no argument at index {index}"
                    ))
                })?
                .value,
            TypestateObjectRole::Argument,
        ),
        SelectorBinding::ArgumentName(_) => unreachable!("formal-name bindings resolve first"),
    };
    let point_id = match phase {
        Some(EndpointObservationPhase::AfterNormalReturn) | None
            if matches!(binding, &SelectorBinding::ReturnValue) =>
        {
            call.normal_continuation.target()
        }
        Some(EndpointObservationPhase::AfterNormalReturn) => call.normal_continuation.target(),
        Some(EndpointObservationPhase::AfterExceptionalReturn) => {
            call.exceptional_continuation.target()
        }
        Some(EndpointObservationPhase::AtMatch | EndpointObservationPhase::BeforeCall) | None => {
            Some(call.point)
        }
    }
    .ok_or_else(|| {
        TypestatePolicyCompileError::SemanticUnavailable(
            "selected call has no requested observation continuation".to_owned(),
        )
    })?;
    let value = procedure
        .value_handle(value_id)
        .expect("validated call value has a scoped handle");
    let point = procedure
        .point_handle(point_id)
        .expect("validated call point has a scoped handle");
    Ok((value, point, role))
}

fn oracle_observation_phase(phase: Option<EndpointObservationPhase>) -> ObservationPhase {
    match phase {
        Some(EndpointObservationPhase::BeforeCall) => ObservationPhase::BeforeEffects,
        Some(
            EndpointObservationPhase::AtMatch
            | EndpointObservationPhase::AfterNormalReturn
            | EndpointObservationPhase::AfterExceptionalReturn,
        )
        | None => ObservationPhase::AfterEffects,
    }
}

fn event_site(
    selection: &ResolvedSelection,
    phase: EndpointObservationPhase,
) -> Result<(TypestateObservationSite, TypestateObjectRole), TypestatePolicyCompileError> {
    if phase == EndpointObservationPhase::AtMatch {
        Ok((
            TypestateObservationSite::program_point(
                selection.observation_point.clone(),
                TypestateBindingContext::root(),
            ),
            selection.role,
        ))
    } else {
        Ok((
            TypestateObservationSite::call_site(
                selection.call.clone().ok_or_else(|| {
                    TypestatePolicyCompileError::SemanticUnavailable(
                        "non-at-match observation does not identify a semantic call site"
                            .to_owned(),
                    )
                })?,
                TypestateBindingContext::root(),
            ),
            selection.role,
        ))
    }
}

/// Lower the closed authoring automaton into the internal protocol compiler.
///
/// This function is deliberately independent of selector execution. A policy
/// with no source matches still has one canonical protocol hash.
pub(crate) fn compile_protocol(
    spec: &ResolvedTypestatePolicySpec,
) -> Result<CompiledProtocol, TypestatePolicyCompileError> {
    let automaton = &spec.automaton;
    let protocol = ProtocolSpec {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        states: automaton
            .states
            .iter()
            .map(|state| state.as_str().to_owned())
            .collect(),
        initial_state: automaton.initial.as_str().to_owned(),
        accepting_states: automaton
            .accepting_states
            .iter()
            .map(|state| state.as_str().to_owned())
            .collect(),
        error_states: automaton
            .error_states
            .iter()
            .map(|state| state.as_str().to_owned())
            .collect(),
        events: automaton
            .events
            .iter()
            .map(|event| ProtocolEventSpec {
                id: event.id.as_str().to_owned(),
                observation: ProtocolObservationSpec {
                    occurrence: event_occurrence(&event.trigger),
                },
            })
            .collect(),
        transitions: automaton
            .transitions
            .iter()
            .map(|transition| ProtocolTransitionSpec {
                from: transition.from.as_str().to_owned(),
                on: transition.on.as_str().to_owned(),
                to: transition.to.as_str().to_owned(),
                guard: ProtocolGuardSpec::Always,
            })
            .collect(),
        terminal_expectations: automaton
            .terminal_expectations
            .iter()
            .map(|expectation| ProtocolTerminalExpectationSpec {
                id: expectation.id.as_str().to_owned(),
                on: terminal_observation(&expectation.trigger),
                expected_states: expectation
                    .expected_states
                    .iter()
                    .map(|state| state.as_str().to_owned())
                    .collect(),
            })
            .collect(),
        semantics: ProtocolSemantics {
            analysis_mode: match spec.mode {
                MayMode::May => ProtocolAnalysisMode::May,
            },
            // An authored event whose selected binding cannot be established
            // must not silently behave like a semantic no-op.
            unmatched_event: ProtocolUnmatchedEventBehavior::MarkInconclusive,
            uncertainty: ProtocolUncertaintySemantics {
                ambiguous_dispatch: ProtocolUncertaintyBehavior::PreserveUncertainty,
                unknown_call: ProtocolUncertaintyBehavior::PreserveUncertainty,
                external_call: ProtocolUncertaintyBehavior::PreserveUncertainty,
                escape: ProtocolUncertaintyBehavior::PreserveUncertainty,
                incomplete_analysis: ProtocolUncertaintyBehavior::PreserveUncertainty,
            }
            .with_unmodeled_call_behavior(spec.call_modeling.unmodeled),
        },
    };
    protocol
        .compile()
        .map_err(TypestatePolicyCompileError::Protocol)
}

fn event_occurrence(trigger: &ResolvedTypestateEventTrigger) -> ProtocolEventOccurrence {
    match trigger {
        ResolvedTypestateEventTrigger::Calls { phase, .. }
        | ResolvedTypestateEventTrigger::MatchEndpoints { phase, .. } => {
            ProtocolEventOccurrence::Endpoint {
                phase: protocol_observation_phase(*phase),
            }
        }
        ResolvedTypestateEventTrigger::SemanticEvent { event } => {
            ProtocolEventOccurrence::ProcedureExit {
                kind: procedure_exit_kind(*event),
            }
        }
    }
}

fn terminal_observation(
    trigger: &ResolvedTypestateTerminalTrigger,
) -> ProtocolTerminalObservationSpec {
    match trigger {
        ResolvedTypestateTerminalTrigger::MatchEndpoints { phase, .. } => {
            ProtocolTerminalObservationSpec::Event {
                observation: ProtocolObservationSpec {
                    occurrence: ProtocolEventOccurrence::Endpoint {
                        phase: protocol_observation_phase(*phase),
                    },
                },
            }
        }
        ResolvedTypestateTerminalTrigger::SemanticEvent { event } => {
            ProtocolTerminalObservationSpec::AnalysisRootExit {
                kind: procedure_exit_kind(*event),
            }
        }
    }
}

const fn protocol_observation_phase(phase: EndpointObservationPhase) -> ProtocolObservationPhase {
    match phase {
        EndpointObservationPhase::AtMatch => ProtocolObservationPhase::AtMatch,
        EndpointObservationPhase::BeforeCall => ProtocolObservationPhase::BeforeCall,
        EndpointObservationPhase::AfterNormalReturn => ProtocolObservationPhase::AfterNormalReturn,
        EndpointObservationPhase::AfterExceptionalReturn => {
            ProtocolObservationPhase::AfterExceptionalReturn
        }
    }
}

const fn procedure_exit_kind(event: PolicySemanticEvent) -> ProtocolProcedureExitKind {
    match event {
        PolicySemanticEvent::NormalProcedureExit { .. } => ProtocolProcedureExitKind::Normal,
        PolicySemanticEvent::ExceptionalProcedureExit { .. } => {
            ProtocolProcedureExitKind::Exceptional
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::dataflow::UnmodeledCallBehavior;
    use crate::analyzer::policy::definition::{
        CallModelingSpec, InconclusivePolicy, TypestateUncertaintySpec,
    };
    use crate::analyzer::policy::resolved::ResolvedTypestateAutomatonSpec;

    fn minimal_resolved_spec(behavior: UnmodeledCallBehavior) -> ResolvedTypestatePolicySpec {
        let open = PolicyTypestateStateId::new("open").unwrap();
        ResolvedTypestatePolicySpec::try_new(
            MayMode::May,
            CallModelingSpec {
                unmodeled: behavior,
            },
            Vec::new(),
            TypestateUncertaintySpec {
                escape: InconclusivePolicy::Inconclusive,
            },
            ResolvedTypestateAutomatonSpec {
                states: vec![open.clone()],
                initial: open.clone(),
                accepting_states: vec![open],
                error_states: Vec::new(),
                events: Vec::new(),
                transitions: Vec::new(),
                terminal_expectations: Vec::new(),
            },
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn public_call_modeling_modes_compile_to_protocol_uncertainty() {
        for (profile, expected) in [
            (
                UnmodeledCallBehavior::Paranoid,
                ProtocolUncertaintyBehavior::ConservativeTransition,
            ),
            (
                UnmodeledCallBehavior::Optimistic,
                ProtocolUncertaintyBehavior::PreserveUncertainty,
            ),
            (
                UnmodeledCallBehavior::RequireModel,
                ProtocolUncertaintyBehavior::Abstain,
            ),
        ] {
            let protocol = compile_protocol(&minimal_resolved_spec(profile)).unwrap();
            let uncertainty = protocol.semantics().uncertainty;
            assert_eq!(uncertainty.unknown_call, expected);
            assert_eq!(uncertainty.external_call, expected);
            assert_eq!(
                uncertainty.escape,
                ProtocolUncertaintyBehavior::PreserveUncertainty
            );
        }
    }

    #[test]
    fn semantic_interruption_is_not_flattened_into_partial_data() {
        let cancelled = SemanticOutcome::<()>::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        };
        assert!(matches!(
            require_uninterrupted_semantic_outcome(&cancelled, "test operation"),
            Err(TypestatePolicyCompileError::QueryIncomplete {
                completion: CodeQueryCompletion::Cancelled,
                ..
            })
        ));

        let budget = SemanticBudget::uniform(1).expect("positive test budget");
        let exceeded = budget
            .check(SemanticWork {
                source_bytes: 2,
                ..SemanticWork::default()
            })
            .expect_err("source-byte charge exceeds the test budget");
        let exhausted = SemanticOutcome::<()>::ExceededBudget {
            partial: None,
            exceeded,
            work: SemanticWork::default(),
        };
        assert!(matches!(
            require_uninterrupted_semantic_outcome(&exhausted, "test operation"),
            Err(TypestatePolicyCompileError::QueryIncomplete {
                completion: CodeQueryCompletion::Incomplete { codes },
                ..
            }) if codes == vec![CodeQueryDiagnosticCode::SemanticBudgetExhausted]
        ));
    }
}
