//! Production lowering and execution for resolved typestate policies.
//!
//! Policy loading owns authoring/composition semantics; this module starts at
//! the closed [`ResolvedTypestatePolicySpec`] boundary and lowers only typed,
//! source-backed values into the diagnostic-neutral typestate engine.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::Range as ByteRange;
use std::sync::Arc;

use crate::budget::PolicyBudget;
use crate::composition::PrecedenceGraph;
use crate::definition::{
    EndpointObservationPhase, MayMode, PolicyEndpointBinding, PolicyReportOptions,
    PolicySelectorPath, PolicySemanticEvent, TypestateCallBinding,
    TypestateEventId as PolicyTypestateEventId,
    TypestateExpectationId as PolicyTypestateExpectationId,
    TypestateStateId as PolicyTypestateStateId,
};
use crate::evaluator::{
    PolicyEvaluationContext, TypestateCompilationFailure, TypestatePolicyEvaluator,
};
use crate::finding::{
    BoundedWitness, CertaintyReason, FindingCertainty, FindingCompleteness,
    FindingIncompleteReason, PolicyDiagnostic, PolicyDiagnosticCode, PolicyDiagnosticImpact,
    PolicyDiagnosticSeverity, PolicyFailureReason, PolicyIncompleteReason,
    PolicyLocationRelationship, PolicyRunCompletion, PolicyWorkMetric, PolicyWorkReport,
    PolicyWorkUnit, ProofMetadata, ProofReason, ProofState, RelatedPolicyLocation, WitnessStepKind,
};
use crate::finding_identity::{
    AnalysisFindingId, AnalysisSubjectRef, StableSemanticIdentity, TypestateScenarioId, WitnessId,
};
use crate::future_evidence::{
    ResolvedTypestateTerminal, TypestateFindingAnchor, TypestatePolicyProjectionFacts,
    TypestateViolationEvidence,
};
use crate::projection::{
    ProjectedFindingReport, TypestateCompilationHashes, TypestateProjectedFinding,
    TypestateProjectionAuthority, TypestateProjectionPayload,
};
use crate::resolved::{
    LoadedPolicy, ResolvedEndpointIdentity, ResolvedPolicySelector, ResolvedPrecedenceEdge,
    ResolvedTypestateBinding, ResolvedTypestateEventTrigger, ResolvedTypestatePolicySpec,
    ResolvedTypestateTerminalTrigger,
};
use crate::selector_compiler::{
    PolicySemanticPeaks, ReceiverBindingApplicability, parameter_names_match,
};
use crate::unit_execution::{UnitAttempt, UnitReuse};
use crate::units::{
    PolicyIncrementalContext, PolicyUnitKey, PolicyUnitProduct, RootProduct, RootWork,
    UnitPartition, WidenReason,
};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots;
use brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger;
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    ProcedureRangeLookupStatus, procedures_in_artifact,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    AbstractObject, AccessPath, AccessPathAtPoint, AccessPathRoot, AliasQuery, AliasRelation,
    CallBinding, CallInvocationMode, CallSiteHandle, CallSiteId, CallTransferSet,
    CandidateCoverage, DispatchOracle, DispatchResult, EvidenceCompleteness,
    FreshObjectPublicationKind, FreshObjectPublicationQuery, HeapOracle, IcfgExitProfile,
    IcfgProvider, IcfgProviderBehaviorIdentity, IcfgSnapshot, IcfgSnapshotLimits, ObservationPhase,
    OracleCallContext, OracleLimits, ProcedureHandle, ProcedurePortHandle, ProcedurePortKind,
    ProgramPointHandle, ProofStatus, SemanticArtifact, SemanticArtifactCollector,
    SemanticArtifactLeaseError, SemanticBudget, SemanticBudgetDimension,
    SemanticBudgetScopeSnapshot, SemanticExecutionBudget, SemanticExecutionWork, SemanticLocator,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticWork, ValueAtPoint,
    ValueFlowOracle, ValueHandle, WorkspaceIcfgProvider,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, CompiledDeclaredEffectCertainty, CompiledDeclaredEffectTiming,
    Completeness,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;
use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, ProjectFile, Range, WorkspaceAnalyzer};
use brokk_bifrost_analysis::path_utils::rel_path_string;
use brokk_bifrost_flow::dataflow::{
    DataflowRequest, SolverBudget, SolverTermination, SummaryReadRecorder, SummaryWitnessStepKind,
    WitnessReconstructionLimits,
};
use brokk_bifrost_flow::typestate::{
    BoundTypestateSubjectSpec, CompiledProtocol, PROTOCOL_SCHEMA_VERSION,
    ProductionSummaryLifecycleCounters, ProductionTypestateExecutionContext,
    ProductionTypestateSummaryRepository, ProtocolAnalysisMode, ProtocolEventKey,
    ProtocolEventOccurrence, ProtocolEventSpec, ProtocolExpectationKey, ProtocolGuardSpec,
    ProtocolObservationPhase, ProtocolObservationSpec, ProtocolProcedureExitKind,
    ProtocolSemantics, ProtocolSpec, ProtocolStateKey, ProtocolTerminalExpectationSpec,
    ProtocolTerminalObservationSpec, ProtocolTransitionSpec, ProtocolUncertaintyBehavior,
    ProtocolUncertaintySemantics, ProtocolUnmatchedEventBehavior, TypestateBindingContext,
    TypestateBindingMultiplicity, TypestateBindingPlan, TypestateBindingQuality,
    TypestateCallNonInterferenceSpec, TypestateEventBindingId, TypestateEventBindingSpec,
    TypestateFinding, TypestateFindingCertainty, TypestateFindingKind, TypestateFindingLimits,
    TypestateFlowProblemError, TypestateInitialSeedSpec, TypestateObjectKey, TypestateObjectRole,
    TypestateObservationSite, TypestateProductionCacheStatus, TypestateSubjectClassKey,
    TypestateSubjectKey, TypestateTerminalBindingId, TypestateTerminalBindingSpec,
    TypestateUncertainty, collect_summary_findings_with_limits,
    solve_typestate_with_production_summaries,
};
use brokk_bifrost_rql::structural::search::CodeQueryExecutionScope;
use brokk_bifrost_rql::structural::{
    CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, CodeQueryExecutionWork,
};

const INTERNAL_ESCAPE_EVENT_KEY: &str = "bifrost-internal-escape";

fn internal_escape_event_key<'a>(
    authored_event_ids: impl IntoIterator<Item = &'a str>,
) -> ProtocolEventKey {
    let authored_event_ids = authored_event_ids.into_iter().collect::<HashSet<_>>();
    for suffix in 0..=authored_event_ids.len() {
        let candidate = if suffix == 0 {
            INTERNAL_ESCAPE_EVENT_KEY.to_owned()
        } else {
            format!("{INTERNAL_ESCAPE_EVENT_KEY}-{suffix}")
        };
        if !authored_event_ids.contains(candidate.as_str()) {
            return ProtocolEventKey::new(candidate)
                .expect("bounded internal escape event key is valid");
        }
    }
    unreachable!("one more internal event key exists than authored collisions")
}

#[derive(Debug)]
pub(crate) enum TypestatePolicyCompileError {
    Protocol(brokk_bifrost_flow::typestate::ProtocolCompileError),
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
    BindingPlan(brokk_bifrost_flow::typestate::TypestateBindingPlanError),
    /// The sliced selector compile cannot claim to have produced what a whole
    /// compile would have produced. Not a compilation failure: the caller
    /// compiles the policy again with no units and reports the reason beside
    /// the run.
    Widen(WidenReason),
}

pub(crate) struct TypestatePolicyCompileFailure {
    error: TypestatePolicyCompileError,
    work: PolicyWorkReport,
}

impl TypestatePolicyCompileFailure {
    /// The reason a sliced compile asked to be compiled again, when that is
    /// what this failure is.
    pub(crate) const fn widen(&self) -> Option<WidenReason> {
        match self.error {
            TypestatePolicyCompileError::Widen(reason) => Some(reason),
            _ => None,
        }
    }
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
            Self::Widen(reason) => write!(
                formatter,
                "the sliced typestate compile widened: {}",
                reason.stable_label()
            ),
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
            | Self::UnsupportedBinding(_)
            | Self::Widen(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledTypestateSubject {
    pub(crate) key: TypestateSubjectKey,
    pub(crate) endpoint: ResolvedEndpointIdentity,
    pub(crate) root: ProcedureHandle,
    /// The abstract object the key projects, retained so an observation whose
    /// own object set does not name this subject can still be related to it
    /// through the heap oracle's alias relation.
    object: AbstractObject,
    member_contracts:
        Vec<brokk_bifrost_analysis::analyzer::semantic_model::CompiledResultMemberContract>,
    fresh_result: bool,
    /// Normal-return observations where the fresh result first exists. These
    /// deliberately precede any success guard that activates the typestate
    /// subject: a store or call between acquisition and validation can still
    /// publish the eventual live resource.
    publication_starts: Vec<ProgramPointHandle>,
    /// Activation sources where publication was proven before the subject's
    /// success-conditioned activation edge.
    escape_starts: Vec<ProgramPointHandle>,
}

struct CompiledCallNonInterference {
    specs: Vec<TypestateCallNonInterferenceSpec>,
    proven_pairs: HashSet<(TypestateSubjectKey, CallSiteHandle)>,
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
    semantic_compile_peaks: PolicySemanticPeaks,
    semantic_remaining: SemanticWork,
    semantic_scope: SemanticBudgetScopeSnapshot,
    semantic_execution_budget: SemanticExecutionBudget,
    selector_scans: u64,
    artifact_leases: super::selector_compiler::PolicyArtifactLeases,
    result_contract_artifact_leases: usize,
    binding_omissions: Box<[String]>,
    binding_omission_subjects: HashSet<TypestateSubjectKey>,
}

struct TypestateEvaluationFailure {
    message: String,
    work: PolicyWorkReport,
}

struct TypestateWorkMeasurements {
    cache_work: ProductionSummaryLifecycleCounters,
    semantic_evaluation_work: SemanticWork,
    semantic_peaks: PolicySemanticPeaks,
    final_execution_work: SemanticExecutionWork,
    evaluation_materialized_files: usize,
    evaluation_traversal_steps: usize,
    semantic_artifact_leases: usize,
    evaluation_semantic_artifact_leases: usize,
    reached_rows: u64,
    subject_rows: u64,
    terminal_rows: u64,
    retained_analysis_findings: u64,
    omitted_analysis_findings: u64,
    retained_findings: u64,
}

pub(crate) struct TypestatePolicyCompiler<'a> {
    selectors: super::selector_compiler::PolicySelectorSession<'a>,
    syntax_trees: HashMap<ProjectFile, tree_sitter::Tree>,
    formal_names: HashMap<FormalPortKey, Box<[String]>>,
    binding_omissions: Vec<String>,
    binding_omission_procedures: HashSet<SemanticLocator>,
}

/// Allocation-independent identity for a cached formal-parameter layout.
///
/// `ProcedurePortHandle` owns the exact semantic artifact that supplied it.
/// Formal-name resolution is scalar, so caching that handle after its bounded
/// lease window closes would retain an uncharged artifact. The procedure
/// locator includes the workspace mount and the port kind includes the formal
/// ordinal, which is the complete durable identity this cache needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FormalPortKey {
    procedure: SemanticLocator,
    kind: ProcedurePortKind,
}

impl FormalPortKey {
    fn of(formal: &ProcedurePortHandle) -> Self {
        Self {
            procedure: formal.procedure().semantics().locator().clone(),
            kind: formal.kind(),
        }
    }
}

struct PolicyIcfgProvider<'a> {
    inner: WorkspaceIcfgProvider<'a>,
    execution_budget: SemanticExecutionBudget,
    artifact_collector: SemanticArtifactCollector,
}

impl<'a> PolicyIcfgProvider<'a> {
    fn new(
        workspace: &'a WorkspaceAnalyzer,
        execution_budget: &SemanticExecutionBudget,
        artifact_collector: SemanticArtifactCollector,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        Self {
            inner: WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
                workspace,
                active_semantic_model_snapshot,
            ),
            execution_budget: execution_budget.clone(),
            artifact_collector,
        }
    }
}

impl DispatchOracle for PolicyIcfgProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        let mut request = request
            .staged_with_execution_budget(&self.execution_budget)
            .with_artifact_collector(&self.artifact_collector);
        self.inner.resolve_call(call, &mut request)
    }
}

impl IcfgProvider for PolicyIcfgProvider<'_> {
    fn behavior_identity(&self) -> IcfgProviderBehaviorIdentity {
        self.inner.behavior_identity()
    }

    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        let mut request = request
            .staged_with_execution_budget(&self.execution_budget)
            .with_artifact_collector(&self.artifact_collector);
        self.inner.call_transfers(caller, call, &mut request)
    }

    fn snapshot(
        &self,
        root: &ProcedureHandle,
        limits: IcfgSnapshotLimits,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError> {
        let mut request = request
            .staged_with_execution_budget(&self.execution_budget)
            .with_artifact_collector(&self.artifact_collector);
        self.inner.snapshot(root, limits, &mut request)
    }

    fn exit_profile(
        &self,
        callee_entry: &ProgramPointHandle,
        callee_exit: &ProgramPointHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
        let mut request = request
            .staged_with_execution_budget(&self.execution_budget)
            .with_artifact_collector(&self.artifact_collector);
        self.inner
            .exit_profile(callee_entry, callee_exit, &mut request)
    }
}

pub(crate) struct ProductionTypestatePolicyEvaluator {
    prepared: RefCell<Option<CompiledTypestatePolicy>>,
    /// What the selector half of this evaluation's sliced attempt did. The
    /// compile and the root solve are two halves of one attempt, so the counts
    /// are carried from the first to the second rather than reported twice.
    selector_units: RefCell<Option<super::selector_compiler::SelectorUnitOutcome>>,
    /// What the sliced attempt did, left here for the caller that records the
    /// reuse review. Compilation and evaluation are one transaction, and the
    /// selector compile and the root solve are two halves of the same attempt.
    attempt: RefCell<Option<(UnitAttempt, Option<WidenReason>)>>,
    /// Coordinator-captured activation shared with the other policy engines.
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
}

impl Default for ProductionTypestatePolicyEvaluator {
    fn default() -> Self {
        Self::with_active_semantic_model_snapshot(None)
    }
}

impl ProductionTypestatePolicyEvaluator {
    pub(crate) fn with_active_semantic_model_snapshot(
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        Self {
            prepared: RefCell::new(None),
            selector_units: RefCell::new(None),
            attempt: RefCell::new(None),
            active_semantic_model_snapshot,
        }
    }

    /// Compile one typestate policy over the workspace this evaluation holds.
    ///
    /// Shared by the compilation seam and by the widening path, which needs a
    /// second compile rather than a second pass: the solver, semantic and
    /// execution budgets a compile hands to the evaluation are shared handles
    /// that a partial sliced pass has already drawn on, and a whole evaluation
    /// run against those would see an allowance no whole evaluation ever has.
    fn compile(
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        workspace: &WorkspaceAnalyzer,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
    ) -> Result<CompiledTypestatePolicy, TypestateCompilationFailure> {
        Self::compile_with_units(policy, spec, workspace, context, budget, None)
            .0
            .map_err(|failure| compile_failure(*failure))
    }

    /// The compile, optionally sliced into per-seed selector units, and what
    /// those units did.
    fn compile_with_units(
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        workspace: &WorkspaceAnalyzer,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
        incremental: Option<&PolicyIncrementalContext<'_>>,
    ) -> (
        Result<CompiledTypestatePolicy, Box<TypestatePolicyCompileFailure>>,
        Option<super::selector_compiler::SelectorUnitOutcome>,
    ) {
        let uncancelled = CancellationToken::default();
        let cancellation = context.cancellation.unwrap_or(&uncancelled);
        let compiler = TypestatePolicyCompiler::new(
            workspace,
            budget.query_limits(),
            budget.max_selector_results(),
            cancellation,
        );
        match incremental {
            Some(incremental) => compiler
                .with_units(policy, incremental, budget)
                .compile_with_units(policy, spec),
            None => compiler.compile_with_units(policy, spec),
        }
    }
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
        let (compiled, units) = Self::compile_with_units(
            policy,
            spec,
            workspace,
            context,
            budget,
            context.incremental,
        );
        let (compiled, units) = match compiled {
            Ok(compiled) => (compiled, units),
            Err(failure) => {
                let Some(reason) = failure.widen() else {
                    return Err(compile_failure(*failure));
                };
                // The sliced compile cannot be merged into the compile a whole
                // run would have produced, so the answer is that compile. A
                // second compiler is built rather than a second pass, because
                // the first handed its selectors budget handles the partial
                // sliced compile has already drawn on.
                let mut units = units.unwrap_or_default();
                units.widen = Some(reason);
                let (recompiled, _) =
                    Self::compile_with_units(policy, spec, workspace, context, budget, None);
                (
                    recompiled.map_err(|failure| compile_failure(*failure))?,
                    Some(units),
                )
            }
        };
        let hashes =
            TypestateCompilationHashes::new(compiled.protocol.hash(), compiled.bindings.hash());
        self.prepared.replace(Some(compiled));
        self.selector_units.replace(units);
        Ok(hashes)
    }

    fn take_unit_attempt(&self) -> Option<(UnitAttempt, Option<WidenReason>)> {
        self.attempt.borrow_mut().take()
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
                compiled_typestate_work_report(&compiled),
            );
        };
        // The workspace owns one content-keyed summary repository, so a
        // procedure this evaluator solves is available to the MCP/search path
        // and the other way around. This evaluator used to construct its own
        // and lease a hardcoded generation, which shared nothing with anything.
        let summaries = context.flow_state.typestate_summaries();
        let selectors = self.selector_units.borrow_mut().take().unwrap_or_default();
        // An evaluation that holds an incremental context has root units to
        // reuse and a workspace to verify them against; one that does not
        // solves every root exactly as it always has.
        let Some(incremental) = context.incremental else {
            return self.whole_pass(
                authority, policy, spec, workspace, context, budget, &compiled, &summaries, None,
            );
        };
        // The selector compile and the root solve are two halves of one
        // attempt. A compile that widened has already been recompiled whole,
        // and its roots are the roots of a whole compile, so nothing about
        // them may be reused either.
        if let Some(reason) = selectors.widen {
            self.attempt
                .replace(Some((selectors.attempt, Some(reason))));
            return self.whole_pass(
                authority, policy, spec, workspace, context, budget, &compiled, &summaries, None,
            );
        }
        let mut units = RootUnits::new(
            policy,
            incremental,
            budget,
            workspace,
            selectors,
            TypestateCompilationHashes::new(compiled.protocol.hash(), compiled.bindings.hash()),
        );
        let sliced = evaluate_compiled_typestate(
            authority,
            policy,
            spec,
            workspace,
            context.cancellation,
            budget,
            &compiled,
            &summaries,
            self.active_semantic_model_snapshot.clone(),
            Some(&mut units),
        );
        let (keys, attempt) = units.into_parts();
        match sliced {
            RootsPass::Complete(payload) => {
                // Every root of this policy is published and merged, so this
                // list is what another run replays to reproduce the product
                // without solving anything. It is empty when any root was not
                // published, and an empty list names nothing.
                if !keys.is_empty() {
                    incremental.record_units(policy.definition().metadata.id.clone(), keys);
                }
                self.attempt.replace(Some((attempt, None)));
                payload
            }
            RootsPass::Failed(failure) => {
                self.attempt.replace(Some((attempt, None)));
                failed_projection_payload(&failure.message, failure.work)
            }
            RootsPass::Widen(reason) => {
                self.attempt.replace(Some((attempt, Some(reason))));
                let recompiled = match Self::compile(policy, spec, workspace, context, budget) {
                    Ok(recompiled) => recompiled,
                    Err(_) => {
                        return failed_projection_payload(
                            "a widened typestate policy could not be compiled a second time",
                            compiled_typestate_work_report(&compiled),
                        );
                    }
                };
                assert_eq!(
                    (recompiled.protocol.hash(), recompiled.bindings.hash()),
                    (compiled.protocol.hash(), compiled.bindings.hash()),
                    "two compiles of one policy over one workspace are the same compile, and the \
                     projection authority is sealed to the first one's hashes"
                );
                self.whole_pass(
                    authority,
                    policy,
                    spec,
                    workspace,
                    context,
                    budget,
                    &recompiled,
                    &summaries,
                    None,
                )
            }
        }
    }
}

impl ProductionTypestatePolicyEvaluator {
    /// Solve every root of `compiled`, reusing nothing.
    #[allow(clippy::too_many_arguments)]
    fn whole_pass(
        &self,
        authority: &TypestateProjectionAuthority,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        workspace: &WorkspaceAnalyzer,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
        compiled: &CompiledTypestatePolicy,
        summaries: &ProductionTypestateSummaryRepository,
        units: Option<&mut RootUnits<'_>>,
    ) -> TypestateProjectionPayload {
        match evaluate_compiled_typestate(
            authority,
            policy,
            spec,
            workspace,
            context.cancellation,
            budget,
            compiled,
            summaries,
            self.active_semantic_model_snapshot.clone(),
            units,
        ) {
            RootsPass::Complete(payload) => payload,
            RootsPass::Failed(failure) => failed_projection_payload(&failure.message, failure.work),
            RootsPass::Widen(_) => unreachable!(
                "a pass with no units has nothing to reuse and never asks to be widened"
            ),
        }
    }
}

fn typestate_work_metric(name: &'static str, unit: PolicyWorkUnit, value: u64) -> PolicyWorkMetric {
    PolicyWorkMetric::try_new(name, unit, value)
        .expect("the fixed typestate work-metric schema is valid")
}

fn typestate_work_report(
    compiled: &CompiledTypestatePolicy,
    measured: &TypestateWorkMeasurements,
) -> PolicyWorkReport {
    let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
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
            "typestate.semantic_artifact_leases",
            measured.semantic_artifact_leases,
        ),
        (
            "typestate.evaluation_semantic_artifact_leases",
            measured.evaluation_semantic_artifact_leases,
        ),
        (
            "typestate.semantic_materialized_files",
            measured.final_execution_work.materialized_files,
        ),
        (
            "typestate.semantic_result_contract_artifact_leases",
            compiled.result_contract_artifact_leases,
        ),
        (
            "typestate.call_noninterference_bindings",
            compiled.bindings.call_noninterference_bindings().len(),
        ),
        (
            "typestate.binding_omissions",
            compiled.binding_omissions.len(),
        ),
        (
            "typestate.terminal_bindings",
            compiled.bindings.terminal_bindings().len(),
        ),
    ]
    .into_iter()
    .map(|(name, value)| typestate_work_metric(name, PolicyWorkUnit::Count, count(value)))
    .chain([
        typestate_work_metric(
            "typestate.reached_rows",
            PolicyWorkUnit::Rows,
            measured.reached_rows,
        ),
        typestate_work_metric(
            "typestate.subject_rows",
            PolicyWorkUnit::Rows,
            measured.subject_rows,
        ),
        typestate_work_metric(
            "typestate.terminal_rows",
            PolicyWorkUnit::Rows,
            measured.terminal_rows,
        ),
        typestate_work_metric(
            "typestate.analysis_findings",
            PolicyWorkUnit::Count,
            measured.retained_analysis_findings,
        ),
        typestate_work_metric(
            "typestate.summary_hits",
            PolicyWorkUnit::Count,
            count(measured.cache_work.hits),
        ),
        typestate_work_metric(
            "typestate.summary_misses",
            PolicyWorkUnit::Count,
            count(measured.cache_work.misses),
        ),
        typestate_work_metric(
            "typestate.summary_rejections",
            PolicyWorkUnit::Count,
            count(measured.cache_work.rejections),
        ),
        typestate_work_metric(
            "typestate.summary_evictions",
            PolicyWorkUnit::Count,
            count(measured.cache_work.evictions),
        ),
        typestate_work_metric(
            "typestate.summary_recomputations",
            PolicyWorkUnit::Count,
            count(measured.cache_work.recomputations),
        ),
        typestate_work_metric(
            "typestate.semantic_traversal_steps",
            PolicyWorkUnit::Count,
            count(measured.final_execution_work.traversal_steps),
        ),
        typestate_work_metric(
            "typestate.selector_scans",
            PolicyWorkUnit::Count,
            compiled.selector_scans,
        ),
        typestate_work_metric(
            "typestate.semantic_peak_row_dimension",
            PolicyWorkUnit::Rows,
            count(measured.semantic_peaks.row_dimension),
        ),
        typestate_work_metric(
            "typestate.semantic_peak_retained_bytes",
            PolicyWorkUnit::Bytes,
            count(measured.semantic_peaks.retained_bytes),
        ),
        typestate_work_metric(
            "typestate.semantic_peak_traversal_steps",
            PolicyWorkUnit::Count,
            count(measured.semantic_peaks.traversal_steps),
        ),
        typestate_work_metric(
            "typestate.selector_semantic_materializations",
            PolicyWorkUnit::Count,
            compiled.query_work.semantic.materialization_attempts,
        ),
        typestate_work_metric(
            "typestate.selector_semantic_traversal_steps",
            PolicyWorkUnit::Count,
            compiled.query_work.semantic.traversal_steps,
        ),
        typestate_work_metric(
            "typestate.evaluation_semantic_materialized_files",
            PolicyWorkUnit::Count,
            count(measured.evaluation_materialized_files),
        ),
        typestate_work_metric(
            "typestate.evaluation_semantic_traversal_steps",
            PolicyWorkUnit::Count,
            count(measured.evaluation_traversal_steps),
        ),
        // Physical source preparation charged during evaluation. A revived
        // leased artifact reuses its rows, but may or may not re-read its
        // source depending on cache residency, so this metric is bounded
        // rather than exact across an eviction (#2877).
        typestate_work_metric(
            "typestate.evaluation_semantic_source_bytes",
            PolicyWorkUnit::Bytes,
            count(measured.semantic_evaluation_work.source_bytes),
        ),
        typestate_work_metric(
            "typestate.evaluation_semantic_procedures",
            PolicyWorkUnit::Rows,
            count(measured.semantic_evaluation_work.procedures),
        ),
        typestate_work_metric(
            "typestate.evaluation_semantic_program_points",
            PolicyWorkUnit::Rows,
            count(measured.semantic_evaluation_work.program_points),
        ),
        typestate_work_metric(
            "typestate.evaluation_semantic_control_edges",
            PolicyWorkUnit::Rows,
            count(measured.semantic_evaluation_work.control_edges),
        ),
        // Physical materialization work charged during evaluation, not a
        // retained-row census. A revived artifact's rows are reused, but a
        // repeat lowering charges the lowering's transient control-flow work,
        // which the retained nested-entry census does not represent. This
        // metric is therefore exact within one cache state and bounded by the
        // repeated physical materializations across states (#2926), the same
        // way `evaluation_semantic_source_bytes` above is.
        typestate_work_metric(
            "typestate.evaluation_semantic_nested_entries",
            PolicyWorkUnit::Rows,
            count(measured.semantic_evaluation_work.nested_entries),
        ),
        typestate_work_metric(
            "typestate.semantic_source_bytes",
            PolicyWorkUnit::Bytes,
            count(
                compiled
                    .semantic_compile_work
                    .source_bytes
                    .saturating_add(measured.semantic_evaluation_work.source_bytes),
            ),
        ),
        typestate_work_metric(
            "typestate.semantic_procedures",
            PolicyWorkUnit::Rows,
            count(
                compiled
                    .semantic_compile_work
                    .procedures
                    .saturating_add(measured.semantic_evaluation_work.procedures),
            ),
        ),
        typestate_work_metric(
            "typestate.semantic_program_points",
            PolicyWorkUnit::Rows,
            count(
                compiled
                    .semantic_compile_work
                    .program_points
                    .saturating_add(measured.semantic_evaluation_work.program_points),
            ),
        ),
        typestate_work_metric(
            "typestate.semantic_control_edges",
            PolicyWorkUnit::Rows,
            count(
                compiled
                    .semantic_compile_work
                    .control_edges
                    .saturating_add(measured.semantic_evaluation_work.control_edges),
            ),
        ),
    ])
    .collect();
    PolicyWorkReport::try_new(
        compiled.query_work.scanned_files,
        compiled.query_work.scanned_source_bytes,
        compiled
            .query_work
            .fact_nodes
            .saturating_add(measured.reached_rows),
        compiled
            .query_work
            .pipeline_rows
            .saturating_add(measured.reached_rows),
        compiled.query_work.examined_references,
        measured.retained_findings,
        measured.omitted_analysis_findings,
        0,
        metrics,
    )
    .expect("the fixed typestate work-report schema is valid")
}

fn compiled_typestate_work_report(compiled: &CompiledTypestatePolicy) -> PolicyWorkReport {
    let execution = compiled.semantic_execution_budget.work();
    typestate_work_report(
        compiled,
        &TypestateWorkMeasurements {
            cache_work: ProductionSummaryLifecycleCounters::default(),
            semantic_evaluation_work: SemanticWork::default(),
            semantic_peaks: compiled.semantic_compile_peaks,
            final_execution_work: execution,
            evaluation_materialized_files: 0,
            evaluation_traversal_steps: 0,
            semantic_artifact_leases: compiled.artifact_leases.len(),
            evaluation_semantic_artifact_leases: 0,
            reached_rows: 0,
            subject_rows: 0,
            terminal_rows: 0,
            retained_analysis_findings: 0,
            omitted_analysis_findings: 0,
            retained_findings: 0,
        },
    )
}

/// What one pass over a compiled policy's roots produced.
///
/// Three outcomes rather than a `Result`, because widening is neither success
/// nor failure: it is the statement that this pass cannot be merged into the
/// bytes a whole evaluation would have produced, and the caller answers it by
/// evaluating the policy in full.
enum RootsPass {
    Complete(TypestateProjectionPayload),
    Widen(WidenReason),
    Failed(TypestateEvaluationFailure),
}

/// The per-root units of one typestate evaluation.
///
/// One of these is built per evaluation that holds an incremental context. It
/// owns the shared reuse decision, the key of every root the compile produced,
/// and the count of what the attempt did with them.
struct RootUnits<'a> {
    reuse: UnitReuse<'a>,
    policy: &'a LoadedPolicy,
    incremental: &'a PolicyIncrementalContext<'a>,
    files_by_rel: HashMap<String, ProjectFile>,
    /// The keys of this evaluation's roots, in root order, so a root's own key
    /// is the one its index names.
    keys: Vec<PolicyUnitKey>,
    /// The keys the same evaluation's compile decided about, carried through
    /// so the run's unit list names both halves.
    selector_keys: Vec<PolicyUnitKey>,
    /// The compile whose roots these are, folded into every root's key: a
    /// root's projections are sealed to it, and the projection authority drops
    /// a projection minted under any other compile.
    compilation: StableDigest,
    attempt: UnitAttempt,
    /// Whether every root this attempt decided about is in the store, either
    /// because it was reused from there or because its solve was published to
    /// it. A run's unit list is what another run replays instead of evaluating
    /// the policy, so a list naming a root that was never published would name
    /// work no run did.
    all_published: bool,
}

impl<'a> RootUnits<'a> {
    /// `selectors` is what the same evaluation's compile did with its own
    /// units: the two halves share one attempt and one unit list, because a
    /// run replays a policy's compile and its solve together or not at all.
    fn new(
        policy: &'a LoadedPolicy,
        incremental: &'a PolicyIncrementalContext<'a>,
        budget: &'a PolicyBudget,
        workspace: &WorkspaceAnalyzer,
        selectors: super::selector_compiler::SelectorUnitOutcome,
        compilation: TypestateCompilationHashes,
    ) -> Self {
        let files_by_rel = workspace
            .analyzer()
            .analyzed_files()
            .into_iter()
            .map(|file| (rel_path_string(&file), file))
            .collect();
        Self {
            reuse: UnitReuse::new(policy, incremental, budget),
            policy,
            incremental,
            files_by_rel,
            keys: Vec::new(),
            selector_keys: selectors.keys,
            compilation: compilation.unit_digest(),
            attempt: selectors.attempt,
            all_published: selectors.all_published,
        }
    }

    /// Key every root the compile produced, and load them all in one batch.
    ///
    /// A root whose file the head does not analyze, or whose path resolves to
    /// no blob, has no content identity to key a unit by, which is missing
    /// evidence rather than evidence of sameness.
    fn enumerate(&mut self, roots: &[ProcedureHandle]) -> Result<(), WidenReason> {
        self.attempt.enumerated(roots.len());
        self.keys.reserve(roots.len());
        for root in roots {
            let locator = root.semantics().locator();
            let rel_path = locator.path().as_str().to_string();
            let Some(file) = self.files_by_rel.get(&rel_path) else {
                return Err(WidenReason::ReverseDependencyEvidenceMissing);
            };
            let language = language_for_file(file);
            let Some(blob) = self.incremental.changed().head_blob(language, &rel_path) else {
                return Err(WidenReason::ReverseDependencyEvidenceMissing);
            };
            self.keys.push(self.incremental.inputs().unit_key(
                self.policy,
                UnitPartition::Root {
                    language,
                    rel_path: rel_path.into_boxed_str(),
                    blob,
                    // The root's own mount-free semantic identity, which is
                    // also the scenario id every finding this root produces
                    // carries: one file declares many procedures, and each is
                    // solved separately.
                    locator: StableDigest::sha256(super::semantic_identity::semantic_root_key(
                        root,
                    )),
                    compilation: self.compilation,
                },
            ));
        }
        self.reuse.prefetch(&self.keys)
    }

    /// The published product for one root, when the head still reads what its
    /// solve read.
    fn published(&mut self, root_index: usize) -> Result<Option<RootProduct>, WidenReason> {
        let key = self.keys[root_index].clone();
        match self.reuse.published(&key)? {
            Some(product) => {
                self.attempt.reused();
                let Some(product) = product.into_root() else {
                    // One key names one product shape; anything else is a
                    // store that answered a different question.
                    return Err(WidenReason::ProductLoadFailed);
                };
                Ok(Some(product))
            }
            None => {
                self.attempt.recomputed();
                Ok(None)
            }
        }
    }

    /// The keys this attempt asked about and what it did with them, with the
    /// keys empty when any root is missing from the store.
    fn into_parts(mut self) -> (Vec<PolicyUnitKey>, UnitAttempt) {
        if self.all_published {
            self.selector_keys.append(&mut self.keys);
            (self.selector_keys, self.attempt)
        } else {
            (Vec::new(), self.attempt)
        }
    }

    /// Publish one solved root under the reads that produced it.
    ///
    /// A solve answered from the production result cache is not published: it
    /// returned before the ICFG provider and the summary funnel were touched,
    /// so its ledger names none of the inputs its result depends on and a unit
    /// published under it would verify against a head that changed everything
    /// it read.
    fn publish(
        &mut self,
        root_index: usize,
        product: RootProduct,
        ledger: &ReadLedger,
        cache_status: TypestateProductionCacheStatus,
    ) {
        if cache_status == TypestateProductionCacheStatus::Hit {
            self.all_published = false;
            let policy_id = &self.policy.definition().metadata.id;
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!(
                    "policy.units policy={policy_id} partition=root unpublished=result_cache_hit"
                )
            });
            return;
        }
        if !ledger.is_bounded() {
            self.all_published = false;
            self.attempt.unbounded();
            return;
        }
        self.reuse.publish(
            self.keys[root_index].clone(),
            PolicyUnitProduct::Root(product),
            ledger.keys(),
        );
    }
}

/// Append one root's product to the run's accumulators, exactly as the loop
/// appends the same values when it solves the root itself.
#[allow(clippy::too_many_arguments)]
fn merge_root_product(
    product: &RootProduct,
    projections: &mut Vec<TypestateProjectedFinding>,
    incomplete_reasons: &mut Vec<PolicyIncompleteReason>,
    reached_rows: &mut u64,
    subject_rows: &mut u64,
    terminal_rows: &mut u64,
    retained_analysis_findings: &mut u64,
    omitted_analysis_findings: &mut u64,
    remaining_finding_reached_rows: &mut usize,
    remaining_finding_candidates: &mut usize,
    remaining_finding_witness_expansions: &mut usize,
    remaining_finding_witness_bytes: &mut usize,
) {
    let work = product.work;
    let lane = |value: u64| usize::try_from(value).unwrap_or(usize::MAX);
    *reached_rows = reached_rows.saturating_add(work.reached_rows);
    *subject_rows = subject_rows.saturating_add(work.subject_rows);
    *terminal_rows = terminal_rows.saturating_add(work.terminal_rows);
    *retained_analysis_findings =
        retained_analysis_findings.saturating_add(work.retained_analysis_findings);
    *omitted_analysis_findings =
        omitted_analysis_findings.saturating_add(work.omitted_analysis_findings);
    // The request-wide finding budget is charged what this root's findings
    // cost, because the budget is shared: a later root that saw an allowance
    // no whole evaluation would have given it could report a finding the whole
    // evaluation omitted.
    *remaining_finding_reached_rows =
        remaining_finding_reached_rows.saturating_sub(lane(work.finding_reached_rows));
    *remaining_finding_candidates =
        remaining_finding_candidates.saturating_sub(lane(work.finding_candidates));
    *remaining_finding_witness_expansions =
        remaining_finding_witness_expansions.saturating_sub(lane(work.finding_witness_expansions));
    *remaining_finding_witness_bytes =
        remaining_finding_witness_bytes.saturating_sub(lane(work.finding_witness_bytes));
    incomplete_reasons.extend(product.incomplete_reasons.iter().copied());
    projections.extend(product.findings.iter().cloned());
}

/// Charge every shared ledger one reused root's own solve drew on.
///
/// `merge_root_product` charges the four request-wide finding lanes, which the
/// loop carries as remaining counters. These four are ledgers the solve itself
/// holds, so they are charged into the ledger: the solver budget a later root
/// solves under, the semantic budget it materializes under, the execution
/// budget's materialized files and traversal steps, and the artifact-lease
/// capacity its window opens against. A reused root therefore leaves each of
/// them exactly where its own solve left them, which is what makes the sliced
/// pass reach a lane at the same root the whole run reaches it at.
///
/// A charge that does not fit means the whole evaluation reaches that lane
/// here, so the caller evaluates the policy in full rather than reporting a
/// completion no whole run would have reported.
///
/// The semantic budget's paid-artifact identities are not replayed: they are
/// process-local digests a stored product never carried, so a later root may
/// pay a census this root already paid. That over-charges the semantic lane
/// and can only widen more often, never less.
fn charge_reused_root_lanes(
    work: &RootWork,
    solver_budget: &mut SolverBudget,
    semantic_budget: Option<&mut SemanticBudget>,
    execution_budget: &SemanticExecutionBudget,
    replayed_artifact_leases: &mut usize,
    replayed_artifact_lease_bytes: &mut usize,
) -> Result<(), WidenReason> {
    let lane = |value: u64| usize::try_from(value).unwrap_or(usize::MAX);
    if solver_budget.charge(work.solver).is_err() {
        return Err(WidenReason::MergedLimitReached);
    }
    let semantic_budget = semantic_budget.expect("a root to reuse is a root the compile produced");
    if semantic_budget.charge(work.semantic).is_err() {
        return Err(WidenReason::MergedLimitReached);
    }
    if !execution_budget
        .charge_external_query_work(lane(work.materialized_files), lane(work.traversal_steps))
    {
        return Err(WidenReason::MergedLimitReached);
    }
    *replayed_artifact_leases = replayed_artifact_leases.saturating_add(lane(work.artifact_leases));
    *replayed_artifact_lease_bytes =
        replayed_artifact_lease_bytes.saturating_add(lane(work.artifact_lease_bytes));
    Ok(())
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
    summaries: &ProductionTypestateSummaryRepository,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    mut units: Option<&mut RootUnits<'_>>,
) -> RootsPass {
    let mut cache_work = ProductionSummaryLifecycleCounters::default();
    let uncancelled = CancellationToken::default();
    let cancellation = cancellation.unwrap_or(&uncancelled);
    let limits = budget.query_limits().typestate;
    let mut solver_budget = SolverBudget::new(limits.solver_work);
    let mut semantic_budget = if compiled.roots.is_empty() {
        None
    } else {
        Some(SemanticBudget::new_child(
            compiled.semantic_remaining,
            &compiled.semantic_scope,
        ))
    };
    let evaluation_execution_budget = compiled.semantic_execution_budget.clone();
    let initial_evaluation_execution_work = evaluation_execution_budget.work();
    let mut evaluation_artifact_leases = compiled
        .artifact_leases
        .snapshot()
        .restrict_to(budget.query_limits().semantic.max_retained_bytes)
        .into_child();
    let mut evaluation_artifact_retained_peak = evaluation_artifact_leases.retained_bytes();
    // What reused roots took out of the shared artifact-lease capacity. The
    // allocations themselves cannot be reproduced -- they are process-local
    // artifacts a stored product never carried -- so they are replayed as
    // anonymous live bytes against the same capacity, exactly as the execution
    // budget replays a query's materializations as anonymous slots. A later
    // root therefore sees the headroom a whole evaluation would have left it.
    let mut replayed_artifact_leases = 0_usize;
    let mut replayed_artifact_lease_bytes = 0_usize;
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

    let mut evaluation_error = None;
    // A lane every root shares. Reusing a root consumes none of it, so a
    // sliced pass that reached one cannot claim to have produced what a whole
    // evaluation would have produced, and the caller evaluates the policy in
    // full instead (`.agents/plans/impact-sliced-diff-base.md`, Decision Log
    // (5b)).
    let mut shared_lane_reached = false;
    if let Some(units) = units.as_deref_mut()
        && let Err(reason) = units.enumerate(&compiled.roots)
    {
        return RootsPass::Widen(reason);
    }
    'roots: for (root_index, root) in compiled.roots.iter().enumerate() {
        let mut root_work = RootWork::default();
        let mut root_reasons = Vec::new();
        if let Some(units) = units.as_deref_mut() {
            // Exactly the check the solved path makes before it projects: a
            // run whose request-wide finding budget is spent stops here, and a
            // reused root must not be appended past a stop a whole evaluation
            // would have made.
            if remaining_finding_reached_rows == 0
                || remaining_finding_candidates == 0
                || remaining_finding_witness_expansions == 0
                || remaining_finding_witness_bytes == 0
            {
                shared_lane_reached = true;
                incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
                omitted_analysis_findings = omitted_analysis_findings.saturating_add(1);
                break;
            }
            match units.published(root_index) {
                Err(reason) => return RootsPass::Widen(reason),
                Ok(Some(product)) => {
                    // Every lane this root's own solve moved, moved again, so
                    // the sliced pass reaches each of them exactly where the
                    // whole run reaches it.
                    if let Err(reason) = charge_reused_root_lanes(
                        &product.work,
                        &mut solver_budget,
                        semantic_budget.as_mut(),
                        &evaluation_execution_budget,
                        &mut replayed_artifact_leases,
                        &mut replayed_artifact_lease_bytes,
                    ) {
                        return RootsPass::Widen(reason);
                    }
                    merge_root_product(
                        &product,
                        &mut projections,
                        &mut incomplete_reasons,
                        &mut reached_rows,
                        &mut subject_rows,
                        &mut terminal_rows,
                        &mut retained_analysis_findings,
                        &mut omitted_analysis_findings,
                        &mut remaining_finding_reached_rows,
                        &mut remaining_finding_candidates,
                        &mut remaining_finding_witness_expansions,
                        &mut remaining_finding_witness_bytes,
                    );
                    continue;
                }
                Ok(None) => {}
            }
        }
        // What this root's own solve takes out of the shared lanes, measured
        // here so the reuse path above can replay exactly it.
        let solver_before = solver_budget.used();
        let semantic_before = semantic_budget
            .as_ref()
            .map_or_else(SemanticWork::default, SemanticBudget::used);
        let execution_before = evaluation_execution_budget.work();
        let leases_before = evaluation_artifact_leases.len();
        let lease_bytes_before = evaluation_artifact_leases.retained_bytes();
        // Every read this root's solve makes, named, so another workspace can
        // be asked whether it still reads the same thing. The ledger is what
        // licenses publishing the product below; with no units it is absent
        // and the solve runs exactly as it always has.
        let root_ledger = units.is_some().then(|| Arc::new(ReadLedger::new()));
        let _root_reads = root_ledger.as_ref().map(|ledger| {
            AnalyzerQueryScope::with_read_ledger(workspace.analyzer(), Arc::clone(ledger))
        });
        let artifact_window =
            evaluation_artifact_leases.begin_window(replayed_artifact_lease_bytes);
        let artifact_collector = artifact_window.collector();
        let icfg_provider = PolicyIcfgProvider::new(
            workspace,
            &evaluation_execution_budget,
            artifact_collector,
            active_semantic_model_snapshot.clone(),
        );
        let mut request = DataflowRequest::new(&mut solver_budget, cancellation);
        // The summary funnel this root crosses records through the analyzer's
        // open read ledgers, exactly as the ICFG provider's artifact and
        // dispatch reads do; with no ledger attached it costs one relaxed load
        // per lookup.
        let summary_reads = SummaryReadRecorder::new(workspace.analyzer());
        let production = solve_typestate_with_production_summaries(
            summaries,
            &summary_reads,
            root,
            &[],
            &icfg_provider,
            &icfg_provider,
            ProductionTypestateExecutionContext::Policy(&icfg_provider.execution_budget),
            &compiled.protocol,
            &compiled.bindings,
            semantic_budget
                .as_mut()
                .expect("nonempty roots retain a semantic budget"),
            &mut request,
        );
        let window_retained_peak = match artifact_window.overflow() {
            Some(SemanticArtifactLeaseError::Capacity(exceeded)) => exceeded.attempted(),
            Some(SemanticArtifactLeaseError::RetainedBytesOverflow) => usize::MAX,
            Some(_) | None => artifact_window
                .retained_bytes()
                .saturating_add(replayed_artifact_lease_bytes),
        };
        evaluation_artifact_retained_peak =
            evaluation_artifact_retained_peak.max(window_retained_peak);
        let production = match production {
            Ok(production) => {
                cache_work.saturating_add_assign(production.lifecycle());
                production
            }
            Err(error) => {
                evaluation_error = Some(error.to_string());
                drop(icfg_provider);
                artifact_window.discard();
                break 'roots;
            }
        };
        // A result-cache hit returns before the ICFG provider and the summary
        // funnel are touched and records nothing, so its ledger names none of
        // the inputs the result depends on and the root is not publishable.
        let cache_status = production.cache_status();
        let solved = production.result();
        let fixed_point = match solved.result().termination() {
            SolverTermination::FixedPoint => true,
            SolverTermination::Cancelled => {
                shared_lane_reached = true;
                incomplete_reasons.push(PolicyIncompleteReason::Cancelled);
                false
            }
            SolverTermination::ExceededBudget(_) => {
                shared_lane_reached = true;
                incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
                false
            }
        };
        root_work.reached_rows = u64::try_from(solved.result().reached().len()).unwrap_or(u64::MAX);
        reached_rows = reached_rows.saturating_add(root_work.reached_rows);
        for reached in solved.result().reached() {
            let Some(fact) = solved.result().fact(reached.fact()) else {
                evaluation_error = Some("typestate solve retained an invalid fact row".to_owned());
                break 'roots;
            };
            if fact.subject().is_some() {
                subject_rows = subject_rows.saturating_add(1);
                root_work.subject_rows = root_work.subject_rows.saturating_add(1);
            }
            if fact.terminal_observation().is_some() {
                terminal_rows = terminal_rows.saturating_add(1);
                root_work.terminal_rows = root_work.terminal_rows.saturating_add(1);
            }
        }
        if !fixed_point {
            drop(production);
            drop(icfg_provider);
            artifact_window.discard();
            continue;
        }
        if remaining_finding_reached_rows == 0
            || remaining_finding_candidates == 0
            || remaining_finding_witness_expansions == 0
            || remaining_finding_witness_bytes == 0
        {
            shared_lane_reached = true;
            incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
            omitted_analysis_findings = omitted_analysis_findings.saturating_add(1);
            drop(production);
            drop(icfg_provider);
            artifact_window.discard();
            break;
        }
        let witness_limits = match WitnessReconstructionLimits::new(
            limits.max_witness_steps,
            limits
                .max_witness_expansions
                .min(remaining_finding_witness_expansions),
        ) {
            Ok(limits) => limits,
            Err(error) => {
                evaluation_error = Some(error.to_string());
                break 'roots;
            }
        };
        let finding_limits = match TypestateFindingLimits::with_witness_limits(
            remaining_finding_reached_rows,
            remaining_finding_candidates,
            witness_limits,
            remaining_finding_witness_expansions,
            remaining_finding_witness_bytes,
        ) {
            Ok(limits) => limits,
            Err(error) => {
                evaluation_error = Some(error.to_string());
                break 'roots;
            }
        };
        let findings = match collect_summary_findings_with_limits(
            &compiled.protocol,
            &compiled.bindings,
            solved,
            finding_limits,
            cancellation,
        ) {
            Ok(findings) => findings,
            Err(TypestateFlowProblemError::FindingCancelled) => {
                shared_lane_reached = true;
                incomplete_reasons.push(PolicyIncompleteReason::Cancelled);
                drop(production);
                drop(icfg_provider);
                artifact_window.discard();
                break;
            }
            Err(TypestateFlowProblemError::FindingBudgetExceeded) => {
                shared_lane_reached = true;
                incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
                omitted_analysis_findings = omitted_analysis_findings.saturating_add(1);
                drop(production);
                drop(icfg_provider);
                artifact_window.discard();
                break;
            }
            Err(error) => {
                evaluation_error = Some(error.to_string());
                drop(production);
                drop(icfg_provider);
                artifact_window.discard();
                break 'roots;
            }
        };
        let mut root_projections = Vec::new();
        let mut root_retained_analysis_findings = 0_u64;
        if !findings.analysis_complete() || findings.omitted() > 0 {
            // The per-root finding limits are the shared remaining lanes
            // narrowed to this root, so an omission here is not a property of
            // the root alone: a run that reused an earlier root would have had
            // more allowance left and might have omitted nothing.
            shared_lane_reached = true;
            root_reasons.push(PolicyIncompleteReason::PartialDiscovery);
            incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
        }
        let finding_work = findings.work();
        let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        root_work.finding_reached_rows = count(finding_work.reached_rows());
        root_work.finding_candidates = count(finding_work.candidates());
        root_work.finding_witness_expansions = count(finding_work.witness_expansions());
        root_work.finding_witness_bytes = count(finding_work.witness_bytes());
        remaining_finding_reached_rows =
            remaining_finding_reached_rows.saturating_sub(finding_work.reached_rows());
        remaining_finding_candidates =
            remaining_finding_candidates.saturating_sub(finding_work.candidates());
        remaining_finding_witness_expansions =
            remaining_finding_witness_expansions.saturating_sub(finding_work.witness_expansions());
        remaining_finding_witness_bytes =
            remaining_finding_witness_bytes.saturating_sub(finding_work.witness_bytes());
        root_work.omitted_analysis_findings = u64::try_from(findings.omitted()).unwrap_or(u64::MAX);
        omitted_analysis_findings =
            omitted_analysis_findings.saturating_add(root_work.omitted_analysis_findings);
        for finding in findings.findings() {
            let Some(subject) = compiled.bindings.subject(finding.subject()) else {
                evaluation_error =
                    Some("typestate finding refers to an unknown bound subject".to_owned());
                break 'roots;
            };
            if compiled.binding_omission_subjects.contains(subject.key()) {
                continue;
            }
            root_retained_analysis_findings = root_retained_analysis_findings.saturating_add(1);
            match project_finding(
                authority, policy, spec, workspace, budget, compiled, root, finding,
            ) {
                Ok(finding_projections) => root_projections.extend(finding_projections),
                Err(error) => {
                    evaluation_error = Some(error);
                    break 'roots;
                }
            }
        }
        drop(findings);
        drop(production);
        drop(icfg_provider);
        match artifact_window.commit(&mut evaluation_artifact_leases) {
            Ok(()) => {
                let execution_after = evaluation_execution_budget.work();
                root_work.solver = solver_budget.used().saturating_sub(solver_before);
                root_work.semantic = semantic_budget
                    .as_ref()
                    .map_or_else(SemanticWork::default, SemanticBudget::used)
                    .saturating_sub(semantic_before);
                root_work.materialized_files = count(
                    execution_after
                        .materialized_files
                        .saturating_sub(execution_before.materialized_files),
                );
                root_work.traversal_steps = count(
                    execution_after
                        .traversal_steps
                        .saturating_sub(execution_before.traversal_steps),
                );
                root_work.artifact_leases = count(
                    evaluation_artifact_leases
                        .len()
                        .saturating_sub(leases_before),
                );
                root_work.artifact_lease_bytes = count(
                    evaluation_artifact_leases
                        .retained_bytes()
                        .saturating_sub(lease_bytes_before),
                );
                root_work.retained_analysis_findings = root_retained_analysis_findings;
                retained_analysis_findings =
                    retained_analysis_findings.saturating_add(root_retained_analysis_findings);
                if let Some(units) = units.as_deref_mut() {
                    units.publish(
                        root_index,
                        RootProduct {
                            findings: root_projections.clone(),
                            incomplete_reasons: root_reasons,
                            work: root_work,
                        },
                        root_ledger.as_ref().expect("a unit run records its reads"),
                        cache_status,
                    );
                }
                projections.extend(root_projections);
                #[cfg(any(test, feature = "test-support"))]
                workspace
                    .analyzer()
                    .test_hooks()
                    .invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test();
            }
            Err(
                SemanticArtifactLeaseError::Capacity(_)
                | SemanticArtifactLeaseError::RetainedBytesOverflow,
            ) => {
                shared_lane_reached = true;
                incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
                omitted_analysis_findings = omitted_analysis_findings
                    .saturating_add(root_retained_analysis_findings.max(1));
                break;
            }
            Err(error) => {
                evaluation_error = Some(format!(
                    "typestate evaluation semantic lease transaction failed: {error}"
                ));
                break 'roots;
            }
        }
    }

    let final_evaluation_execution_work = evaluation_execution_budget.work();
    let evaluation_materialized_files = final_evaluation_execution_work
        .materialized_files
        .saturating_sub(initial_evaluation_execution_work.materialized_files);
    let evaluation_traversal_steps = final_evaluation_execution_work
        .traversal_steps
        .saturating_sub(initial_evaluation_execution_work.traversal_steps);
    let completed_evaluation = evaluation_error.is_none();
    if completed_evaluation && final_evaluation_execution_work.exhausted {
        incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
    }
    if completed_evaluation && !compiled.binding_omissions.is_empty() {
        incomplete_reasons.push(PolicyIncompleteReason::PartialDiscovery);
    }
    let semantic_evaluation_work = semantic_budget
        .as_ref()
        .map_or_else(SemanticWork::default, SemanticBudget::used);
    let semantic_peaks = compiled.semantic_compile_peaks.with_child_evaluation(
        compiled.semantic_compile_work,
        semantic_evaluation_work,
        evaluation_artifact_retained_peak,
        final_evaluation_execution_work.traversal_steps,
    );
    let work = typestate_work_report(
        compiled,
        &TypestateWorkMeasurements {
            cache_work,
            semantic_evaluation_work,
            semantic_peaks,
            final_execution_work: final_evaluation_execution_work,
            evaluation_materialized_files,
            evaluation_traversal_steps,
            semantic_artifact_leases: evaluation_artifact_leases
                .len()
                .saturating_add(replayed_artifact_leases),
            evaluation_semantic_artifact_leases: evaluation_artifact_leases
                .additions_len()
                .saturating_add(replayed_artifact_leases),
            reached_rows,
            subject_rows,
            terminal_rows,
            retained_analysis_findings,
            omitted_analysis_findings,
            retained_findings: if completed_evaluation {
                u64::try_from(projections.len()).unwrap_or(u64::MAX)
            } else {
                0
            },
        },
    );
    if let Some(message) = evaluation_error {
        return RootsPass::Failed(TypestateEvaluationFailure { message, work });
    }
    if units.is_some() && (shared_lane_reached || final_evaluation_execution_work.exhausted) {
        return RootsPass::Widen(WidenReason::MergedLimitReached);
    }
    incomplete_reasons.sort();
    incomplete_reasons.dedup();
    let completion = if incomplete_reasons.is_empty() {
        PolicyRunCompletion::Complete
    } else {
        PolicyRunCompletion::inconclusive(incomplete_reasons)
            .expect("deduplicated typestate incomplete reasons are canonical")
    };
    let diagnostics_truncated = compiled.binding_omissions.len() > budget.max_diagnostics();
    let diagnostics = compiled
        .binding_omissions
        .iter()
        .take(budget.max_diagnostics())
        .map(|omission| {
            PolicyDiagnostic::try_new(
                PolicyDiagnosticCode::CodeQuery {
                    code: CodeQueryDiagnosticCode::SemanticCapabilityUnsupported,
                },
                PolicyDiagnosticSeverity::Warning,
                PolicyDiagnosticImpact::RunIncomplete,
                format!("typestate endpoint binding omitted: {omission}"),
                None,
                Vec::new(),
            )
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>();
    let diagnostics = match diagnostics {
        Ok(diagnostics) => diagnostics,
        Err(message) => {
            return RootsPass::Failed(TypestateEvaluationFailure {
                message,
                work: work.clone(),
            });
        }
    };
    RootsPass::Complete(TypestateProjectionPayload {
        projections,
        completion,
        diagnostics,
        diagnostics_truncated,
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
    // Every spelling through which this subject was observed. A protocol
    // subject follows the object, so a reader has to be able to see the other
    // names the same object was reached under -- the alias a close was written
    // on is not otherwise anywhere in the report. For a subject with one
    // spelling this is exactly the acquisition set above and adds nothing.
    let mut spellings = compiled
        .bindings
        .event_bindings()
        .iter()
        .filter(|binding| {
            binding.subject() == finding.subject()
                && binding.role() != TypestateObjectRole::EscapedObject
        })
        .map(|binding| binding.site().identity())
        .chain(
            compiled
                .bindings
                .terminal_bindings()
                .iter()
                .filter(|binding| binding.subject() == finding.subject())
                .map(|binding| binding.site().identity()),
        )
        .collect::<Vec<_>>();
    spellings.sort_unstable();
    spellings.dedup();
    let subject_locator = acquisitions
        .first()
        .copied()
        .ok_or_else(|| "typestate finding subject has no acquisition observation".to_owned())?;
    let subject_path = subject_locator.path().clone();
    let subject_namespace = subject_locator.language().config_label();
    let site_path = site.path().clone();
    let site_namespace = site.language().config_label();
    let scenario_key = super::semantic_identity::semantic_root_key(root);
    let scenario = TypestateScenarioId::try_new("bifrost", &scenario_key)
        .map_err(|error| error.to_string())?;
    let site_key = super::semantic_identity::semantic_site_key(workspace, site);
    let site_identity =
        StableSemanticIdentity::protocol_violation_site(site_namespace, site_path, &site_key)
            .map_err(|error| error.to_string())?;
    let subject_key = super::semantic_identity::stable_hex(
        bound_subject.key().public_canonical_rendering().as_bytes(),
    );
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
        // The anchor names the finding, not the compile: the projection facts
        // above still carry the binding-plan hash the authority seals them to,
        // and the anchor carries only what this violation is (#2968).
        let anchor = TypestateFindingAnchor::strong(
            authority.protocol_hash(),
            subject_identity.clone(),
            site_identity.clone(),
            facts.scenario_set_hash,
            &violation,
        )
        .map_err(|error| error.to_string())?;
        let finding_key = super::semantic_identity::stable_hex(
            format!("{}:{}:{}", subject_key, site_key, facts.semantic_hash).as_bytes(),
        );
        let (report, witness_refs) = projected_report(
            workspace,
            finding,
            &acquisitions,
            &spellings,
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
    state: brokk_bifrost_flow::typestate::ProtocolStateId,
) -> Result<PolicyTypestateStateId, String> {
    let key = protocol
        .state_key(state)
        .ok_or_else(|| "typestate finding state is absent from the protocol".to_owned())?;
    PolicyTypestateStateId::new(key.as_str()).map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn projected_report(
    workspace: &WorkspaceAnalyzer,
    finding: &TypestateFinding,
    acquisitions: &[&brokk_bifrost_analysis::analyzer::semantic::SemanticLocator],
    spellings: &[&brokk_bifrost_analysis::analyzer::semantic::SemanticLocator],
    finding_key: &str,
    report_options: &PolicyReportOptions,
    budget: &PolicyBudget,
) -> Result<(ProjectedFindingReport, Vec<WitnessId>), String> {
    let primary = super::semantic_identity::policy_location(workspace, finding.site())?;
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
        let id_key =
            super::semantic_identity::stable_hex(format!("{finding_key}:{index}").as_bytes());
        let id = WitnessId::try_new("bifrost", &id_key).map_err(|error| error.to_string())?;
        let projected = super::witness_projection::project_summary_witness(
            workspace,
            witness.summary(),
            id.clone(),
            retained_step_limit,
            retained_byte_limit,
            |kind| match kind {
                SummaryWitnessStepKind::Seed => (WitnessStepKind::Source, "typestate seed"),
                SummaryWitnessStepKind::Edge(_) => {
                    (WitnessStepKind::Propagation, "typestate propagation")
                }
                SummaryWitnessStepKind::EndSummaryGap(_) => {
                    (WitnessStepKind::Return, "typestate summary boundary")
                }
            },
        )?;
        let Some(projected) = projected else {
            omitted_witnesses = omitted_witnesses.saturating_add(1);
            continue;
        };
        witnesses.push(projected);
        witness_refs.push(id);
    }
    let witnesses_truncated = omitted_witnesses > 0;
    let mut incomplete = Vec::new();
    if !evidence.proof_complete_for(finding.certainty()) {
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
    for (relationship, locators) in [
        (PolicyLocationRelationship::Source, acquisitions),
        (PolicyLocationRelationship::Subject, spellings),
    ] {
        for locator in locators {
            let location = super::semantic_identity::policy_location(workspace, locator)?;
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
                RelatedPolicyLocation::try_new(relationship, location, Vec::new())
                    .map_err(|error| error.to_string())?,
            );
        }
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
            display_path: None,
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

fn failed_projection_payload(message: &str, work: PolicyWorkReport) -> TypestateProjectionPayload {
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
        work,
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
        // A widening compile is answered by compiling again, never by this
        // projection: the caller checks `TypestatePolicyCompileFailure::widen`
        // before it converts a failure at all.
        TypestatePolicyCompileError::MissingWorkspace
        | TypestatePolicyCompileError::SemanticProvider(_)
        | TypestatePolicyCompileError::Widen(_) => TypestateCompilationFailure::failed_with_work(
            PolicyFailureReason::InternalInvariant,
            message,
            work,
        ),
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

fn typestate_selector_error(
    error: super::selector_compiler::PolicySelectorSessionError,
) -> TypestatePolicyCompileError {
    match error {
        super::selector_compiler::PolicySelectorSessionError::Incomplete { completion, detail } => {
            TypestatePolicyCompileError::QueryIncomplete { completion, detail }
        }
        super::selector_compiler::PolicySelectorSessionError::Unavailable(detail) => {
            TypestatePolicyCompileError::SemanticUnavailable(detail)
        }
        super::selector_compiler::PolicySelectorSessionError::Provider(detail) => {
            TypestatePolicyCompileError::SemanticProvider(SemanticProviderError::internal(detail))
        }
        super::selector_compiler::PolicySelectorSessionError::Widen(reason) => {
            TypestatePolicyCompileError::Widen(reason)
        }
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
        max_selector_results: usize,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            selectors: super::selector_compiler::PolicySelectorSession::new(
                workspace,
                "typestate",
                query_limits,
                max_selector_results,
                cancellation,
                // The seed scope every selector of this compile enumerates
                // over. A compile that holds units narrows it per unit
                // instead; a compile that does not runs one whole-workspace
                // scan per selector, exactly as it always has.
                CodeQueryExecutionScope::whole_workspace(),
            ),
            syntax_trees: HashMap::new(),
            formal_names: HashMap::new(),
            binding_omissions: Vec::new(),
            binding_omission_procedures: HashSet::new(),
        }
    }

    /// Compile each of this policy's selectors one seed file at a time,
    /// reusing what a previous run published.
    pub(crate) fn with_units(
        mut self,
        policy: &'a LoadedPolicy,
        incremental: &'a PolicyIncrementalContext<'a>,
        budget: &'a PolicyBudget,
    ) -> Self {
        self.selectors.with_units(policy, incremental, budget);
        self
    }

    /// The compile, and what its selector units did.
    ///
    /// The units come out even when the compile failed, because a compile that
    /// asked to be widened still reports the attempt that asked.
    pub(crate) fn compile_with_units(
        mut self,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
    ) -> (
        Result<CompiledTypestatePolicy, Box<TypestatePolicyCompileFailure>>,
        Option<super::selector_compiler::SelectorUnitOutcome>,
    ) {
        let compiled = self.compile_inner(policy, spec);
        let units = self.selectors.take_units();
        let compiled = match compiled {
            Ok(compiled) => Ok(compiled),
            Err(error) => Err(Box::new(TypestatePolicyCompileFailure {
                error,
                work: self.selectors.work_report("typestate"),
            })),
        };
        (compiled, units)
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

        let mut subjects: Vec<CompiledTypestateSubject> = Vec::new();
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
                for resolved in self.resolve_selection(selection, &binding, None)? {
                    let seed_site = TypestateObservationSite::program_point(
                        resolved.observation_point.clone(),
                        TypestateBindingContext::root(),
                    );
                    let activation_edges = if resolved.activation_edges.is_empty() {
                        vec![None]
                    } else {
                        resolved.activation_edges.iter().map(Some).collect()
                    };
                    for object in &resolved.objects {
                        let mut publications = Vec::with_capacity(activation_edges.len());
                        for activation_edge in &activation_edges {
                            let activation_edge_handle =
                                activation_edge.map(|activation| &activation.edge);
                            let publication = if resolved.fresh_result_identity {
                                self.fresh_result_publication_before_activation(
                                    &object.object,
                                    &resolved.observation_point,
                                    activation_edge_handle,
                                )?
                            } else {
                                FreshResultPreActivationPublication::NotPublished
                            };
                            publications.push(publication);
                        }
                        for (activation_edge, publication) in
                            activation_edges.iter().zip(publications)
                        {
                            let exact_activation = activation_edge.is_some_and(|activation| {
                                matches!(&activation.proof, ProofStatus::Proven)
                                    && matches!(
                                        &activation.completeness,
                                        EvidenceCompleteness::Complete
                                    )
                            });
                            if resolved.retained_incomplete_result_contract_query
                                && matches!(
                                    publication,
                                    FreshResultPreActivationPublication::Published
                                        | FreshResultPreActivationPublication::PossiblePublication
                                )
                                && !(exact_activation
                                    && publication
                                        == FreshResultPreActivationPublication::Published)
                            {
                                // A positive pair is authoritative only when the
                                // activation and publication are both exact. A
                                // candidate edge or possible publication cannot
                                // acquire ownership or manufacture an escape. Omit
                                // only that pair: an independently proven sibling
                                // remains valid evidence for the same exact object.
                                continue;
                            }
                            let activation_quality = activation_edge.map_or_else(
                                || object.quality.clone(),
                                |activation| {
                                    TypestateBindingQuality::new(
                                        conjoin_proof(object.quality.proof(), &activation.proof),
                                        conjoin_completeness(
                                            object.quality.completeness(),
                                            &activation.completeness,
                                        ),
                                        object.quality.multiplicity(),
                                    )
                                },
                            );
                            let quality = match publication {
                                FreshResultPreActivationPublication::Incomplete
                                | FreshResultPreActivationPublication::PossiblePublication => {
                                    TypestateBindingQuality::new(
                                        activation_quality.proof().clone(),
                                        EvidenceCompleteness::Partial(
                                            "pre-activation publication analysis is incomplete"
                                                .into(),
                                        ),
                                        activation_quality.multiplicity(),
                                    )
                                }
                                FreshResultPreActivationPublication::NotPublished => {
                                    activation_quality
                                }
                                FreshResultPreActivationPublication::Published => {
                                    activation_quality
                                }
                            };
                            pending_subjects.push(PendingSubjectBinding {
                                class: class.clone(),
                                endpoint: subject.identity.clone(),
                                root: resolved.procedure.clone(),
                                site: seed_site.clone(),
                                activation_edge: activation_edge
                                    .map(|activation| activation.edge.clone()),
                                role: resolved.role,
                                object: object.object.clone(),
                                subject_quality: object.quality.clone(),
                                quality,
                                member_contracts: resolved.member_contracts.clone(),
                                fresh_result: resolved.fresh_result_identity,
                                escapes_before_activation: publication
                                    == FreshResultPreActivationPublication::Published,
                            });
                        }
                    }
                }
            }
        }
        let initial_state = ProtocolStateKey::new(spec.automaton.initial.as_str())
            .map_err(|error| TypestatePolicyCompileError::UnsupportedBinding(error.to_string()))?;
        let mut subject_indexes = HashMap::<TypestateSubjectKey, usize>::new();
        for subject in reduce_subject_bindings(pending_subjects, &endpoint_precedence)? {
            let key = TypestateSubjectKey::for_object(subject.class.clone(), &subject.object);
            let publication_start = subject
                .site
                .program_point_handle()
                .expect("validated typestate seeds retain program points")
                .clone();
            let escape_start = subject.escapes_before_activation.then(|| {
                let activation = subject
                    .activation_edge
                    .as_ref()
                    .expect("pre-activation escape requires an activation edge");
                let edge = activation
                    .procedure()
                    .semantics()
                    .control_edge(activation.id())
                    .expect("validated typestate activation edge resolves");
                activation
                    .procedure()
                    .point_handle(edge.source_point)
                    .expect("validated typestate activation edge retains its source")
            });
            if let Some(index) = subject_indexes.get(&key).copied() {
                if !subjects[index]
                    .publication_starts
                    .contains(&publication_start)
                {
                    subjects[index]
                        .publication_starts
                        .push(publication_start.clone());
                }
                if let Some(escape_start) = escape_start
                    && !subjects[index].escape_starts.contains(&escape_start)
                {
                    subjects[index].escape_starts.push(escape_start);
                }
            } else {
                let index = subjects.len();
                subject_indexes.insert(key.clone(), index);
                subject_specs.push(BoundTypestateSubjectSpec::new(
                    subject.class,
                    subject.object.clone(),
                    subject.subject_quality,
                ));
                roots.push(subject.root.clone());
                subjects.push(CompiledTypestateSubject {
                    key: key.clone(),
                    endpoint: subject.endpoint,
                    root: subject.root,
                    object: subject.object,
                    member_contracts: subject.member_contracts,
                    fresh_result: subject.fresh_result,
                    publication_starts: vec![publication_start.clone()],
                    escape_starts: escape_start.into_iter().collect(),
                });
            }
            seeds.push(match (subject.fresh_result, subject.activation_edge) {
                (true, Some(edge)) => {
                    TypestateInitialSeedSpec::new_reviewed_fresh_result_on_control_edge(
                        key,
                        initial_state.clone(),
                        subject.site,
                        edge,
                        subject.role,
                        subject.quality,
                    )
                }
                (true, None) => TypestateInitialSeedSpec::new_reviewed_fresh_result(
                    key,
                    initial_state.clone(),
                    subject.site,
                    subject.role,
                    subject.quality,
                ),
                (false, Some(edge)) => TypestateInitialSeedSpec::new_on_control_edge(
                    key,
                    initial_state.clone(),
                    subject.site,
                    edge,
                    subject.role,
                    subject.quality,
                ),
                (false, None) => TypestateInitialSeedSpec::new(
                    key,
                    initial_state.clone(),
                    subject.site,
                    subject.role,
                    subject.quality,
                ),
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
                        modeled_external_effect: None,
                        alias_derived: false,
                    });
                }
                continue;
            }
            for trigger in self.event_selections(policy, &selectors, &event.trigger)? {
                let endpoint = trigger.endpoint.clone();
                for resolved in self.resolve_selection(
                    trigger.selection,
                    &trigger.binding,
                    Some(trigger.phase),
                )? {
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
                            let modeled_external_effect =
                                modeled_external_effect_id(subject, &resolved, trigger.phase);
                            let quality = if modeled_external_effect.is_some()
                                && subject.fresh_result
                                && resolved.multiplicity.retained() == 1
                            {
                                TypestateBindingQuality::proven_unique()
                            } else {
                                object.quality.clone()
                            };
                            events.push(PendingEventBinding {
                                event: event_key.clone(),
                                policy_event: event.id.clone(),
                                subject: subject.key.clone(),
                                site,
                                phase: EventObservationPhase::Endpoint(trigger.phase),
                                order,
                                role,
                                quality,
                                endpoint: endpoint.clone(),
                                modeled_external_effect,
                                alias_derived: false,
                            });
                        }
                    }
                    let unnamed = subjects_absent_from(&resolved, &subjects, |subject| {
                        event.applies_to_subjects.contains(&subject.endpoint)
                    });
                    for aliased in self.alias_bound_subjects(&resolved, &unnamed)? {
                        let (site, role) = event_site(&resolved, trigger.phase)?;
                        let modeled_external_effect = subjects
                            .iter()
                            .find(|subject| subject.key == aliased)
                            .and_then(|subject| {
                                modeled_external_effect_id(subject, &resolved, trigger.phase)
                            });
                        events.push(PendingEventBinding {
                            event: event_key.clone(),
                            policy_event: event.id.clone(),
                            subject: aliased,
                            site,
                            phase: EventObservationPhase::Endpoint(trigger.phase),
                            order,
                            role,
                            quality: may_alias_quality(resolved.multiplicity),
                            endpoint: endpoint.clone(),
                            modeled_external_effect,
                            alias_derived: true,
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
                            alias_derived: false,
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
                            for resolved in
                                self.resolve_selection(selection, &binding, Some(*phase))?
                            {
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
                                            alias_derived: false,
                                        });
                                    }
                                }
                                let unnamed =
                                    subjects_absent_from(&resolved, &subjects, |subject| {
                                        expectation.applies_to_subjects.contains(&subject.endpoint)
                                    });
                                for aliased in self.alias_bound_subjects(&resolved, &unnamed)? {
                                    let (site, role) = event_site(&resolved, *phase)?;
                                    terminals.push(PendingTerminalBinding {
                                        expectation: expectation_key.clone(),
                                        policy_expectation: expectation.id.clone(),
                                        subject: aliased,
                                        site,
                                        phase: TerminalObservationPhase::Endpoint(*phase),
                                        role,
                                        quality: may_alias_quality(resolved.multiplicity),
                                        endpoint: Some(endpoint.clone()),
                                        alias_derived: true,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut detached_escape_transfers =
            HashMap::<SemanticLocator, Vec<(TypestateObjectKey, ProgramPointHandle)>>::new();
        for subject in &mut subjects {
            let root_locator = subject.root.semantics().locator().clone();
            if !detached_escape_transfers.contains_key(&root_locator) {
                let transfers = self.exact_detached_task_transfers(&subject.root)?;
                detached_escape_transfers.insert(root_locator.clone(), transfers);
            }
            let subject_object = TypestateObjectKey::for_object(&subject.object);
            for (_, escape_start) in detached_escape_transfers[&root_locator]
                .iter()
                .filter(|(object, _)| *object == subject_object)
            {
                if !subject.escape_starts.contains(escape_start) {
                    subject.escape_starts.push(escape_start.clone());
                }
            }
        }

        roots.sort_by(|left, right| left.semantics().locator().cmp(right.semantics().locator()));
        roots.dedup_by(|left, right| left == right);
        subjects.sort_by(|left, right| left.key.cmp(&right.key));
        let mut events = reduce_event_bindings(events, &endpoint_precedence, &event_precedence)?;
        let mut terminals =
            reduce_terminal_bindings(terminals, &endpoint_precedence, &expectation_precedence)?;
        let trusted_modeled_calls = events
            .iter()
            .filter(|binding| {
                binding.modeled_external_effect.is_some() && binding.quality.is_definitive()
            })
            .filter_map(|binding| {
                binding
                    .site
                    .call_site_handle()
                    .cloned()
                    .map(|call| (binding.subject.clone(), call))
            })
            .collect::<HashSet<_>>();
        let call_noninterference =
            self.call_noninterference_specs(&subjects, &trusted_modeled_calls)?;
        events.retain(|binding| {
            !binding.alias_derived
                || binding.site.call_site_handle().is_none_or(|call| {
                    !call_noninterference
                        .proven_pairs
                        .contains(&(binding.subject.clone(), call.clone()))
                })
        });
        terminals.retain(|binding| {
            !binding.alias_derived
                || binding.site.call_site_handle().is_none_or(|call| {
                    !call_noninterference
                        .proven_pairs
                        .contains(&(binding.subject.clone(), call.clone()))
                })
        });
        let escape_event =
            internal_escape_event_key(spec.automaton.events.iter().map(|event| event.id.as_str()));
        let escape_order = u32::try_from(spec.automaton.events.len()).map_err(|_| {
            TypestatePolicyCompileError::UnsupportedBinding(
                "too many ordered typestate events".to_owned(),
            )
        })?;
        let escape_bindings = subjects
            .iter()
            .flat_map(|subject| {
                subject.escape_starts.iter().map(|start| {
                    (
                        subject.key.clone(),
                        TypestateObservationSite::program_point(
                            start.clone(),
                            TypestateBindingContext::root(),
                        ),
                    )
                })
            })
            .collect::<Vec<_>>();
        let mut event_provenance = events
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
        event_provenance.extend(escape_bindings.iter().map(|(subject, site)| {
            (
                EventProvenanceKey {
                    event: escape_event.clone(),
                    subject: subject.clone(),
                    site: site.clone(),
                    order: escape_order,
                    role: TypestateObjectRole::EscapedObject,
                },
                None,
            )
        }));
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
            .map(|binding| match binding.modeled_external_effect {
                Some(effect_id) => TypestateEventBindingSpec::new_modeled_external_effect(
                    binding.event,
                    binding.subject,
                    binding.site,
                    binding.order,
                    binding.role,
                    binding.quality,
                    effect_id,
                ),
                None => TypestateEventBindingSpec::new(
                    binding.event,
                    binding.subject,
                    binding.site,
                    binding.order,
                    binding.role,
                    binding.quality,
                ),
            })
            .chain(escape_bindings.into_iter().map(|(subject, site)| {
                TypestateEventBindingSpec::new(
                    escape_event.clone(),
                    subject,
                    site,
                    escape_order,
                    TypestateObjectRole::EscapedObject,
                    TypestateBindingQuality::proven_unique(),
                )
            }))
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
        let incomplete_subjects = subjects
            .iter()
            .filter(|subject| {
                self.binding_omission_procedures
                    .contains(subject.root.semantics().locator())
            })
            .map(|subject| subject.key.clone())
            .collect::<HashSet<_>>();
        let incomplete_result_contract_selectors = self
            .selectors
            .retained_incomplete_result_contract_selectors();
        if incomplete_result_contract_selectors > 0 {
            self.binding_omissions.push(format!(
                "{incomplete_result_contract_selectors} result-contract selector query retained independently proven rows while guard or use discovery was incomplete"
            ));
        }
        for subject in &mut subject_specs {
            if incomplete_subjects.contains(subject.key()) {
                subject.mark_discovery_incomplete(
                    "one or more endpoint calls in the subject's procedure were not materialized",
                );
            }
        }
        let bindings = Arc::new(
            TypestateBindingPlan::try_new_with_call_noninterference(
                &protocol,
                subject_specs,
                seeds,
                event_specs,
                call_noninterference.specs,
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
        let semantic_compile_work = self.selectors.semantic_used();
        let semantic_compile_peaks = self.selectors.semantic_peaks();
        let semantic_remaining = self.selectors.semantic_remaining();
        let semantic_scope = self.selectors.semantic_scope_snapshot();
        let query_work = self.selectors.query_work();
        let semantic_execution_budget = self.selectors.execution_budget().clone();
        let selector_scans = self.selectors.selector_scans();
        let result_contract_artifact_leases = self.selectors.result_contract_artifact_leases();
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
        let artifact_leases = self.selectors.take_artifact_leases();
        assert!(
            result_contract_artifact_leases <= artifact_leases.len(),
            "result-contract lease admissions remain a subset of compiled leases"
        );
        {
            let leased = artifact_leases.snapshot();
            bindings.for_each_retained_artifact(|artifact| {
                assert!(
                    leased.contains_exact(artifact),
                    "every semantic artifact retained by a compiled typestate binding must be leased"
                );
            });
        }
        Ok(CompiledTypestatePolicy {
            protocol,
            bindings,
            roots: roots.into_boxed_slice(),
            subjects: subjects.into_boxed_slice(),
            event_endpoints: event_endpoints.into_boxed_slice(),
            terminal_endpoints: terminal_endpoints.into_boxed_slice(),
            query_work,
            semantic_compile_work,
            semantic_compile_peaks,
            semantic_remaining,
            semantic_scope,
            semantic_execution_budget,
            selector_scans,
            artifact_leases,
            result_contract_artifact_leases,
            binding_omissions: std::mem::take(&mut self.binding_omissions).into_boxed_slice(),
            binding_omission_subjects: incomplete_subjects,
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
        let sites = self
            .selectors
            .select_with_artifact_continuation(selector)
            .map_err(typestate_selector_error)?;
        Ok(sites
            .into_iter()
            .map(|site| SelectedSite {
                file: site.file,
                span: site.span,
                require_exact_call: matches!(binding, SelectorBinding::MatchedValue),
                proof: site.proof,
                completeness: site.completeness,
                result_contract: site.result_contract,
                call_shape: site.call_shape,
                retained_incomplete_result_contract_query: site
                    .retained_incomplete_result_contract_query,
            })
            .collect())
    }

    fn resolve_selection(
        &mut self,
        mut selection: SelectedSite,
        binding: &SelectorBinding,
        phase: Option<EndpointObservationPhase>,
    ) -> Result<Vec<ResolvedSelection>, TypestatePolicyCompileError> {
        if let Some(contract) = &selection.result_contract {
            let SelectorBinding::ResultIndex(index) = binding else {
                return Err(TypestatePolicyCompileError::UnsupportedBinding(
                    "a result-contract subject requires an indexed-result binding".to_owned(),
                ));
            };
            if *index != contract.result_ordinal {
                return Err(TypestatePolicyCompileError::UnsupportedBinding(format!(
                    "result-contract subject binds result {index}, but the contract validates result {}",
                    contract.result_ordinal
                )));
            }
            if contract.success_guard_coverage.is_exhaustive()
                && contract.success_guard_edges.is_empty()
            {
                return Ok(Vec::new());
            }
            if !contract.success_guard_coverage.is_exhaustive()
                && contract.success_guard_edges.is_empty()
                && contract.possible_success_guard_edges.is_empty()
            {
                return Ok(Vec::new());
            }
        }
        if matches!(binding, SelectorBinding::MatchedValue)
            && matches!(phase, None | Some(EndpointObservationPhase::AtMatch))
        {
            return self
                .resolve_matched_selection(selection)
                .map(|resolved| vec![resolved]);
        }
        let artifact = self
            .selectors
            .materialize_with_artifact_continuation(&selection.file)
            .map_err(typestate_selector_error)?;
        let lookup = procedures_in_artifact(
            &artifact,
            self.selectors
                .remaining_semantic_traversal_steps()
                .map_err(typestate_selector_error)?,
            self.selectors.cancellation(),
        );
        if !self
            .selectors
            .execution_budget()
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
        let calls = select_calls(&lookup.handles, &selection)?;
        if calls.is_empty() {
            self.binding_omission_procedures.extend(
                lookup
                    .handles
                    .iter()
                    .map(|procedure| procedure.semantics().locator().clone()),
            );
            self.binding_omissions.push(format!(
                "{}:{}..{} does not identify a materialized semantic call site",
                selection.file, selection.span.start, selection.span.end
            ));
        }
        if !calls.is_empty() && matches!(binding, SelectorBinding::Receiver) {
            match self
                .selectors
                .receiver_binding_applicability(&calls)
                .map_err(typestate_selector_error)?
            {
                ReceiverBindingApplicability::Applicable => {}
                ReceiverBindingApplicability::CandidateReceiver => {
                    selection.proof = ProofStatus::Unproven(
                        "receiver applicability remains a structured candidate".into(),
                    );
                    selection.completeness = EvidenceCompleteness::Partial(
                        "receiver dispatch cannot exclude a function-valued field".into(),
                    );
                }
                ReceiverBindingApplicability::ExactNonMatch => return Ok(Vec::new()),
                ReceiverBindingApplicability::Indeterminate => {
                    return Err(TypestatePolicyCompileError::SemanticUnavailable(
                        "receiver binding remains ambiguous after semantic dispatch refinement"
                            .to_owned(),
                    ));
                }
                ReceiverBindingApplicability::Inconsistent => {
                    return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(
                        "semantic lowerings for one selected call disagree whether it has a receiver"
                            .to_owned(),
                    ));
                }
            }
        }
        let mut resolved = Vec::with_capacity(calls.len());
        for (procedure, call) in calls {
            if let Some(call_selection) =
                self.resolve_call_selection(&selection, binding, phase, procedure, call)?
            {
                resolved.push(call_selection);
            }
        }
        Ok(resolved)
    }

    fn resolve_call_selection(
        &mut self,
        selection: &SelectedSite,
        binding: &SelectorBinding,
        phase: Option<EndpointObservationPhase>,
        procedure: ProcedureHandle,
        call: CallSiteHandle,
    ) -> Result<Option<ResolvedSelection>, TypestatePolicyCompileError> {
        let named_argument;
        let effective_binding = if let SelectorBinding::ArgumentName(name) = binding {
            named_argument =
                SelectorBinding::ArgumentIndex(self.resolve_named_argument_index(&call, name)?);
            &named_argument
        } else {
            binding
        };
        let invocation_mode = procedure
            .semantics()
            .call_site(call.id())
            .expect("validated call handle resolves")
            .invocation_mode;
        if detached_call_lacks_requested_observation(invocation_mode, effective_binding, phase) {
            self.binding_omission_procedures
                .insert(procedure.semantics().locator().clone());
            self.binding_omissions.push(format!(
                "{}:{}..{} requests target completion from a detached call, whose completion is not observable in the caller",
                selection.file, selection.span.start, selection.span.end
            ));
            return Ok(None);
        }
        let (value, observation_point, role) =
            select_value(&procedure, &call, &selection.span, effective_binding, phase)?;
        let oracle = self.selectors.workspace().semantic_oracle_provider();
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
        let continuation = self
            .selectors
            .continue_semantic(|request| oracle.pointees(&at_point, request))
            .map_err(typestate_selector_error)?;
        require_uninterrupted_semantic_outcome(continuation.outcome(), "heap analysis")?;
        self.selectors
            .require_execution_budget("heap analysis")
            .map_err(typestate_selector_error)?;
        let result = continuation.outcome().available_value().ok_or_else(|| {
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
        let reviewed_fresh_result = selection
            .result_contract
            .as_ref()
            .is_some_and(|contract| contract.fresh_allocation);
        let exact_call_result_identity = result.objects().candidates().len() == 1
            && result.objects().candidates()[0].value().identity()
                == &AccessPathRoot::Value(at_point.value().clone());
        let fresh_result_identity = reviewed_fresh_result
            && matches!(&selection.proof, ProofStatus::Proven)
            && matches!(&selection.completeness, EvidenceCompleteness::Complete)
            && exact_call_result_identity;
        if reviewed_fresh_result && !fresh_result_identity {
            if !selection.retained_incomplete_result_contract_query {
                self.binding_omissions.push(format!(
                    "{}:{}..{} reviewed fresh-allocation result does not have Proven+Complete evidence for one exact call-result identity",
                    selection.file, selection.span.start, selection.span.end
                ));
            }
            continuation
                .finish_scalar((), "heap analysis")
                .map_err(typestate_selector_error)?;
            return Ok(None);
        }
        let effective_multiplicity = if fresh_result_identity {
            TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1)
                .expect("one exact fresh result is valid multiplicity")
        } else {
            multiplicity
        };
        let objects = result
            .objects()
            .candidates()
            .iter()
            .map(|candidate| ResolvedObject {
                object: candidate.value().clone(),
                quality: if fresh_result_identity {
                    TypestateBindingQuality::proven_unique()
                } else {
                    TypestateBindingQuality::new(
                        conjoin_proof(&selection.proof, candidate.proof()),
                        conjoin_completeness(&selection.completeness, candidate.completeness()),
                        effective_multiplicity,
                    )
                },
            })
            .collect();
        let mut activation_edges = Vec::new();
        if let Some(contract) = &selection.result_contract {
            let resolve_edge =
                |edge_locator: &brokk_bifrost_analysis::analyzer::semantic::ControlEdgeLocator| {
                    edge_locator.resolve(&procedure).map_err(|error| {
                        TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                            "result-contract success edge cannot be reconstructed: {error}"
                        ))
                    })
                };
            for edge_locator in &contract.success_guard_edges {
                activation_edges.push(ResolvedActivationEdge {
                    edge: resolve_edge(edge_locator)?,
                    proof: ProofStatus::Proven,
                    completeness: EvidenceCompleteness::Complete,
                });
            }
            if !contract.success_guard_coverage.is_exhaustive() {
                for edge_locator in &contract.possible_success_guard_edges {
                    if contract.success_guard_edges.contains(edge_locator) {
                        continue;
                    }
                    activation_edges.push(ResolvedActivationEdge {
                        edge: resolve_edge(edge_locator)?,
                        proof: ProofStatus::Unproven(
                            "result-contract success-guard identity is a structured candidate"
                                .into(),
                        ),
                        completeness: EvidenceCompleteness::Partial(
                            "result-contract success-guard projection is incomplete".into(),
                        ),
                    });
                }
            }
        }
        let resolved = ResolvedSelection {
            procedure,
            call: Some(call),
            observation_point,
            role,
            objects,
            observation: at_point,
            coverage: result.objects().coverage(),
            multiplicity,
            activation_edges,
            member_contracts: selection
                .result_contract
                .as_ref()
                .map(|contract| contract.member_contracts.clone())
                .unwrap_or_default(),
            call_shape: selection.call_shape.clone(),
            fresh_result_identity,
            retained_incomplete_result_contract_query: selection
                .retained_incomplete_result_contract_query,
        };
        if !resolved.retained_artifact_coverage(|artifact| continuation.contains_exact(artifact)) {
            return Err(TypestatePolicyCompileError::SemanticUnavailable(
                "heap analysis produced identity-bearing handles outside its bounded complete-artifact window"
                    .to_owned(),
            ));
        }
        let outcome = continuation
            .commit(&mut self.selectors, "heap analysis")
            .map_err(typestate_selector_error)?;
        drop(outcome);
        Ok(Some(resolved))
    }

    fn resolve_matched_selection(
        &mut self,
        selection: SelectedSite,
    ) -> Result<ResolvedSelection, TypestatePolicyCompileError> {
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        let continuation = self
            .selectors
            .continue_semantic(|request| {
                oracle.pointees_at_source(
                    &selection.file,
                    super::selector_compiler::source_range(&selection.span),
                    request,
                )
            })
            .map_err(typestate_selector_error)?;
        require_uninterrupted_semantic_outcome(
            continuation.outcome(),
            "matched source heap analysis",
        )?;
        self.selectors
            .require_execution_budget("matched source heap analysis")
            .map_err(typestate_selector_error)?;
        let result = continuation.outcome().available_value().ok_or_else(|| {
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
        let resolved = ResolvedSelection {
            procedure: observation.query().point().procedure().clone(),
            call: None,
            observation_point: observation.query().point().clone(),
            role: TypestateObjectRole::MatchedValue,
            objects,
            observation: observation.query().clone(),
            coverage: observation.objects().coverage(),
            multiplicity,
            activation_edges: Vec::new(),
            member_contracts: selection
                .result_contract
                .as_ref()
                .map(|contract| contract.member_contracts.clone())
                .unwrap_or_default(),
            call_shape: selection.call_shape,
            fresh_result_identity: false,
            retained_incomplete_result_contract_query: selection
                .retained_incomplete_result_contract_query,
        };
        if !resolved.retained_artifact_coverage(|artifact| continuation.contains_exact(artifact)) {
            return Err(TypestatePolicyCompileError::SemanticUnavailable(
                "matched source heap analysis produced identity-bearing handles outside its bounded complete-artifact window"
                    .to_owned(),
            ));
        }
        let outcome = continuation
            .commit(&mut self.selectors, "matched source heap analysis")
            .map_err(typestate_selector_error)?;
        drop(outcome);
        Ok(resolved)
    }

    /// Publication of a fresh result before its success guard activates the
    /// typestate subject.
    ///
    /// Multi-result Go assignments perform their stores before a following
    /// error check. A direct store into a receiver field therefore transfers
    /// ownership before the result contract's success edge creates the live
    /// subject. Exact Published evidence on a Proven+Complete activation keeps
    /// the established structured escape event even when a sibling guard left
    /// the selector incomplete. A candidate activation or possible publication
    /// is instead omitted at that edge-local boundary: partial guard recovery
    /// must not broaden into wrapper ownership without ownership closure. A
    /// call-only or incomplete publication answer makes the seed partial
    /// because ordinary call modeling cannot observe a subject that does not
    /// exist until the later edge.
    fn fresh_result_publication_before_activation(
        &mut self,
        object: &AbstractObject,
        ownership_start: &ProgramPointHandle,
        activation_edge: Option<&brokk_bifrost_analysis::analyzer::semantic::ControlEdgeHandle>,
    ) -> Result<FreshResultPreActivationPublication, TypestatePolicyCompileError> {
        let Some(activation_edge) = activation_edge else {
            return Ok(FreshResultPreActivationPublication::NotPublished);
        };
        let edge = activation_edge
            .procedure()
            .semantics()
            .control_edge(activation_edge.id())
            .expect("validated typestate activation edge resolves");
        let observation = activation_edge
            .procedure()
            .point_handle(edge.target_point)
            .expect("validated typestate activation edge retains its target");
        let query = FreshObjectPublicationQuery::new(
            object.clone(),
            ownership_start.clone(),
            observation,
            OracleCallContext::empty(),
        )
        .map_err(|error| {
            TypestatePolicyCompileError::SemanticProvider(SemanticProviderError::internal(
                error.to_string(),
            ))
        })?;
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        let continuation = self
            .selectors
            .continue_semantic(|request| oracle.fresh_object_publications(&query, request))
            .map_err(typestate_selector_error)?;
        require_uninterrupted_semantic_outcome(
            continuation.outcome(),
            "pre-activation fresh-object publication analysis",
        )?;
        self.selectors
            .require_execution_budget("pre-activation fresh-object publication analysis")
            .map_err(typestate_selector_error)?;
        let outcome_complete = continuation.outcome().is_complete();
        let Some(result) = continuation.outcome().available_value() else {
            return continuation
                .finish_scalar(
                    FreshResultPreActivationPublication::Incomplete,
                    "pre-activation fresh-object publication analysis",
                )
                .map_err(typestate_selector_error);
        };
        let publications = result.publications().candidates();
        let exact_publication_inventory = outcome_complete
            && result.publications().coverage().is_exhaustive()
            && !publications.iter().any(|publication| {
                !matches!(publication.proof(), ProofStatus::Proven)
                    || !matches!(publication.completeness(), EvidenceCompleteness::Complete)
            });
        let has_non_call_publication = publications
            .iter()
            .any(|publication| publication.value().kind() != FreshObjectPublicationKind::Call);
        let answer = if has_non_call_publication {
            if exact_publication_inventory {
                FreshResultPreActivationPublication::Published
            } else {
                FreshResultPreActivationPublication::PossiblePublication
            }
        } else if !exact_publication_inventory || !publications.is_empty() {
            // The subject does not exist until the later success edge, so the
            // ordinary call policy cannot classify a retained call, and an
            // open publication inventory cannot prove absence. A reviewed call
            // summary or ownership closure may eventually close the answer;
            // until then, keep the seed partial without claiming escape.
            FreshResultPreActivationPublication::Incomplete
        } else {
            FreshResultPreActivationPublication::NotPublished
        };
        continuation
            .finish_scalar(answer, "pre-activation fresh-object publication analysis")
            .map_err(typestate_selector_error)
    }

    /// Calls proven unable to observe one fresh typestate subject.
    ///
    /// The observation is the call's normal continuation, so the structured
    /// publication slice includes the call itself as well as every earlier
    /// operation on a path from ownership establishment. Every retained
    /// publication must be the same reviewed complete call effect already in
    /// the binding plan. A store, capture, return, unmodeled call, open slice,
    /// or interrupted oracle answer simply withholds the proof; it never
    /// converts uncertainty into a clean result.
    fn call_noninterference_specs(
        &mut self,
        subjects: &[CompiledTypestateSubject],
        trusted_modeled_calls: &HashSet<(TypestateSubjectKey, CallSiteHandle)>,
    ) -> Result<CompiledCallNonInterference, TypestatePolicyCompileError> {
        let mut specs = Vec::new();
        let mut proven_pairs = HashSet::new();
        for subject in subjects.iter().filter(|subject| subject.fresh_result) {
            let calls = subject
                .root
                .semantics()
                .call_sites()
                .iter()
                .filter_map(|call| subject.root.call_site_handle(call.id))
                .collect::<Vec<_>>();
            for call in calls {
                let row = call
                    .procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("validated call-site handles resolve");
                let Some(after_call) = row
                    .normal_continuation
                    .target()
                    .and_then(|point| call.procedure().point_handle(point))
                else {
                    continue;
                };
                let mut proven = true;
                for start in &subject.publication_starts {
                    let query = FreshObjectPublicationQuery::new(
                        subject.object.clone(),
                        start.clone(),
                        after_call.clone(),
                        OracleCallContext::empty(),
                    )
                    .expect("fresh subject ownership and calls share one procedure");
                    let oracle = self.selectors.workspace().semantic_oracle_provider();
                    let continuation = self
                        .selectors
                        .continue_semantic(|request| {
                            oracle.fresh_object_publications(&query, request)
                        })
                        .map_err(typestate_selector_error)?;
                    require_uninterrupted_semantic_outcome(
                        continuation.outcome(),
                        "fresh-object publication analysis",
                    )?;
                    self.selectors
                        .require_execution_budget("fresh-object publication analysis")
                        .map_err(typestate_selector_error)?;
                    let Some(result) = continuation
                        .outcome()
                        .is_complete()
                        .then(|| continuation.outcome().available_value())
                        .flatten()
                    else {
                        proven = false;
                        break;
                    };
                    let valid = result.publications().coverage().is_exhaustive()
                        && !result
                            .publications()
                            .candidates()
                            .iter()
                            .any(|publication| {
                                !matches!(publication.proof(), ProofStatus::Proven)
                                    || !matches!(
                                        publication.completeness(),
                                        EvidenceCompleteness::Complete
                                    )
                                    || publication.value().kind()
                                        != FreshObjectPublicationKind::Call
                                    || publication.value().call_site().is_none_or(
                                        |published_call| {
                                            !trusted_modeled_calls.contains(&(
                                                subject.key.clone(),
                                                published_call.clone(),
                                            ))
                                        },
                                    )
                            });
                    let valid = continuation
                        .finish_scalar(valid, "fresh-object publication analysis")
                        .map_err(typestate_selector_error)?;
                    if !valid {
                        proven = false;
                        break;
                    }
                }
                if proven {
                    proven_pairs.insert((subject.key.clone(), call.clone()));
                    specs.push(TypestateCallNonInterferenceSpec::new(
                        subject.key.clone(),
                        call,
                    ));
                }
            }
        }
        Ok(CompiledCallNonInterference {
            specs,
            proven_pairs,
        })
    }

    /// Detached work takes ownership at registration, before the child task
    /// executes. An escape is therefore established only when the structured
    /// transfer value resolves to one Proven+Complete object and that object
    /// is the exact typestate subject. Open or ambiguous object sets retain the
    /// ordinary call uncertainty without manufacturing an escape event.
    fn exact_detached_task_transfers(
        &mut self,
        root: &ProcedureHandle,
    ) -> Result<Vec<(TypestateObjectKey, ProgramPointHandle)>, TypestatePolicyCompileError> {
        let mut exact_transfers = Vec::new();
        for transfer in brokk_bifrost_flow::detached_task::detached_task_transfers(root.semantics())
        {
            let value = root
                .value_handle(transfer.value)
                .expect("validated detached transfer retains its value");
            let point = root
                .point_handle(transfer.point)
                .expect("validated detached transfer retains its registration point");
            let observation_point = root
                .point_handle(transfer.observation_point)
                .expect("validated detached transfer retains its observation point");
            let observation = ValueAtPoint::new(
                value,
                observation_point,
                ObservationPhase::BeforeEffects,
                OracleCallContext::empty(),
            )
            .expect("detached transfer value and registration point share one procedure");
            let oracle = self.selectors.workspace().semantic_oracle_provider();
            let continuation = self
                .selectors
                .continue_semantic(|request| oracle.pointees(&observation, request))
                .map_err(typestate_selector_error)?;
            require_uninterrupted_semantic_outcome(
                continuation.outcome(),
                "detached-task transfer heap analysis",
            )?;
            self.selectors
                .require_execution_budget("detached-task transfer heap analysis")
                .map_err(typestate_selector_error)?;
            let exact_object = continuation
                .outcome()
                .is_complete()
                .then(|| continuation.outcome().available_value())
                .flatten()
                .filter(|result| result.objects().coverage().is_exhaustive())
                .and_then(|result| {
                    let [candidate] = result.objects().candidates() else {
                        return None;
                    };
                    candidate.is_proven_complete().then_some(candidate.value())
                })
                .map(TypestateObjectKey::for_object);
            let exact_object = continuation
                .finish_scalar(exact_object, "detached-task transfer heap analysis")
                .map_err(typestate_selector_error)?;
            if let Some(object) = exact_object
                && !exact_transfers
                    .iter()
                    .any(|(existing, start)| existing == &object && start == &point)
            {
                exact_transfers.push((object, point));
            }
        }
        Ok(exact_transfers)
    }

    /// Subjects this observation may act on that its own object set did not
    /// name, in the order the caller supplied them.
    ///
    /// A protocol subject follows the object, not the spelling, so an event on
    /// a proven alias of the subject has to reach the same subject state. The
    /// object set `pointees` already produced answers that for every subject it
    /// names. This answers it for the rest, and only when the object set is
    /// open: a closed set that does not name the subject has proved the value
    /// does not denote it, and no further question is worth asking. When the
    /// set is open the heap oracle's [`AliasRelation`] is the only admissible
    /// source of the answer -- there is no second alias engine here -- and a
    /// `MayAlias` answer binds here. A later compiler pass may remove that
    /// tentative binding only when the fresh-object publication oracle proves
    /// the same subject/call pair noninterfering.
    ///
    /// The query is procedure-local by contract ([`AliasQuery`] rejects two
    /// observations in different procedures), so a subject rooted outside the
    /// observation's procedure keeps today's behaviour and is skipped.
    fn alias_bound_subjects(
        &mut self,
        resolved: &ResolvedSelection,
        subjects: &[&CompiledTypestateSubject],
    ) -> Result<Vec<TypestateSubjectKey>, TypestatePolicyCompileError> {
        if resolved.coverage.is_exhaustive() || subjects.is_empty() {
            return Ok(Vec::new());
        }
        let limits = *self
            .selectors
            .workspace()
            .semantic_oracle_provider()
            .limits();
        let observed = access_path_at_observation(
            resolved,
            AccessPathRoot::Value(resolved.observation.value().clone()),
            limits,
        )
        .expect("the observed value is scoped to the observation point's procedure");
        let mut bound = Vec::new();
        for subject in subjects {
            let Some(candidate) =
                access_path_at_observation(resolved, subject.object.identity().clone(), limits)
            else {
                continue;
            };
            let query = AliasQuery::new(observed.clone(), candidate)
                .expect("both alias operands were built at the same observation");
            let oracle = self.selectors.workspace().semantic_oracle_provider();
            let continuation = self
                .selectors
                .continue_semantic(|request| oracle.alias(&query, request))
                .map_err(typestate_selector_error)?;
            require_uninterrupted_semantic_outcome(
                continuation.outcome(),
                "subject alias analysis",
            )?;
            self.selectors
                .require_execution_budget("subject alias analysis")
                .map_err(typestate_selector_error)?;
            let Some(answer) = continuation
                .outcome()
                .available_value()
                .map(|result| *result.answer().value())
            else {
                continue;
            };
            let answer = continuation
                .finish_scalar(answer, "subject alias analysis")
                .map_err(typestate_selector_error)?;
            match answer {
                AliasRelation::MustAlias | AliasRelation::MayAlias => {
                    bound.push(subject.key.clone());
                }
                AliasRelation::Disjoint => {}
            }
        }
        Ok(bound)
    }

    fn resolve_named_argument_index(
        &mut self,
        call: &CallSiteHandle,
        expected_name: &str,
    ) -> Result<u32, TypestatePolicyCompileError> {
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        let leases = self.selectors.begin_semantic_lease_window();
        let dispatch_outcome = self
            .selectors
            .continue_semantic_in_window(&leases, |request| oracle.resolve_call(call, request))
            .map_err(typestate_selector_error)?;
        require_uninterrupted_semantic_outcome(&dispatch_outcome, "formal-name dispatch")?;
        self.selectors
            .require_execution_budget("formal-name dispatch")
            .map_err(typestate_selector_error)?;
        if !dispatch_outcome.is_complete() {
            return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                "formal-name binding `{expected_name}` requires complete dispatch"
            )));
        }
        let dispatch = dispatch_outcome.available_value().ok_or_else(|| {
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
        if dispatch
            .candidates()
            .iter()
            .any(|candidate| !matches!(candidate.proof(), ProofStatus::Proven))
        {
            return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                "formal-name binding `{expected_name}` has an unproven dispatch target"
            )));
        }
        let mut common_index = None;
        for candidate in dispatch.candidates() {
            let bindings_outcome = self
                .selectors
                .continue_semantic_in_window(&leases, |request| {
                    oracle.call_bindings(call, candidate, &OracleCallContext::empty(), request)
                })
                .map_err(typestate_selector_error)?;
            require_uninterrupted_semantic_outcome(
                &bindings_outcome,
                "formal-name argument binding",
            )?;
            self.selectors
                .require_execution_budget("formal-name argument binding")
                .map_err(typestate_selector_error)?;
            if !bindings_outcome.is_complete() {
                return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                    "formal-name binding `{expected_name}` requires complete argument binding"
                )));
            }
            let bindings = bindings_outcome.available_value().ok_or_else(|| {
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
        let common_index = common_index.ok_or_else(|| {
            TypestatePolicyCompileError::SemanticUnavailable(format!(
                "formal-name binding `{expected_name}` has no mapped argument"
            ))
        })?;
        drop(dispatch_outcome);
        leases
            .finish_scalar(common_index, "formal-name argument binding")
            .map_err(typestate_selector_error)
    }

    fn formal_parameter_has_name(
        &mut self,
        formal: &ProcedurePortHandle,
        expected_name: &str,
    ) -> Result<bool, TypestatePolicyCompileError> {
        let ProcedurePortKind::Parameter { ordinal } = formal.kind() else {
            return Ok(false);
        };
        let formal_key = FormalPortKey::of(formal);
        if let Some(names) = self.formal_names.get(&formal_key) {
            return Ok(parameter_names_match(names, expected_name));
        }
        if self.selectors.cancellation().is_cancelled() {
            return Err(TypestatePolicyCompileError::QueryIncomplete {
                completion: CodeQueryCompletion::Cancelled,
                detail: "formal-parameter layout resolution was cancelled".to_owned(),
            });
        }
        self.selectors
            .remaining_semantic_traversal_steps()
            .map_err(typestate_selector_error)?;
        if !self.selectors.execution_budget().charge_traversal(1) {
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
            self.selectors
                .workspace()
                .analyzer()
                .project()
                .root()
                .to_path_buf(),
            locator.path().as_path(),
        );
        let Some(source) = self.selectors.workspace().analyzer().indexed_source(&file) else {
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
        self.formal_names.insert(formal_key, names);
        Ok(matches)
    }
}

#[derive(Clone)]
enum SelectorBinding {
    MatchedValue,
    Receiver,
    ReturnValue,
    ResultIndex(u32),
    ArgumentIndex(u32),
    ArgumentName(String),
}

impl SelectorBinding {
    fn from_subject(binding: &ResolvedTypestateBinding) -> Self {
        match binding {
            ResolvedTypestateBinding::MatchedValue => Self::MatchedValue,
            ResolvedTypestateBinding::Receiver => Self::Receiver,
            ResolvedTypestateBinding::ReturnValue => Self::ReturnValue,
            ResolvedTypestateBinding::ResultIndex { index } => Self::ResultIndex(*index),
            ResolvedTypestateBinding::ArgumentIndex { index } => Self::ArgumentIndex(*index),
            ResolvedTypestateBinding::ArgumentName { name } => Self::ArgumentName(name.clone()),
        }
    }

    fn from_call(binding: &TypestateCallBinding) -> Self {
        match binding {
            TypestateCallBinding::Receiver => Self::Receiver,
            TypestateCallBinding::ReturnValue => Self::ReturnValue,
            TypestateCallBinding::ResultIndex { index } => Self::ResultIndex(*index),
            TypestateCallBinding::ArgumentIndex { index } => Self::ArgumentIndex(*index),
            TypestateCallBinding::ArgumentName { name } => Self::ArgumentName(name.clone()),
        }
    }

    fn from_endpoint(binding: &PolicyEndpointBinding) -> Self {
        match binding {
            PolicyEndpointBinding::MatchedValue => Self::MatchedValue,
            PolicyEndpointBinding::Receiver => Self::Receiver,
            PolicyEndpointBinding::ReturnValue => Self::ReturnValue,
            PolicyEndpointBinding::ResultIndex { index } => Self::ResultIndex(*index),
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
    result_contract: Option<super::selector_compiler::PolicyResultContractSelection>,
    call_shape: Option<super::selector_compiler::PolicyCallShapeSelection>,
    /// This row came from a query that already contributes the selector-level
    /// run-incomplete diagnostic for retained result-contract evidence.
    retained_incomplete_result_contract_query: bool,
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
    activation_edge: Option<brokk_bifrost_analysis::analyzer::semantic::ControlEdgeHandle>,
    role: TypestateObjectRole,
    object: AbstractObject,
    /// Quality of the selected object itself. Activation uncertainty belongs
    /// to the individual seed edge and must not weaken a sibling exact edge.
    subject_quality: TypestateBindingQuality,
    quality: TypestateBindingQuality,
    member_contracts:
        Vec<brokk_bifrost_analysis::analyzer::semantic_model::CompiledResultMemberContract>,
    fresh_result: bool,
    escapes_before_activation: bool,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SubjectObservationGroupKey {
    site: TypestateObservationSite,
    activation_edge: Option<brokk_bifrost_analysis::analyzer::semantic::ControlEdgeHandle>,
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
                activation_edge: candidate.activation_edge.clone(),
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
    modeled_external_effect: Option<String>,
    alias_derived: bool,
}

fn modeled_external_effect_id(
    subject: &CompiledTypestateSubject,
    selection: &ResolvedSelection,
    phase: EndpointObservationPhase,
) -> Option<String> {
    if !subject.fresh_result || phase != EndpointObservationPhase::AfterNormalReturn {
        return None;
    }
    let shape = selection.call_shape.as_ref()?;
    let callee = shape.callee_name.as_deref()?;
    subject
        .member_contracts
        .iter()
        .find(|contract| {
            contract.member == callee
                && contract.parameter_count == shape.argument_count
                && contract.completeness == Completeness::Complete
                && contract.declared_effects.len() == 1
                && contract.declared_effects[0].timing == CompiledDeclaredEffectTiming::Immediate
                && contract.declared_effects[0].certainty
                    == CompiledDeclaredEffectCertainty::Definite
        })
        .map(|contract| contract.declared_effects[0].id.clone())
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
    alias_derived: bool,
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

/// The applicable subjects this observation's own object set did not name.
///
/// These are exactly the subjects the identity match above skipped, so asking
/// the heap oracle about them adds bindings rather than changing any.
fn subjects_absent_from<'a>(
    resolved: &ResolvedSelection,
    subjects: &'a [CompiledTypestateSubject],
    applies: impl Fn(&CompiledTypestateSubject) -> bool,
) -> Vec<&'a CompiledTypestateSubject> {
    subjects
        .iter()
        .filter(|subject| {
            applies(subject)
                && !resolved.objects.iter().any(|object| {
                    subject.key.object()
                        == TypestateSubjectKey::for_object(
                            subject.key.class().clone(),
                            &object.object,
                        )
                        .object()
                })
        })
        .collect()
}

/// One object identity as a whole-object access path at this observation.
///
/// `None` means the root belongs to another procedure, or to an artifact this
/// observation's materialization no longer holds. Neither is an error here: an
/// alias query relates two paths at one point in one procedure, so a root from
/// somewhere else is a question this oracle cannot be asked rather than a
/// question it answered badly. The caller skips that subject, which is the
/// behaviour it had before alias binding existed.
fn access_path_at_observation(
    resolved: &ResolvedSelection,
    root: AccessPathRoot,
    limits: OracleLimits,
) -> Option<AccessPathAtPoint> {
    let path = AccessPath::exact(root, Vec::new(), limits).ok()?;
    AccessPathAtPoint::new(
        path,
        resolved.observation.point().clone(),
        resolved.observation.phase(),
        resolved.observation.context().clone(),
    )
    .ok()
}

/// The quality one may-alias subject binding carries.
///
/// A binding the heap oracle could not prove must never be definitive. This is
/// the whole guard against a `MayAlias` answer being reported as a clean
/// protocol run: the event still reaches the subject, and every finding it
/// produces stays a possible one.
fn may_alias_quality(multiplicity: TypestateBindingMultiplicity) -> TypestateBindingQuality {
    const REASON: &str = "typestate subject binding rests on a heap-oracle may-alias";
    TypestateBindingQuality::new(
        ProofStatus::Unproven(REASON.into()),
        EvidenceCompleteness::Partial(REASON.into()),
        multiplicity,
    )
}

struct ResolvedSelection {
    procedure: ProcedureHandle,
    call: Option<CallSiteHandle>,
    observation_point: ProgramPointHandle,
    role: TypestateObjectRole,
    objects: Vec<ResolvedObject>,
    /// The exact value observation the object set above answers, retained so a
    /// subject the object set did not name can still be asked about through
    /// the heap oracle's alias relation.
    observation: ValueAtPoint,
    /// Whether that object set is closed. An open set means the value may
    /// denote an object the oracle did not enumerate, so a subject missing
    /// from the set is not thereby excluded.
    coverage: CandidateCoverage,
    multiplicity: TypestateBindingMultiplicity,
    /// Normalized guard edges on which this conditional subject begins to
    /// exist, with edge-local quality. Empty means an ordinary unconditional
    /// subject selection. An open relation may retain exact edges beside
    /// additional positioned partial-positive candidates.
    activation_edges: Vec<ResolvedActivationEdge>,
    member_contracts:
        Vec<brokk_bifrost_analysis::analyzer::semantic_model::CompiledResultMemberContract>,
    call_shape: Option<super::selector_compiler::PolicyCallShapeSelection>,
    fresh_result_identity: bool,
    retained_incomplete_result_contract_query: bool,
}

impl ResolvedSelection {
    /// Return whether every exact artifact retained by this selection
    /// satisfies `predicate`.
    fn retained_artifact_coverage(
        &self,
        mut predicate: impl FnMut(&Arc<SemanticArtifact>) -> bool,
    ) -> bool {
        let mut all_covered = true;
        let mut visit = |artifact: &Arc<SemanticArtifact>| {
            all_covered &= predicate(artifact);
        };

        visit(self.procedure.artifact());
        if let Some(call) = &self.call {
            visit(call.procedure().artifact());
        }
        visit(self.observation_point.procedure().artifact());
        visit(self.observation.value().procedure().artifact());
        visit(self.observation.point().procedure().artifact());
        for call in self.observation.context().calls() {
            visit(call.procedure().artifact());
        }
        for object in &self.objects {
            object
                .object
                .identity()
                .for_each_retained_artifact(&mut visit);
        }
        for activation in &self.activation_edges {
            visit(activation.edge.procedure().artifact());
        }
        all_covered
    }
}

#[derive(Clone)]
struct ResolvedActivationEdge {
    edge: brokk_bifrost_analysis::analyzer::semantic::ControlEdgeHandle,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FreshResultPreActivationPublication {
    NotPublished,
    Published,
    PossiblePublication,
    Incomplete,
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

fn select_calls(
    procedures: &[ProcedureHandle],
    selection: &SelectedSite,
) -> Result<Vec<(ProcedureHandle, CallSiteHandle)>, TypestatePolicyCompileError> {
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
        return Ok(Vec::new());
    };
    let best_rank = (best.0, best.1);
    let best_procedure = best.2.semantics().locator().clone();
    let equally_ranked = candidates
        .into_iter()
        .take_while(|candidate| (candidate.0, candidate.1) == best_rank)
        .collect::<Vec<_>>();
    if equally_ranked
        .iter()
        .any(|candidate| candidate.2.semantics().locator() != &best_procedure)
    {
        return Err(TypestatePolicyCompileError::AmbiguousSemanticSite(
            "selected source row identifies equal semantic call sites in different procedures"
                .to_owned(),
        ));
    }
    Ok(equally_ranked
        .into_iter()
        .map(|(_, _, procedure, call)| (procedure, call))
        .collect())
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
        SelectorBinding::ResultIndex(index) => (
            call.normal_result(usize::try_from(*index).map_err(|_| {
                TypestatePolicyCompileError::UnsupportedBinding(
                    "result index does not fit this platform".to_owned(),
                )
            })?)
            .ok_or_else(|| {
                TypestatePolicyCompileError::SemanticUnavailable(format!(
                    "selected call has no normal result at index {index}"
                ))
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
            if matches!(
                binding,
                &SelectorBinding::ReturnValue | &SelectorBinding::ResultIndex(_)
            ) =>
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

fn detached_call_lacks_requested_observation(
    invocation_mode: CallInvocationMode,
    binding: &SelectorBinding,
    phase: Option<EndpointObservationPhase>,
) -> bool {
    invocation_mode == CallInvocationMode::Detached
        && match phase {
            Some(
                EndpointObservationPhase::AfterNormalReturn
                | EndpointObservationPhase::AfterExceptionalReturn,
            ) => true,
            None => matches!(
                binding,
                SelectorBinding::ReturnValue | SelectorBinding::ResultIndex(_)
            ),
            Some(EndpointObservationPhase::AtMatch | EndpointObservationPhase::BeforeCall) => false,
        }
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
    let escape_event =
        internal_escape_event_key(automaton.events.iter().map(|event| event.id.as_str()));
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
            .chain(std::iter::once(ProtocolEventSpec {
                id: escape_event.as_str().to_owned(),
                observation: ProtocolObservationSpec {
                    occurrence: ProtocolEventOccurrence::Escape,
                },
            }))
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
    use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
    use crate::definition::{
        CallModelingSpec, InconclusivePolicy, TypestateExitScope, TypestateUncertaintySpec,
    };
    use crate::inline_project::InlineTestProject;
    use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
    use crate::resolved::{ResolvedTypestateAutomatonSpec, ResolvedTypestateEventSpec};
    use brokk_bifrost_analysis::analyzer::semantic::{
        AdapterSemanticsVersion, ConfigurationFingerprint, ContentIdentity, DeclarationLocator,
        DeclarationSegment, DeclarationSegmentKind, DependencyFingerprint, ScopedSemanticLocator,
        SemanticArtifactKey, SemanticCapabilities, SemanticIrVersion, SemanticLanguage,
        SemanticRole, SourceAnchor, SourcePosition, SourceRevision, SourceSpan, WorkspaceMountId,
        WorkspaceRelativePath,
    };
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language};
    use brokk_bifrost_flow::dataflow::UnmodeledCallBehavior;

    /// A sliced compile mints the compile a whole compile mints.
    ///
    /// The four things a later stage of the evaluation reads out of a compile:
    /// the protocol and binding-plan hashes, which every finding identity
    /// folds; the semantic budget the root solves inherit; and the artifact
    /// leases the evaluation's windows open against. A sliced compile that
    /// moved any of them differently would hand the solve a different
    /// evaluation, not the same one computed a cheaper way
    /// (`.agents/plans/impact-sliced-diff-base.md`, Decision Log (5c)).
    #[test]
    fn a_sliced_selector_compile_produces_the_compile_a_whole_one_produces() {
        const POLICY_PATH: &str = "policies/sliced-lifecycle.rqlp";
        // Two selectors over the same seed files -- the subject's and the
        // close event's -- because one selector could not show that two
        // selectors of one policy get separate units.
        const POLICY: &str = r#"(policy
  :schema-version 1
  :id "bifrost.test.sliced-lifecycle"
  :name "Sliced resource lifecycle"
  :message "resource was not closed"
  :severity warning
  :analysis
    (analysis
      :type typestate
      :mode may
      :subjects
        (subject-set
          :entries [
            (subject :id res
              :selector (rql :schema-version 1
                (language go (call :callee (name "OpenRes"))))
              :subject return-value)])
      :uncertainty (uncertainty :escape inconclusive)
      :automaton
        (automaton
          :states [open closed violated]
          :initial open
          :accepting-states [closed]
          :error-states [violated]
          :events [
            (event :id close
              :calls (calls
                :selector (rql :schema-version 1
                  (language go (call :callee (name "CloseRes"))))
                :subject (argument :index 0)
                :phase after-normal-return))]
          :transitions [
            (transition :from open :on close :to closed)
            (transition :from closed :on close :to violated)]
          :terminal-expectations [
            (terminal-expectation :id normal-exit
              :on (normal-procedure-exit :scope analysis-root)
              :expected-states [closed])])))"#;
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/sliced-lifecycle\n")
            .file(
                "res.go",
                "package lifecycle\n\ntype Res struct{}\n\nfunc OpenRes() *Res { return &Res{} }\n\nfunc CloseRes(r *Res) {}\n",
            )
            .file(
                "app.go",
                "package lifecycle\n\nfunc Run() {\n\tr := OpenRes()\n\tCloseRes(r)\n}\n",
            )
            .file(POLICY_PATH, POLICY)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry = PolicyRegistry::new_for_workspace(
            project.root().to_path_buf(),
            catalogs,
            PolicyRegistryLimits::default(),
        )
        .expect("absolute inline workspace opens for policy loading");
        let policy = registry
            .load_policy_path(POLICY_PATH)
            .expect("fixture typestate policy loads");
        let spec = policy
            .resolved_typestate()
            .expect("fixture policy resolves typestate authoring");
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let compile = |units: Option<&PolicyIncrementalContext<'_>>| {
            let compiler = TypestatePolicyCompiler::new(
                &workspace,
                budget.query_limits(),
                budget.max_selector_results(),
                &cancellation,
            );
            let (compiled, outcome) = match units {
                Some(incremental) => compiler
                    .with_units(policy, incremental, &budget)
                    .compile_with_units(policy, spec),
                None => compiler.compile_with_units(policy, spec),
            };
            let compiled = compiled
                .unwrap_or_else(|failure| panic!("fixture policy compiles: {}", failure.error));
            (compiled, outcome)
        };

        // One compile ahead of the two that are compared. The workspace's
        // content-keyed semantic caches are warmed by whichever compile runs
        // first, and a cold compile charges its own materializations while a
        // warm one does not, so two compiles are comparable only from the same
        // cache state. This one puts both of them in it.
        let _warm = compile(None);

        // The store starts empty, so every unit is executed here and
        // published: this is the compile a base evaluation performs.
        let store = RefCell::new(crate::units::InMemoryPolicyUnitStore::new());
        let store: &RefCell<dyn crate::units::PolicyUnitStore> = &store;
        let changed =
            brokk_bifrost_analysis::analyzer::ChangedFacts::between(&workspace, &workspace);
        let incremental = PolicyIncrementalContext::new(
            store,
            &workspace,
            &changed,
            crate::units::WorkspaceUnitInputs::of(
                &workspace,
                workspace
                    .analyzer()
                    .active_semantic_model_snapshot()
                    .as_deref(),
            ),
            crate::units::IncrementalBaseState::Evaluated,
        );
        let (sliced, sliced_units) = compile(Some(&incremental));
        let sliced_units = sliced_units.expect("a compile with units reports what they did");
        assert_eq!(
            sliced_units.widen, None,
            "this policy's selectors are partitionable by seed file"
        );
        assert!(
            sliced_units.attempt.total() > 0,
            "the sliced compile decided about at least one unit: {sliced_units:#?}"
        );

        let (whole, whole_units) = compile(None);
        assert!(
            whole_units.is_none(),
            "a compile with no incremental context decides about no unit"
        );

        assert_eq!(
            (sliced.protocol.hash(), sliced.bindings.hash()),
            (whole.protocol.hash(), whole.bindings.hash()),
            "two compiles of one policy over one workspace are the same compile"
        );
        assert_eq!(
            sliced.semantic_remaining, whole.semantic_remaining,
            "a sliced compile leaves the root solves the semantic budget a whole compile leaves"
        );
        assert_eq!(
            (
                sliced.artifact_leases.len(),
                sliced.artifact_leases.retained_bytes()
            ),
            (
                whole.artifact_leases.len(),
                whole.artifact_leases.retained_bytes()
            ),
            "a sliced compile retains the artifact allocations a whole compile retains"
        );
    }

    /// A selector whose plan is not partitionable by seed asks to be compiled
    /// again rather than being sliced anyway.
    ///
    /// A set node gives each branch a fair share of the live budget and
    /// re-runs a starved branch, so a branch's rows depend on what earlier
    /// branches consumed and no per-seed execution reproduces them
    /// (`PlanPartitioning::classify`). The compile says so with the typed
    /// reason instead of publishing units that do not partition anything.
    #[test]
    fn a_selector_whose_plan_crosses_seeds_widens_the_compile() {
        const POLICY_PATH: &str = "policies/set-source-lifecycle.rqlp";
        const POLICY: &str = r#"(policy
  :schema-version 1
  :id "bifrost.test.set-source-lifecycle"
  :name "Set-source resource lifecycle"
  :message "resource was not closed"
  :severity warning
  :analysis
    (analysis
      :type typestate
      :mode may
      :subjects
        (subject-set
          :entries [
            (subject :id res
              :selector (rql :schema-version 1
                (union
                  (language go (call :callee (name "OpenRes")))
                  (language go (call :callee (name "OpenOther")))))
              :subject return-value)])
      :uncertainty (uncertainty :escape inconclusive)
      :automaton
        (automaton
          :states [open closed violated]
          :initial open
          :accepting-states [closed]
          :error-states [violated]
          :events [
            (event :id close
              :calls (calls
                :selector (rql :schema-version 1
                  (language go (call :callee (name "CloseRes"))))
                :subject (argument :index 0)
                :phase after-normal-return))]
          :transitions [
            (transition :from open :on close :to closed)
            (transition :from closed :on close :to violated)]
          :terminal-expectations [
            (terminal-expectation :id normal-exit
              :on (normal-procedure-exit :scope analysis-root)
              :expected-states [closed])])))"#;
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/set-source-lifecycle\n")
            .file(
                "res.go",
                "package lifecycle\n\ntype Res struct{}\n\nfunc OpenRes() *Res { return &Res{} }\n\nfunc OpenOther() *Res { return &Res{} }\n\nfunc CloseRes(r *Res) {}\n",
            )
            .file(
                "app.go",
                "package lifecycle\n\nfunc Run() {\n\tr := OpenRes()\n\tCloseRes(r)\n}\n",
            )
            .file(POLICY_PATH, POLICY)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry = PolicyRegistry::new_for_workspace(
            project.root().to_path_buf(),
            catalogs,
            PolicyRegistryLimits::default(),
        )
        .expect("absolute inline workspace opens for policy loading");
        let policy = registry
            .load_policy_path(POLICY_PATH)
            .expect("fixture typestate policy loads");
        let spec = policy
            .resolved_typestate()
            .expect("fixture policy resolves typestate authoring");
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let store = RefCell::new(crate::units::InMemoryPolicyUnitStore::new());
        let store: &RefCell<dyn crate::units::PolicyUnitStore> = &store;
        let changed =
            brokk_bifrost_analysis::analyzer::ChangedFacts::between(&workspace, &workspace);
        let incremental = PolicyIncrementalContext::new(
            store,
            &workspace,
            &changed,
            crate::units::WorkspaceUnitInputs::of(
                &workspace,
                workspace
                    .analyzer()
                    .active_semantic_model_snapshot()
                    .as_deref(),
            ),
            crate::units::IncrementalBaseState::Evaluated,
        );
        let (compiled, units) = TypestatePolicyCompiler::new(
            &workspace,
            budget.query_limits(),
            budget.max_selector_results(),
            &cancellation,
        )
        .with_units(policy, &incremental, &budget)
        .compile_with_units(policy, spec);
        let failure =
            compiled.expect_err("a compile that cannot be sliced does not return a sliced compile");
        assert_eq!(
            failure.widen(),
            Some(WidenReason::PlanCrossesSeeds),
            "a set-source selector is not partitionable by seed file: {}",
            failure.error
        );
        assert_eq!(
            units
                .expect("a compile with units reports what they did")
                .widen,
            Some(WidenReason::PlanCrossesSeeds),
            "the attempt reports the reason it stopped"
        );
    }

    fn scoped_root_fixture(source: &str) -> (Arc<SemanticArtifact>, ScopedSemanticLocator) {
        let path = WorkspaceRelativePath::new("scope.go").expect("portable fixture path");
        let key = SemanticArtifactKey::new(
            WorkspaceMountId::hash_bytes(b"policy retained-artifact visitor mount"),
            path.clone(),
            SemanticLanguage::Standard(Language::Go),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(source.as_bytes()),
            },
            AdapterSemanticsVersion::hash_bytes("policy-retained-visitor-go", b"adapter")
                .expect("non-empty adapter name"),
            SemanticIrVersion::hash_bytes(b"policy retained-artifact visitor IR"),
            ConfigurationFingerprint::hash_bytes(b"policy retained-artifact visitor configuration"),
            DependencyFingerprint::hash_bytes(b"policy retained-artifact visitor dependencies"),
        );
        let start = SourcePosition::new(0, 0, 0);
        let end = SourcePosition::new(1, 0, 1);
        let anchor = SourceAnchor::new(
            SourceSpan::new(start, end).expect("ordered fixture span"),
            0,
        );
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::File, "scope.go", anchor, 0)
                .expect("valid fixture declaration segment"),
        ])
        .expect("non-empty fixture declaration");
        let locator = SemanticLocator::new(
            key.mount(),
            path,
            key.language(),
            declaration,
            SemanticRole::MemoryLocation,
            anchor,
        );
        let artifact = Arc::new(
            SemanticArtifact::try_new(key, SemanticCapabilities::default(), Vec::new())
                .expect("empty complete fixture artifact"),
        );
        let scoped = ScopedSemanticLocator::new(Arc::clone(&artifact), locator)
            .expect("fixture locator shares the artifact mount");
        (artifact, scoped)
    }

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

    fn work_metric(work: &PolicyWorkReport, name: &str) -> u64 {
        work.metrics()
            .iter()
            .find(|metric| metric.name() == name)
            .unwrap_or_else(|| panic!("missing metric {name}: {:#?}", work.metrics()))
            .value()
    }

    #[test]
    fn detached_calls_reject_only_target_completion_observations() {
        let argument = SelectorBinding::ArgumentIndex(0);
        let result = SelectorBinding::ResultIndex(0);

        assert!(detached_call_lacks_requested_observation(
            CallInvocationMode::Detached,
            &argument,
            Some(EndpointObservationPhase::AfterNormalReturn),
        ));
        assert!(detached_call_lacks_requested_observation(
            CallInvocationMode::Detached,
            &argument,
            Some(EndpointObservationPhase::AfterExceptionalReturn),
        ));
        assert!(detached_call_lacks_requested_observation(
            CallInvocationMode::Detached,
            &result,
            None,
        ));
        assert!(!detached_call_lacks_requested_observation(
            CallInvocationMode::Detached,
            &argument,
            Some(EndpointObservationPhase::AtMatch),
        ));
        assert!(!detached_call_lacks_requested_observation(
            CallInvocationMode::Detached,
            &argument,
            Some(EndpointObservationPhase::BeforeCall),
        ));
        assert!(!detached_call_lacks_requested_observation(
            CallInvocationMode::Detached,
            &argument,
            None,
        ));
        assert!(!detached_call_lacks_requested_observation(
            CallInvocationMode::Ordinary,
            &argument,
            Some(EndpointObservationPhase::AfterNormalReturn),
        ));
    }

    #[test]
    fn exact_detached_arguments_and_captures_escape_at_registration() {
        const POLICY_PATH: &str = "policies/detached-resource-lifecycle.rqlp";
        const POLICY: &str = r#"(policy
  :schema-version 1
  :id "bifrost.test.detached-resource-lifecycle"
  :name "Detached resource lifecycle"
  :message "Resource lifecycle transferred to detached work"
  :severity error
  :analysis
    (analysis
      :type typestate
      :mode may
      :call-modeling (call-modeling :unmodeled paranoid)
      :subjects
        (subject-set
          :include-matches [
            (match-directory
              :path "policies/endpoints"
              :scope recursive
              :categories (all [resource.acquire]))]
          :entries [])
      :uncertainty (uncertainty :escape inconclusive)
      :automaton
        (automaton
          :states [open error]
          :initial open
          :accepting-states [open]
          :error-states [error]
          :events [
            (event :id finish :on (normal-procedure-exit :scope analysis-root))]
          :transitions [
            (transition :from open :on finish :to error)]
          :terminal-expectations [])))"#;
        const ACQUIRE_ENDPOINT: &str = r#"(endpoint
  :schema-version 1
  :id "bifrost.test.detached-resource-lifecycle.acquire"
  :name "Resource acquisition"
  :display-name "acquired resource"
  :role source
  :categories [resource.acquire]
  :selector (rql :schema-version 1 (language go (call :callee (name "OpenRes"))))
  :binding return-value
  :supersedes [])"#;

        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/detached-resource-lifecycle\n")
            .file(
                "resource.go",
                r#"package lifecycle

type Res struct{}

func OpenRes() *Res { return &Res{} }
func Consume(*Res) {}

func ExactArgumentEscape() {
    resource := OpenRes()
    go Consume(resource)
}

func ExactCaptureEscape() {
    resource := OpenRes()
    go func() { Consume(resource) }()
}

func OrdinaryNearMiss() {
    resource := OpenRes()
    Consume(resource)
}

func DeferredNearMiss() {
    resource := OpenRes()
    defer Consume(resource)
}

func AmbiguousNearMiss(flag bool) {
    var resource *Res
    if flag { resource = OpenRes() } else { resource = OpenRes() }
    go Consume(resource)
}
"#,
            )
            .file(POLICY_PATH, POLICY)
            .file("policies/endpoints/acquire.rqlp", ACQUIRE_ENDPOINT)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry = PolicyRegistry::new_for_workspace(
            project.root().to_path_buf(),
            catalogs,
            PolicyRegistryLimits::default(),
        )
        .expect("absolute inline workspace opens for policy loading");
        let policy = registry
            .load_policy_path(POLICY_PATH)
            .expect("fixture typestate policy loads");
        let spec = policy
            .resolved_typestate()
            .expect("fixture policy resolves typestate authoring");
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let compiled = TypestatePolicyCompiler::new(
            &workspace,
            budget.query_limits(),
            budget.max_selector_results(),
            &cancellation,
        )
        .compile_with_units(policy, spec)
        .0
        .unwrap_or_else(|failure| panic!("fixture policy compiles: {}", failure.error));

        let escapes = compiled
            .bindings
            .event_bindings()
            .iter()
            .filter(|binding| binding.role() == TypestateObjectRole::EscapedObject)
            .collect::<Vec<_>>();
        assert_eq!(
            escapes.len(),
            2,
            "only exact detached argument and immutable capture transfers escape: {:#?}",
            compiled.bindings.event_bindings()
        );
        let escape_event = compiled
            .protocol
            .event_id(&internal_escape_event_key(std::iter::empty()))
            .expect("compiler appends its internal escape event");
        assert!(
            escapes
                .iter()
                .all(|binding| binding.event() == escape_event)
        );
    }

    #[test]
    fn projection_failure_retains_compile_and_partial_evaluation_work() {
        const POLICY_PATH: &str = "policies/resource-lifecycle.rqlp";
        const POLICY: &str = r#"(policy
  :schema-version 1
  :id "bifrost.test.measured-projection-failure"
  :name "Measured projection failure"
  :message "Resource is not closed before exit"
  :severity error
  :analysis
    (analysis
      :type typestate
      :mode may
      :call-modeling (call-modeling :unmodeled paranoid)
      :subjects
        (subject-set
          :include-matches [
            (match-directory
              :path "policies/endpoints"
              :scope recursive
              :categories (all [resource.acquire]))]
          :entries [])
      :uncertainty (uncertainty :escape inconclusive)
      :automaton
        (automaton
          :states [open closed error]
          :initial open
          :accepting-states [closed]
          :error-states [error]
          :events [
            (event :id close
              :matches (match-directory :path "policies/endpoints" :scope recursive
                        :role sink :phase after-normal-return
                        :categories (all [resource.close]))
              :supersedes [])]
          :transitions [
            (transition :from open :on close :to closed)
            (transition :from closed :on close :to error)]
          :terminal-expectations [
            (terminal-expectation
              :id "normal-exit-closed"
              :on (normal-procedure-exit :scope analysis-root)
              :expected-states [closed]
              :supersedes [])])))"#;
        const ACQUIRE_ENDPOINT: &str = r#"(endpoint
  :schema-version 1
  :id "bifrost.test.measured-projection-failure.acquire"
  :name "Resource acquisition"
  :display-name "acquired resource"
  :role source
  :categories [resource.acquire]
  :selector (rql :schema-version 1 (language go (call :callee (name "OpenRes"))))
  :binding return-value
  :supersedes [])"#;
        const CLOSE_ENDPOINT: &str = r#"(endpoint
  :schema-version 1
  :id "bifrost.test.measured-projection-failure.close"
  :name "Resource close"
  :display-name "resource close"
  :role sink
  :categories [resource.close]
  :selector (rql :schema-version 1 (language go (call :callee (name "Close"))))
  :binding receiver
  :supersedes [])"#;

        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/measured-projection-failure\n")
            .file(
                "resource.go",
                r#"package lifecycle

type Res struct{}

func OpenRes() *Res { return &Res{} }

func MissingClose() {
    resource := OpenRes()
    _ = resource
}
"#,
            )
            .file(POLICY_PATH, POLICY)
            .file("policies/endpoints/acquire.rqlp", ACQUIRE_ENDPOINT)
            .file("policies/endpoints/close.rqlp", CLOSE_ENDPOINT)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry = PolicyRegistry::new_for_workspace(
            project.root().to_path_buf(),
            catalogs,
            PolicyRegistryLimits::default(),
        )
        .expect("absolute inline workspace opens for policy loading");
        let policy = registry
            .load_policy_path(POLICY_PATH)
            .expect("fixture typestate policy loads");
        let spec = policy
            .resolved_typestate()
            .expect("fixture policy resolves typestate authoring");
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let compiled = TypestatePolicyCompiler::new(
            &workspace,
            budget.query_limits(),
            budget.max_selector_results(),
            &cancellation,
        )
        .compile_with_units(policy, spec)
        .0
        .unwrap_or_else(|failure| panic!("fixture policy compiles: {}", failure.error));
        let authority = TypestateProjectionAuthority::from_loaded_compilation(
            policy,
            compiled.protocol.hash(),
            compiled.bindings.hash(),
        )
        .expect("compiled fixture mints projection authority");
        let mut mismatched_spec = spec.clone();
        mismatched_spec.subjects.clear();

        let failure = match evaluate_compiled_typestate(
            &authority,
            policy,
            &mismatched_spec,
            &workspace,
            Some(&cancellation),
            &budget,
            &compiled,
            &ProductionTypestateSummaryRepository::new(),
            None,
            None,
        ) {
            RootsPass::Failed(failure) => failure,
            RootsPass::Complete(_) | RootsPass::Widen(_) => {
                panic!("projection must reject a subject absent from the supplied spec")
            }
        };
        assert_eq!(
            failure.message,
            "typestate finding subject is absent from the loaded policy"
        );
        let work = failure.work.clone();
        assert!(
            work_metric(&work, "typestate.selector_scans") > 0,
            "failed projection must retain compile-time selector work: {work:#?}"
        );
        assert!(
            work_metric(&work, "typestate.evaluation_semantic_source_bytes") > 0,
            "failed projection must retain partial evaluation work: {work:#?}"
        );
        assert!(
            work_metric(&work, "typestate.evaluation_semantic_traversal_steps") > 0,
            "failed projection must retain partial evaluation traversal: {work:#?}"
        );
        assert!(
            work_metric(&work, "typestate.semantic_traversal_steps")
                >= work_metric(&work, "typestate.evaluation_semantic_traversal_steps"),
            "shared traversal must contain the evaluation delta without recounting it: {work:#?}"
        );
        assert_eq!(
            work_metric(&work, "typestate.semantic_peak_traversal_steps"),
            work_metric(&work, "typestate.semantic_traversal_steps"),
            "failed projection must retain the cumulative traversal peak"
        );
        assert_eq!(work.retained_findings(), 0);

        let payload = failed_projection_payload(&failure.message, failure.work);
        assert!(payload.projections.is_empty());
        assert!(matches!(
            payload.completion,
            PolicyRunCompletion::Failed { .. }
        ));
        assert_eq!(payload.work, work);
        assert_eq!(payload.diagnostics.len(), 1);
        assert_eq!(payload.diagnostics[0].message(), failure.message);
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
    fn internal_escape_event_avoids_authored_event_ids() {
        let mut spec = minimal_resolved_spec(UnmodeledCallBehavior::Paranoid);
        let event = PolicySemanticEvent::NormalProcedureExit {
            scope: TypestateExitScope::AnalysisRoot,
        };
        spec.automaton.events = ["bifrost-internal-escape", "bifrost-internal-escape-1"]
            .into_iter()
            .map(|id| {
                ResolvedTypestateEventSpec::new(
                    PolicyTypestateEventId::new(id).unwrap(),
                    ResolvedTypestateEventTrigger::SemanticEvent { event },
                    Vec::new(),
                    Vec::new(),
                )
            })
            .collect();

        let protocol = compile_protocol(&spec).expect("authored event IDs must not collide");
        let hidden = ProtocolEventKey::new("bifrost-internal-escape-2").unwrap();
        assert!(protocol.event_id(&hidden).is_some());
        assert_eq!(protocol.events().len(), 3);
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

    #[test]
    fn scoped_object_roots_visit_their_exact_scope_allocation() {
        let (artifact, scoped) = scoped_root_fixture("same source");
        for root in [
            AccessPathRoot::Static(scoped.clone()),
            AccessPathRoot::TypeSummary(scoped.clone()),
            AccessPathRoot::ModuleObject(scoped.clone()),
            AccessPathRoot::External(scoped),
        ] {
            let mut visited = Vec::new();
            root.for_each_retained_artifact(|candidate| visited.push(Arc::clone(candidate)));
            assert_eq!(visited.len(), 1);
            assert!(Arc::ptr_eq(&visited[0], &artifact));
        }

        let (same_key_distinct_artifact, same_key_distinct_scope) =
            scoped_root_fixture("same source");
        assert_eq!(artifact.key(), same_key_distinct_artifact.key());
        assert!(!Arc::ptr_eq(&artifact, &same_key_distinct_artifact));
        let mut all_covered = true;
        AccessPathRoot::External(same_key_distinct_scope).for_each_retained_artifact(|candidate| {
            all_covered &= Arc::ptr_eq(candidate, &artifact);
        });
        assert!(
            !all_covered,
            "same-key distinct allocations must not satisfy exact lease coverage"
        );
    }

    #[test]
    fn formal_port_cache_key_is_allocation_independent_and_arc_free() {
        let (first_artifact, first_scope) = scoped_root_fixture("same formal source");
        let (second_artifact, second_scope) = scoped_root_fixture("same formal source");
        assert_eq!(first_artifact.key(), second_artifact.key());
        assert!(!Arc::ptr_eq(&first_artifact, &second_artifact));

        let first_strong_count = Arc::strong_count(&first_artifact);
        let second_strong_count = Arc::strong_count(&second_artifact);
        let first = FormalPortKey {
            procedure: first_scope.locator().clone(),
            kind: ProcedurePortKind::Parameter { ordinal: 2 },
        };
        let second = FormalPortKey {
            procedure: second_scope.locator().clone(),
            kind: ProcedurePortKind::Parameter { ordinal: 2 },
        };
        assert_eq!(first, second);
        assert_eq!(Arc::strong_count(&first_artifact), first_strong_count);
        assert_eq!(Arc::strong_count(&second_artifact), second_strong_count);

        let different_ordinal = FormalPortKey {
            procedure: second_scope.locator().clone(),
            kind: ProcedurePortKind::Parameter { ordinal: 3 },
        };
        assert_ne!(first, different_ordinal);
    }
}
