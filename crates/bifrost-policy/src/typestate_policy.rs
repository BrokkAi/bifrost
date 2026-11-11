//! Production lowering and execution for resolved typestate policies.
//!
//! Policy loading owns authoring/composition semantics; this module starts at
//! the closed [`ResolvedTypestatePolicySpec`] boundary and lowers only typed,
//! source-backed values into the diagnostic-neutral typestate engine.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::Range as ByteRange;
use std::sync::{Arc, Mutex};

use crate::PolicyFindingId;
use crate::budget::PolicyBudget;
use crate::composition::PrecedenceGraph;
use crate::definition::{
    EndpointObservationPhase, MayMode, PolicyEndpointBinding, PolicyId, PolicyReportOptions,
    PolicySelectorPath, PolicySemanticEvent, TypestateArgumentCondition, TypestateCallBinding,
    TypestateEventId as PolicyTypestateEventId, TypestateEventSetSpec,
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
    PolicyWorkUnit, ProofMetadata, ProofReason, ProofState, WitnessStepKind,
};
use crate::finding::{
    FindingLocationBound, FurtherFindingsAbsent, PolicyByteSpan, PolicySourceLocation,
    PolicySubjectVerdict, PolicySubjectVerdicts, SubjectEnumeration, SubjectSelectorEnumeration,
    SubjectVerdict,
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
use crate::unit_execution::{
    UnitAttempt, UnitDecodeError, UnitReuse, UnitSlice, evaluate_reusable_slice,
};
use crate::units::{
    PolicyIncrementalContext, PolicyUnitKey, PolicyUnitProduct, RootProduct, RootWork, StagedUnits,
    UnitPartition, WidenReason,
};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots;
use brokk_bifrost_analysis::analyzer::semantic::SemanticLanguage;
use brokk_bifrost_analysis::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, forward_reachability_avoiding,
};
use brokk_bifrost_analysis::analyzer::semantic::ids::{LengthDelimitedDigest, StableDigest};
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    ProcedureRangeLookupStatus, procedures_in_artifact,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    AbstractObject, AccessPath, AccessPathAtPoint, AccessPathRoot, AliasQuery, AliasRelation,
    ArgumentCardinality, CallArgumentEndpoint, CallBinding, CallInvocationMode, CallSiteHandle,
    CallSiteId, CallTransferSet, CandidateCoverage, DispatchOracle, DispatchResult,
    EvidenceCompleteness, FreshObjectPublicationKind, FreshObjectPublicationQuery, HeapOracle,
    IcfgExitProfile, IcfgProvider, IcfgProviderBehaviorIdentity, IcfgSnapshot, IcfgSnapshotLimits,
    ObservationPhase, OracleCallContext, OracleLimits, ProcedureHandle, ProcedureId,
    ProcedurePortHandle, ProcedurePortKind, ProgramPointHandle, ProgramPointId, ProofStatus,
    SemanticArtifact, SemanticArtifactCollector, SemanticArtifactKey, SemanticArtifactLeaseChild,
    SemanticArtifactLeaseError, SemanticBudget, SemanticBudgetDimension,
    SemanticBudgetScopeSnapshot, SemanticEffect, SemanticExecutionBudget, SemanticExecutionWork,
    SemanticLocator, SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticValueKind,
    SemanticWork, ValueAtPoint, ValueFlowEndpoint, ValueFlowOracle, ValueFlowRelationKind,
    ValueHandle, WorkspaceIcfgProvider,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivatedProcedureSummary, ActiveSemanticModelSnapshot, AuthoredCoverageSubject,
    AuthoredSummaryExitKind, CompiledDeclaredEffectCertainty, CompiledDeclaredEffectTiming,
    CompiledSummaryEffect, CompiledSummaryExitKind, CompiledSummaryInput, CompiledSummaryOutput,
    Completeness, ProcedureSummaryMemberKey, ResolvedActiveSemanticModels,
    SemanticModelMatchDisposition,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;
use brokk_bifrost_analysis::analyzer::{Language, ProjectFile, Range, ReadKey, WorkspaceAnalyzer};
use brokk_bifrost_analysis::path_utils::rel_path_string;
use brokk_bifrost_flow::composition::{
    TypestateCompositionProvider, WorkspaceCompositionDiscovery,
};
use brokk_bifrost_flow::dataflow::{
    DataflowRequest, SolverBudget, SolverTermination, SummaryReadRecorder, SummaryWitnessStepKind,
    WitnessReconstructionLimits,
};
use brokk_bifrost_flow::taint::compose::{CompositionBudget, ObjectAnchor, search_object_roots};
use brokk_bifrost_flow::typestate::{
    BoundTypestateSubjectSpec, CompiledProtocol, CoverageCandidateGroupSpec,
    CoverageCandidatePhase, CoverageCandidateSpec, CoverageDecisionKind, CoverageDecisionSpec,
    CoverageRecordKey, CoverageRefusalReason, DirectScalarSource, PROTOCOL_SCHEMA_VERSION,
    ProductionSummaryLifecycleCounters, ProductionTypestateExecutionContext,
    ProductionTypestateSummaryRepository, ProtocolAnalysisMode, ProtocolEventKey,
    ProtocolEventOccurrence, ProtocolEventSpec, ProtocolExpectationKey, ProtocolGuardSpec,
    ProtocolObservationPhase, ProtocolObservationSpec, ProtocolProcedureExitKind,
    ProtocolSemantics, ProtocolSpec, ProtocolStateKey, ProtocolTerminalExpectationSpec,
    ProtocolTerminalObservationSpec, ProtocolTransitionSpec, ProtocolUncertaintyBehavior,
    ProtocolUncertaintySemantics, ProtocolUnmatchedEventBehavior, RootCallClosure,
    RootCallClosureIncompleteReason, TypestateBindingContext, TypestateBindingMultiplicity,
    TypestateBindingPlan, TypestateBindingQuality, TypestateCallNonInterferenceSpec,
    TypestateCoverageEventSet, TypestateCoverageSpec, TypestateEventBindingId,
    TypestateEventBindingSpec, TypestateEventBindings, TypestateEventCondition, TypestateEventPort,
    TypestateFinding, TypestateFindingCertainty, TypestateFindingKind, TypestateFindingLimits,
    TypestateFlowProblemError, TypestateInitialSeedSpec, TypestateObjectKey, TypestateObjectRole,
    TypestateObservationSite, TypestateProductionCacheStatus, TypestateSelectedOperand,
    TypestateSubjectClassKey, TypestateSubjectKey, TypestateSummaryResult,
    TypestateTerminalBindingId, TypestateTerminalBindingSpec, TypestateUncertainty,
    UnprovenEventRelation, collect_summary_findings_with_limits, direct_scalar_source,
    project_workspace_root_call_closure, solve_typestate_with_production_summaries,
};
use brokk_bifrost_flow::typestate::{TypestateComposeLabels, judge_object_roots};
use brokk_bifrost_flow::value_flow::{ValueFlowCache, WorkspaceValueFlowProvider};
use brokk_bifrost_rql::structural::CodeQueryTypestateLimits;
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
    InvalidEventSet(&'static str),
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
            Self::InvalidEventSet(reason) => {
                write!(formatter, "invalid typestate event set: {reason}")
            }
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
            | Self::InvalidEventSet(_)
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
    /// The selected syntax sites this subject was bound from: a subject
    /// verdict is reported at the site its selector chose, never at an
    /// observation point inside it.
    selected_sites: Vec<(ProjectFile, ByteRange<usize>)>,
    /// Activation sources where publication was proven before the subject's
    /// success-conditioned activation edge.
    escape_starts: Vec<ProgramPointHandle>,
}

struct CompiledCallNonInterference {
    specs: Vec<TypestateCallNonInterferenceSpec>,
    proven_pairs: HashSet<(TypestateSubjectKey, CallSiteHandle)>,
}

/// One compile chooses a single engine. Composition is admitted only for the
/// Rust lifecycle rule on complete stored IR; an incomplete composition must
/// report incomplete rather than restart with the ICFG engine.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TypestateEngine {
    Composition,
    Icfg { reason: Box<str> },
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypestateEngineOverride {
    Composition,
    Icfg,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TYPESTATE_ENGINE_OVERRIDE: std::cell::Cell<Option<TypestateEngineOverride>> =
        const { std::cell::Cell::new(None) };
}

/// Force either evaluator for one thread and restore its previous selection.
#[cfg(any(test, feature = "test-support"))]
pub fn with_typestate_engine_for_test<T>(
    engine: TypestateEngineOverride,
    run: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<TypestateEngineOverride>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TYPESTATE_ENGINE_OVERRIDE.set(self.0);
        }
    }
    let restore = Restore(TYPESTATE_ENGINE_OVERRIDE.replace(Some(engine)));
    let result = run();
    drop(restore);
    result
}

fn select_typestate_engine(
    policy_id: &PolicyId,
    roots: &[ProcedureHandle],
    workspace: &WorkspaceAnalyzer,
) -> Result<TypestateEngine, TypestatePolicyCompileError> {
    #[cfg(any(test, feature = "test-support"))]
    match TYPESTATE_ENGINE_OVERRIDE.get() {
        Some(TypestateEngineOverride::Composition) => return Ok(TypestateEngine::Composition),
        Some(TypestateEngineOverride::Icfg) => {
            return Ok(TypestateEngine::Icfg {
                reason: "test override".into(),
            });
        }
        None => {}
    }
    let icfg = |reason: &str| TypestateEngine::Icfg {
        reason: reason.into(),
    };
    if policy_id.as_str() != "bifrost.correctness.resource-lifecycle" {
        return Ok(icfg("policy"));
    }
    if roots.is_empty() {
        return Ok(icfg("no-roots"));
    }
    let mut seen = HashSet::new();
    for root in roots {
        let key = root.artifact().key();
        if !seen.insert(key) {
            continue;
        }
        if key.language() != SemanticLanguage::Standard(Language::Rust) {
            return Ok(icfg("language"));
        }
        if !workspace
            .has_complete_semantic_ir_rows(key)
            .map_err(|error| TypestatePolicyCompileError::SemanticUnavailable(error.to_string()))?
        {
            return Ok(icfg("no-complete-rows"));
        }
    }
    Ok(TypestateEngine::Composition)
}

#[derive(Debug)]
pub(crate) struct CompiledTypestatePolicy {
    /// Number of compiler runs in this policy evaluation.
    compilations: u64,
    engine: TypestateEngine,
    pub(crate) protocol: Arc<CompiledProtocol>,
    pub(crate) bindings: Arc<TypestateBindingPlan>,
    pub(crate) roots: Box<[ProcedureHandle]>,
    pub(crate) subjects: Box<[CompiledTypestateSubject]>,
    event_endpoints: Box<[Option<ResolvedEndpointIdentity>]>,
    terminal_endpoints: Box<[Option<ResolvedEndpointIdentity>]>,
    query_work: CodeQueryExecutionWork,
    semantic_compile_work: SemanticWork,
    semantic_compile_resident_peak: SemanticWork,
    semantic_compile_root_work_peak: SemanticWork,
    semantic_compile_peaks: PolicySemanticPeaks,
    semantic_remaining: SemanticWork,
    semantic_scope: SemanticBudgetScopeSnapshot,
    semantic_execution_budget: SemanticExecutionBudget,
    selector_scans: u64,
    artifact_leases: super::selector_compiler::PolicyArtifactLeases,
    result_contract_artifact_leases: usize,
    binding_omissions: Box<[String]>,
    /// Every site each subject selector selected, as (selector, file, span),
    /// recorded before binding. A site an omission, a resolution without a
    /// subject, or precedence reduction left without a subject of its own
    /// selector still has to be accounted for in the verdicts.
    selected_subject_sites: Vec<(String, ProjectFile, ByteRange<usize>)>,
    selection_fingerprint: Vec<String>,
    undecided_sites: Vec<UndecidedSelectorSite>,
    binding_omission_subjects: HashSet<TypestateSubjectKey>,
    /// Why a workspace helper did not discharge one subject's obligation.
    /// Keyed by subject so a finding can name the helpers it called.
    close_contract_reasons: HashMap<TypestateSubjectKey, Vec<String>>,
}

struct TypestateEvaluationFailure {
    message: String,
    work: PolicyWorkReport,
}

struct TypestateWorkMeasurements {
    cache_work: ProductionSummaryLifecycleCounters,
    semantic_evaluation_work: SemanticWork,
    semantic_evaluation_resident_peak: SemanticWork,
    semantic_evaluation_root_work_peak: SemanticWork,
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

/// A structural site whose semantic selection could not be decided. It has no binding.
#[derive(Debug)]
struct UndecidedSelectorSite {
    selector: String,
    file: ProjectFile,
    span: ByteRange<usize>,
    reasons: Vec<super::selector_compiler::candidate_enumeration::CandidateReason>,
}

impl std::fmt::Display for UndecidedSelectorSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{:?}: {:?} ({:?})",
            self.selector,
            rel_path_string(&self.file),
            self.span,
            self.reasons
                .iter()
                .map(|reason| reason.label())
                .collect::<Vec<_>>(),
            self.reasons
        )
    }
}

pub(crate) struct TypestatePolicyCompiler<'a> {
    selectors: super::selector_compiler::PolicySelectorSession<'a>,
    subject_scope: CodeQueryExecutionScope<'a>,
    /// The immutable activation whose model member and procedure identities
    /// the selector rows name. A compile retains only this bounded snapshot;
    /// it does not build a workspace-sized summary index.
    active_semantic_models: Option<Arc<ResolvedActiveSemanticModels>>,
    syntax_trees: HashMap<ProjectFile, tree_sitter::Tree>,
    formal_names: HashMap<FormalPortKey, Box<[String]>>,
    selected_template_targets: HashMap<TemplateCallKey, Option<TemplateTarget>>,
    /// Close contracts already computed, keyed by the formal they answer for
    /// and the recursion depth that was still available when they were asked.
    ///
    /// Depth is part of the key because a deeper walk may discharge a contract
    /// this walk cannot: the same formal must be recomputed, not answered with
    /// the shallower, more conservative result.
    close_contracts: HashMap<(FormalPortKey, u32), CloseContract>,
    /// The formals whose contracts are being computed right now, so a
    /// recursive helper that closes through itself answers `Cycle` instead of
    /// recursing forever.
    close_contract_stack: Vec<FormalPortKey>,
    binding_omissions: Vec<String>,
    selected_subject_sites: Vec<(String, ProjectFile, ByteRange<usize>)>,
    selection_fingerprint: Vec<String>,
    undecided_sites: Vec<UndecidedSelectorSite>,
    unproven_relations: Vec<UnprovenEventRelation>,
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

/// What one resolved close call acts on, in the performing procedure's terms.
///
/// Only three answers matter to a close contract: the call closes one of the
/// performing procedure's own formal parameters, a different formal of that
/// same procedure, or an object no caller argument binds to. Keeping that
/// classification at collection time avoids retaining a full durable object
/// identity for every close the workspace resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseSiteTarget {
    /// The close acts on formal `ordinal` of the procedure that performs it.
    Formal { ordinal: u32 },
    /// The close acts on a receiver, local, allocation, or static of the
    /// performing procedure: an object no caller argument binds to.
    NonFormal,
    /// The close acts on a slot that belongs to another procedure or artifact.
    Foreign,
}

/// One close call resolved inside one workspace procedure.
#[derive(Debug, Clone)]
struct CloseSiteFact {
    /// The procedure whose body performs the close. Retained so a contract can
    /// walk exactly the control-flow graph its own points came from.
    procedure: ProcedureHandle,
    target: CloseSiteTarget,
    /// The close call's own invoke point. Every control path that performs the
    /// close passes it, including the exceptional continuation of the close
    /// itself, so it is the barrier a reachability walk cuts.
    point: ProgramPointHandle,
    /// Whether the heap analysis proved this candidate target relation.
    proven: bool,
}

/// Which analysis-root exits stay reachable when every proven close is a
/// barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CloseExitGap {
    normal: bool,
    exceptional: bool,
}

impl CloseExitGap {
    /// The exits that stay reachable when every proven close is a barrier,
    /// phrased as the second half of the contract reason.
    fn describe(self) -> &'static str {
        match (self.normal, self.exceptional) {
            (true, true) => "its normal and exceptional exits are reachable without a close of it",
            (true, false) => "its normal exit is reachable without a close of it",
            (false, true) => "its exceptional exit is reachable without a close of it",
            // A gap with no reachable exit is the discharged answer, so the
            // caller never asks for a description of it.
            (false, false) => unreachable!("a discharged close contract has no exit gap"),
        }
    }
}

/// What a caller learns about closing one formal parameter of one workspace
/// callee.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CloseContract {
    /// Every path from the callee's entry to either exit passes a proven close
    /// of this formal, directly or through a discharged nested call.
    Discharged,
    /// Some exit keeps a path that performs no proven close of this formal.
    Partial(CloseExitGap),
    /// The callee provably closes a different formal parameter instead.
    DifferentObject,
    /// The callee provably closes something that is not one of its formals.
    UnboundClose,
    /// The recursion bound stopped the proof before reaching a close.
    BeyondBound,
    /// The callee's contract depends on itself.
    Cycle,
    /// This callee resolves no close call at all.
    NoEvidence,
}

/// One authored argument-form release event, as the compile lowered it.
///
/// A workspace helper close is discharged through this same vocabulary: the
/// policy already says what "an argument of this call was closed" means, and
/// the interprocedural contract proves that meaning for the callee body.
#[derive(Debug, Clone)]
struct ArgumentFormReleaseEvent {
    phase: EndpointObservationPhase,
    event: ProtocolEventKey,
    policy_event: PolicyTypestateEventId,
    semantic_effect: Option<Arc<str>>,
    order: u32,
}

/// One call whose actual provably binds one exact object to one callee formal.
///
/// The caller-side discharge and the nested-call walk of a close contract ask
/// the same question in the same words, so they share this answer: which
/// workspace procedure receives `object` in which of its formal parameters at
/// which call site.
#[derive(Clone)]
struct ExactArgumentBinding {
    call: CallSiteHandle,
    /// The call's own invoke point, the barrier a discharge would cut.
    point: ProgramPointHandle,
    /// The callee's formal parameter the object is handed to.
    formal: ProcedurePortHandle,
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
        let execution_budget = request
            .execution_budget()
            .cloned()
            .unwrap_or_else(|| self.execution_budget.clone());
        let mut request = request
            .staged_with_execution_budget(&execution_budget)
            .with_artifact_collector(&self.artifact_collector);
        self.inner.resolve_call(call, &mut request)
    }
}

impl IcfgProvider for PolicyIcfgProvider<'_> {
    fn memo_dependency_reacquirer(
        &self,
    ) -> Option<&dyn brokk_bifrost_analysis::analyzer::semantic::MemoDependencyReacquirer> {
        self.inner.memo_dependency_reacquirer()
    }

    fn memo_attribution(
        &self,
    ) -> brokk_bifrost_analysis::analyzer::workspace_authority::OwnedMemoCapability {
        self.inner.memo_attribution()
    }

    fn behavior_identity(&self) -> IcfgProviderBehaviorIdentity {
        self.inner.behavior_identity()
    }

    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        let execution_budget = request
            .execution_budget()
            .cloned()
            .unwrap_or_else(|| self.execution_budget.clone());
        let mut request = request
            .staged_with_execution_budget(&execution_budget)
            .with_artifact_collector(&self.artifact_collector);
        self.inner.call_transfers(caller, call, &mut request)
    }

    fn snapshot(
        &self,
        root: &ProcedureHandle,
        limits: IcfgSnapshotLimits,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError> {
        let execution_budget = request
            .execution_budget()
            .cloned()
            .unwrap_or_else(|| self.execution_budget.clone());
        let mut request = request
            .staged_with_execution_budget(&execution_budget)
            .with_artifact_collector(&self.artifact_collector);
        self.inner.snapshot(root, limits, &mut request)
    }

    fn exit_profile(
        &self,
        callee_entry: &ProgramPointHandle,
        callee_exit: &ProgramPointHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
        let execution_budget = request
            .execution_budget()
            .cloned()
            .unwrap_or_else(|| self.execution_budget.clone());
        let mut request = request
            .staged_with_execution_budget(&execution_budget)
            .with_artifact_collector(&self.artifact_collector);
        self.inner
            .exit_profile(callee_entry, callee_exit, &mut request)
    }
}

pub(crate) struct ProductionTypestatePolicyEvaluator {
    prepared: Mutex<HashMap<crate::definition::PolicyId, CompiledTypestatePolicy>>,
    /// What the selector half of this evaluation's sliced attempt did. The
    /// compile and the root solve are two halves of one attempt, so the counts
    /// are carried from the first to the second rather than reported twice.
    selector_units: Mutex<
        HashMap<crate::definition::PolicyId, Option<super::selector_compiler::SelectorUnitOutcome>>,
    >,
    /// What the sliced attempt did, left here for the caller that records the
    /// reuse review. Compilation and evaluation are one transaction, and the
    /// selector compile and the root solve are two halves of the same attempt.
    attempt: Mutex<HashMap<crate::definition::PolicyId, (UnitAttempt, Option<WidenReason>)>>,
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
            prepared: Mutex::new(HashMap::new()),
            selector_units: Mutex::new(HashMap::new()),
            attempt: Mutex::new(HashMap::new()),
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
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Result<CompiledTypestatePolicy, TypestateCompilationFailure> {
        Self::compile_with_units(
            policy,
            spec,
            workspace,
            context,
            budget,
            active_semantic_model_snapshot,
            CodeQueryExecutionScope::whole_workspace(),
            None,
        )
        .0
        .map_err(|failure| compile_failure(*failure))
    }

    /// The compile, optionally sliced into per-seed selector units, and what
    /// those units did.
    #[allow(clippy::too_many_arguments)]
    fn compile_with_units(
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        workspace: &WorkspaceAnalyzer,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        subject_scope: CodeQueryExecutionScope<'_>,
        incremental: Option<&PolicyIncrementalContext<'_>>,
    ) -> (
        Result<CompiledTypestatePolicy, Box<TypestatePolicyCompileFailure>>,
        Option<super::selector_compiler::SelectorUnitOutcome>,
    ) {
        let uncancelled = CancellationToken::default();
        let cancellation = context.cancellation.unwrap_or(&uncancelled);
        let compiler = TypestatePolicyCompiler::new(
            workspace,
            context.flow_resources(),
            budget.query_limits(),
            budget.max_selector_results(),
            cancellation,
            active_semantic_model_snapshot,
        )
        .with_subject_scope(subject_scope);
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
        subject_scope: CodeQueryExecutionScope<'_>,
        budget: &PolicyBudget,
    ) -> Result<TypestateCompilationHashes, TypestateCompilationFailure> {
        assert!(
            subject_scope.seed_files().is_none() || context.incremental.is_none(),
            "scoped typestate compilation cannot replay or publish units"
        );
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
            self.active_semantic_model_snapshot.clone(),
            subject_scope.clone(),
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
                let (recompiled, _) = Self::compile_with_units(
                    policy,
                    spec,
                    workspace,
                    context,
                    budget,
                    self.active_semantic_model_snapshot.clone(),
                    subject_scope,
                    None,
                );
                let mut recompiled = recompiled.map_err(|failure| compile_failure(*failure))?;
                recompiled.compilations += 1;
                (recompiled, Some(units))
            }
        };
        let hashes =
            TypestateCompilationHashes::new(compiled.protocol.hash(), compiled.bindings.hash());
        let policy_id = policy.definition().metadata.id.clone();
        self.prepared
            .lock()
            .expect("typestate prepared compilations mutex poisoned")
            .insert(policy_id.clone(), compiled);
        self.selector_units
            .lock()
            .expect("typestate selector units mutex poisoned")
            .insert(policy_id, units);
        Ok(hashes)
    }

    fn take_unit_attempt(
        &self,
        policy_id: &crate::definition::PolicyId,
    ) -> Option<(UnitAttempt, Option<WidenReason>)> {
        self.attempt
            .lock()
            .expect("typestate unit attempts mutex poisoned")
            .remove(policy_id)
    }

    fn evaluate_typestate(
        &self,
        authority: &TypestateProjectionAuthority,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        context: &PolicyEvaluationContext<'_>,
        budget: &PolicyBudget,
    ) -> TypestateProjectionPayload {
        let policy_id = policy.definition().metadata.id.clone();
        let compiled = self
            .prepared
            .lock()
            .expect("typestate prepared compilations mutex poisoned")
            .remove(&policy_id)
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
        let summaries = context.flow_state.typestate_summaries(workspace);
        let selectors = self
            .selector_units
            .lock()
            .expect("typestate selector units mutex poisoned")
            .remove(&policy_id)
            .flatten()
            .unwrap_or_default();
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
                .lock()
                .expect("typestate unit attempts mutex poisoned")
                .insert(policy_id.clone(), (selectors.attempt, Some(reason)));
            return self.whole_pass(
                authority, policy, spec, workspace, context, budget, &compiled, &summaries, None,
            );
        }
        let compilation =
            TypestateCompilationHashes::new(compiled.protocol.hash(), compiled.bindings.hash());
        // Engine selection depends on roots and semantic row completeness, which can differ for equal binding hashes.
        let mut selection_digest = LengthDelimitedDigest::new(b"typestate-selection-outcomes-v1");
        selection_digest.push(compilation.unit_digest().as_bytes());
        for site in &compiled.selection_fingerprint {
            selection_digest.push(site.as_bytes());
        }
        let selection_digest = selection_digest.finish();
        let root_digest = match &compiled.engine {
            TypestateEngine::Icfg { .. } => selection_digest,
            TypestateEngine::Composition => {
                let mut digest = LengthDelimitedDigest::new(COMPOSITION_ROOT_ENGINE_DOMAIN);
                digest.push(selection_digest.as_bytes());
                digest.finish()
            }
        };
        let mut units = RootUnits::new(
            policy,
            incremental,
            budget,
            workspace,
            selectors,
            root_digest,
            &context.flow_resources(),
        );
        let sliced = self.evaluate_pass(
            authority,
            policy,
            spec,
            workspace,
            context.cancellation,
            budget,
            &compiled,
            &summaries,
            Some(&mut units),
        );
        let (keys, attempt, staged) = units.into_parts();
        match sliced {
            RootsPass::Complete(payload) => {
                // Every root of this policy is published and merged, so this
                // list is what another run replays to reproduce the product
                // without solving anything. It is empty when any root was not
                // published, and an empty list names nothing; its staged units
                // are discarded with it.
                if !keys.is_empty() {
                    incremental.commit_units(policy.definition().metadata.id.clone(), staged, keys);
                }
                self.attempt
                    .lock()
                    .expect("typestate unit attempts mutex poisoned")
                    .insert(policy_id.clone(), (attempt, None));
                payload
            }
            RootsPass::Failed(failure) => {
                self.attempt
                    .lock()
                    .expect("typestate unit attempts mutex poisoned")
                    .insert(policy_id.clone(), (attempt, None));
                failed_projection_payload(&failure.message, failure.work)
            }
            RootsPass::Widen(reason) => {
                self.attempt
                    .lock()
                    .expect("typestate unit attempts mutex poisoned")
                    .insert(policy_id.clone(), (attempt, Some(reason)));
                let mut recompiled = match Self::compile(
                    policy,
                    spec,
                    workspace,
                    context,
                    budget,
                    self.active_semantic_model_snapshot.clone(),
                ) {
                    Ok(recompiled) => recompiled,
                    Err(_) => {
                        return failed_projection_payload(
                            "a widened typestate policy could not be compiled a second time",
                            compiled_typestate_work_report(&compiled),
                        );
                    }
                };
                recompiled.compilations += compiled.compilations;
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
    #[allow(clippy::too_many_arguments)]
    fn evaluate_pass(
        &self,
        authority: &TypestateProjectionAuthority,
        policy: &LoadedPolicy,
        spec: &ResolvedTypestatePolicySpec,
        workspace: &WorkspaceAnalyzer,
        cancellation: Option<&CancellationToken>,
        budget: &PolicyBudget,
        compiled: &CompiledTypestatePolicy,
        summaries: &ProductionTypestateSummaryRepository,
        units: Option<&mut RootUnits<'_>>,
    ) -> RootsPass {
        evaluate_compiled_typestate(
            authority,
            policy,
            spec,
            workspace,
            cancellation,
            budget,
            compiled,
            summaries,
            self.active_semantic_model_snapshot.clone(),
            units,
        )
    }

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
        match self.evaluate_pass(
            authority,
            policy,
            spec,
            workspace,
            context.cancellation,
            budget,
            compiled,
            summaries,
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
    let mut metrics: Vec<PolicyWorkMetric> = [
        ("typestate.compilations", compiled.compilations as usize),
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
    let cumulative = compiled
        .semantic_compile_work
        .conservative_add(measured.semantic_evaluation_work);
    let resident = compiled
        .semantic_compile_resident_peak
        .component_max(measured.semantic_evaluation_resident_peak);
    let root_work = compiled
        .semantic_compile_root_work_peak
        .component_max(measured.semantic_evaluation_root_work_peak);
    super::finding::append_semantic_budget_metrics(
        &mut metrics,
        "typestate",
        cumulative,
        resident,
        root_work,
    );
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
            semantic_evaluation_resident_peak: SemanticWork::default(),
            semantic_evaluation_root_work_peak: SemanticWork::default(),
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
const COMPOSITION_ROOT_ENGINE_DOMAIN: &[u8] = b"bifrost-policy-typestate-composition-root/v1";

type TemplateTarget = (SemanticArtifactKey, ProcedureId);
type TemplateCallKey = (TemplateTarget, CallSiteId);

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
    /// Whether the selector compile published all its units. Root publication
    /// is tracked by `attempt.all_recomputed_published()` in `into_parts`.
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
        compilation: StableDigest,
        flow: &brokk_bifrost_flow::FlowWorkspaceState,
    ) -> Self {
        let files_by_rel = workspace
            .analyzer()
            .analyzed_files()
            .into_iter()
            .map(|file| (rel_path_string(&file), file))
            .collect();
        Self {
            reuse: UnitReuse::continuing(policy, incremental, budget, flow, selectors.staged),
            policy,
            incremental,
            files_by_rel,
            keys: Vec::new(),
            selector_keys: selectors.keys,
            compilation,
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
        self.reuse.prefetch(&self.keys, None)
    }

    /// The keys this attempt asked about, what it did with them, and the
    /// units both halves staged, with the keys empty when any root is missing
    /// from the store.
    fn into_parts(mut self) -> (Vec<PolicyUnitKey>, UnitAttempt, StagedUnits) {
        let staged = self.reuse.take_staged();
        if self.all_published && self.attempt.all_recomputed_published() {
            self.selector_keys.append(&mut self.keys);
            (self.selector_keys, self.attempt, staged)
        } else {
            (Vec::new(), self.attempt, staged)
        }
    }
}

/// Charge every shared ledger one reused root's own solve drew on.
///
/// The solver budget a later root solves under, the semantic budget it
/// materializes under, and the execution
/// budget's materialized files and traversal steps, and the artifact-lease
/// capacity its window opens against. A reused root therefore leaves each of
/// them exactly where its own solve left them, which is what makes the sliced
/// pass reach a lane at the same root the whole run reaches it at.
///
/// The caller checks every refusing lane before charging this work.
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
    if semantic_budget.replay_product(work.semantic).is_err() {
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

struct RootPassInputs<'a> {
    engine: TypestateEngine,
    authority: &'a TypestateProjectionAuthority<'a>,
    policy: &'a LoadedPolicy,
    spec: &'a ResolvedTypestatePolicySpec,
    workspace: &'a WorkspaceAnalyzer,
    cancellation: &'a CancellationToken,
    budget: &'a PolicyBudget,
    compiled: &'a CompiledTypestatePolicy,
    summaries: &'a ProductionTypestateSummaryRepository,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    limits: CodeQueryTypestateLimits,
}

/// One gap that kept a typestate evaluation from concluding.
///
/// Every place that makes the run inconclusive records the gap it hit rather
/// than a bare [`PolicyIncompleteReason`]. The completion's reasons and the
/// run's diagnostics both derive from the same list, so an inconclusive run
/// always says what was incomplete (#10001). A root's gaps are part of its
/// stored unit product, so a reused root reports what a solved one reports.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(tag = "gap", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TypestateGap {
    Cancelled,
    SolverBudgetExhausted,
    FindingBudgetExhausted,
    FindingAnalysisIncomplete,
    ExecutionBudgetExhausted,
    SemanticArtifactCapacity,
    CallClosureBudgetStop,
    CallControlCoverageRefused,
    SummaryProjectionRefused,
    BindingsIncomplete,
    /// Solved facts carry uncertainty, named by their stable typestate codes,
    /// or abstained.
    SolveUncertain {
        uncertainty: Vec<String>,
        abstained: bool,
    },
    SolveResultIncomplete,
    /// An event relation the compile could not prove may observe the subject
    /// in a procedure this root's call closure does not exclude.
    UnprovenEventRelation {
        event: String,
        phase: String,
        reason: String,
    },
    CompositionJudgmentIncomplete,
    CompositionAdmissionIncomplete,
    /// A selected endpoint the compile could not bind to a subject.
    BindingOmitted {
        omission: String,
    },
}

impl TypestateGap {
    /// A gap of a shared budget or of the whole request: no root's own solve
    /// can be complete while it stands.
    fn is_evaluation_wide(&self) -> bool {
        matches!(
            self,
            Self::Cancelled
                | Self::SolverBudgetExhausted
                | Self::FindingBudgetExhausted
                | Self::ExecutionBudgetExhausted
                | Self::SemanticArtifactCapacity
        )
    }

    /// The stable label a subject verdict names this gap by.
    fn label(&self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::SolverBudgetExhausted => "solver_budget_exhausted",
            Self::FindingBudgetExhausted => "finding_budget_exhausted",
            Self::FindingAnalysisIncomplete => "finding_analysis_incomplete",
            Self::ExecutionBudgetExhausted => "execution_budget_exhausted",
            Self::SemanticArtifactCapacity => "semantic_artifact_capacity",
            Self::CallClosureBudgetStop => "call_closure_budget_stop",
            Self::CallControlCoverageRefused => "call_control_coverage_refused",
            Self::SummaryProjectionRefused => "summary_projection_refused",
            Self::BindingsIncomplete => "bindings_incomplete",
            Self::SolveUncertain { .. } => "solve_uncertain",
            Self::SolveResultIncomplete => "solve_result_incomplete",
            Self::UnprovenEventRelation { .. } => "unproven_event_relation",
            Self::CompositionJudgmentIncomplete => "composition_judgment_incomplete",
            Self::CompositionAdmissionIncomplete => "composition_admission_incomplete",
            Self::BindingOmitted { .. } => "binding_omitted",
        }
    }

    fn reason(&self) -> PolicyIncompleteReason {
        match self {
            Self::Cancelled => PolicyIncompleteReason::Cancelled,
            _ => PolicyIncompleteReason::PartialDiscovery,
        }
    }

    fn diagnostic_code(&self) -> CodeQueryDiagnosticCode {
        match self {
            Self::Cancelled => CodeQueryDiagnosticCode::Cancelled,
            Self::SolverBudgetExhausted => CodeQueryDiagnosticCode::TypestateSolverBudgetExhausted,
            Self::FindingBudgetExhausted => {
                CodeQueryDiagnosticCode::TypestateFindingBudgetExhausted
            }
            Self::ExecutionBudgetExhausted => CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
            Self::SemanticArtifactCapacity | Self::CallClosureBudgetStop => {
                CodeQueryDiagnosticCode::SemanticBudgetExhausted
            }
            Self::BindingOmitted { .. } => CodeQueryDiagnosticCode::SemanticCapabilityUnsupported,
            Self::FindingAnalysisIncomplete
            | Self::CallControlCoverageRefused
            | Self::SummaryProjectionRefused
            | Self::BindingsIncomplete
            | Self::SolveUncertain { .. }
            | Self::SolveResultIncomplete
            | Self::UnprovenEventRelation { .. }
            | Self::CompositionJudgmentIncomplete
            | Self::CompositionAdmissionIncomplete => {
                CodeQueryDiagnosticCode::TypestateAnalysisPartial
            }
        }
    }

    fn message(&self) -> String {
        match self {
            Self::Cancelled => "typestate evaluation was cancelled".to_owned(),
            Self::SolverBudgetExhausted => {
                "typestate solver work budget was exhausted before a fixed point".to_owned()
            }
            Self::FindingBudgetExhausted => {
                "typestate finding budget was exhausted, so findings were omitted".to_owned()
            }
            Self::FindingAnalysisIncomplete => {
                "typestate finding collection could not complete its analysis".to_owned()
            }
            Self::ExecutionBudgetExhausted => {
                "typestate semantic execution budget was exhausted".to_owned()
            }
            Self::SemanticArtifactCapacity => {
                "typestate semantic artifact capacity was exhausted".to_owned()
            }
            Self::CallClosureBudgetStop => {
                "typestate root call closure stopped at the semantic budget".to_owned()
            }
            Self::CallControlCoverageRefused => {
                "scoped call/control coverage was refused, so the summaries a root consumes are \
                 not proven complete"
                    .to_owned()
            }
            Self::SummaryProjectionRefused => {
                "typestate summary projection was refused at a call/control boundary".to_owned()
            }
            Self::BindingsIncomplete => {
                "typestate subject or event bindings did not cover every candidate".to_owned()
            }
            Self::SolveUncertain {
                uncertainty,
                abstained,
            } => {
                let mut message = "typestate solve kept uncertain facts".to_owned();
                if !uncertainty.is_empty() {
                    message.push_str(&format!(": {}", uncertainty.join(", ")));
                }
                if *abstained {
                    message.push_str(" (some facts abstained)");
                }
                if uncertainty.iter().any(|code| {
                    code == "typestate-unknown-call" || code == "typestate-external-call"
                }) {
                    message.push_str(
                        "; an unmodeled or unresolved call needs a complete summary or model \
                         before the solve can be complete",
                    );
                }
                message
            }
            Self::SolveResultIncomplete => {
                "typestate solve did not cover its result, and no reviewed binding closed it"
                    .to_owned()
            }
            Self::UnprovenEventRelation {
                event,
                phase,
                reason,
            } => format!(
                "event `{event}` ({phase}) may observe the subject in a procedure the root's call \
                 closure does not exclude: {reason}"
            ),
            Self::CompositionJudgmentIncomplete => {
                "typestate composition could not judge every terminal root".to_owned()
            }
            Self::CompositionAdmissionIncomplete => {
                "typestate composition could not admit every composed finding".to_owned()
            }
            Self::BindingOmitted { omission } => {
                format!("typestate endpoint binding omitted: {omission}")
            }
        }
    }

    /// The gaps a finished solve left, one per independent cause.
    fn of_solve(solved: &TypestateSummaryResult) -> Vec<Self> {
        let mut gaps = Vec::new();
        if !solved.bindings_complete() {
            gaps.push(Self::BindingsIncomplete);
        }
        if !solved.execution_complete() {
            let facts = solved.result().facts();
            let uncertainty = TYPESTATE_UNCERTAINTY_CODES
                .iter()
                .filter(|(cause, _)| facts.iter().any(|fact| fact.uncertainty().contains(*cause)))
                .map(|(_, code)| (*code).to_owned())
                .collect();
            gaps.push(Self::SolveUncertain {
                uncertainty,
                abstained: facts.iter().any(|fact| fact.abstained()),
            });
        }
        if !solved.result_complete() {
            gaps.push(Self::SolveResultIncomplete);
        }
        debug_assert_eq!(gaps.is_empty(), solved.is_complete());
        gaps
    }
}

/// Each typestate uncertainty cause and its stable code. A finding carries the
/// code as its certainty reason, except ambiguous dispatch, which has a typed
/// certainty reason of its own.
const TYPESTATE_UNCERTAINTY_CODES: [(TypestateUncertainty, &str); 7] = [
    (
        TypestateUncertainty::AmbiguousDispatch,
        "typestate-ambiguous-dispatch",
    ),
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
    (
        TypestateUncertainty::ConditionalAlias,
        "typestate-conditional-alias",
    ),
];

/// One gap per unproven event relation whose observing procedure the root's
/// call closure does not exclude.
fn unproven_relation_gaps<'a>(
    bindings: &'a TypestateBindingPlan,
    closure: &'a RootCallClosure,
) -> impl Iterator<Item = TypestateGap> + 'a {
    bindings
        .unproven_relations()
        .iter()
        .filter(|relation| !closure.excludes(&relation.observation_procedure))
        .map(|relation| TypestateGap::UnprovenEventRelation {
            event: relation.event.clone(),
            phase: relation.phase.clone(),
            reason: relation.reason.clone(),
        })
}

struct RootPassState {
    cache_work: ProductionSummaryLifecycleCounters,
    solver_budget: SolverBudget,
    semantic_budget: Option<SemanticBudget>,
    evaluation_execution_budget: SemanticExecutionBudget,
    initial_evaluation_execution_work: SemanticExecutionWork,
    evaluation_artifact_leases: SemanticArtifactLeaseChild,
    evaluation_artifact_retained_peak: usize,
    replayed_artifact_leases: usize,
    replayed_artifact_lease_bytes: usize,
    projections: Vec<TypestateProjectedFinding>,
    gaps: Vec<TypestateGap>,
    root_gaps: HashMap<ProcedureHandle, Vec<TypestateGap>>,
    reached_rows: u64,
    subject_rows: u64,
    terminal_rows: u64,
    retained_analysis_findings: u64,
    omitted_analysis_findings: u64,
    remaining_finding_reached_rows: usize,
    remaining_finding_candidates: usize,
    remaining_finding_witness_expansions: usize,
    remaining_finding_witness_bytes: usize,
    evaluation_error: Option<String>,
    shared_lane_reached: bool,
}

struct RootExecutionBoundary {
    solver_refusals: usize,
    semantic_refusals: Option<usize>,
    generation: u64,
}

impl RootExecutionBoundary {
    fn before(state: &RootPassState, inputs: &RootPassInputs<'_>) -> Self {
        Self {
            solver_refusals: state.solver_budget.refusal_count(),
            semantic_refusals: state
                .semantic_budget
                .as_ref()
                .map(SemanticBudget::refusal_count),
            generation: inputs.workspace.analyzer().project().analysis_generation(),
        }
    }

    fn execution_dependent(&self, state: &RootPassState, inputs: &RootPassInputs<'_>) -> bool {
        let cancelled = inputs.cancellation.is_cancelled();
        let solver = state.solver_budget.refusal_count() > self.solver_refusals;
        let semantic = state
            .semantic_budget
            .as_ref()
            .map(SemanticBudget::refusal_count)
            != self.semantic_refusals;
        let execution = state.evaluation_execution_budget.work().exhausted;
        let snapshot =
            inputs.workspace.analyzer().project().analysis_generation() != self.generation;
        let dependent = cancelled || solver || semantic || execution || snapshot;
        if dependent {
            brokk_bifrost_analysis::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=root_boundary cancelled={} solver={} semantic={} execution={} snapshot={}",
                    file!(),
                    line!(),
                    cancelled,
                    solver,
                    semantic,
                    execution,
                    snapshot
                )
            });
        }
        dependent
    }
}

// Keep the root product inline: this transient result crosses one root boundary.
#[allow(clippy::large_enum_variant)]
enum RootStep {
    Solved {
        product: RootProduct,
        cache_status: TypestateProductionCacheStatus,
        execution_dependent: bool,
    },
    Unfinished,
    Stopped,
    Failed,
}

impl RootPassState {
    fn new(inputs: &RootPassInputs<'_>) -> Self {
        let cache_work = ProductionSummaryLifecycleCounters::default();
        let limits = inputs.limits;
        let solver_budget = SolverBudget::new(limits.solver_work);
        let semantic_budget = if inputs.compiled.roots.is_empty() {
            None
        } else {
            Some(SemanticBudget::new_carved_child(
                inputs.compiled.semantic_remaining,
                &inputs.compiled.semantic_scope,
            ))
        };
        let evaluation_execution_budget = inputs.compiled.semantic_execution_budget.clone();
        let initial_evaluation_execution_work = evaluation_execution_budget.work();
        let evaluation_artifact_leases = inputs
            .compiled
            .artifact_leases
            .snapshot()
            .restrict_to(inputs.budget.query_limits().semantic.max_retained_bytes)
            .into_child();
        let evaluation_artifact_retained_peak = evaluation_artifact_leases.retained_bytes();
        // What reused roots took out of the shared artifact-lease capacity. The
        // allocations themselves cannot be reproduced -- they are process-local
        // artifacts a stored product never carried -- so they are replayed as
        // anonymous live bytes against the same capacity, exactly as the execution
        // budget replays a query's materializations as anonymous slots. A later
        // root therefore sees the headroom a whole evaluation would have left it.
        let replayed_artifact_leases = 0_usize;
        let replayed_artifact_lease_bytes = 0_usize;
        let projections = Vec::new();
        let gaps = Vec::new();
        let reached_rows = 0_u64;
        let subject_rows = 0_u64;
        let terminal_rows = 0_u64;
        let retained_analysis_findings = 0_u64;
        let omitted_analysis_findings = 0_u64;
        let remaining_finding_reached_rows = limits.max_reached_rows;
        let remaining_finding_candidates = limits.max_candidates;
        let remaining_finding_witness_expansions = limits.max_total_witness_expansions;
        let remaining_finding_witness_bytes = limits.max_witness_bytes;

        let evaluation_error = None;
        // A lane every root shares. Reusing a root consumes none of it, so a
        // sliced pass that reached one cannot claim to have produced what a whole
        // evaluation would have produced, and the caller evaluates the policy in
        // full instead.
        let shared_lane_reached = false;
        Self {
            cache_work,
            solver_budget,
            semantic_budget,
            evaluation_execution_budget,
            initial_evaluation_execution_work,
            evaluation_artifact_leases,
            evaluation_artifact_retained_peak,
            replayed_artifact_leases,
            replayed_artifact_lease_bytes,
            projections,
            gaps,
            root_gaps: HashMap::new(),
            reached_rows,
            subject_rows,
            terminal_rows,
            retained_analysis_findings,
            omitted_analysis_findings,
            remaining_finding_reached_rows,
            remaining_finding_candidates,
            remaining_finding_witness_expansions,
            remaining_finding_witness_bytes,
            evaluation_error,
            shared_lane_reached,
        }
    }

    fn begin_root(&mut self) {
        if let Some(budget) = &mut self.semantic_budget {
            budget.begin_root();
        }
    }

    fn solve_root(&mut self, inputs: &RootPassInputs<'_>, root: &ProcedureHandle) -> RootStep {
        if matches!(inputs.engine, TypestateEngine::Composition) {
            return self.solve_root_composition(inputs, root);
        }
        let mut root_work = RootWork::default();
        let mut root_gaps = Vec::new();
        // What this root's own solve takes out of the shared lanes, measured
        // here so the reuse path above can replay exactly it.
        let execution_boundary = RootExecutionBoundary::before(self, inputs);
        let solver_before = self.solver_budget.used();
        let semantic_before = self
            .semantic_budget
            .as_mut()
            .map(SemanticBudget::replay_snapshot);
        let execution_before = self.evaluation_execution_budget.work();
        let leases_before = self.evaluation_artifact_leases.len();
        let lease_bytes_before = self.evaluation_artifact_leases.retained_bytes();
        let artifact_window = self
            .evaluation_artifact_leases
            .begin_window(self.replayed_artifact_lease_bytes);
        let artifact_collector = artifact_window.collector();
        let icfg_provider = PolicyIcfgProvider::new(
            inputs.workspace,
            &self.evaluation_execution_budget,
            artifact_collector,
            inputs.active_semantic_model_snapshot.clone(),
        );
        let mut request = DataflowRequest::new(&mut self.solver_budget, inputs.cancellation);
        // The summary funnel this root crosses records through the analyzer's
        // open read ledgers, exactly as the ICFG provider's artifact and
        // dispatch reads do; with no ledger attached it costs one relaxed load
        // per lookup.
        let summary_reads = SummaryReadRecorder::new(inputs.workspace.analyzer());
        let production = solve_typestate_with_production_summaries(
            inputs.summaries,
            &summary_reads,
            root,
            &[],
            &icfg_provider,
            &icfg_provider,
            Some(inputs.workspace),
            ProductionTypestateExecutionContext::Policy(&icfg_provider.execution_budget),
            &inputs.compiled.protocol,
            &inputs.compiled.bindings,
            self.semantic_budget
                .as_mut()
                .expect("nonempty roots retain a semantic budget"),
            &mut request,
        );
        let window_retained_peak = match artifact_window.overflow() {
            Some(SemanticArtifactLeaseError::Capacity(exceeded)) => exceeded.attempted(),
            Some(SemanticArtifactLeaseError::RetainedBytesOverflow) => usize::MAX,
            Some(_) | None => artifact_window
                .retained_bytes()
                .saturating_add(self.replayed_artifact_lease_bytes),
        };
        self.evaluation_artifact_retained_peak = self
            .evaluation_artifact_retained_peak
            .max(window_retained_peak);
        let production = match production {
            Ok(production) => {
                self.cache_work
                    .saturating_add_assign(production.lifecycle());
                production
            }
            Err(error) => {
                self.evaluation_error = Some(error.to_string());
                drop(icfg_provider);
                artifact_window.discard();
                return RootStep::Failed;
            }
        };
        root_gaps.extend(unproven_relation_gaps(
            &inputs.compiled.bindings,
            production.root_call_closure(),
        ));
        // A result-cache hit returns before the ICFG provider and the summary
        // funnel are touched and records nothing, so its ledger names none of
        // the inputs the result depends on and the root is not publishable.
        let cache_status = production.cache_status();
        let solved = production.result();
        root_gaps.extend(TypestateGap::of_solve(solved));
        if production.projection_refused() {
            root_gaps.push(TypestateGap::SummaryProjectionRefused);
        }
        if !production
            .root_call_closure()
            .summary_completeness_justified()
        {
            root_gaps.push(TypestateGap::CallControlCoverageRefused);
        }
        let fixed_point = match solved.result().termination() {
            SolverTermination::FixedPoint => true,
            SolverTermination::Cancelled => {
                self.shared_lane_reached = true;
                self.gaps.push(TypestateGap::Cancelled);
                false
            }
            SolverTermination::ExceededBudget(_) => {
                self.shared_lane_reached = true;
                self.gaps.push(TypestateGap::SolverBudgetExhausted);
                false
            }
        };
        root_work.reached_rows = u64::try_from(solved.result().reached().len()).unwrap_or(u64::MAX);
        self.reached_rows = self.reached_rows.saturating_add(root_work.reached_rows);
        for reached in solved.result().reached() {
            let Some(fact) = solved.result().fact(reached.fact()) else {
                self.evaluation_error =
                    Some("typestate solve retained an invalid fact row".to_owned());
                return RootStep::Failed;
            };
            if fact.subject().is_some() {
                self.subject_rows = self.subject_rows.saturating_add(1);
                root_work.subject_rows = root_work.subject_rows.saturating_add(1);
            }
            if fact.terminal_observation().is_some() {
                self.terminal_rows = self.terminal_rows.saturating_add(1);
                root_work.terminal_rows = root_work.terminal_rows.saturating_add(1);
            }
        }
        if !fixed_point {
            drop(production);
            drop(icfg_provider);
            artifact_window.discard();
            return RootStep::Unfinished;
        }
        if self.remaining_finding_reached_rows == 0
            || self.remaining_finding_candidates == 0
            || self.remaining_finding_witness_expansions == 0
            || self.remaining_finding_witness_bytes == 0
        {
            self.shared_lane_reached = true;
            self.gaps.push(TypestateGap::FindingBudgetExhausted);
            self.omitted_analysis_findings = self.omitted_analysis_findings.saturating_add(1);
            drop(production);
            drop(icfg_provider);
            artifact_window.discard();
            return RootStep::Stopped;
        }
        let witness_limits = match WitnessReconstructionLimits::new(
            inputs.limits.max_witness_steps,
            inputs
                .limits
                .max_witness_expansions
                .min(self.remaining_finding_witness_expansions),
        ) {
            Ok(limits) => limits,
            Err(error) => {
                self.evaluation_error = Some(error.to_string());
                return RootStep::Failed;
            }
        };
        let finding_limits = match TypestateFindingLimits::with_witness_limits(
            self.remaining_finding_reached_rows,
            self.remaining_finding_candidates,
            witness_limits,
            self.remaining_finding_witness_expansions,
            self.remaining_finding_witness_bytes,
        ) {
            Ok(limits) => limits,
            Err(error) => {
                self.evaluation_error = Some(error.to_string());
                return RootStep::Failed;
            }
        };
        let findings = match collect_summary_findings_with_limits(
            &inputs.compiled.protocol,
            &inputs.compiled.bindings,
            solved,
            finding_limits,
            inputs.cancellation,
        ) {
            Ok(findings) => findings,
            Err(TypestateFlowProblemError::FindingCancelled) => {
                self.shared_lane_reached = true;
                self.gaps.push(TypestateGap::Cancelled);
                drop(production);
                drop(icfg_provider);
                artifact_window.discard();
                return RootStep::Stopped;
            }
            Err(TypestateFlowProblemError::FindingBudgetExceeded) => {
                self.shared_lane_reached = true;
                self.gaps.push(TypestateGap::FindingBudgetExhausted);
                self.omitted_analysis_findings = self.omitted_analysis_findings.saturating_add(1);
                drop(production);
                drop(icfg_provider);
                artifact_window.discard();
                return RootStep::Stopped;
            }
            Err(error) => {
                self.evaluation_error = Some(error.to_string());
                drop(production);
                drop(icfg_provider);
                artifact_window.discard();
                return RootStep::Failed;
            }
        };
        let mut root_projections = Vec::new();
        let mut root_retained_analysis_findings = 0_u64;
        if !findings.analysis_complete() || findings.omitted() > 0 {
            // The per-root finding limits are the shared remaining lanes
            // narrowed to this root, so an omission here is not a property of
            // the root alone: a run that reused an earlier root would have had
            // more allowance left and might have omitted nothing.
            self.shared_lane_reached = true;
            for (incomplete, gap) in [
                (
                    !findings.analysis_complete(),
                    TypestateGap::FindingAnalysisIncomplete,
                ),
                (findings.omitted() > 0, TypestateGap::FindingBudgetExhausted),
            ] {
                if incomplete {
                    root_gaps.push(gap.clone());
                    self.gaps.push(gap);
                }
            }
        }
        let finding_work = findings.work();
        let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        root_work.finding_reached_rows = count(finding_work.reached_rows());
        root_work.finding_candidates = count(finding_work.candidates());
        root_work.finding_witness_expansions = count(finding_work.witness_expansions());
        root_work.finding_witness_bytes = count(finding_work.witness_bytes());
        self.remaining_finding_reached_rows = self
            .remaining_finding_reached_rows
            .saturating_sub(finding_work.reached_rows());
        self.remaining_finding_candidates = self
            .remaining_finding_candidates
            .saturating_sub(finding_work.candidates());
        self.remaining_finding_witness_expansions = self
            .remaining_finding_witness_expansions
            .saturating_sub(finding_work.witness_expansions());
        self.remaining_finding_witness_bytes = self
            .remaining_finding_witness_bytes
            .saturating_sub(finding_work.witness_bytes());
        root_work.omitted_analysis_findings = u64::try_from(findings.omitted()).unwrap_or(u64::MAX);
        self.omitted_analysis_findings = self
            .omitted_analysis_findings
            .saturating_add(root_work.omitted_analysis_findings);
        for finding in findings.findings() {
            let Some(subject) = inputs.compiled.bindings.subject(finding.subject()) else {
                self.evaluation_error =
                    Some("typestate finding refers to an unknown bound subject".to_owned());
                return RootStep::Failed;
            };
            if inputs
                .compiled
                .binding_omission_subjects
                .contains(subject.key())
            {
                continue;
            }
            root_retained_analysis_findings = root_retained_analysis_findings.saturating_add(1);
            match project_finding(
                inputs.authority,
                inputs.policy,
                inputs.spec,
                inputs.workspace,
                inputs.budget,
                inputs.compiled,
                root,
                finding,
            ) {
                Ok(finding_projections) => root_projections.extend(finding_projections),
                Err(error) => {
                    self.evaluation_error = Some(error);
                    return RootStep::Failed;
                }
            }
        }
        drop(findings);
        drop(production);
        drop(icfg_provider);
        match artifact_window.commit(&mut self.evaluation_artifact_leases) {
            Ok(()) => {
                let execution_after = self.evaluation_execution_budget.work();
                root_work.solver = self.solver_budget.used().saturating_sub(solver_before);
                root_work.semantic = self
                    .semantic_budget
                    .as_ref()
                    .zip(semantic_before.as_ref())
                    .map(|(budget, before)| budget.replay_since(before))
                    .unwrap_or_default();
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
                    self.evaluation_artifact_leases
                        .len()
                        .saturating_sub(leases_before),
                );
                root_work.artifact_lease_bytes = count(
                    self.evaluation_artifact_leases
                        .retained_bytes()
                        .saturating_sub(lease_bytes_before),
                );
                root_work.retained_analysis_findings = root_retained_analysis_findings;
                self.retained_analysis_findings = self
                    .retained_analysis_findings
                    .saturating_add(root_retained_analysis_findings);
                let execution_dependent = execution_boundary.execution_dependent(self, inputs);
                #[cfg(any(test, feature = "test-support"))]
                inputs
                    .workspace
                    .analyzer()
                    .test_hooks()
                    .invalidate_evaluation_root_continuation_semantic_cache_if_armed_for_test();
                RootStep::Solved {
                    product: RootProduct {
                        findings: root_projections,
                        gaps: root_gaps,
                        work: root_work,
                    },
                    cache_status,
                    execution_dependent,
                }
            }
            Err(
                SemanticArtifactLeaseError::Capacity(_)
                | SemanticArtifactLeaseError::RetainedBytesOverflow,
            ) => {
                self.shared_lane_reached = true;
                self.gaps.push(TypestateGap::SemanticArtifactCapacity);
                self.omitted_analysis_findings = self
                    .omitted_analysis_findings
                    .saturating_add(root_retained_analysis_findings.max(1));
                RootStep::Stopped
            }
            Err(error) => {
                self.evaluation_error = Some(format!(
                    "typestate evaluation semantic lease transaction failed: {error}"
                ));
                RootStep::Failed
            }
        }
    }

    fn solve_root_composition(
        &mut self,
        inputs: &RootPassInputs<'_>,
        root: &ProcedureHandle,
    ) -> RootStep {
        let execution_boundary = RootExecutionBoundary::before(self, inputs);
        let mut composition_execution_dependent = false;
        let composition_budget = CompositionBudget {
            max_procedures: inputs.budget.max_composition_procedures(),
            max_hops: inputs.budget.max_composition_hops(),
            max_callers_per_procedure: inputs.budget.max_composition_callers_per_procedure(),
        };
        let mut projections = Vec::new();
        let mut root_gaps = Vec::new();
        let closure = {
            let provider = WorkspaceIcfgProvider::new(inputs.workspace);
            let mut request = SemanticRequest::new(
                self.semantic_budget
                    .as_mut()
                    .expect("a compiled root retains a semantic budget"),
                inputs.cancellation,
            );
            project_workspace_root_call_closure(root, &provider, inputs.workspace, &mut request)
        };
        let closure = match closure {
            Ok(closure) => closure,
            Err(error) => {
                self.evaluation_error = Some(error.to_string());
                return RootStep::Failed;
            }
        };
        if closure
            .incomplete_reasons()
            .contains(&RootCallClosureIncompleteReason::BudgetStop)
        {
            // The semantic allowance is shared by all roots in this pass.
            self.shared_lane_reached = true;
            root_gaps.push(TypestateGap::CallClosureBudgetStop);
        }
        if !closure.summary_completeness_justified() {
            root_gaps.push(TypestateGap::CallControlCoverageRefused);
        }
        root_gaps.extend(unproven_relation_gaps(&inputs.compiled.bindings, &closure));
        let mut root_work = RootWork::default();
        for subject in inputs.compiled.bindings.subjects() {
            let rooted_here = inputs.compiled.bindings.initial_seeds().iter().any(|seed| {
                seed.subject() == subject.id()
                    && match seed.site() {
                        TypestateObservationSite::ProgramPoint { point, .. } => {
                            point.procedure().durable_key() == root.durable_key()
                        }
                        TypestateObservationSite::CallSite { call, .. } => {
                            call.procedure().durable_key() == root.durable_key()
                        }
                    }
            });
            if !rooted_here {
                continue;
            }
            let discovery = WorkspaceCompositionDiscovery::new(
                inputs.workspace,
                WorkspaceValueFlowProvider::new(
                    inputs.workspace,
                    ValueFlowCache::new(
                        inputs.budget.query_limits().semantic.max_retained_bytes as u64,
                    ),
                ),
            );
            let provider = TypestateCompositionProvider::new(
                discovery,
                self.evaluation_execution_budget.clone(),
                composition_budget,
                &inputs.compiled.protocol,
                &inputs.compiled.bindings,
                subject,
                TypestateBindingContext::root(),
                inputs.budget.query_limits().semantic.max_retained_bytes,
            );
            let mut seen = HashSet::new();
            let roots: Vec<ObjectAnchor> = provider
                .terminal_roots()
                .into_iter()
                .map(|(_, anchor)| anchor)
                .filter(|anchor| seen.insert(anchor.clone()))
                .collect();
            if roots.is_empty() {
                continue;
            }
            let mut request = SemanticRequest::new(
                self.semantic_budget
                    .as_mut()
                    .expect("a compiled root retains a semantic budget"),
                inputs.cancellation,
            );
            let outcome = match search_object_roots(
                roots,
                TypestateComposeLabels::new(&inputs.compiled.protocol, &inputs.compiled.bindings),
                &provider,
                composition_budget,
                &mut request,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.evaluation_error = Some(format!("typestate composition: {error:?}"));
                    return RootStep::Failed;
                }
            };
            composition_execution_dependent |= provider
                .execution_observation(&outcome)
                .execution_dependent();
            let judgments = judge_object_roots(
                &provider.terminal_roots(),
                &outcome,
                &inputs.compiled.protocol,
                &inputs.compiled.bindings,
            );
            if judgments.iter().any(|judgment| !judgment.complete) {
                root_gaps.push(TypestateGap::CompositionJudgmentIncomplete);
                self.gaps.push(TypestateGap::CompositionJudgmentIncomplete);
            }
            let (findings, admission_complete) =
                match provider.composed_findings(&outcome, &mut request) {
                    Ok(result) => result,
                    Err(error) => {
                        self.evaluation_error = Some(error.to_string());
                        return RootStep::Failed;
                    }
                };
            if !admission_complete {
                root_gaps.push(TypestateGap::CompositionAdmissionIncomplete);
                self.gaps.push(TypestateGap::CompositionAdmissionIncomplete);
            }
            root_work.reached_rows = root_work
                .reached_rows
                .saturating_add(u64::try_from(outcome.object_reaches.len()).unwrap_or(u64::MAX));
            for finding in &findings {
                let Some(bound_subject) = inputs.compiled.bindings.subject(finding.subject())
                else {
                    self.evaluation_error = Some("composed finding has no subject".into());
                    return RootStep::Failed;
                };
                if inputs
                    .compiled
                    .binding_omission_subjects
                    .contains(bound_subject.key())
                {
                    continue;
                }
                match project_finding(
                    inputs.authority,
                    inputs.policy,
                    inputs.spec,
                    inputs.workspace,
                    inputs.budget,
                    inputs.compiled,
                    root,
                    finding,
                ) {
                    Ok(rows) => projections.extend(rows),
                    Err(error) => {
                        self.evaluation_error = Some(error);
                        return RootStep::Failed;
                    }
                }
            }
            root_work.retained_analysis_findings = root_work
                .retained_analysis_findings
                .saturating_add(u64::try_from(findings.len()).unwrap_or(u64::MAX));
        }
        self.reached_rows = self.reached_rows.saturating_add(root_work.reached_rows);
        self.retained_analysis_findings = self
            .retained_analysis_findings
            .saturating_add(root_work.retained_analysis_findings);
        let boundary_execution_dependent = execution_boundary.execution_dependent(self, inputs);
        let computed_execution_dependent =
            composition_execution_dependent || boundary_execution_dependent;
        RootStep::Solved {
            product: RootProduct {
                findings: projections,
                gaps: root_gaps,
                work: root_work,
            },
            cache_status: TypestateProductionCacheStatus::MissIncomplete,
            execution_dependent: computed_execution_dependent,
        }
    }

    fn charge_reused(&mut self, product: &RootProduct) -> Result<(), WidenReason> {
        charge_reused_root_lanes(
            &product.work,
            &mut self.solver_budget,
            self.semantic_budget.as_mut(),
            &self.evaluation_execution_budget,
            &mut self.replayed_artifact_leases,
            &mut self.replayed_artifact_lease_bytes,
        )?;
        let work = product.work;
        let lane = |value: u64| usize::try_from(value).unwrap_or(usize::MAX);
        self.reached_rows = self.reached_rows.saturating_add(work.reached_rows);
        self.subject_rows = self.subject_rows.saturating_add(work.subject_rows);
        self.terminal_rows = self.terminal_rows.saturating_add(work.terminal_rows);
        self.retained_analysis_findings = self
            .retained_analysis_findings
            .saturating_add(work.retained_analysis_findings);
        self.omitted_analysis_findings = self
            .omitted_analysis_findings
            .saturating_add(work.omitted_analysis_findings);
        self.remaining_finding_reached_rows = self
            .remaining_finding_reached_rows
            .saturating_sub(lane(work.finding_reached_rows));
        self.remaining_finding_candidates = self
            .remaining_finding_candidates
            .saturating_sub(lane(work.finding_candidates));
        self.remaining_finding_witness_expansions = self
            .remaining_finding_witness_expansions
            .saturating_sub(lane(work.finding_witness_expansions));
        self.remaining_finding_witness_bytes = self
            .remaining_finding_witness_bytes
            .saturating_sub(lane(work.finding_witness_bytes));
        Ok(())
    }

    fn reused_fits(&self, product: &RootProduct) -> bool {
        let work = product.work;
        let lane = |value: u64| usize::try_from(value).unwrap_or(usize::MAX);
        self.solver_budget.replay_fits(work.solver)
            && self
                .semantic_budget
                .as_ref()
                .is_some_and(|budget| budget.replay_product_fits(work.semantic))
            && self
                .evaluation_execution_budget
                .external_query_work_fits(lane(work.materialized_files), lane(work.traversal_steps))
            && self
                .evaluation_artifact_leases
                .len()
                .checked_add(self.replayed_artifact_leases)
                .and_then(|total| total.checked_add(lane(work.artifact_leases)))
                .is_some()
            && self
                .replayed_artifact_lease_bytes
                .checked_add(lane(work.artifact_lease_bytes))
                .is_some_and(|bytes| self.evaluation_artifact_leases.window_fits(bytes))
            && lane(work.finding_reached_rows) <= self.remaining_finding_reached_rows
            && lane(work.finding_candidates) <= self.remaining_finding_candidates
            && lane(work.finding_witness_expansions) <= self.remaining_finding_witness_expansions
            && lane(work.finding_witness_bytes) <= self.remaining_finding_witness_bytes
    }

    fn widen_reason(&self) -> Option<WidenReason> {
        (self.shared_lane_reached || self.evaluation_execution_budget.work().exhausted)
            .then_some(WidenReason::MergedLimitReached)
    }

    fn finish(mut self, inputs: &RootPassInputs<'_>) -> RootsPass {
        let final_evaluation_execution_work = self.evaluation_execution_budget.work();
        let evaluation_materialized_files = final_evaluation_execution_work
            .materialized_files
            .saturating_sub(self.initial_evaluation_execution_work.materialized_files);
        let evaluation_traversal_steps = final_evaluation_execution_work
            .traversal_steps
            .saturating_sub(self.initial_evaluation_execution_work.traversal_steps);
        let completed_evaluation = self.evaluation_error.is_none();
        if completed_evaluation && final_evaluation_execution_work.exhausted {
            self.gaps.push(TypestateGap::ExecutionBudgetExhausted);
        }
        // The gaps no single root owns, which every subject site depends on:
        // cancellation and the shared budgets always, and any other gap no
        // recorded root names. A root's gaps reach the evaluation's list more
        // than once (the solve and the product merge both add them), so
        // ownership is by value, not by count. Undecided candidates and
        // binding omissions are added below and enter the verdicts per site.
        let global_gaps = self
            .gaps
            .iter()
            .filter(|gap| {
                gap.is_evaluation_wide() || !self.root_gaps.values().any(|gaps| gaps.contains(gap))
            })
            .cloned()
            .collect::<Vec<_>>();
        // Unproven event relations are decided per root: each engine records
        // an unproven-relation gap unless the root's complete call closure
        // excludes the relation's observing procedure. A policy-wide check
        // here would override that exclusion for relations every root rules
        // out.
        if completed_evaluation {
            self.gaps
                .extend(inputs.compiled.undecided_sites.iter().map(|site| {
                    TypestateGap::BindingOmitted {
                        omission: site.to_string(),
                    }
                }));
            self.gaps
                .extend(inputs.compiled.binding_omissions.iter().map(|omission| {
                    TypestateGap::BindingOmitted {
                        omission: omission.clone(),
                    }
                }));
        }
        let semantic_evaluation_work = self
            .semantic_budget
            .as_ref()
            .map_or_else(SemanticWork::default, SemanticBudget::used);
        let semantic_peaks = inputs
            .compiled
            .semantic_compile_peaks
            .with_child_evaluation(
                inputs.compiled.semantic_compile_work,
                semantic_evaluation_work,
                self.evaluation_artifact_retained_peak,
                final_evaluation_execution_work.traversal_steps,
            );
        let work = typestate_work_report(
            inputs.compiled,
            &TypestateWorkMeasurements {
                cache_work: self.cache_work,
                semantic_evaluation_work,
                semantic_evaluation_resident_peak: self
                    .semantic_budget
                    .as_ref()
                    .map_or_else(SemanticWork::default, SemanticBudget::resident_peak),
                semantic_evaluation_root_work_peak: self
                    .semantic_budget
                    .as_ref()
                    .map_or_else(SemanticWork::default, SemanticBudget::root_work_peak),
                semantic_peaks,
                final_execution_work: final_evaluation_execution_work,
                evaluation_materialized_files,
                evaluation_traversal_steps,
                semantic_artifact_leases: self
                    .evaluation_artifact_leases
                    .len()
                    .saturating_add(self.replayed_artifact_leases),
                evaluation_semantic_artifact_leases: self
                    .evaluation_artifact_leases
                    .additions_len()
                    .saturating_add(self.replayed_artifact_leases),
                reached_rows: self.reached_rows,
                subject_rows: self.subject_rows,
                terminal_rows: self.terminal_rows,
                retained_analysis_findings: self.retained_analysis_findings,
                omitted_analysis_findings: self.omitted_analysis_findings,
                retained_findings: if completed_evaluation {
                    u64::try_from(self.projections.len()).unwrap_or(u64::MAX)
                } else {
                    0
                },
            },
        );
        if let Some(message) = self.evaluation_error {
            return RootsPass::Failed(TypestateEvaluationFailure { message, work });
        }
        self.gaps.sort();
        self.gaps.dedup();
        let mut reasons = self
            .gaps
            .iter()
            .map(TypestateGap::reason)
            .collect::<Vec<_>>();
        reasons.sort();
        reasons.dedup();
        let completion = if reasons.is_empty() {
            PolicyRunCompletion::Complete
        } else {
            PolicyRunCompletion::inconclusive(reasons)
                .expect("deduplicated typestate incomplete reasons are canonical")
        };
        // Every gap is a diagnostic, so an inconclusive run names what it
        // could not conclude.
        let diagnostics_truncated = self.gaps.len() > inputs.budget.max_diagnostics();
        let diagnostics = self
            .gaps
            .iter()
            .take(inputs.budget.max_diagnostics())
            .map(|gap| {
                PolicyDiagnostic::try_new(
                    PolicyDiagnosticCode::CodeQuery {
                        code: gap.diagnostic_code(),
                    },
                    PolicyDiagnosticSeverity::Warning,
                    PolicyDiagnosticImpact::RunIncomplete,
                    gap.message(),
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
        let subjects =
            match subject_verdicts(inputs, &self.root_gaps, &global_gaps, &self.projections) {
                Ok(subjects) => subjects,
                Err(message) => {
                    return RootsPass::Failed(TypestateEvaluationFailure {
                        message,
                        work: work.clone(),
                    });
                }
            };
        RootsPass::Complete(TypestateProjectionPayload {
            projections: self.projections,
            completion,
            diagnostics,
            diagnostics_truncated,
            work,
            subjects: Some(subjects),
        })
    }
}

/// One completed evaluation's verdict for every subject site (#10985).
///
/// A Selected site groups the subjects bound from one selected syntax site of
/// one selector, the same location an undecided candidate is reported at. Its
/// further findings are absent only if every root serving those subjects was
/// solved without a gap, no gap belongs to the whole evaluation, and no
/// subject at the site had a binding omitted.
/// An undecided candidate never binds, so it contaminates a selected site only
/// through the gaps its roots recorded.
fn subject_verdicts(
    inputs: &RootPassInputs<'_>,
    root_gaps: &HashMap<ProcedureHandle, Vec<TypestateGap>>,
    global_gaps: &[TypestateGap],
    projections: &[TypestateProjectedFinding],
) -> Result<PolicySubjectVerdicts, String> {
    use super::selector_compiler::candidate_enumeration::WhitelistedCallSelector;
    let compiled = inputs.compiled;
    let policy_id = &inputs.policy.definition().metadata.id;
    // The enumeration status follows the selector's shape, never a unit, so
    // a warm run reports what a cold run does.
    let mut selectors: Vec<SubjectSelectorEnumeration> = Vec::new();
    for subject in &inputs.spec.subjects {
        let selector = inputs
            .policy
            .resolved_selectors()
            .iter()
            .find(|selector| selector.path == subject.selector_path)
            .ok_or_else(|| {
                "typestate subject selector is absent from the loaded policy".to_owned()
            })?;
        let name = selector.path.to_string();
        if selectors.iter().any(|known| known.selector == name) {
            continue;
        }
        let certified = selector
            .as_query()
            .is_some_and(|(_, query)| WhitelistedCallSelector::check(query).is_some());
        // Only the certified shape proves its candidate universe; any other
        // selection may keep a proven subset of an incomplete query.
        let enumeration = if certified {
            SubjectEnumeration::Certified
        } else {
            SubjectEnumeration::Uncertified
        };
        selectors.push(SubjectSelectorEnumeration {
            selector: name,
            enumeration,
        });
    }
    let mut findings_by_subject: HashMap<&AnalysisSubjectRef, Vec<PolicyFindingId>> =
        HashMap::new();
    for projection in projections {
        findings_by_subject
            .entry(&projection.subject)
            .or_default()
            .push(PolicyFindingId::from_typestate_anchor(
                policy_id,
                &projection.anchor,
            ));
    }
    type SiteKey = (String, String, Option<PolicyByteSpan>);
    struct SiteGroup<'c> {
        location: PolicySourceLocation,
        subjects: Vec<&'c CompiledTypestateSubject>,
    }
    let mut locations = super::semantic_identity::FileSpanLocations::default();
    let mut groups: HashMap<SiteKey, SiteGroup<'_>> = HashMap::new();
    // A subject selected at several sites reports its findings at the first.
    let mut subject_sites: HashMap<&TypestateSubjectKey, SiteKey> = HashMap::new();
    for subject in compiled.subjects.iter() {
        let spec_subject = inputs
            .spec
            .subjects
            .iter()
            .find(|candidate| candidate.identity == subject.endpoint)
            .ok_or_else(|| "typestate subject is absent from the loaded policy".to_owned())?;
        for (file, span) in &subject.selected_sites {
            let location = locations.location(inputs.workspace, file, span)?;
            let key = (
                spec_subject.selector_path.to_string(),
                location.path().to_owned(),
                location.byte_span(),
            );
            subject_sites
                .entry(&subject.key)
                .and_modify(|first| {
                    if key < *first {
                        *first = key.clone();
                    }
                })
                .or_insert_with(|| key.clone());
            let group = groups.entry(key).or_insert_with(|| SiteGroup {
                location,
                subjects: Vec::new(),
            });
            if !group.subjects.iter().any(|known| known.key == subject.key) {
                group.subjects.push(subject);
            }
        }
    }
    let mut entries = Vec::with_capacity(groups.len() + compiled.undecided_sites.len());
    for (key, group) in groups {
        let mut findings = Vec::new();
        let mut reasons: Vec<String> = global_gaps
            .iter()
            .map(|gap| gap.label().to_owned())
            .collect();
        let mut roots: Vec<&ProcedureHandle> = Vec::new();
        // An omitted event, terminal or result-contract binding can hide a
        // transition from any subject, so no site can claim complete absence.
        if !compiled.binding_omissions.is_empty() {
            reasons.push("binding_incomplete".to_owned());
        }
        for subject in &group.subjects {
            if subject_sites.get(&subject.key) != Some(&key) {
                // This subject's findings are reported at its first site.
                reasons.push("subject_shared_with_other_site".to_owned());
            } else {
                // The same reference project_finding mints for this subject.
                let subject_ref = AnalysisSubjectRef::try_new(
                    "bifrost",
                    super::semantic_identity::stable_hex(
                        subject.key.public_canonical_rendering().as_bytes(),
                    ),
                )
                .map_err(|error| error.to_string())?;
                findings.extend(
                    findings_by_subject
                        .get(&subject_ref)
                        .into_iter()
                        .flatten()
                        .copied(),
                );
            }
            if compiled.binding_omission_subjects.contains(&subject.key) {
                reasons.push("binding_incomplete".to_owned());
            }
            if !roots.contains(&&subject.root) {
                roots.push(&subject.root);
            }
        }
        for root in roots {
            match root_gaps.get(root) {
                Some(gaps) => reasons.extend(gaps.iter().map(|gap| gap.label().to_owned())),
                None => reasons.push("root_unfinished".to_owned()),
            }
        }
        findings.sort_unstable();
        findings.dedup();
        let partial = !reasons.is_empty();
        entries.push(PolicySubjectVerdict {
            selector: key.0,
            location: group.location,
            verdict: SubjectVerdict::Selected {
                bindings: u32::try_from(group.subjects.len()).unwrap_or(u32::MAX),
                findings,
                further_findings_absent: if partial {
                    FurtherFindingsAbsent::partial(reasons)
                } else {
                    FurtherFindingsAbsent::Complete
                },
                finding_location_bound: partial.then_some(FindingLocationBound::Unbounded),
            },
        });
    }
    // Two subjects that share a selector classify its candidates twice.
    let mut undecided_seen = HashSet::new();
    for site in &compiled.undecided_sites {
        if !undecided_seen.insert((&site.selector, &site.file, site.span.clone())) {
            continue;
        }
        let mut reasons = site
            .reasons
            .iter()
            .map(|reason| reason.label())
            .collect::<Vec<_>>();
        reasons.sort();
        reasons.dedup();
        entries.push(PolicySubjectVerdict {
            selector: site.selector.clone(),
            location: locations.location(inputs.workspace, &site.file, &site.span)?,
            verdict: SubjectVerdict::Undecided {
                reasons,
                finding_location_bound: FindingLocationBound::Unbounded,
            },
        });
    }
    // A selected site with no subject of its own selector (its binding was
    // omitted, it resolved to no subject, or precedence reduction gave its
    // object to another selector's subject) has no entry. Count it as an
    // omitted selected entry so no reader takes its location for a
    // non-selection.
    let bound_sites = compiled
        .subjects
        .iter()
        .flat_map(|subject| {
            let selector = inputs
                .spec
                .subjects
                .iter()
                .find(|candidate| candidate.identity == subject.endpoint)
                .map(|candidate| candidate.selector_path.to_string());
            subject
                .selected_sites
                .iter()
                .map(move |(file, span)| (selector.clone(), file, span))
        })
        .collect::<HashSet<_>>();
    let unbound_selected_sites = compiled
        .selected_subject_sites
        .iter()
        .filter(|(selector, file, span)| {
            !bound_sites.contains(&(Some(selector.clone()), file, span))
        })
        .collect::<HashSet<_>>()
        .len();
    let mut verdicts = PolicySubjectVerdicts::new(selectors, entries);
    verdicts.omitted.selected = verdicts
        .omitted
        .selected
        .saturating_add(u64::try_from(unbound_selected_sites).unwrap_or(u64::MAX));
    Ok(verdicts)
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
    units: Option<&mut RootUnits<'_>>,
) -> RootsPass {
    let engine = compiled.engine.clone();
    let uncancelled = CancellationToken::default();
    let inputs = RootPassInputs {
        engine,
        authority,
        policy,
        spec,
        workspace,
        cancellation: cancellation.unwrap_or(&uncancelled),
        budget,
        compiled,
        summaries,
        active_semantic_model_snapshot,
        limits: budget.query_limits().typestate,
    };
    let mut state = RootPassState::new(&inputs);
    if let Some(units) = units {
        if let Err(reason) = units.enumerate(&compiled.roots) {
            return RootsPass::Widen(reason);
        }
        let slice = TypestateRootSlice {
            inputs: &inputs,
            state: RefCell::new(Some(state)),
            marker: std::marker::PhantomData,
        };
        return match evaluate_reusable_slice(
            &slice,
            compiled.roots.iter().zip(&units.keys),
            &mut units.reuse,
            &mut units.attempt,
            workspace.analyzer(),
            Some(inputs.cancellation),
        ) {
            Ok(pass) => pass,
            Err(reason) => RootsPass::Widen(reason),
        };
    }
    for root in &compiled.roots {
        state.begin_root();
        match state.solve_root(&inputs, root) {
            RootStep::Solved { product, .. } => {
                state.root_gaps.insert(root.clone(), product.gaps.clone());
                state.gaps.extend(product.gaps);
                state.projections.extend(product.findings);
            }
            RootStep::Unfinished => continue,
            RootStep::Stopped | RootStep::Failed => break,
        }
    }
    state.finish(&inputs)
}

struct TypestateRootSlice<'a, 'b, 'r> {
    inputs: &'a RootPassInputs<'b>,
    state: RefCell<Option<RootPassState>>,
    marker: std::marker::PhantomData<&'r ProcedureHandle>,
}

enum RootOutcome {
    Reused(ProcedureHandle, RootProduct),
    Solved {
        root: ProcedureHandle,
        product: RootProduct,
        cache_status: TypestateProductionCacheStatus,
        execution_dependent: bool,
    },
    Unfinished,
}

enum RootStop {
    Widen(WidenReason),
    Failed,
}

impl<'r> UnitSlice for TypestateRootSlice<'_, '_, 'r> {
    type Seed = &'r ProcedureHandle;
    type Prefix = RootOutcome;
    type Error = RootStop;
    type BudgetState = ();
    type Allowance = ();
    type Capture<'a> = ();
    type Merged = ();
    type Output = RootsPass;

    fn before_lookup(&self, _: &mut (), _: &Self::Seed) -> Result<(), WidenReason> {
        let mut state = self.state.borrow_mut();
        let state = state.as_mut().expect("root state available");
        state.begin_root();
        if state.remaining_finding_reached_rows == 0
            || state.remaining_finding_candidates == 0
            || state.remaining_finding_witness_expansions == 0
            || state.remaining_finding_witness_bytes == 0
        {
            state.shared_lane_reached = true;
            state.gaps.push(TypestateGap::FindingBudgetExhausted);
            state.omitted_analysis_findings = state.omitted_analysis_findings.saturating_add(1);
            return Err(WidenReason::MergedLimitReached);
        }
        Ok(())
    }
    fn remaining(&self, _: &()) -> Option<()> {
        Some(())
    }
    fn prefix(&self, seed: &Self::Seed, _: ()) -> Result<Self::Prefix, Self::Error> {
        let mut state = self.state.borrow_mut();
        match state
            .as_mut()
            .expect("root state available")
            .solve_root(self.inputs, seed)
        {
            RootStep::Solved {
                product,
                cache_status,
                execution_dependent,
            } => Ok(RootOutcome::Solved {
                root: (*seed).clone(),
                product,
                cache_status,
                execution_dependent,
            }),
            RootStep::Unfinished => Ok(RootOutcome::Unfinished),
            RootStep::Stopped => Err(RootStop::Widen(WidenReason::MergedLimitReached)),
            RootStep::Failed => Err(RootStop::Failed),
        }
    }
    fn decode(
        &self,
        seed: &Self::Seed,
        product: PolicyUnitProduct,
        _: &[ReadKey],
    ) -> Result<Self::Prefix, UnitDecodeError> {
        product
            .into_root()
            .map(|product| RootOutcome::Reused((*seed).clone(), product))
            .ok_or(UnitDecodeError::Widen(WidenReason::ProductLoadFailed))
    }
    fn encode(&self, prefix: &Self::Prefix) -> PolicyUnitProduct {
        match prefix {
            RootOutcome::Solved { product, .. } | RootOutcome::Reused(_, product) => {
                PolicyUnitProduct::Root(product.clone())
            }
            RootOutcome::Unfinished => unreachable!("unfinished roots are not published"),
        }
    }
    fn charge(&self, _: &mut (), prefix: &Self::Prefix) {
        if let RootOutcome::Reused(_, product) = prefix {
            self.state
                .borrow_mut()
                .as_mut()
                .expect("root state available")
                .charge_reused(product)
                .expect("reused root fit was checked");
        }
    }
    fn fits(&self, _: &(), prefix: &Self::Prefix) -> bool {
        match prefix {
            RootOutcome::Reused(_, product) => self
                .state
                .borrow()
                .as_ref()
                .expect("root state available")
                .reused_fits(product),
            _ => true,
        }
    }
    fn capture(&self, _: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer) {}
    fn publishable(&self, prefix: &Self::Prefix) -> bool {
        match prefix {
            RootOutcome::Solved {
                cache_status: TypestateProductionCacheStatus::Hit,
                ..
            } => {
                let policy_id = &self.inputs.policy.definition().metadata.id;
                brokk_bifrost_analysis::profiling::note_with(|| {
                    format!(
                        "policy.units policy={policy_id} partition=root unpublished=result_cache_hit"
                    )
                });
                false
            }
            RootOutcome::Solved { .. } => true,
            _ => false,
        }
    }
    fn execution_dependent(&self, prefix: &Self::Prefix) -> bool {
        matches!(
            prefix,
            RootOutcome::Solved {
                execution_dependent: true,
                ..
            }
        )
    }
    fn failure(&self, error: Self::Error, _: Vec<Self::Prefix>) -> Self::Output {
        match error {
            RootStop::Widen(reason) => RootsPass::Widen(reason),
            RootStop::Failed => self
                .state
                .borrow_mut()
                .take()
                .expect("root state available")
                .finish(self.inputs),
        }
    }
    fn merge(&self, products: impl IntoIterator<Item = Self::Prefix>) {
        let mut state = self.state.borrow_mut();
        let state = state.as_mut().expect("root state available");
        for product in products {
            match product {
                RootOutcome::Reused(root, product) => {
                    state.root_gaps.insert(root, product.gaps.clone());
                    state.gaps.extend(product.gaps);
                    state.projections.extend(product.findings);
                }
                RootOutcome::Solved { root, product, .. } => {
                    state.root_gaps.insert(root, product.gaps.clone());
                    state.gaps.extend(product.gaps);
                    state.projections.extend(product.findings);
                }
                RootOutcome::Unfinished => {}
            }
        }
    }
    fn suffix(&self, _: (), _: usize) -> Self::Output {
        let state = self
            .state
            .borrow_mut()
            .take()
            .expect("root state available");
        if let Some(reason) = state.widen_reason() {
            RootsPass::Widen(reason)
        } else {
            state.finish(self.inputs)
        }
    }
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
    let close_contract_reasons = compiled
        .close_contract_reasons
        .get(bound_subject.key())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
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
            close_contract_reasons,
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
            model_attribution: None,
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
    endpoint_provenance_slot(
        &compiled.event_endpoints,
        binding.get() as usize,
        "typestate event binding has no policy provenance slot",
    )
}

fn terminal_endpoint(
    compiled: &CompiledTypestatePolicy,
    binding: TypestateTerminalBindingId,
) -> Result<Option<ResolvedEndpointIdentity>, String> {
    endpoint_provenance_slot(
        &compiled.terminal_endpoints,
        binding.get() as usize,
        "typestate terminal binding has no policy provenance slot",
    )
}

fn endpoint_provenance_slot(
    endpoints: &[Option<ResolvedEndpointIdentity>],
    index: usize,
    missing_message: &'static str,
) -> Result<Option<ResolvedEndpointIdentity>, String> {
    endpoints
        .get(index)
        .cloned()
        .ok_or_else(|| missing_message.to_owned())
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
    close_contract_reasons: &[String],
    finding_key: &str,
    report_options: &PolicyReportOptions,
    budget: &PolicyBudget,
) -> Result<(ProjectedFindingReport, Vec<WitnessId>), String> {
    let primary = super::semantic_identity::policy_location(workspace, finding.site())?;
    let certainty = match finding.certainty() {
        TypestateFindingCertainty::Must => FindingCertainty::Definite,
        TypestateFindingCertainty::May | TypestateFindingCertainty::Inconclusive => {
            FindingCertainty::possible(certainty_reasons(finding, close_contract_reasons)?)
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
                SummaryWitnessStepKind::ModeledReceiver => {
                    (WitnessStepKind::Propagation, "receiver operand")
                }
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
    for (_, locator) in finding.relation_sites() {
        let location = super::semantic_identity::policy_location(workspace, locator)?;
        super::projection::retain_related_location(
            &mut related,
            &primary,
            PolicyLocationRelationship::Evidence,
            location,
            related_limit,
            &mut omitted_related_locations,
        )?;
    }
    for (relationship, locators) in [
        (PolicyLocationRelationship::Source, acquisitions),
        (PolicyLocationRelationship::Subject, spellings),
    ] {
        for locator in locators {
            let location = super::semantic_identity::policy_location(workspace, locator)?;
            super::projection::retain_related_location(
                &mut related,
                &primary,
                relationship,
                location,
                related_limit,
                &mut omitted_related_locations,
            )?;
        }
    }
    Ok((
        ProjectedFindingReport {
            value_type_barrier_notes: Default::default(),
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

fn certainty_reasons(
    finding: &TypestateFinding,
    close_contract_reasons: &[String],
) -> Result<Vec<CertaintyReason>, String> {
    let uncertainty = finding.evidence().uncertainty();
    let mut reasons = Vec::new();
    if uncertainty.contains(TypestateUncertainty::AmbiguousDispatch) {
        reasons.push(CertaintyReason::AmbiguousDispatch);
    }
    for (cause, code) in TYPESTATE_UNCERTAINTY_CODES {
        if cause != TypestateUncertainty::AmbiguousDispatch && uncertainty.contains(cause) {
            reasons.push(
                CertaintyReason::analyzer_ambiguity(code).map_err(|error| error.to_string())?,
            );
        }
    }
    for (kind, _) in finding.relation_sites() {
        let code = match kind {
            brokk_bifrost_flow::typestate::FirstUnprovenRelationKind::Handoff => {
                "typestate-unproven-handoff"
            }
            brokk_bifrost_flow::typestate::FirstUnprovenRelationKind::UnresolvedCall => {
                "typestate-unresolved-call"
            }
            brokk_bifrost_flow::typestate::FirstUnprovenRelationKind::UnprovenConversion => {
                "typestate-unproven-conversion"
            }
            brokk_bifrost_flow::typestate::FirstUnprovenRelationKind::Guard => {
                "typestate-unproven-guard"
            }
        };
        let reason =
            CertaintyReason::analyzer_ambiguity(code).map_err(|error| error.to_string())?;
        if !reasons.contains(&reason) {
            reasons.push(reason);
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
    // A helper call the contract did not discharge is the concrete reason this
    // finding kept its obligation, so it belongs in the report beside the
    // generic path uncertainty above.
    for reason in close_contract_reasons {
        reasons.push(CertaintyReason::MayEvidence {
            reason: reason.clone(),
        });
    }
    Ok(reasons)
}

fn failed_projection_payload(message: &str, work: PolicyWorkReport) -> TypestateProjectionPayload {
    let completion = PolicyRunCompletion::failed(vec![PolicyFailureReason::InternalInvariant])
        .expect("one failure reason is canonical");
    TypestateProjectionPayload {
        projections: Vec::new(),
        completion,
        diagnostics: vec![super::projection::failed_projection_diagnostic(message)],
        diagnostics_truncated: false,
        work,
        subjects: None,
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
            let mut reasons = super::evaluator::incomplete_reasons(&completion);
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
        | TypestatePolicyCompileError::InvalidEventSet(_)
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
        completion: super::selector_compiler::incomplete_code_query_completion(code),
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
    super::selector_compiler::semantic_outcome_failure(outcome, operation).map_or(
        Ok(()),
        |(completion, detail)| {
            Err(TypestatePolicyCompileError::QueryIncomplete { completion, detail })
        },
    )
}

/// The protocol events the automaton treats as a close.
///
/// An event is a release event when some transition on it leads into a state a
/// terminal expectation accepts: that is the structural meaning of "the policy
/// is satisfied", and it does not depend on how a policy spells the event, so
/// a policy that calls its close something else still earns a contract.
fn release_event_keys(protocol: &CompiledProtocol) -> HashSet<ProtocolEventKey> {
    let accepted = protocol
        .terminal_expectations()
        .iter()
        .flat_map(|expectation| expectation.expected_states().iter().copied())
        .collect::<HashSet<_>>();
    protocol
        .transitions()
        .iter()
        .filter(|transition| accepted.contains(&transition.to()))
        .filter_map(|transition| protocol.event(transition.on()))
        .map(|event| event.key().clone())
        .collect()
}

/// The authored release events a workspace-helper close is discharged through.
///
/// Only an argument-form release describes "the object this call was handed is
/// closed". The injected binding names the caller's own call site and subject,
/// so the reviewed argument position is not part of the claim and every
/// argument-form release row applies.
fn argument_form_release_events(
    spec: &ResolvedTypestatePolicySpec,
    release_events: &HashSet<ProtocolEventKey>,
) -> Result<Vec<ArgumentFormReleaseEvent>, TypestatePolicyCompileError> {
    let mut releases = Vec::new();
    for (event_order, event) in spec.automaton.events.iter().enumerate() {
        let ResolvedTypestateEventTrigger::Calls { subject, phase, .. } = &event.trigger else {
            continue;
        };
        if !matches!(subject, TypestateCallBinding::ArgumentIndex { .. }) {
            continue;
        }
        let event_key = ProtocolEventKey::new(event.id.as_str())
            .map_err(|error| TypestatePolicyCompileError::UnsupportedBinding(error.to_string()))?;
        if !release_events.contains(&event_key) {
            continue;
        }
        let order = u32::try_from(event_order).map_err(|_| {
            TypestatePolicyCompileError::UnsupportedBinding(
                "too many ordered typestate events".to_owned(),
            )
        })?;
        releases.push(ArgumentFormReleaseEvent {
            phase: *phase,
            event: event_key,
            policy_event: event.id.clone(),
            semantic_effect: event.semantic_effect.as_deref().map(Arc::from),
            order,
        });
    }
    Ok(releases)
}

/// How many workspace call frames a close contract may follow.
///
/// The bound matches the interprocedural depth the analyzer itself inlines, so
/// a discharge never claims more than the call graph the rest of the compile
/// reasons about.
fn close_contract_depth() -> u32 {
    IcfgSnapshotLimits::default().max_call_depth
}

fn cfg_algorithm_error(
    error: CfgAlgorithmError<ProgramPointId>,
    operation: &str,
) -> TypestatePolicyCompileError {
    match error {
        CfgAlgorithmError::Cancelled { .. } => TypestatePolicyCompileError::QueryIncomplete {
            completion: CodeQueryCompletion::Cancelled,
            detail: format!("{operation} was cancelled"),
        },
        CfgAlgorithmError::ExceededBudget(exceeded) => query_budget_error(
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
            format!("{operation} exceeded its CFG work budget: {exceeded:?}"),
        ),
        CfgAlgorithmError::InvalidNode(node) => {
            unreachable!("a procedure graph only yields its own program points: {node:?}")
        }
    }
}

/// The reason a workspace callee did not discharge its caller's obligation.
///
/// Every reason but `NoEvidence` names what the caller would have to fix, and
/// each one names the callee so a finding that keeps the obligation can be
/// traced to the helper that failed to remove it. `NoEvidence` is silent: a
/// call that resolves no close at all is not a helper that failed, it is just
/// a call.
fn close_contract_reason(formal: &ProcedurePortHandle, contract: &CloseContract) -> Option<String> {
    let callee = procedure_display_name(formal.procedure());
    match contract {
        CloseContract::Discharged | CloseContract::NoEvidence => None,
        CloseContract::Partial(gap) => Some(format!(
            "the helper {callee} closes the argument only on some paths: {}",
            gap.describe()
        )),
        CloseContract::DifferentObject => Some(format!(
            "the helper {callee} closes a different resource than the argument bound at this call"
        )),
        CloseContract::UnboundClose => Some(format!(
            "the helper {callee} closes a resource that no caller argument binds to"
        )),
        CloseContract::BeyondBound => Some(format!(
            "the helper {callee} closes the argument only through a chain deeper than the interprocedural analysis bound"
        )),
        CloseContract::Cycle => Some(format!(
            "the helper {callee} closes the argument only through a call cycle"
        )),
    }
}

/// The source-facing name of a procedure, taken from its declaration locator.
///
/// This is the name a reader of the finding sees in the code, which is what a
/// reason has to name to be actionable.
fn procedure_display_name(procedure: &ProcedureHandle) -> String {
    procedure
        .semantics()
        .locator()
        .declaration()
        .segments()
        .iter()
        .rev()
        .find_map(|segment| segment.name())
        .unwrap_or("an unnamed helper")
        .to_owned()
}

/// How many distinct helper reasons one subject's findings may carry.
///
/// A subject can call many helpers; a finding carries enough reasons to name
/// the ones a reader can act on without letting a pathological workspace grow
/// the report without bound.
const MAX_CLOSE_CONTRACT_REASONS: usize = 32;

impl<'a> TypestatePolicyCompiler<'a> {
    pub(crate) fn new(
        workspace: &'a WorkspaceAnalyzer,
        flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
        query_limits: CodeQueryExecutionLimits,
        max_selector_results: usize,
        cancellation: &'a CancellationToken,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        let flow_state = flow_state.into();
        Self {
            selectors: super::selector_compiler::PolicySelectorSession::new(
                workspace,
                &flow_state,
                "typestate",
                query_limits,
                max_selector_results,
                cancellation,
                // Auxiliary event and terminal selectors stay global, even when
                // the same query also selects scoped starting subjects.
                CodeQueryExecutionScope::whole_workspace(),
            ),
            subject_scope: CodeQueryExecutionScope::whole_workspace(),
            active_semantic_models: active_semantic_model_snapshot
                .as_ref()
                .map(|snapshot| Arc::clone(snapshot.active_models())),
            syntax_trees: HashMap::new(),
            formal_names: HashMap::new(),
            selected_template_targets: HashMap::new(),
            close_contracts: HashMap::new(),
            close_contract_stack: Vec::new(),
            binding_omissions: Vec::new(),
            selected_subject_sites: Vec::new(),
            selection_fingerprint: Vec::new(),
            undecided_sites: Vec::new(),
            unproven_relations: Vec::new(),
            binding_omission_procedures: HashSet::new(),
        }
    }

    fn with_subject_scope(mut self, subject_scope: CodeQueryExecutionScope<'a>) -> Self {
        self.subject_scope = subject_scope;
        self
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
            let selections = self.select_subject(selector, &binding)?;
            let class =
                TypestateSubjectClassKey::new(format!("endpoint.{}", subject.semantic_hash))
                    .map_err(|error| {
                        TypestatePolicyCompileError::UnsupportedBinding(error.to_string())
                    })?;
            for selection in selections {
                let selected_site = (selection.file.clone(), selection.subject_span.clone());
                let inactive = selection.has_no_result_activation();
                let resolved_selections = self.resolve_selection(selection, &binding, None)?;
                // Binding validation still runs for a proven inactive result.
                // It has no lifecycle subject, rather than a missing binding.
                if inactive {
                    debug_assert!(resolved_selections.is_empty());
                    continue;
                }
                self.selected_subject_sites.push((
                    subject.selector_path.to_string(),
                    selected_site.0.clone(),
                    selected_site.1.clone(),
                ));
                for resolved in resolved_selections {
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
                                selected_site: selected_site.clone(),
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
                    .selected_sites
                    .contains(&subject.selected_site)
                {
                    subjects[index]
                        .selected_sites
                        .push(subject.selected_site.clone());
                }
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
                    selected_sites: vec![subject.selected_site.clone()],
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

        // The protocol's release events are identified from the automaton, not
        // from an event name, so a policy that spells its close differently
        // still gets an interprocedural contract for as long as the close
        // event is what leaves the obligation satisfied.
        let engine = select_typestate_engine(
            &policy.definition().metadata.id,
            &roots,
            self.selectors.workspace(),
        )?;
        let release_events = release_event_keys(&protocol);
        let argument_form_releases = argument_form_release_events(spec, &release_events)?;
        // Every close call this compile resolves in a workspace body, kept
        // before any subject filter so a callee's contract does not depend on
        // which caller happened to name it.
        let mut close_sites: Vec<CloseSiteFact> = Vec::new();
        let mut events = Vec::new();
        let mut event_templates = Vec::new();
        let mut coverage_selections = HashMap::<
            (TypestateSubjectKey, CallSiteHandle),
            Option<(ActivatedProcedureSummary, String)>,
        >::new();
        for (event_order, event) in spec.automaton.events.iter().enumerate() {
            let order = u32::try_from(event_order).map_err(|_| {
                TypestatePolicyCompileError::UnsupportedBinding(
                    "too many ordered typestate events".to_owned(),
                )
            })?;
            let event_key = ProtocolEventKey::new(event.id.as_str()).map_err(|error| {
                TypestatePolicyCompileError::UnsupportedBinding(error.to_string())
            })?;
            let argument_condition = authored_argument_condition(&event.trigger);
            if let ResolvedTypestateEventTrigger::SemanticEvent {
                event: semantic_event,
            } = &event.trigger
            {
                for subject in subjects
                    .iter()
                    .filter(|subject| event.applies_to_subjects.contains(&subject.endpoint))
                {
                    for (point, quality) in semantic_event_points(&subject.root, *semantic_event)? {
                        events.push(PendingEventBinding {
                            event: event_key.clone(),
                            policy_event: event.id.clone(),
                            subject: subject.key.clone(),
                            site: TypestateObservationSite::program_point(
                                point,
                                TypestateBindingContext::root(),
                            ),
                            phase: EventObservationPhase::AnalysisRoot(*semantic_event),
                            order,
                            role: TypestateObjectRole::CurrentObject,
                            quality,
                            endpoint: None,
                            modeled_external_effect: None,
                            semantic_effect: event.semantic_effect.as_deref().map(Arc::from),
                            condition: None,
                            alias_derived: false,
                            selected_operand: None,
                        });
                    }
                }
                continue;
            }
            for trigger in self.event_selections(policy, &selectors, &event.trigger)? {
                let endpoint = trigger.endpoint.clone();
                let release_event =
                    matches!(&event.trigger, ResolvedTypestateEventTrigger::Calls { .. })
                        && release_events.contains(&event_key);
                for resolved in self.resolve_selection(
                    trigger.selection,
                    &trigger.binding,
                    Some(trigger.phase),
                )? {
                    let condition_matches = argument_condition
                        .map(|condition| evaluate_argument_condition(&resolved, condition));
                    let condition_unknown = matches!(condition_matches, Some(None));
                    if condition_unknown {
                        self.binding_omissions.push(format!(
                            "typestate event {} argument Boolean value is unknown at {:?}",
                            event.id,
                            resolved.procedure.semantics().locator(),
                        ));
                    }
                    let flow_condition = argument_condition.map(|condition| {
                        TypestateEventCondition::boolean_argument(condition.index, condition.equals)
                    });
                    if release_event && !matches!(condition_matches, Some(None | Some(false))) {
                        self.note_close_sites(&resolved, &mut close_sites)?;
                    }
                    // A selected formal may name a different caller subject.
                    // Keep the selector's event as an inert, subject-specific
                    // template; only a guarded summary can use it.
                    if engine == TypestateEngine::Composition
                        && trigger.phase != EndpointObservationPhase::AtMatch
                        && let Some(selected_operand) = &resolved.selected_operand
                        && resolved.objects.len() == 1
                        && resolved.modeled_target_origin.is_none()
                    {
                        let object = &resolved.objects[0];
                        let eligible_subjects = subjects
                            .iter()
                            .filter(|subject| {
                                event.applies_to_subjects.contains(&subject.endpoint)
                                    && self
                                        .modeled_external_effect_id(
                                            subject,
                                            &resolved,
                                            trigger.phase,
                                        )
                                        .is_none()
                                    && subject.key.object()
                                        != TypestateSubjectKey::for_object(
                                            subject.key.class().clone(),
                                            &object.object,
                                        )
                                        .object()
                            })
                            .collect::<Vec<_>>();
                        if !eligible_subjects.is_empty()
                            && let Some(selected_target) =
                                self.selected_template_target(selected_operand.call())?
                        {
                            for subject in eligible_subjects {
                                let (site, role) = event_site(&resolved, trigger.phase)?;
                                event_templates.push(PendingEventBinding {
                                    event: event_key.clone(),
                                    policy_event: event.id.clone(),
                                    subject: subject.key.clone(),
                                    site,
                                    phase: EventObservationPhase::Endpoint(trigger.phase),
                                    order,
                                    role,
                                    quality: if condition_unknown {
                                        condition_incomplete_quality(object.quality.clone())
                                    } else {
                                        object.quality.clone()
                                    },
                                    endpoint: endpoint.clone(),
                                    modeled_external_effect: None,
                                    semantic_effect: None,
                                    condition: flow_condition,
                                    alias_derived: false,
                                    selected_operand: Some(
                                        selected_operand
                                            .clone()
                                            .with_selected_target(selected_target.clone()),
                                    ),
                                });
                            }
                        }
                    }
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
                            if spec.automaton.event_set.is_some()
                                && let Some(call) = resolved.call.as_ref()
                            {
                                let selected = self
                                    .authored_external_summary(&resolved)
                                    .zip(resolved.modeled_member_id.clone());
                                coverage_selections
                                    .entry((subject.key.clone(), call.clone()))
                                    .and_modify(|prior| {
                                        if !same_coverage_selection(prior, &selected) {
                                            *prior = None;
                                        }
                                    })
                                    .or_insert(selected);
                            }
                            let modeled_external_effect =
                                self.modeled_external_effect_id(subject, &resolved, trigger.phase);
                            let quality = if modeled_external_effect.is_some()
                                && subject.fresh_result
                                && resolved.multiplicity.retained() == 1
                            {
                                TypestateBindingQuality::proven_unique()
                            } else {
                                object.quality.clone()
                            };
                            let quality = if condition_unknown {
                                condition_incomplete_quality(quality)
                            } else {
                                quality
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
                                semantic_effect: event.semantic_effect.as_deref().map(Arc::from),
                                condition: flow_condition,
                                alias_derived: false,
                                selected_operand: (trigger.phase
                                    != EndpointObservationPhase::AtMatch)
                                    .then(|| resolved.selected_operand.clone())
                                    .flatten(),
                            });
                        }
                    }
                    let unnamed = subjects_absent_from(&resolved, &subjects, |subject| {
                        event.applies_to_subjects.contains(&subject.endpoint)
                    });
                    let (absence_site, _) = event_site(&resolved, trigger.phase)?;
                    for aliased in self.alias_bound_subjects(
                        &resolved,
                        &unnamed,
                        event_key.as_str(),
                        format!("{:?}", trigger.phase).as_str(),
                        &absence_site,
                    )? {
                        let (site, role) = event_site(&resolved, trigger.phase)?;
                        if spec.automaton.event_set.is_some()
                            && let Some(call) = resolved.call.as_ref()
                        {
                            let selected = self
                                .authored_external_summary(&resolved)
                                .zip(resolved.modeled_member_id.clone());
                            coverage_selections
                                .entry((aliased.clone(), call.clone()))
                                .and_modify(|prior| {
                                    if !same_coverage_selection(prior, &selected) {
                                        *prior = None;
                                    }
                                })
                                .or_insert(selected);
                        }
                        let modeled_external_effect = subjects
                            .iter()
                            .find(|subject| subject.key == aliased)
                            .and_then(|subject| {
                                self.modeled_external_effect_id(subject, &resolved, trigger.phase)
                            });
                        let quality = may_alias_quality(resolved.multiplicity);
                        let quality = if condition_unknown {
                            condition_incomplete_quality(quality)
                        } else {
                            quality
                        };
                        events.push(PendingEventBinding {
                            event: event_key.clone(),
                            policy_event: event.id.clone(),
                            subject: aliased,
                            site,
                            phase: EventObservationPhase::Endpoint(trigger.phase),
                            order,
                            role,
                            quality,
                            endpoint: endpoint.clone(),
                            modeled_external_effect,
                            semantic_effect: event.semantic_effect.as_deref().map(Arc::from),
                            condition: flow_condition,
                            alias_derived: true,
                            selected_operand: (trigger.phase != EndpointObservationPhase::AtMatch)
                                .then(|| resolved.selected_operand.clone())
                                .flatten(),
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
                    for subject in subjects.iter().filter(|subject| {
                        expectation.applies_to_subjects.contains(&subject.endpoint)
                    }) {
                        for (point, quality) in semantic_event_points(&subject.root, *event)? {
                            terminals.push(PendingTerminalBinding {
                                expectation: expectation_key.clone(),
                                policy_expectation: expectation.id.clone(),
                                subject: subject.key.clone(),
                                site: TypestateObservationSite::program_point(
                                    point,
                                    TypestateBindingContext::root(),
                                ),
                                phase: TerminalObservationPhase::AnalysisRoot(*event),
                                role: TypestateObjectRole::CurrentObject,
                                quality,
                                endpoint: None,
                                alias_derived: false,
                            });
                        }
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
                                let (absence_site, _) = event_site(&resolved, *phase)?;
                                for aliased in self.alias_bound_subjects(
                                    &resolved,
                                    &unnamed,
                                    expectation_key.as_str(),
                                    format!("{:?}", phase).as_str(),
                                    &absence_site,
                                )? {
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
        let mut coverage_candidates =
            HashMap::<EventObservationGroupKey, Vec<CoverageCandidateSpec>>::new();
        for binding in &events {
            record_coverage_candidate(&mut coverage_candidates, binding);
        }
        let mut events = reduce_event_bindings(events, &endpoint_precedence, &event_precedence)?;
        let event_templates = reduce_event_template_bindings(
            event_templates,
            &endpoint_precedence,
            &event_precedence,
        );
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
        // A workspace callee that provably closes the object it is handed on
        // every exit path discharges its caller's obligation. The discharge is
        // expressed in the policy's own argument-form release events, bound to
        // the caller's call, so it is the reviewed close vocabulary applied to
        // a call the contract proved. A call that already carries one of those
        // events at the same site, order, and subject keeps the authored
        // binding alone: the binding plan admits one event per observation
        // order.
        let CloseDischarges {
            injections: mut close_discharges,
            reasons: close_contract_reasons,
        } = self.close_discharge_bindings(&subjects, &close_sites, &argument_form_releases)?;
        let mut observed = events
            .iter()
            .map(|binding| (binding.subject.clone(), binding.order, binding.site.clone()))
            .collect::<HashSet<_>>();
        close_discharges.retain(|injection| {
            observed.insert((
                injection.subject.clone(),
                injection.order,
                injection.site.clone(),
            ))
        });
        for injection in &close_discharges {
            record_coverage_candidate(&mut coverage_candidates, injection);
        }
        events.extend(close_discharges);
        let coverage_candidate_groups = coverage_candidates
            .into_iter()
            .map(|(key, candidates)| CoverageCandidateGroupSpec {
                subject: key.subject,
                site: key.site,
                phase: coverage_candidate_phase(key.phase),
                candidates,
            })
            .collect::<Vec<_>>();
        let mut coverage_decisions = Vec::new();
        if let Some(event_set) = spec.automaton.event_set.as_ref() {
            for ((subject, call), selected) in coverage_selections {
                let site = TypestateObservationSite::call_site(
                    call.clone(),
                    TypestateBindingContext::root(),
                );
                for (phase, exit) in [
                    (
                        CoverageCandidatePhase::AfterNormalReturn,
                        AuthoredSummaryExitKind::Normal,
                    ),
                    (
                        CoverageCandidatePhase::AfterExceptionalReturn,
                        AuthoredSummaryExitKind::Exceptional,
                    ),
                ] {
                    let candidates = coverage_candidate_groups.iter().find(|group| {
                        group.subject == subject && group.site == site && group.phase == phase
                    });
                    let record = selected.as_ref().map(|(summary, member_id)| {
                        let shard = &summary.shard;
                        CoverageRecordKey {
                            active_model_set_hash: self
                                .active_semantic_models
                                .as_ref()
                                .expect("selected summary has an active model set")
                                .active_model_set_hash()
                                .to_owned(),
                            pack_id: shard.manifest.pack_id.clone(),
                            pack_digest: shard.manifest.content_sha256.clone(),
                            shard_id: shard.descriptor.shard_id.clone(),
                            shard_digest: shard.descriptor.content_sha256.clone(),
                            record_id: summary.record.id.clone(),
                            model_id: summary.record.model_id.clone(),
                            record_digest: summary.record.content_sha256.clone(),
                            selected_member_id: member_id.clone(),
                            context: site.context().key().clone(),
                            claim_id: None,
                            witness_ids: Vec::new(),
                        }
                    });
                    let kind = adjudicate_lifecycle_coverage(
                        &call,
                        &site,
                        selected.as_ref().map(|(summary, _)| summary),
                        record,
                        event_set,
                        exit,
                        candidates,
                    );
                    coverage_decisions.push(CoverageDecisionSpec {
                        subject: subject.clone(),
                        site: site.clone(),
                        phase,
                        kind,
                    });
                }
            }
        }
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
            .chain(event_templates.iter())
            .map(|binding| {
                (
                    EventProvenanceKey {
                        event: binding.event.clone(),
                        subject: binding.subject.clone(),
                        site: binding.site.clone(),
                        order: binding.order,
                        role: binding.role,
                        selected_operand: binding.selected_operand.clone(),
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
                    selected_operand: None,
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
            .map(|binding| {
                let condition = binding.condition;
                let selected_operand = binding.selected_operand;
                let spec = match binding.modeled_external_effect {
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
                };
                let spec = spec.with_semantic_effect(binding.semantic_effect);
                let spec = match condition {
                    Some(condition) => spec.with_condition(condition),
                    None => spec,
                };
                match selected_operand {
                    Some(operand) => spec.with_selected_operand(operand),
                    None => spec,
                }
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
        let template_specs = event_templates
            .into_iter()
            .map(|binding| {
                let mut spec = TypestateEventBindingSpec::new(
                    binding.event,
                    binding.subject,
                    binding.site,
                    binding.order,
                    binding.role,
                    binding.quality,
                );
                if let Some(condition) = binding.condition {
                    spec = spec.with_condition(condition);
                }
                spec.with_selected_operand(
                    binding
                        .selected_operand
                        .expect("selected template has an operand"),
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
            TypestateBindingPlan::try_new_with_coverage(
                &protocol,
                subject_specs,
                seeds,
                TypestateEventBindings {
                    events: event_specs,
                    templates: template_specs,
                },
                call_noninterference.specs,
                terminal_specs,
                TypestateCoverageSpec {
                    event_set: spec.automaton.event_set.as_ref().map(|set| {
                        TypestateCoverageEventSet {
                            name: set.name.clone(),
                            version: set.version,
                            effects: set.effects.clone(),
                        }
                    }),
                    candidate_groups: coverage_candidate_groups,
                    decisions: coverage_decisions,
                    unproven_relations: std::mem::take(&mut self.unproven_relations),
                },
            )
            .map_err(TypestatePolicyCompileError::BindingPlan)?,
        );
        let event_endpoints = bindings
            .event_bindings()
            .iter()
            .chain(bindings.event_templates().iter())
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
                        selected_operand: binding.selected_operand().cloned(),
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
        let semantic_compile_resident_peak = self.selectors.semantic_resident_peak();
        let semantic_compile_root_work_peak = self.selectors.semantic_root_work_peak();
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
            selection_fingerprint: std::mem::take(&mut self.selection_fingerprint),
            undecided_sites: std::mem::take(&mut self.undecided_sites),
            compilations: 1,
            engine,
            protocol,
            bindings,
            roots: roots.into_boxed_slice(),
            subjects: subjects.into_boxed_slice(),
            event_endpoints: event_endpoints.into_boxed_slice(),
            terminal_endpoints: terminal_endpoints.into_boxed_slice(),
            query_work,
            semantic_compile_work,
            semantic_compile_resident_peak,
            semantic_compile_root_work_peak,
            semantic_compile_peaks,
            semantic_remaining,
            semantic_scope,
            semantic_execution_budget,
            selector_scans,
            artifact_leases,
            result_contract_artifact_leases,
            binding_omissions: std::mem::take(&mut self.binding_omissions).into_boxed_slice(),
            selected_subject_sites: std::mem::take(&mut self.selected_subject_sites),
            binding_omission_subjects: incomplete_subjects,
            close_contract_reasons,
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
                ..
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

    fn select_subject(
        &mut self,
        selector: &ResolvedPolicySelector,
        binding: &SelectorBinding,
    ) -> Result<Vec<SelectedSite>, TypestatePolicyCompileError> {
        // A selector without a certified candidate inventory keeps the
        // ordinary whole-selector answer. Only a certified selector has
        // undecided candidates whose identities and reason classes extend the
        // compilation fingerprint.
        if !self
            .selectors
            .subject_uses_candidate_enumeration(selector)
            .map_err(typestate_selector_error)?
        {
            return self.select(selector, binding);
        }
        use super::selector_compiler::candidate_enumeration::CandidateReason;
        let selection = if self.subject_scope.seed_files().is_some() {
            self.selectors
                .select_subject_candidates_in_scope(selector, self.subject_scope.clone())
        } else {
            self.selectors.select_subject_candidates(selector)
        }
        .map_err(typestate_selector_error)?;
        // Selected subjects already enter the compilation through the
        // canonical bindings hash; the undecided candidates do not, so their
        // identities and reason classes extend the fingerprint roots key on.
        for candidate in selection.undecided {
            let mut classes = candidate
                .reasons
                .iter()
                .map(|reason| match reason {
                    CandidateReason::Read(_) => "read",
                    CandidateReason::SilentDrop => "silent_drop",
                    CandidateReason::IncompleteQuery(_) => "incomplete_query",
                    CandidateReason::Disagreement { .. } => "disagreement",
                })
                .collect::<Vec<_>>();
            classes.sort_unstable();
            classes.dedup();
            self.selection_fingerprint.push(format!(
                "undecided:{}:{}:{:?}:{classes:?}",
                selector.path, candidate.file, candidate.span
            ));
            self.undecided_sites.push(UndecidedSelectorSite {
                selector: selector.path.to_string(),
                file: candidate.file,
                span: candidate.span,
                reasons: candidate.reasons,
            });
        }
        Ok(Self::bound_selected_sites(selection.sites, binding))
    }

    // An undecided transition can change a selected subject's history. Until
    // that uncertainty can be attributed to subjects, retain whole-selector
    // failure for event and terminal discovery rather than inventing findings.
    fn select(
        &mut self,
        selector: &ResolvedPolicySelector,
        binding: &SelectorBinding,
    ) -> Result<Vec<SelectedSite>, TypestatePolicyCompileError> {
        let sites = self
            .selectors
            .select_with_artifact_continuation(selector)
            .map_err(typestate_selector_error)?;
        Ok(Self::bound_selected_sites(sites, binding))
    }

    fn bound_selected_sites(
        sites: Vec<super::selector_compiler::PolicySelectedSite>,
        binding: &SelectorBinding,
    ) -> Vec<SelectedSite> {
        sites
            .into_iter()
            .map(|site| SelectedSite {
                subject_span: site
                    .call_binding
                    .as_ref()
                    .map_or_else(|| site.span.clone(), |binding| binding.call_span.clone()),
                file: site.file,
                span: site.span,
                require_exact_call: matches!(binding, SelectorBinding::MatchedValue),
                proof: site.proof,
                completeness: site.completeness,
                result_contract: site.result_contract,
                call_shape: site.call_shape,
                modeled_member_id: site.modeled_member_id,
                modeled_target_origin: site.modeled_target_origin,
                retained_incomplete_result_contract_query: site
                    .retained_incomplete_result_contract_query,
            })
            .collect()
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
            if selection.has_no_result_activation() {
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
        let lookup = procedures_in_artifact(&artifact, usize::MAX, self.selectors.cancellation());
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
        let selected_port = match effective_binding {
            SelectorBinding::Receiver => Some(TypestateEventPort::Receiver),
            SelectorBinding::ArgumentIndex(ordinal) => {
                Some(TypestateEventPort::Argument { ordinal: *ordinal })
            }
            SelectorBinding::ReturnValue => Some(TypestateEventPort::Result { ordinal: None }),
            SelectorBinding::ResultIndex(ordinal) => Some(TypestateEventPort::Result {
                ordinal: Some(*ordinal),
            }),
            SelectorBinding::MatchedValue => None,
            SelectorBinding::ArgumentName(_) => unreachable!("formal-name bindings resolve first"),
        };
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
        let owned_receiver_query = matches!(effective_binding, SelectorBinding::Receiver)
            && matches!(
                phase,
                Some(
                    EndpointObservationPhase::AfterNormalReturn
                        | EndpointObservationPhase::AfterExceptionalReturn
                )
            )
            && procedure.artifact().key().language() == SemanticLanguage::Standard(Language::Rust);
        let mut owned_continuation = if owned_receiver_query {
            let workspace = self.selectors.workspace();
            let discovery = WorkspaceCompositionDiscovery::new(
                workspace,
                WorkspaceValueFlowProvider::new(workspace, ValueFlowCache::default()),
            );
            Some(
                self.selectors
                    .continue_semantic(|request| {
                        let value = brokk_bifrost_flow::typestate::ordered::selected_owned_receiver_event_object(
                            &discovery,
                            &procedure,
                            &call,
                            at_point.context(),
                            request,
                        )?;
                        Ok(SemanticOutcome::Complete {
                            value,
                            work: SemanticWork::default(),
                        })
                    })
                    .map_err(typestate_selector_error)?,
            )
        } else {
            None
        };
        let owned_receiver = owned_continuation
            .as_ref()
            .and_then(|continuation| continuation.outcome().available_value())
            .and_then(Option::as_ref)
            .cloned();
        if owned_receiver.is_none()
            && let Some(continuation) = owned_continuation.take()
        {
            continuation
                .finish_scalar((), "selected receiver event object")
                .map_err(typestate_selector_error)?;
        }
        let mut heap_continuation = None;
        let (objects, coverage, multiplicity, fresh_result_identity) = if let Some((
            object,
            quality,
        )) = owned_receiver
        {
            let quality = TypestateBindingQuality::new(
                conjoin_proof(&selection.proof, quality.proof()),
                conjoin_completeness(&selection.completeness, quality.completeness()),
                quality.multiplicity(),
            );
            let multiplicity = quality.multiplicity();
            (
                vec![ResolvedObject { object, quality }],
                CandidateCoverage::Exhaustive,
                multiplicity,
                false,
            )
        } else {
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
            let modeled_fresh_result =
                self.authored_external_summary_fresh_result_for_call(selection, &call);
            let fresh_result_identity = (reviewed_fresh_result || modeled_fresh_result)
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
            let coverage = result.objects().coverage();
            heap_continuation = Some(continuation);
            (objects, coverage, multiplicity, fresh_result_identity)
        };
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
            selected_operand: selected_port
                .map(|port| TypestateSelectedOperand::new(call.clone(), port)),
            call: Some(call),
            observation_point,
            role,
            objects,
            observation: at_point,
            coverage,
            multiplicity,
            activation_edges,
            member_contracts: selection
                .result_contract
                .as_ref()
                .map(|contract| contract.member_contracts.clone())
                .unwrap_or_default(),
            call_shape: selection.call_shape.clone(),
            modeled_member_id: selection.modeled_member_id.clone(),
            modeled_target_origin: selection.modeled_target_origin,
            fresh_result_identity,
            retained_incomplete_result_contract_query: selection
                .retained_incomplete_result_contract_query,
        };
        if !resolved.retained_artifact_coverage(|artifact| {
            owned_continuation
                .as_ref()
                .is_some_and(|continuation| continuation.contains_exact(artifact))
                || heap_continuation
                    .as_ref()
                    .is_some_and(|continuation| continuation.contains_exact(artifact))
        }) {
            return Err(TypestatePolicyCompileError::SemanticUnavailable(
                "heap analysis produced identity-bearing handles outside its bounded complete-artifact window"
                    .to_owned(),
            ));
        }
        if let Some(continuation) = owned_continuation {
            let outcome = continuation
                .commit(&mut self.selectors, "selected receiver event object")
                .map_err(typestate_selector_error)?;
            drop(outcome);
        }
        if let Some(continuation) = heap_continuation {
            let outcome = continuation
                .commit(&mut self.selectors, "heap analysis")
                .map_err(typestate_selector_error)?;
            drop(outcome);
        }
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
            selected_operand: None,
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
            modeled_member_id: selection.modeled_member_id,
            modeled_target_origin: selection.modeled_target_origin,
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
        event: &str,
        phase: &str,
        site: &TypestateObservationSite,
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
                self.unproven_relations.push(UnprovenEventRelation {
                    subject: subject.key.clone(),
                    site: site.clone(),
                    event: event.to_owned(),
                    phase: phase.to_owned(),
                    exit: None,
                    observation_procedure: resolved.procedure.semantics().locator().clone(),
                    reason: "subject access path unavailable at observation".to_owned(),
                });
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
                self.unproven_relations.push(UnprovenEventRelation {
                    subject: subject.key.clone(),
                    site: site.clone(),
                    event: event.to_owned(),
                    phase: phase.to_owned(),
                    exit: None,
                    observation_procedure: resolved.procedure.semantics().locator().clone(),
                    reason: "alias answer unavailable".to_owned(),
                });
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

    /// Record every close call one resolved release selection names.
    ///
    /// This collection is deliberately independent of subjects: a callee's
    /// contract is a property of the callee's own body, so it must not depend
    /// on which caller first happened to name the close. The target is kept in
    /// the performing procedure's terms because that is the only form a
    /// contract can compare against its own formal parameters.
    fn note_close_sites(
        &mut self,
        resolved: &ResolvedSelection,
        close_sites: &mut Vec<CloseSiteFact>,
    ) -> Result<(), TypestatePolicyCompileError> {
        let Some(call) = resolved.call.as_ref() else {
            return Ok(());
        };
        let procedure = call.procedure();
        let row = procedure
            .semantics()
            .call_site(call.id())
            .expect("validated call handle resolves");
        let point = procedure
            .point_handle(row.point)
            .expect("validated call point has a scoped handle");
        let performing = procedure.durable_key();
        for object in &resolved.objects {
            let mut targets = match object.object.identity() {
                AccessPathRoot::ProcedurePort(port)
                    if port.procedure().durable_key() == performing =>
                {
                    match port.kind() {
                        ProcedurePortKind::Parameter { ordinal } => {
                            vec![CloseSiteTarget::Formal { ordinal }]
                        }
                        _ => vec![CloseSiteTarget::NonFormal],
                    }
                }
                AccessPathRoot::CallSubstitution {
                    procedure: owner, ..
                } if owner.durable_key() == performing => {
                    let mut targets = Vec::new();
                    let oracle = self.selectors.workspace().semantic_oracle_provider();
                    let leases = self.selectors.begin_semantic_lease_window();
                    for value in procedure.semantics().values() {
                        let SemanticValueKind::Parameter { ordinal, .. } = &value.kind else {
                            continue;
                        };
                        let parameter = procedure
                            .value_handle(value.id)
                            .expect("parameter value has a scoped handle");
                        let observation = ValueAtPoint::new(
                            parameter,
                            resolved.observation.point().clone(),
                            resolved.observation.phase(),
                            resolved.observation.context().clone(),
                        )
                        .expect("formal observation belongs to its procedure");
                        let outcome = self
                            .selectors
                            .continue_semantic_in_window(&leases, |request| {
                                oracle.pointees(&observation, request)
                            })
                            .map_err(typestate_selector_error)?;
                        require_uninterrupted_semantic_outcome(
                            &outcome,
                            "close-site formal identity",
                        )?;
                        self.selectors
                            .require_execution_budget("close-site formal identity")
                            .map_err(typestate_selector_error)?;
                        let matches_formal = outcome.available_value().is_some_and(|result| {
                            result.objects().candidates().iter().any(|candidate| {
                                candidate.is_proven_complete()
                                    && candidate.value().identity() == object.object.identity()
                            })
                        });
                        if matches_formal {
                            let target = CloseSiteTarget::Formal { ordinal: *ordinal };
                            if !targets.contains(&target) {
                                targets.push(target);
                            }
                        }
                    }
                    leases
                        .finish_scalar((), "close-site formal identity")
                        .map_err(typestate_selector_error)?;
                    targets
                }
                AccessPathRoot::ProcedurePort(_) | AccessPathRoot::CallSubstitution { .. } => {
                    vec![CloseSiteTarget::Foreign]
                }
                _ => vec![CloseSiteTarget::NonFormal],
            };
            if targets.is_empty() {
                targets.push(CloseSiteTarget::NonFormal);
            }
            for target in targets {
                close_sites.push(CloseSiteFact {
                    procedure: procedure.clone(),
                    target,
                    point: point.clone(),
                    proven: matches!(object.quality.proof(), ProofStatus::Proven),
                });
            }
        }
        Ok(())
    }

    /// The close contract of one workspace callee's formal parameter: whether
    /// every path from the callee's entry to one of its exits provably closes
    /// the object that formal is handed.
    ///
    /// The answer is memoized per formal and remaining depth, and guarded by an
    /// in-progress stack, so a helper that closes through itself answers
    /// `Cycle` instead of recursing without end.
    fn close_contract(
        &mut self,
        formal: &ProcedurePortHandle,
        close_sites: &[CloseSiteFact],
    ) -> Result<CloseContract, TypestatePolicyCompileError> {
        self.close_contract_at_depth(formal, close_sites, close_contract_depth())
    }

    fn close_contract_at_depth(
        &mut self,
        formal: &ProcedurePortHandle,
        close_sites: &[CloseSiteFact],
        remaining_depth: u32,
    ) -> Result<CloseContract, TypestatePolicyCompileError> {
        let key = FormalPortKey::of(formal);
        if let Some(contract) = self.close_contracts.get(&(key.clone(), remaining_depth)) {
            return Ok(contract.clone());
        }
        if self.close_contract_stack.contains(&key) {
            return Ok(CloseContract::Cycle);
        }
        if remaining_depth == 0 {
            return Ok(CloseContract::BeyondBound);
        }
        self.close_contract_stack.push(key.clone());
        let computed = self.compute_close_contract(formal, close_sites, remaining_depth);
        self.close_contract_stack.pop();
        let contract = computed?;
        // `Cycle` describes where this walk had already been, not a property of
        // the formal, so it is never memoized.
        if contract != CloseContract::Cycle {
            self.close_contracts
                .insert((key, remaining_depth), contract.clone());
        }
        Ok(contract)
    }

    fn compute_close_contract(
        &mut self,
        formal: &ProcedurePortHandle,
        close_sites: &[CloseSiteFact],
        remaining_depth: u32,
    ) -> Result<CloseContract, TypestatePolicyCompileError> {
        let ProcedurePortKind::Parameter { ordinal } = formal.kind() else {
            return Ok(CloseContract::UnboundClose);
        };
        let callee = formal.procedure().clone();
        let performing = callee.durable_key();
        let mut barriers = Vec::new();
        let mut different_formal = false;
        let mut unbound = false;
        // Different callers can supply different objects for the same formal.
        // A close point is a barrier for this formal only when every fact
        // recorded there is a proven close of this formal.
        let mut definite_points = HashMap::new();
        for fact in close_sites
            .iter()
            .filter(|fact| fact.procedure.durable_key() == performing)
        {
            let closes_formal = fact.proven
                && matches!(fact.target, CloseSiteTarget::Formal { ordinal: closed } if closed == ordinal);
            definite_points
                .entry(fact.point.id())
                .and_modify(|definite| *definite &= closes_formal)
                .or_insert(closes_formal);
            if !fact.proven {
                continue;
            }
            match fact.target {
                CloseSiteTarget::Formal { ordinal: closed } if closed == ordinal => {}
                CloseSiteTarget::Formal { .. } => different_formal = true,
                CloseSiteTarget::NonFormal | CloseSiteTarget::Foreign => unbound = true,
            }
        }
        barriers.extend(
            definite_points
                .into_iter()
                .filter_map(|(point, definite)| definite.then_some(point)),
        );
        // A nested call that provably hands this same formal to a callee whose
        // own contract is discharged is a close of it too, so the walk cuts at
        // the call that performs it. The nested walk runs even when this body
        // performs no close of its own: a helper that only forwards the formal
        // to another helper still closes it.
        let handed = AccessPathRoot::ProcedurePort(formal.clone());
        let calls = callee
            .semantics()
            .call_sites()
            .iter()
            .filter_map(|row| callee.call_site_handle(row.id))
            .collect::<Vec<_>>();
        let mut nested_undecided = false;
        for call in calls {
            let bindings = self.exact_argument_bindings(&call, &handed)?;
            for binding in bindings {
                let nested = self.close_contract_at_depth(
                    &binding.formal,
                    close_sites,
                    remaining_depth - 1,
                )?;
                if nested == CloseContract::Discharged {
                    barriers.push(binding.point.id());
                } else if nested != CloseContract::NoEvidence {
                    // A helper this body hands the formal to does not prove a
                    // close of it on every path. That keeps the obligation, so
                    // the exits below stay reachable and the caller gets this
                    // callee's gap rather than silence.
                    nested_undecided = true;
                }
            }
        }
        if barriers.is_empty() && !nested_undecided {
            if different_formal {
                return Ok(CloseContract::DifferentObject);
            }
            if unbound {
                return Ok(CloseContract::UnboundClose);
            }
            return Ok(CloseContract::NoEvidence);
        }
        barriers.sort_unstable();
        barriers.dedup();
        let graph = callee.semantics();
        let mut budget = CfgAlgorithmBudget::default();
        let mut request = CfgAlgorithmRequest::new(&mut budget, self.selectors.cancellation());
        let reachable = forward_reachability_avoiding(
            graph,
            graph.entry_point(),
            |point| barriers.binary_search(&point).is_ok(),
            &mut request,
        )
        .map_err(|error| cfg_algorithm_error(error, "interprocedural close reachability"))?;
        let normal = reachable.contains(graph, graph.normal_exit_point());
        let exceptional = reachable.contains(graph, graph.exceptional_exit_point());
        let work = reachable.work();
        drop(reachable);
        if !self
            .selectors
            .execution_budget()
            .charge_traversal(work.node_visits + work.edge_visits)
        {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "interprocedural close reachability exhausted the shared traversal budget",
            ));
        }
        if !normal && !exceptional {
            return Ok(CloseContract::Discharged);
        }
        Ok(CloseContract::Partial(CloseExitGap {
            normal,
            exceptional,
        }))
    }

    /// Every call at which one actual provably denotes exactly `object` and
    /// provably binds that object into a workspace callee's formal parameter.
    ///
    /// Every gate here is an exactness gate: a partial dispatch, an open
    /// argument group, an unproven mapping, or an object set with more than one
    /// candidate all answer "no" rather than "maybe". A discharge claims an
    /// obligation is gone, so an inexact question must never produce one.
    fn exact_argument_bindings(
        &mut self,
        call: &CallSiteHandle,
        object: &AccessPathRoot,
    ) -> Result<Vec<ExactArgumentBinding>, TypestatePolicyCompileError> {
        let object_identity = object
            .durable_identity()
            .map_err(|error| TypestatePolicyCompileError::UnsupportedBinding(error.to_string()))?;
        let row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("validated call handle resolves");
        let point = call
            .procedure()
            .point_handle(row.point)
            .expect("validated call point has a scoped handle");
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        let leases = self.selectors.begin_semantic_lease_window();
        let formal_parameter = match object {
            AccessPathRoot::ProcedurePort(port)
                if port.procedure() == call.procedure()
                    && matches!(port.kind(), ProcedurePortKind::Parameter { .. }) =>
            {
                let ProcedurePortKind::Parameter { ordinal } = port.kind() else {
                    unreachable!("parameter port was matched above");
                };
                call.procedure()
                    .semantics()
                    .values()
                    .iter()
                    .find(|value| {
                        matches!(
                            &value.kind,
                            SemanticValueKind::Parameter {
                                ordinal: value_ordinal,
                                ..
                            } if *value_ordinal == ordinal
                        )
                    })
                    .map(|value| {
                        call.procedure()
                            .value_handle(value.id)
                            .expect("parameter value has a scoped handle")
                    })
            }
            _ => None,
        };
        let forwarded_formal_values = if let Some(parameter) = formal_parameter.as_ref() {
            let expected_source = ValueFlowEndpoint::for_value(parameter.clone());
            let relations_outcome = self
                .selectors
                .continue_semantic_in_window(&leases, |request| {
                    oracle.procedure_relations(
                        call.procedure(),
                        &OracleCallContext::empty(),
                        request,
                    )
                })
                .map_err(typestate_selector_error)?;
            require_uninterrupted_semantic_outcome(
                &relations_outcome,
                "close-contract formal forwarding",
            )?;
            self.selectors
                .require_execution_budget("close-contract formal forwarding")
                .map_err(typestate_selector_error)?;
            // Procedure coverage may be open because of unrelated language
            // capabilities. Use only individually proven, complete identity
            // edges, and require a unique incoming edge at every value below.
            let forwarded = relations_outcome
                .available_value()
                .map(|snapshot| {
                    let mut incoming_counts = HashMap::<ValueHandle, usize>::new();
                    let mut identity_edges = HashMap::<ValueFlowEndpoint, Vec<ValueHandle>>::new();
                    for relation in snapshot.relations() {
                        let ValueFlowEndpoint::Value(target) = &relation.target else {
                            continue;
                        };
                        *incoming_counts.entry(target.clone()).or_default() += 1;
                        if matches!(
                            relation.kind,
                            ValueFlowRelationKind::Parameter | ValueFlowRelationKind::Assignment
                        ) && relation.transfer.is_none()
                            && relation.is_proven_complete()
                        {
                            identity_edges
                                .entry(relation.source.clone())
                                .or_default()
                                .push(target.clone());
                        }
                    }
                    let mut pending = vec![expected_source];
                    let mut visited = HashSet::new();
                    let mut forwarded = HashSet::new();
                    while let Some(source) = pending.pop() {
                        if !visited.insert(source.clone()) {
                            continue;
                        }
                        for target in identity_edges.get(&source).into_iter().flatten() {
                            if incoming_counts.get(target) == Some(&1)
                                && forwarded.insert(target.clone())
                            {
                                pending.push(ValueFlowEndpoint::Value(target.clone()));
                            }
                        }
                    }
                    forwarded
                })
                .unwrap_or_default();
            drop(relations_outcome);
            forwarded
        } else {
            HashSet::new()
        };
        let object_identities = if let Some(parameter) = formal_parameter.as_ref() {
            let observation = ValueAtPoint::new(
                parameter.clone(),
                point.clone(),
                ObservationPhase::BeforeEffects,
                OracleCallContext::empty(),
            )
            .expect("formal observation belongs to its procedure");
            let outcome = self
                .selectors
                .continue_semantic_in_window(&leases, |request| {
                    oracle.pointees(&observation, request)
                })
                .map_err(typestate_selector_error)?;
            require_uninterrupted_semantic_outcome(&outcome, "close-contract formal identity")?;
            self.selectors
                .require_execution_budget("close-contract formal identity")
                .map_err(typestate_selector_error)?;
            let identity = if outcome.is_complete() {
                if let Some(result) = outcome.available_value() {
                    let objects = result.objects();
                    if objects.coverage() != CandidateCoverage::Exhaustive {
                        None
                    } else {
                        let mut candidates = objects.candidates().iter();
                        match (candidates.next(), candidates.next()) {
                            (Some(candidate), None) if candidate.is_proven_complete() => {
                                Some(candidate.value().identity().durable_identity().map_err(
                                    |error| {
                                        TypestatePolicyCompileError::UnsupportedBinding(
                                            error.to_string(),
                                        )
                                    },
                                )?)
                            }
                            _ => None,
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };
            drop(outcome);
            identity.into_iter().collect()
        } else {
            vec![object_identity]
        };
        let mut found: Vec<ExactArgumentBinding> = Vec::new();
        {
            let dispatch_outcome = self
                .selectors
                .continue_semantic_in_window(&leases, |request| oracle.resolve_call(call, request))
                .map_err(typestate_selector_error)?;
            require_uninterrupted_semantic_outcome(&dispatch_outcome, "close-contract dispatch")?;
            self.selectors
                .require_execution_budget("close-contract dispatch")
                .map_err(typestate_selector_error)?;
            let dispatch = dispatch_outcome
                .is_complete()
                .then(|| dispatch_outcome.available_value())
                .flatten()
                .filter(|dispatch| {
                    dispatch.coverage() == CandidateCoverage::Exhaustive
                        && !dispatch.candidates().is_empty()
                        && dispatch.boundaries().is_empty()
                        && dispatch
                            .candidates()
                            .iter()
                            .all(|candidate| matches!(candidate.proof(), ProofStatus::Proven))
                });
            let Some(dispatch) = dispatch else {
                drop(dispatch_outcome);
                leases
                    .finish_scalar((), "close-contract dispatch")
                    .map_err(typestate_selector_error)?;
                return Ok(found);
            };
            for candidate in dispatch.candidates() {
                let bindings_outcome = self
                    .selectors
                    .continue_semantic_in_window(&leases, |request| {
                        oracle.call_bindings(call, candidate, &OracleCallContext::empty(), request)
                    })
                    .map_err(typestate_selector_error)?;
                require_uninterrupted_semantic_outcome(
                    &bindings_outcome,
                    "close-contract argument binding",
                )?;
                self.selectors
                    .require_execution_budget("close-contract argument binding")
                    .map_err(typestate_selector_error)?;
                if !bindings_outcome.is_complete() {
                    continue;
                }
                let Some(bindings) = bindings_outcome.available_value() else {
                    continue;
                };
                if bindings.coverage() != CandidateCoverage::Exhaustive {
                    continue;
                }
                for binding in bindings.bindings() {
                    let CallBinding::ArgumentGroup(group) = binding else {
                        continue;
                    };
                    if group.coverage() != CandidateCoverage::Exhaustive {
                        continue;
                    }
                    let proven = group
                        .mappings()
                        .iter()
                        .filter(|mapping| matches!(mapping.proof(), ProofStatus::Proven))
                        .count();
                    if !matches!(
                        group.cardinality(),
                        ArgumentCardinality::Exact(count) if count == proven
                    ) {
                        continue;
                    }
                    for mapping in group.mappings() {
                        if !matches!(mapping.proof(), ProofStatus::Proven)
                            || !mapping.value().preserves_reference_identity()
                        {
                            continue;
                        }
                        let formal = mapping.value().formal().clone();
                        if !matches!(formal.kind(), ProcedurePortKind::Parameter { .. }) {
                            continue;
                        }
                        let CallArgumentEndpoint::Value(actual) = mapping.value().actual() else {
                            continue;
                        };
                        // An Address names the borrow value, while this close
                        // contract asks which resource was borrowed. Use its
                        // unique, proven structured source. A missing or
                        // competing association cannot discharge an object.
                        let referent = if call
                            .procedure()
                            .semantics()
                            .value(actual.id())
                            .is_some_and(|row| row.kind == SemanticValueKind::Address)
                        {
                            let mut associations = call
                                .procedure()
                                .semantics()
                                .points()
                                .iter()
                                .flat_map(|point| &point.events)
                                .filter(|event| {
                                    matches!(event.effect, SemanticEffect::Assignment { target, .. } if target == actual.id())
                                });
                            match (associations.next(), associations.next()) {
                                (Some(event), None)
                                    if call
                                        .procedure()
                                        .semantics()
                                        .evidence_row(event.evidence)
                                        .is_some_and(|evidence| {
                                            evidence.proof.establishes_complete_evidence(
                                                &evidence.completeness,
                                            )
                                        }) =>
                                {
                                    let SemanticEffect::Assignment { value, .. } = event.effect
                                    else {
                                        unreachable!("selected assignment has an assignment effect")
                                    };
                                    call.procedure().value_handle(value)
                                }
                                _ => None,
                            }
                        } else {
                            Some(actual.clone())
                        };
                        let Some(referent) = referent else {
                            continue;
                        };
                        let same_formal = formal_parameter.as_ref().is_some_and(|parameter| {
                            (referent.procedure() == parameter.procedure()
                                && referent.id() == parameter.id())
                                || forwarded_formal_values.contains(&referent)
                        });
                        let exact = if same_formal {
                            // A complete call binding that forwards this exact
                            // formal value preserves its symbolic object identity
                            // even when the language has no closed points-to set
                            // for the formal itself.
                            true
                        } else {
                            let at_point = ValueAtPoint::new(
                                referent,
                                point.clone(),
                                ObservationPhase::BeforeEffects,
                                OracleCallContext::empty(),
                            )
                            .expect("the bound actual is scoped to the call's own procedure");
                            let pointees_outcome = self
                                .selectors
                                .continue_semantic_in_window(&leases, |request| {
                                    oracle.pointees(&at_point, request)
                                })
                                .map_err(typestate_selector_error)?;
                            require_uninterrupted_semantic_outcome(
                                &pointees_outcome,
                                "close-contract heap analysis",
                            )?;
                            self.selectors
                                .require_execution_budget("close-contract heap analysis")
                                .map_err(typestate_selector_error)?;
                            if !pointees_outcome.is_complete() {
                                false
                            } else if let Some(result) = pointees_outcome.available_value() {
                                let objects = result.objects();
                                if !objects.coverage().is_exhaustive() {
                                    false
                                } else {
                                    let mut candidates = objects.candidates().iter();
                                    match (candidates.next(), candidates.next()) {
                                        (Some(candidate), None)
                                            if candidate.is_proven_complete() =>
                                        {
                                            let identity = candidate
                                                .value()
                                                .identity()
                                                .durable_identity()
                                                .map_err(|error| {
                                                    TypestatePolicyCompileError::UnsupportedBinding(
                                                        error.to_string(),
                                                    )
                                                })?;
                                            object_identities.contains(&identity)
                                        }
                                        (_, _) => false,
                                    }
                                }
                            } else {
                                false
                            }
                        };
                        if exact
                            && !found
                                .iter()
                                .any(|existing| existing.call == *call && existing.formal == formal)
                        {
                            found.push(ExactArgumentBinding {
                                call: call.clone(),
                                point: point.clone(),
                                formal,
                            });
                        }
                    }
                }
            }
            drop(dispatch_outcome);
        }
        leases
            .finish_scalar((), "close-contract argument binding")
            .map_err(typestate_selector_error)?;
        Ok(found)
    }

    /// Discharge each tracked subject whose own analysis root hands it to a
    /// workspace helper that provably closes it on every exit.
    ///
    /// The injected events are the policy's own argument-form release events:
    /// the caller's call binds the subject as an argument exactly as the
    /// reviewed argument-form close does, so the same rows describe it. A
    /// callee that keeps its obligation produces a reason instead, which the
    /// report shows beside the finding it did not discharge.
    fn close_discharge_bindings(
        &mut self,
        subjects: &[CompiledTypestateSubject],
        close_sites: &[CloseSiteFact],
        releases: &[ArgumentFormReleaseEvent],
    ) -> Result<CloseDischarges, TypestatePolicyCompileError> {
        let mut injections = Vec::new();
        let mut reasons = HashMap::<TypestateSubjectKey, Vec<String>>::new();
        if releases.is_empty() {
            return Ok(CloseDischarges {
                injections,
                reasons,
            });
        }
        for subject in subjects {
            let object = subject.object.identity().clone();
            let calls = subject
                .root
                .semantics()
                .call_sites()
                .iter()
                .filter_map(|row| subject.root.call_site_handle(row.id))
                .collect::<Vec<_>>();
            for call in calls {
                let bindings = self.exact_argument_bindings(&call, &object)?;
                for binding in bindings {
                    let contract = self.close_contract(&binding.formal, close_sites)?;
                    if contract == CloseContract::Discharged {
                        let site = TypestateObservationSite::call_site(
                            call.clone(),
                            TypestateBindingContext::root(),
                        );
                        for release in releases {
                            injections.push(PendingEventBinding {
                                event: release.event.clone(),
                                policy_event: release.policy_event.clone(),
                                subject: subject.key.clone(),
                                site: site.clone(),
                                phase: EventObservationPhase::Endpoint(release.phase),
                                order: release.order,
                                role: TypestateObjectRole::Argument,
                                quality: TypestateBindingQuality::proven_unique(),
                                endpoint: None,
                                modeled_external_effect: None,
                                semantic_effect: release.semantic_effect.clone(),
                                condition: None,
                                alias_derived: false,
                                selected_operand: None,
                            });
                        }
                    } else if let Some(reason) = close_contract_reason(&binding.formal, &contract) {
                        let entry = reasons.entry(subject.key.clone()).or_default();
                        if entry.len() < MAX_CLOSE_CONTRACT_REASONS && !entry.contains(&reason) {
                            entry.push(reason);
                        }
                    }
                }
            }
        }
        Ok(CloseDischarges {
            injections,
            reasons,
        })
    }
}

/// What one compile's helper-close scan produced.
struct CloseDischarges {
    /// Release rows that discharge one tracked subject at a call its own
    /// analysis root makes.
    injections: Vec<PendingEventBinding>,
    /// Why a workspace helper kept a subject's obligation, keyed by subject so
    /// its finding can carry the reasons.
    reasons: HashMap<TypestateSubjectKey, Vec<String>>,
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
    /// The selected call's whole span when the row binds an argument of it,
    /// so a subject verdict names the call, as an undecided candidate does.
    subject_span: ByteRange<usize>,
    require_exact_call: bool,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    result_contract: Option<super::selector_compiler::PolicyResultContractSelection>,
    call_shape: Option<super::selector_compiler::PolicyCallShapeSelection>,
    modeled_member_id: Option<String>,
    modeled_target_origin: Option<&'static str>,
    /// This row came from a query that already contributes the selector-level
    /// run-incomplete diagnostic for retained result-contract evidence.
    retained_incomplete_result_contract_query: bool,
}

impl SelectedSite {
    fn has_no_result_activation(&self) -> bool {
        self.result_contract.as_ref().is_some_and(|contract| {
            contract.success_guard_coverage.is_exhaustive()
                && contract.success_guard_edges.is_empty()
        })
    }
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

fn authored_argument_condition(
    trigger: &ResolvedTypestateEventTrigger,
) -> Option<TypestateArgumentCondition> {
    match trigger {
        ResolvedTypestateEventTrigger::Calls {
            argument_condition: Some(condition),
            ..
        } => Some(*condition),
        ResolvedTypestateEventTrigger::Calls {
            argument_condition: None,
            ..
        }
        | ResolvedTypestateEventTrigger::MatchEndpoints { .. }
        | ResolvedTypestateEventTrigger::SemanticEvent { .. } => None,
    }
}

fn evaluate_argument_condition(
    resolved: &ResolvedSelection,
    condition: TypestateArgumentCondition,
) -> Option<bool> {
    let call = resolved.call.as_ref()?;
    let semantics = call.procedure().semantics();
    let call_row = semantics.call_site(call.id())?;
    let argument = call_row.arguments.get(condition.index as usize)?;
    match direct_scalar_source(semantics, argument.value) {
        Some(DirectScalarSource::Boolean(value)) => Some(value == condition.equals),
        Some(DirectScalarSource::Port(_))
        | Some(DirectScalarSource::UnsignedInteger(_))
        | Some(DirectScalarSource::ConstantString(_))
        | Some(DirectScalarSource::IntegerOffset { .. })
        | None => None,
    }
}

fn condition_incomplete_quality(quality: TypestateBindingQuality) -> TypestateBindingQuality {
    const REASON: &str = "typestate event argument Boolean value is unknown";
    TypestateBindingQuality::new(
        quality.proof().clone(),
        EvidenceCompleteness::Partial(REASON.into()),
        quality.multiplicity(),
    )
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
    selected_site: (ProjectFile, ByteRange<usize>),
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

#[derive(Clone)]
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
    semantic_effect: Option<Arc<str>>,
    condition: Option<TypestateEventCondition>,
    alias_derived: bool,
    selected_operand: Option<TypestateSelectedOperand>,
}

impl<'a> TypestatePolicyCompiler<'a> {
    fn selected_template_target(
        &mut self,
        call: &CallSiteHandle,
    ) -> Result<Option<(SemanticArtifactKey, ProcedureId)>, TypestatePolicyCompileError> {
        let key = call.durable_key();
        if let Some(target) = self.selected_template_targets.get(&key) {
            return Ok(target.clone());
        }
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        let continuation = self
            .selectors
            .continue_semantic(|request| oracle.resolve_call(call, request))
            .map_err(typestate_selector_error)?;
        require_uninterrupted_semantic_outcome(
            continuation.outcome(),
            "typestate template dispatch",
        )?;
        self.selectors
            .require_execution_budget("typestate template dispatch")
            .map_err(typestate_selector_error)?;
        let target = continuation
            .outcome()
            .is_complete()
            .then(|| continuation.outcome().available_value())
            .flatten()
            .filter(|dispatch| {
                dispatch.coverage() == CandidateCoverage::Exhaustive
                    && dispatch.boundaries().is_empty()
            })
            .and_then(|dispatch| match dispatch.candidates() {
                [candidate] if matches!(candidate.proof(), ProofStatus::Proven) => {
                    Some(candidate.target().durable_key())
                }
                _ => None,
            });
        continuation
            .finish_scalar((), "typestate template dispatch")
            .map_err(typestate_selector_error)?;
        self.selected_template_targets.insert(key, target.clone());
        Ok(target)
    }

    fn modeled_external_effect_id(
        &self,
        subject: &CompiledTypestateSubject,
        selection: &ResolvedSelection,
        phase: EndpointObservationPhase,
    ) -> Option<String> {
        if phase != EndpointObservationPhase::AfterNormalReturn {
            return None;
        }
        if self
            .authored_external_summary(selection)
            .is_some_and(|selected| !selected.record.lifecycle_coverage().is_empty())
        {
            return None;
        }
        if let Some(effect_id) = self.authored_external_summary_effect(selection) {
            return Some(effect_id);
        }
        if !subject.fresh_result {
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
                    && contract.declared_effects[0].timing
                        == CompiledDeclaredEffectTiming::Immediate
                    && contract.declared_effects[0].certainty
                        == CompiledDeclaredEffectCertainty::Definite
            })
            .map(|contract| contract.declared_effects[0].id.clone())
    }

    /// A selector row's model member identity is the analyzer's structured
    /// bridge from the written call to one activated procedure summary. The
    /// summary must itself describe a complete call; a bare declaration fact
    /// never closes an external call.
    fn authored_external_summary(
        &self,
        selection: &ResolvedSelection,
    ) -> Option<ActivatedProcedureSummary> {
        let call = selection.call.as_ref()?;
        self.authored_external_summary_for_call(
            selection.modeled_target_origin,
            selection.modeled_member_id.as_deref(),
            call,
        )
    }

    fn authored_external_summary_for_call(
        &self,
        modeled_target_origin: Option<&'static str>,
        modeled_member_id: Option<&str>,
        call: &CallSiteHandle,
    ) -> Option<ActivatedProcedureSummary> {
        if modeled_target_origin != Some("semantic_model") {
            return None;
        }
        let member_id = modeled_member_id?;
        let active = self.active_semantic_models.as_deref()?;
        let language = call
            .procedure()
            .artifact()
            .key()
            .language()
            .semantic_pack_label();
        let realm = brokk_bifrost_analysis::analyzer::semantic_pack_realm(language);
        let mut members = active.members_with_id(member_id);
        members.records.retain(|record| {
            brokk_bifrost_analysis::analyzer::semantic_pack_realm(&record.shard.manifest.language)
                == realm
        });
        let [member] = members.records.as_slice() else {
            return None;
        };
        let mut owners = active.types_with_id(&member.record.owner);
        owners.records.retain(|record| {
            brokk_bifrost_analysis::analyzer::semantic_pack_realm(&record.shard.manifest.language)
                == realm
        });
        let [owner] = owners.records.as_slice() else {
            return None;
        };
        let semantic_call = call.procedure().semantics().call_site(call.id())?;
        let parameter_count = u32::try_from(semantic_call.arguments.len()).ok()?;
        let matched = active.procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
            language,
            &owner.record.name,
            &member.record.name,
            !member.record.is_static,
            parameter_count,
        ));
        if matched.disposition != SemanticModelMatchDisposition::Unique {
            return None;
        }
        let [summary] = matched.records.as_slice() else {
            return None;
        };
        if summary.record.completeness != Completeness::Complete
            || (!member.record.is_static && !summary.record.covers_overrides)
        {
            return None;
        }
        Some(summary.clone())
    }

    fn authored_external_summary_fresh_result_for_call(
        &self,
        selection: &SelectedSite,
        call: &CallSiteHandle,
    ) -> bool {
        self.authored_external_summary_for_call(
            selection.modeled_target_origin,
            selection.modeled_member_id.as_deref(),
            call,
        )
        .is_some_and(|summary| {
            summary.record.effects.iter().any(|effect| {
                matches!(
                    effect,
                    CompiledSummaryEffect::Allocation {
                        output: CompiledSummaryOutput::NormalReturn {},
                        ..
                    }
                )
            })
        })
    }

    /// The summary's model identity is retained on the event row so the
    /// typestate solver can record which external contract supplied the call
    /// behavior.
    fn authored_external_summary_effect(&self, selection: &ResolvedSelection) -> Option<String> {
        let summary = self.authored_external_summary(selection)?;
        // A participating record must be checked per exit against its claim.
        // The legacy marker closes a whole boundary and is valid only for a
        // record with no lifecycle coverage claims at all.
        if !summary.record.lifecycle_coverage().is_empty() {
            return None;
        }
        let summary = &summary.record;
        let receiver_identity = summary.transfers.iter().any(|transfer| {
            transfer.exit_kind == CompiledSummaryExitKind::Normal
                && matches!(transfer.input, CompiledSummaryInput::Receiver {})
                && matches!(
                    transfer.output,
                    CompiledSummaryOutput::NormalReturn {} | CompiledSummaryOutput::Receiver {}
                )
        });
        let modeled_behavior = receiver_identity
            || !summary.effects.is_empty()
            || !summary.declared_effects.is_empty();
        modeled_behavior.then(|| summary.model_id.clone())
    }
}

fn same_coverage_selection(
    left: &Option<(ActivatedProcedureSummary, String)>,
    right: &Option<(ActivatedProcedureSummary, String)>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some((left, left_member)), Some((right, right_member))) => {
            left_member == right_member
                && left.record.id == right.record.id
                && left.record.model_id == right.record.model_id
                && left.record.content_sha256 == right.record.content_sha256
                && left.shard.manifest.pack_id == right.shard.manifest.pack_id
                && left.shard.manifest.content_sha256 == right.shard.manifest.content_sha256
                && left.shard.descriptor.shard_id == right.shard.descriptor.shard_id
                && left.shard.descriptor.content_sha256 == right.shard.descriptor.content_sha256
        }
        _ => false,
    }
}

/// Compile-root adjudication of one selected call, subject, and exit. S4-R
/// must supply a full #9378 selected-receiver reference certificate before a
/// participating record can ever close uncertainty; this slice produces only
/// named refusals. The order below is stable so the first failed obligation
/// is the published reason.
fn adjudicate_lifecycle_coverage(
    call: &CallSiteHandle,
    site: &TypestateObservationSite,
    selected: Option<&ActivatedProcedureSummary>,
    record: Option<CoverageRecordKey>,
    event_set: &TypestateEventSetSpec,
    exit: AuthoredSummaryExitKind,
    group: Option<&CoverageCandidateGroupSpec>,
) -> CoverageDecisionKind {
    use CoverageRefusalReason as Reason;
    let Some(selected) = selected else {
        return CoverageDecisionKind::Refused {
            reason: Reason::MissingSelectedRecord,
            record,
        };
    };
    let mut record = record.expect("selected summary has record provenance");
    if site.context() != &TypestateBindingContext::root() || site.context().was_truncated() {
        return CoverageDecisionKind::Refused {
            reason: Reason::MissingContext,
            record: Some(record),
        };
    }
    if selected.record.lifecycle_coverage().is_empty() {
        return CoverageDecisionKind::Unclaimed { record };
    }
    let Some(claim) = selected
        .record
        .lifecycle_coverage()
        .iter()
        .find(|claim| {
            claim.exit == exit
                && claim.event_set.name == event_set.name
                && claim.event_set.version == event_set.version
                && claim.event_set.effects == event_set.effects
        })
        .or_else(|| {
            selected
                .record
                .lifecycle_coverage()
                .iter()
                .find(|claim| claim.exit == exit)
        })
    else {
        return CoverageDecisionKind::Refused {
            reason: Reason::MissingClaim,
            record: Some(record),
        };
    };
    record.claim_id = Some(claim.id.clone());
    record.witness_ids = claim.witnesses.clone();
    let reason = if claim.event_set.name != event_set.name
        || claim.event_set.version != event_set.version
        || claim.event_set.effects != event_set.effects
    {
        Some(Reason::EventSetMismatch)
    } else if claim.subject != AuthoredCoverageSubject::Receiver {
        Some(Reason::SubjectMismatch)
    } else {
        let semantic_call = call.procedure().semantics().call_site(call.id());
        if semantic_call.is_none_or(|call| call.receiver.is_none() || !call.arguments.is_empty()) {
            Some(Reason::ExtraActual)
        } else {
            let candidates = group.map_or(&[][..], |group| group.candidates.as_slice());
            if candidates.len() > 1 {
                Some(Reason::MultipleCandidates)
            } else if candidates
                .first()
                .is_some_and(|candidate| !candidate.is_definitive())
            {
                Some(Reason::CandidateUnproven)
            } else if candidates
                .first()
                .is_some_and(|candidate| candidate.semantic_effect.is_none())
            {
                Some(Reason::UnmappedCandidate)
            } else if candidates.len() != claim.witnesses.len() {
                Some(Reason::WitnessCountMismatch)
            } else if let (Some(candidate), Some(witness_id)) =
                (candidates.first(), claim.witnesses.first())
            {
                let witness = selected
                    .record
                    .subject_effects()
                    .iter()
                    .find(|witness| &witness.id == witness_id)
                    .expect("validated claim witness resolves");
                if candidate.semantic_effect.as_deref() != Some(witness.effect.as_str())
                    || witness.subject != AuthoredCoverageSubject::Receiver
                    || witness.exit != exit
                {
                    Some(Reason::WitnessEffectMismatch)
                } else if witness.certainty != CompiledDeclaredEffectCertainty::Definite
                    || witness.timing != CompiledDeclaredEffectTiming::Immediate
                {
                    Some(Reason::WitnessNotDefinite)
                } else {
                    Some(Reason::ReceiverTransportUnproven)
                }
            } else {
                Some(Reason::ReceiverTransportUnproven)
            }
        }
    };
    CoverageDecisionKind::Refused {
        reason: reason.expect("participating record cannot be Covered before S4-R"),
        record: Some(record),
    }
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
    selected_operand: Option<TypestateSelectedOperand>,
}

fn coverage_candidate_phase(phase: EventObservationPhase) -> CoverageCandidatePhase {
    match phase {
        EventObservationPhase::Endpoint(EndpointObservationPhase::AtMatch) => {
            CoverageCandidatePhase::AtMatch
        }
        EventObservationPhase::Endpoint(EndpointObservationPhase::BeforeCall) => {
            CoverageCandidatePhase::BeforeCall
        }
        EventObservationPhase::Endpoint(EndpointObservationPhase::AfterNormalReturn) => {
            CoverageCandidatePhase::AfterNormalReturn
        }
        EventObservationPhase::Endpoint(EndpointObservationPhase::AfterExceptionalReturn) => {
            CoverageCandidatePhase::AfterExceptionalReturn
        }
        EventObservationPhase::AnalysisRoot(PolicySemanticEvent::NormalProcedureExit {
            ..
        }) => CoverageCandidatePhase::NormalProcedureExit,
        EventObservationPhase::AnalysisRoot(PolicySemanticEvent::ExceptionalProcedureExit {
            ..
        }) => CoverageCandidatePhase::ExceptionalProcedureExit,
        EventObservationPhase::AnalysisRoot(PolicySemanticEvent::SuspensionBoundary { .. }) => {
            CoverageCandidatePhase::SuspensionBoundary
        }
    }
}

fn record_coverage_candidate(
    groups: &mut HashMap<EventObservationGroupKey, Vec<CoverageCandidateSpec>>,
    binding: &PendingEventBinding,
) {
    let key = EventObservationGroupKey {
        subject: binding.subject.clone(),
        site: binding.site.clone(),
        phase: binding.phase,
        selected_operand: None,
    };
    groups.entry(key).or_default().push(CoverageCandidateSpec {
        event: binding.policy_event.as_str().to_owned(),
        semantic_effect: binding.semantic_effect.clone(),
        quality: binding.quality.clone(),
        alias_derived: binding.alias_derived,
    });
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct EventProvenanceKey {
    event: ProtocolEventKey,
    subject: TypestateSubjectKey,
    site: TypestateObservationSite,
    order: u32,
    role: TypestateObjectRole,
    selected_operand: Option<TypestateSelectedOperand>,
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

fn precedence_graph<K>(
    nodes: impl IntoIterator<Item = K>,
    edges: impl IntoIterator<Item = (K, K)>,
    on_error: impl FnOnce(String) -> TypestatePolicyCompileError,
) -> Result<PrecedenceGraph<K>, TypestatePolicyCompileError>
where
    K: Clone + Eq + std::fmt::Debug + std::hash::Hash + Ord,
{
    PrecedenceGraph::try_new(nodes, edges).map_err(|error| on_error(error.to_string()))
}

fn endpoint_precedence_graph(
    policy: &LoadedPolicy,
    spec: &ResolvedTypestatePolicySpec,
) -> Result<PrecedenceGraph<ResolvedEndpointIdentity>, TypestatePolicyCompileError> {
    precedence_graph(
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
        |error| {
            TypestatePolicyCompileError::EndpointDominanceUndecidable(format!(
                "invalid endpoint precedence graph: {error}"
            ))
        },
    )
}

fn event_precedence_graph(
    policy: &LoadedPolicy,
    spec: &ResolvedTypestatePolicySpec,
) -> Result<PrecedenceGraph<PolicyTypestateEventId>, TypestatePolicyCompileError> {
    precedence_graph(
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
        |error| {
            TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                "invalid typestate-event precedence graph: {error}"
            ))
        },
    )
}

fn expectation_precedence_graph(
    policy: &LoadedPolicy,
    spec: &ResolvedTypestatePolicySpec,
) -> Result<PrecedenceGraph<PolicyTypestateExpectationId>, TypestatePolicyCompileError> {
    precedence_graph(
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
        |error| {
            TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                "invalid typestate-expectation precedence graph: {error}"
            ))
        },
    )
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

fn reduce_precedence_bindings<Binding, GroupKey, Key>(
    candidates: Vec<Binding>,
    group_key: impl Fn(&Binding) -> GroupKey,
    precedence_key: impl Fn(&Binding) -> Key,
    endpoint: impl Fn(&Binding) -> Option<ResolvedEndpointIdentity>,
    endpoint_precedence: &PrecedenceGraph<ResolvedEndpointIdentity>,
    choose_winner: impl Fn(Vec<Key>) -> Result<Key, TypestatePolicyCompileError>,
    winner_invariant: &'static str,
) -> Result<Vec<Binding>, TypestatePolicyCompileError>
where
    GroupKey: Eq + std::hash::Hash,
    Key: Clone + Eq + std::hash::Hash,
{
    let mut groups = HashMap::<GroupKey, Vec<Binding>>::new();
    for candidate in candidates {
        groups
            .entry(group_key(&candidate))
            .or_default()
            .push(candidate);
    }
    let mut reduced = Vec::new();
    for group in groups.into_values() {
        let mut by_key = HashMap::<Key, Vec<Binding>>::new();
        for candidate in group {
            by_key
                .entry(precedence_key(&candidate))
                .or_default()
                .push(candidate);
        }
        let mut key_candidates = Vec::with_capacity(by_key.len());
        for (key, mut candidates) in by_key {
            let endpoints = candidates.iter().map(&endpoint).collect::<Vec<_>>();
            let winner = endpoint_winner_index(&endpoints, endpoint_precedence)?;
            key_candidates.push((key, candidates.swap_remove(winner)));
        }
        let winner = choose_winner(key_candidates.iter().map(|(key, _)| key.clone()).collect())?;
        reduced.push(
            key_candidates
                .into_iter()
                .find_map(|(key, candidate)| (key == winner).then_some(candidate))
                .expect(winner_invariant),
        );
    }
    Ok(reduced)
}

fn reduce_event_bindings(
    candidates: Vec<PendingEventBinding>,
    endpoint_precedence: &PrecedenceGraph<ResolvedEndpointIdentity>,
    event_precedence: &PrecedenceGraph<PolicyTypestateEventId>,
) -> Result<Vec<PendingEventBinding>, TypestatePolicyCompileError> {
    reduce_precedence_bindings(
        candidates,
        |candidate| EventObservationGroupKey {
            subject: candidate.subject.clone(),
            site: candidate.site.clone(),
            phase: candidate.phase,
            selected_operand: candidate.selected_operand.clone(),
        },
        |candidate| candidate.policy_event.clone(),
        |candidate| candidate.endpoint.clone(),
        endpoint_precedence,
        |candidates| {
            event_precedence
                .unique_winner(candidates)
                .map_err(|error| {
                    TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                        "same-site typestate event precedence is undecidable: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    TypestatePolicyCompileError::SemanticUnavailable(
                        "same-site typestate event candidate set is empty".to_owned(),
                    )
                })
        },
        "precedence winner belongs to the reduced event candidates",
    )
}

/// A template with undecidable same-site authority is absent. Its guarded
/// consumer then keeps the old uncertain bypass instead of choosing a peer.
fn reduce_event_template_bindings(
    candidates: Vec<PendingEventBinding>,
    endpoint_precedence: &PrecedenceGraph<ResolvedEndpointIdentity>,
    event_precedence: &PrecedenceGraph<PolicyTypestateEventId>,
) -> Vec<PendingEventBinding> {
    let mut groups = HashMap::<EventObservationGroupKey, Vec<PendingEventBinding>>::new();
    for candidate in candidates {
        groups
            .entry(EventObservationGroupKey {
                subject: candidate.subject.clone(),
                site: candidate.site.clone(),
                phase: candidate.phase,
                selected_operand: candidate.selected_operand.clone(),
            })
            .or_default()
            .push(candidate);
    }
    groups
        .into_values()
        .filter_map(|group| {
            let winner =
                reduce_event_bindings(group.clone(), endpoint_precedence, event_precedence)
                    .ok()
                    .and_then(|mut winners| winners.pop())?;
            // Precedence chooses an event and endpoint, not one of several
            // incompatible evidence qualities for that same meaning.
            let consistent = group
                .iter()
                .filter(|candidate| {
                    candidate.policy_event == winner.policy_event
                        && candidate.endpoint == winner.endpoint
                })
                .all(|candidate| {
                    candidate.quality == winner.quality
                        && candidate.condition == winner.condition
                        && candidate.modeled_external_effect == winner.modeled_external_effect
                });
            consistent.then_some(winner)
        })
        .collect()
}

fn reduce_terminal_bindings(
    candidates: Vec<PendingTerminalBinding>,
    endpoint_precedence: &PrecedenceGraph<ResolvedEndpointIdentity>,
    expectation_precedence: &PrecedenceGraph<PolicyTypestateExpectationId>,
) -> Result<Vec<PendingTerminalBinding>, TypestatePolicyCompileError> {
    reduce_precedence_bindings(
        candidates,
        |candidate| TerminalObservationGroupKey {
            subject: candidate.subject.clone(),
            site: candidate.site.clone(),
            phase: candidate.phase,
        },
        |candidate| candidate.policy_expectation.clone(),
        |candidate| candidate.endpoint.clone(),
        endpoint_precedence,
        |candidates| {
            expectation_precedence
                .unique_winner(candidates)
                .map_err(|error| {
                    TypestatePolicyCompileError::AmbiguousSemanticSite(format!(
                        "same-site typestate expectation precedence is undecidable: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    TypestatePolicyCompileError::SemanticUnavailable(
                        "same-site typestate expectation candidate set is empty".to_owned(),
                    )
                })
        },
        "precedence winner belongs to the reduced expectation candidates",
    )
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
    selected_operand: Option<TypestateSelectedOperand>,
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
    modeled_member_id: Option<String>,
    modeled_target_origin: Option<&'static str>,
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
    super::selector_compiler::find_resolved_selector(selectors, path)
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
            let mut call_range = span.start_byte() as usize..span.end_byte() as usize;
            // A deferred implicit call can have a narrower dispatch anchor than
            // its structural cleanup point. ResourceRelease selectors still
            // identify that point, including every close in a multi-resource try.
            if call.member_selection.is_some() {
                let point = procedure
                    .semantics()
                    .point(call.point)
                    .expect("validated semantic call has a program point");
                let point_mapping = procedure
                    .semantics()
                    .source_mapping(point.source)
                    .expect("validated semantic point has a source mapping");
                let point_span = point_mapping.locator.anchor().span();
                let point_range = point_span.start_byte() as usize..point_span.end_byte() as usize;
                if point_range == selection.span {
                    call_range = point_range;
                }
            }
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
    if let Some(set) = &automaton.event_set {
        if !valid_coverage_effect_id(&set.name)
            || set.version == 0
            || set.effects.is_empty()
            || set
                .effects
                .iter()
                .any(|effect| !valid_coverage_effect_id(effect))
        {
            return Err(TypestatePolicyCompileError::InvalidEventSet(
                "invalid-event-set-identity",
            ));
        }
        if !automaton
            .events
            .iter()
            .any(|event| event.semantic_effect.is_some())
        {
            return Err(TypestatePolicyCompileError::InvalidEventSet(
                "event-set-without-mapped-event",
            ));
        }
        for event in &automaton.events {
            if let Some(effect) = &event.semantic_effect {
                if !valid_coverage_effect_id(effect) {
                    return Err(TypestatePolicyCompileError::InvalidEventSet(
                        "invalid-semantic-effect-id",
                    ));
                }
                if !set.effects.contains(effect) {
                    return Err(TypestatePolicyCompileError::InvalidEventSet(
                        "semantic-effect-outside-event-set",
                    ));
                }
            }
        }
    } else if automaton
        .events
        .iter()
        .any(|event| event.semantic_effect.is_some())
    {
        return Err(TypestatePolicyCompileError::InvalidEventSet(
            "missing-event-set",
        ));
    }
    if automaton.events.iter().any(|event| {
        event.semantic_effect.is_some()
            && matches!(
                &event.trigger,
                ResolvedTypestateEventTrigger::Calls {
                    argument_condition: Some(_),
                    ..
                }
            )
    }) {
        return Err(TypestatePolicyCompileError::InvalidEventSet(
            "conditional-semantic-effect",
        ));
    }
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

fn valid_coverage_effect_id(value: &str) -> bool {
    value.len() <= 256
        && value.contains('.')
        && crate::definition::is_valid_namespaced_identifier(value)
}

fn event_occurrence(trigger: &ResolvedTypestateEventTrigger) -> ProtocolEventOccurrence {
    match trigger {
        ResolvedTypestateEventTrigger::Calls { phase, .. }
        | ResolvedTypestateEventTrigger::MatchEndpoints { phase, .. } => {
            ProtocolEventOccurrence::Endpoint {
                phase: protocol_observation_phase(*phase),
            }
        }
        ResolvedTypestateEventTrigger::SemanticEvent { event } => semantic_event_occurrence(*event),
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
        ResolvedTypestateTerminalTrigger::SemanticEvent { event } => match event {
            PolicySemanticEvent::SuspensionBoundary { .. } => {
                ProtocolTerminalObservationSpec::Event {
                    observation: ProtocolObservationSpec {
                        occurrence: ProtocolEventOccurrence::SuspensionBoundary,
                    },
                }
            }
            PolicySemanticEvent::NormalProcedureExit { .. } => {
                ProtocolTerminalObservationSpec::AnalysisRootExit {
                    kind: ProtocolProcedureExitKind::Normal,
                }
            }
            PolicySemanticEvent::ExceptionalProcedureExit { .. } => {
                ProtocolTerminalObservationSpec::AnalysisRootExit {
                    kind: ProtocolProcedureExitKind::Exceptional,
                }
            }
        },
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

const fn semantic_event_occurrence(event: PolicySemanticEvent) -> ProtocolEventOccurrence {
    match event {
        PolicySemanticEvent::NormalProcedureExit { .. } => ProtocolEventOccurrence::ProcedureExit {
            kind: ProtocolProcedureExitKind::Normal,
        },
        PolicySemanticEvent::ExceptionalProcedureExit { .. } => {
            ProtocolEventOccurrence::ProcedureExit {
                kind: ProtocolProcedureExitKind::Exceptional,
            }
        }
        PolicySemanticEvent::SuspensionBoundary { .. } => {
            ProtocolEventOccurrence::SuspensionBoundary
        }
    }
}

fn semantic_event_points(
    root: &ProcedureHandle,
    event: PolicySemanticEvent,
) -> Result<Vec<(ProgramPointHandle, TypestateBindingQuality)>, TypestatePolicyCompileError> {
    use brokk_bifrost_analysis::analyzer::semantic::{SemanticCapability, SemanticEffect};
    let semantics = root.semantics();
    match event {
        PolicySemanticEvent::SuspensionBoundary { .. } => {
            if !root
                .artifact()
                .capabilities()
                .is_available(SemanticCapability::AsyncSuspendResume)
            {
                return Err(TypestatePolicyCompileError::SemanticUnavailable(
                    "async suspension evidence is unsupported for the analysis root".to_owned(),
                ));
            }
            let gaps = semantics
                .gaps()
                .iter()
                .filter(|gap| gap.capability == SemanticCapability::AsyncSuspendResume)
                .collect::<Vec<_>>();
            if !gaps.is_empty() {
                return Err(TypestatePolicyCompileError::SemanticUnavailable(format!(
                    "suspension boundary coverage is incomplete: {gaps:?}"
                )));
            }
            let mut points = Vec::new();
            for point in semantics.points() {
                for event in &point.events {
                    if matches!(event.effect, SemanticEffect::AsyncSuspend { .. }) {
                        let evidence = semantics
                            .evidence_row(event.evidence)
                            .expect("validated suspension retains evidence");
                        points.push((
                            root.point_handle(point.id)
                                .expect("validated suspension retains its point"),
                            TypestateBindingQuality::new(
                                evidence.proof.clone(),
                                evidence.completeness.clone(),
                                TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1)
                                    .expect("one current object is valid multiplicity"),
                            ),
                        ));
                    }
                }
            }
            Ok(points)
        }
        PolicySemanticEvent::NormalProcedureExit { .. } => Ok(vec![(
            root.point_handle(semantics.normal_exit_point())
                .expect("validated procedure retains normal exit"),
            TypestateBindingQuality::proven_unique(),
        )]),
        PolicySemanticEvent::ExceptionalProcedureExit { .. } => Ok(vec![(
            root.point_handle(semantics.exceptional_exit_point())
                .expect("validated procedure retains exceptional exit"),
            TypestateBindingQuality::proven_unique(),
        )]),
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
    use brokk_bifrost_test_macros::hardwon;

    #[derive(Debug, Clone, Copy)]
    enum CoverageCompileCase {
        Baseline,
        ExtraActual,
        SetMismatch,
        MissingClaim,
        UnmappedCandidate,
        PrecedenceDropped,
    }

    struct CoverageCompileObservation {
        candidates: Vec<(String, Option<String>, TypestateBindingQuality)>,
        reason: CoverageRefusalReason,
        retained_bindings: usize,
        plan_hash: String,
    }

    fn compile_reviewed_coverage_case(case: CoverageCompileCase) -> CoverageCompileObservation {
        use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            CatalogOptions, CompilerOptions, SemanticModelActivationControl,
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelControlAction, SemanticModelControlScope, SemanticModelPackSelector,
            SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
            SessionPackSource, SessionPackSourceKind, SourceFormat, acquire_active_semantic_models,
            compile_source,
        };
        use serde_json::{Value, json};

        const POLICY_PATH: &str = "policies/coverage.rqlp";
        const POLICY: &str = r#"(policy
  :schema-version 1
  :id "bifrost.test.coverage-compile"
  :name "Coverage compile"
  :message "Resource remains open"
  :severity error
  :analysis (analysis
    :type typestate
    :mode may
    :call-modeling (call-modeling :unmodeled paranoid)
    :subjects (subject-set :entries [
      (subject :id resource
        :selector (rql :schema-version 1 (language go
          (resolved-call :resolves-to "example.test/wire.Conn.Close" :proof declared
            (call-bindings (call-shape (call :callee (name "Close")))))))
        :subject receiver)])
    :uncertainty (uncertainty :escape inconclusive)
    :automaton (automaton
      :states [open closed violated]
      :initial open
      :accepting-states [closed]
      :error-states [violated]
      :event-set (event-set :name "bifrost.resource-lifecycle" :version 1
        :effects ["bifrost.resource.release"])
      :events [
        (event :id close :semantic-effect "bifrost.resource.release"
          :calls (calls
            :selector (rql :schema-version 1
              (language go
                (resolved-call :resolves-to "example.test/wire.Conn.Close" :proof declared
                  (call-bindings (call-shape (call :callee (name "Close")))))))
            :subject receiver :phase after-normal-return))]
      :transitions [
        (transition :from open :on close :to closed)
        (transition :from closed :on close :to violated)]
      :terminal-expectations [
        (terminal-expectation :id normal-exit
          :on (normal-procedure-exit :scope analysis-root)
          :expected-states [closed])])))"#;
        const GO_MOD: &str = "module example.test/network\n\ngo 1.23\n";
        const APP: &str = "package network\nimport \"example.test/wire\"\nfunc run() {\n    conn, _ := wire.Dial(\"tcp\", \"local\")\n    conn.Close()\n}\n";
        // Copies of the synthetic #9053 `example.test/wire` models; a public crate
        // test must not include the private root fixture corpus.
        let mut declarations: Value = serde_json::from_str(include_str!(
            "../testdata/lifecycle-coverage-go/declarations.json"
        ))
        .unwrap();
        let mut summaries: Value = serde_json::from_str(include_str!(
            "../testdata/lifecycle-coverage-go/summaries.json"
        ))
        .unwrap();
        summaries["schema_version"] = json!(26);
        summaries["pack_id"] = json!("test.lifecycle-coverage-go-summaries");
        summaries["provenance"]["source"] = json!("test-only #9431 review controls");
        let close = summaries["shards"][0]["payload"]["summaries"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|summary| summary["id"] == "test.wire.conn.close")
            .unwrap();
        close["transfers"] = json!([{
            "input":{"kind":"receiver"}, "exit_kind":"normal", "output":{"kind":"receiver"}
        }]);
        close["subject_effects"] = json!([{
            "id":"release", "effect":"bifrost.resource.release",
            "subject":"receiver", "exit":"normal", "condition":"always",
            "timing":"immediate", "certainty":"definite"
        }]);
        close["lifecycle_coverage"] = json!([{
            "id":"normal-lifecycle",
            "event_set":{"name":"bifrost.resource-lifecycle", "version":1,
                "effects":["bifrost.resource.release"]},
            "subject":"receiver", "exit":"normal", "witnesses":["release"]
        }]);
        if matches!(case, CoverageCompileCase::SetMismatch) {
            close["lifecycle_coverage"][0]["event_set"]["version"] = json!(2);
        }
        if matches!(case, CoverageCompileCase::ExtraActual) {
            close["target"]["parameter_count"] = json!(1);
            let member = declarations["shards"][0]["payload"]["members"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|member| member["name"] == "Close")
                .unwrap();
            member["signature"]["parameters"] = json!([{
                "name":"flag", "type":{"kind":"named", "name":"int", "arguments":[], "nullable":false},
                "optional":false, "variadic":false
            }]);
        }
        let second = "(event :id close-again :semantic-effect \"bifrost.resource.release\" :calls (calls :selector (rql :schema-version 1 (language go (resolved-call :resolves-to \"example.test/wire.Conn.Close\" :proof declared (call-bindings (call-shape (call :callee (name \"Close\"))))))) :subject receiver :phase after-normal-return))";
        let mut policy = POLICY.to_owned();
        match case {
            CoverageCompileCase::MissingClaim => {
                policy = policy.replace("after-normal-return", "after-exceptional-return");
            }
            CoverageCompileCase::PrecedenceDropped => {
                policy = policy.replace(
                    ":phase after-normal-return))]",
                    &format!(":phase after-normal-return)) {second}]"),
                );
                if matches!(case, CoverageCompileCase::PrecedenceDropped) {
                    policy = policy.replace(
                        ":phase after-normal-return)) (event :id close-again",
                        ":phase after-normal-return) :supersedes [close-again]) (event :id close-again",
                    );
                }
            }
            CoverageCompileCase::UnmappedCandidate => {
                policy = policy
                    .replace(":semantic-effect \"bifrost.resource.release\"", "")
                    .replace(
                        ":phase after-normal-return))]",
                        ":phase after-normal-return)) (event :id mapped-dial :semantic-effect \"bifrost.resource.release\" :calls (calls :selector (rql :schema-version 1 (language go (resolved-call :resolves-to \"example.test/wire.Dial\" :proof declared (call-bindings (call-shape (call :callee (name \"Dial\"))))))) :subject (result :index 0) :phase after-normal-return))]",
                    )
                    .replace(":transitions [", ":transitions [(transition :from open :on mapped-dial :to open) ");
            }
            CoverageCompileCase::Baseline
            | CoverageCompileCase::ExtraActual
            | CoverageCompileCase::SetMismatch => {}
        }
        let app = if matches!(case, CoverageCompileCase::ExtraActual) {
            APP.replace("conn.Close()", "conn.Close(1)")
        } else {
            APP.to_owned()
        };
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", GO_MOD)
            .file("main.go", app)
            .file(POLICY_PATH, policy)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        for (id, value) in [
            ("test:coverage-declarations", declarations),
            ("test:coverage-summaries", summaries),
        ] {
            let source = serde_json::to_vec(&value).unwrap();
            let pack = compile_source(SourceFormat::Json, &source, &CompilerOptions::default())
                .unwrap_or_else(|diagnostics| panic!("{case:?}: {diagnostics:#?}"));
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: id.into(),
                    },
                )
                .unwrap();
        }
        let request = SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "go".into(),
                ecosystem: "go-stdlib".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: [
                "test.go-model-interface-dispatch-declarations",
                "test.lifecycle-coverage-go-summaries",
            ]
            .into_iter()
            .map(|pack_id| SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: pack_id.into(),
                    version: None,
                    manifest_digest: None,
                },
            })
            .collect(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let activation = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &request,
            &CancellationToken::default(),
        );
        let SemanticModelRuntimeOutcome::Ready { snapshot, .. } = activation else {
            panic!("{case:?}: activation failed: {activation:#?}");
        };
        let _scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            Some(Arc::clone(&snapshot)),
        );
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry = PolicyRegistry::new_for_workspace(
            project.root().to_path_buf(),
            catalogs,
            PolicyRegistryLimits::default(),
        )
        .unwrap();
        let loaded = registry
            .load_policy_path_with_analyzer(POLICY_PATH, workspace.analyzer())
            .unwrap();
        let spec = loaded.resolved_typestate().unwrap();
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let compiled = TypestatePolicyCompiler::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            budget.query_limits(),
            budget.max_selector_results(),
            &cancellation,
            Some(snapshot),
        )
        .compile_with_units(loaded, spec)
        .0
        .unwrap_or_else(|failure| panic!("{case:?}: policy compile: {}", failure.error));
        let binding = compiled
            .bindings
            .event_bindings()
            .iter()
            .find(|binding| {
                compiled
                    .protocol
                    .event(binding.event())
                    .unwrap()
                    .key()
                    .as_str()
                    == "close"
            })
            .unwrap_or_else(|| panic!("{case:?}: close binding absent"));
        let phase = if matches!(case, CoverageCompileCase::MissingClaim) {
            CoverageCandidatePhase::AfterExceptionalReturn
        } else {
            CoverageCandidatePhase::AfterNormalReturn
        };
        let group =
            compiled
                .bindings
                .coverage_candidate_group(binding.subject(), binding.site(), phase);
        let decision = compiled
            .bindings
            .coverage_decision(binding.subject(), binding.site(), phase)
            .unwrap_or_else(|| panic!("{case:?}: decision absent"));
        let CoverageDecisionKind::Refused { reason, .. } = decision.kind() else {
            panic!("{case:?}: expected refusal, got {:?}", decision.kind());
        };
        CoverageCompileObservation {
            candidates: group
                .map(|group| {
                    group
                        .candidates()
                        .iter()
                        .map(|candidate| {
                            (
                                candidate.event.clone(),
                                candidate.semantic_effect.as_ref().map(ToString::to_string),
                                candidate.quality.clone(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            reason: *reason,
            retained_bindings: compiled
                .bindings
                .event_bindings()
                .iter()
                .filter(|other| {
                    other.subject() == binding.subject() && other.site() == binding.site()
                })
                .count(),
            plan_hash: format!("{:?}", compiled.bindings.hash()),
        }
    }

    #[test]
    #[hardwon("#9431: handcrafted candidate groups masked a dropped real policy binding")]
    fn compiled_coverage_groups_and_refusals_keep_the_full_candidate_set() {
        let baseline = compile_reviewed_coverage_case(CoverageCompileCase::Baseline);
        assert_eq!(baseline.candidates.len(), 1, "{:?}", baseline.candidates);
        assert_eq!(baseline.reason, CoverageRefusalReason::CandidateUnproven);

        let dropped = compile_reviewed_coverage_case(CoverageCompileCase::PrecedenceDropped);
        assert_eq!(dropped.retained_bindings, 1);
        assert_eq!(dropped.candidates.len(), 2, "{:?}", dropped.candidates);
        assert_eq!(
            dropped
                .candidates
                .iter()
                .map(|row| row.0.as_str())
                .collect::<HashSet<_>>(),
            HashSet::from(["close", "close-again"]),
        );
        assert!(dropped.candidates.iter().all(|row| {
            row.1.as_deref() == Some("bifrost.resource.release")
                && matches!(row.2.proof(), ProofStatus::Unproven(_))
                && matches!(row.2.completeness(), EvidenceCompleteness::Partial(_))
                && row.2.multiplicity().coverage() == CandidateCoverage::Open
                && row.2.multiplicity().retained() == 1
        }));
        assert_eq!(dropped.reason, CoverageRefusalReason::MultipleCandidates);
        assert_ne!(dropped.plan_hash, baseline.plan_hash);

        for (case, expected) in [
            (
                CoverageCompileCase::ExtraActual,
                CoverageRefusalReason::ExtraActual,
            ),
            (
                CoverageCompileCase::SetMismatch,
                CoverageRefusalReason::EventSetMismatch,
            ),
            (
                CoverageCompileCase::MissingClaim,
                CoverageRefusalReason::MissingClaim,
            ),
            (
                CoverageCompileCase::UnmappedCandidate,
                CoverageRefusalReason::CandidateUnproven,
            ),
        ] {
            let observed = compile_reviewed_coverage_case(case);
            assert_eq!(
                observed.reason, expected,
                "{case:?}: {:?}",
                observed.candidates
            );
            if matches!(case, CoverageCompileCase::UnmappedCandidate) {
                assert_eq!(observed.candidates.len(), 1);
                assert_eq!(observed.candidates[0].1, None);
            }
        }
    }

    /// A sliced compile mints the compile a whole compile mints.
    ///
    /// The four things a later stage of the evaluation reads out of a compile:
    /// the protocol and binding-plan hashes, which every finding identity
    /// folds; the semantic budget the root solves inherit; and the artifact
    /// leases the evaluation's windows open against. A sliced compile that
    /// moved any of them differently would hand the solve a different
    /// evaluation, not the same one computed a cheaper way.
    #[test]
    #[hardwon("#9550: an unproven event relation must survive cold and replayed policy evaluation")]
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
          :event-set (event-set :name "test.resource-lifecycle" :version 1
            :effects ["test.release"])
          :events [
            (event :id close :semantic-effect "test.release"
              :calls (calls
                :selector (rql :schema-version 1
                  (language go (call :callee (name "CloseRes"))))
                :subject (argument :index 0)
                :phase after-normal-return)
              :supersedes [close-shadow])
            (event :id close-shadow :semantic-effect "test.release"
              :calls (calls
                :selector (rql :schema-version 1
                  (language go (call :callee (name "CloseRes"))))
                :subject (argument :index 0)
                :phase after-normal-return))]
          :transitions [
            (transition :from open :on close :to closed)
            (transition :from closed :on close :to violated)
            (transition :from open :on close-shadow :to closed)]
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
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                budget.query_limits(),
                budget.max_selector_results(),
                &cancellation,
                None,
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
        let store = std::sync::Mutex::new(crate::units::InMemoryPolicyUnitStore::new());
        let store: &std::sync::Mutex<dyn crate::units::PolicyUnitStore> = &store;
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
                None,
            ),
            crate::units::IncrementalBaseState::Evaluated,
            crate::units::UnitSnapshots::of(
                crate::units::workspace_snapshot(&workspace)
                    .expect("an analyzed workspace states its content identity"),
            ),
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

        // These are production selector bindings. The ordinary reduction
        // retained the superseding close, while the coverage group retains
        // both same-effect candidates, so a duplicate cannot look unique.
        let close = whole
            .bindings
            .event_bindings()
            .iter()
            .find(|binding| {
                whole
                    .protocol
                    .event(binding.event())
                    .unwrap()
                    .key()
                    .as_str()
                    == "close"
            })
            .expect("the superseding close survives reduction");
        let group = whole
            .bindings
            .coverage_candidate_group(
                close.subject(),
                close.site(),
                CoverageCandidatePhase::AfterNormalReturn,
            )
            .expect("real compile records the pre-reduction call group");
        assert_eq!(group.candidates().len(), 2, "{:#?}", group.candidates());
        assert!(group.candidates().iter().all(|candidate| {
            candidate.semantic_effect.as_deref() == Some("test.release")
                && candidate.is_definitive()
        }));
        assert_eq!(
            group
                .candidates()
                .iter()
                .map(|candidate| candidate.event.as_str())
                .collect::<HashSet<_>>(),
            HashSet::from(["close", "close-shadow"]),
        );
        assert_eq!(
            whole
                .bindings
                .event_bindings()
                .iter()
                .filter(|binding| {
                    binding.subject() == close.subject() && binding.site() == close.site()
                })
                .count(),
            1,
            "ordinary event reduction still keeps only its precedence winner"
        );

        // Build a competing pre-reduction group on the real call site. The
        // reducer still chooses the same event, while the plan retains every
        // alternative for the later coverage certificate.
        let bound = whole
            .bindings
            .event_bindings()
            .first()
            .expect("close call is bound");
        let subject = whole
            .bindings
            .subjects()
            .iter()
            .find(|subject| subject.id() == bound.subject())
            .unwrap();
        let winner = PolicyTypestateEventId::new("close").unwrap();
        let alias = PolicyTypestateEventId::new("alias").unwrap();
        let uncertain = PolicyTypestateEventId::new("uncertain").unwrap();
        let unmapped = PolicyTypestateEventId::new("unmapped").unwrap();
        let ids = [
            winner.clone(),
            alias.clone(),
            uncertain.clone(),
            unmapped.clone(),
        ];
        let event_graph = PrecedenceGraph::try_new(
            ids.to_vec(),
            [alias.clone(), uncertain.clone(), unmapped.clone()]
                .into_iter()
                .map(|loser| (winner.clone(), loser)),
        )
        .unwrap();
        let endpoint_graph =
            PrecedenceGraph::try_new(Vec::<ResolvedEndpointIdentity>::new(), Vec::new()).unwrap();
        let candidates = ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| PendingEventBinding {
                event: if index == 0 {
                    whole.protocol.event(bound.event()).unwrap().key().clone()
                } else {
                    ProtocolEventKey::new(id.as_str()).unwrap()
                },
                policy_event: id,
                subject: subject.key().clone(),
                site: bound.site().clone(),
                phase: EventObservationPhase::Endpoint(EndpointObservationPhase::AfterNormalReturn),
                order: bound.order(),
                role: bound.role(),
                quality: match index {
                    2 => TypestateBindingQuality::new(
                        ProofStatus::Unproven("uncertain".into()),
                        EvidenceCompleteness::Complete,
                        TypestateBindingMultiplicity::new(CandidateCoverage::Exhaustive, 1)
                            .unwrap(),
                    ),
                    _ => TypestateBindingQuality::proven_unique(),
                },
                endpoint: None,
                modeled_external_effect: None,
                semantic_effect: (index != 3).then(|| Arc::from("test.release")),
                condition: None,
                alias_derived: index == 1,
                selected_operand: None,
            })
            .collect::<Vec<_>>();
        let mut groups = HashMap::new();
        for candidate in &candidates {
            record_coverage_candidate(&mut groups, candidate);
        }
        let reduced = reduce_event_bindings(candidates, &endpoint_graph, &event_graph).unwrap();
        assert_eq!(reduced.len(), 1);
        assert_eq!(reduced[0].policy_event, winner);
        let candidate_groups = groups
            .into_iter()
            .map(|(key, candidates)| CoverageCandidateGroupSpec {
                subject: key.subject,
                site: key.site,
                phase: coverage_candidate_phase(key.phase),
                candidates,
            })
            .collect();
        let subject_spec = BoundTypestateSubjectSpec::new(
            subject.key().class().clone(),
            subject.object().clone(),
            subject.quality().clone(),
        );
        let event_spec = TypestateEventBindingSpec::new(
            reduced[0].event.clone(),
            reduced[0].subject.clone(),
            reduced[0].site.clone(),
            reduced[0].order,
            reduced[0].role,
            reduced[0].quality.clone(),
        )
        .with_semantic_effect(reduced[0].semantic_effect.clone());
        let plan = TypestateBindingPlan::try_new_with_coverage(
            &whole.protocol,
            vec![subject_spec.clone()],
            Vec::new(),
            TypestateEventBindings {
                events: vec![event_spec.clone()],
                templates: Vec::new(),
            },
            Vec::new(),
            Vec::new(),
            TypestateCoverageSpec {
                event_set: Some(TypestateCoverageEventSet {
                    name: "test.resource".into(),
                    version: 1,
                    effects: vec!["test.release".into()],
                }),
                candidate_groups,
                decisions: Vec::new(),
                unproven_relations: Vec::new(),
            },
        )
        .unwrap();
        let group = plan
            .coverage_candidate_group(
                plan.subjects()[0].id(),
                bound.site(),
                CoverageCandidatePhase::AfterNormalReturn,
            )
            .unwrap();
        assert_eq!(group.candidates().len(), 4);
        assert!(
            group
                .candidates()
                .iter()
                .any(|candidate| candidate.alias_derived && !candidate.is_definitive())
        );
        assert!(
            group
                .candidates()
                .iter()
                .any(|candidate| candidate.event == "uncertain" && !candidate.is_definitive())
        );
        assert!(
            group
                .candidates()
                .iter()
                .any(|candidate| candidate.semantic_effect.is_none())
        );
        assert_eq!(
            plan.event_bindings()[0].semantic_effect(),
            Some("test.release")
        );
        let without_group = TypestateBindingPlan::try_new_with_coverage(
            &whole.protocol,
            vec![subject_spec.clone()],
            Vec::new(),
            TypestateEventBindings {
                events: vec![event_spec.clone()],
                templates: Vec::new(),
            },
            Vec::new(),
            Vec::new(),
            TypestateCoverageSpec {
                event_set: Some(TypestateCoverageEventSet {
                    name: "test.resource".into(),
                    version: 1,
                    effects: vec!["test.release".into()],
                }),
                candidate_groups: Vec::new(),
                decisions: Vec::new(),
                unproven_relations: Vec::new(),
            },
        )
        .unwrap();
        assert_ne!(plan.hash(), without_group.hash());
        let marker_site = bound.site().clone();
        let procedure = match &marker_site {
            TypestateObservationSite::ProgramPoint { point, .. } => point.procedure(),
            TypestateObservationSite::CallSite { call, .. } => call.procedure(),
        };
        let artifact = procedure.artifact().key().clone();
        let declaration = procedure.semantics().locator().declaration().clone();
        let observation_procedure = procedure.semantics().locator().clone();
        let with_marker = TypestateBindingPlan::try_new_with_coverage(
            &whole.protocol,
            vec![subject_spec],
            Vec::new(),
            TypestateEventBindings {
                events: vec![event_spec],
                templates: Vec::new(),
            },
            Vec::new(),
            Vec::new(),
            TypestateCoverageSpec {
                event_set: Some(TypestateCoverageEventSet {
                    name: "test.resource".into(),
                    version: 1,
                    effects: vec!["test.release".into()],
                }),
                candidate_groups: Vec::new(),
                decisions: Vec::new(),
                unproven_relations: vec![UnprovenEventRelation {
                    subject: subject.key().clone(),
                    site: marker_site,
                    event: "close".into(),
                    phase: "AfterNormalReturn".into(),
                    exit: None,
                    observation_procedure,
                    reason: "alias answer unavailable".into(),
                }],
            },
        )
        .unwrap();
        assert_ne!(without_group.hash(), with_marker.hash());
        assert_ne!(
            without_group.summary_hash_for(&artifact, &declaration),
            with_marker.summary_hash_for(&artifact, &declaration)
        );

        // Exercise the marker through the policy evaluator, including its
        // exact-result cache. Each compile gets a fresh execution allowance;
        // the repository is shared across cold, warm, and replayed solves.
        let marked_bindings = Arc::new(with_marker);
        let summaries = ProductionTypestateSummaryRepository::new(
            brokk_bifrost_analysis::analyzer::workspace_authority::workspace_memo_attribution(
                &workspace,
            ),
        );
        let mut cold_answer = None;
        for phase in ["cold", "warm", "replayed"] {
            let (mut compiled, _) = compile(None);
            compiled.bindings = Arc::clone(&marked_bindings);
            let authority = TypestateProjectionAuthority::from_loaded_compilation(
                policy,
                compiled.protocol.hash(),
                compiled.bindings.hash(),
            )
            .expect("marked compile mints projection authority");
            let RootsPass::Complete(payload) = evaluate_compiled_typestate(
                &authority,
                policy,
                spec,
                &workspace,
                Some(&cancellation),
                &budget,
                &compiled,
                &summaries,
                None,
                None,
            ) else {
                panic!("{phase}: marked policy evaluation must return a report");
            };
            assert!(
                matches!(&payload.completion, PolicyRunCompletion::Inconclusive { reasons, .. }
                    if reasons.contains(&PolicyIncompleteReason::PartialDiscovery)),
                "{phase}: a reached unproven event relation cannot be Complete: {:?}",
                payload.completion
            );
            if phase == "cold" {
                assert!(
                    work_metric(&payload.work, "typestate.summary_misses") > 0,
                    "cold marked solve must compute a result: {:#?}",
                    payload.work
                );
            } else {
                assert!(
                    work_metric(&payload.work, "typestate.summary_hits") > 0,
                    "{phase}: expired source sessions must be re-acquired: {:#?}",
                    payload.work
                );
            }
            if phase == "cold" {
                cold_answer = Some((payload.projections, payload.completion));
            } else {
                let (projections, completion) = cold_answer.as_ref().unwrap();
                assert_eq!(
                    &payload.projections, projections,
                    "{phase}: findings agree with cold"
                );
                assert_eq!(
                    &payload.completion, completion,
                    "{phase}: completion agrees with cold"
                );
            }
        }
    }

    /// A selector whose plan is not partitionable by seed asks to be compiled
    /// again rather than being sliced anyway.
    ///
    /// Cross-seed intersection needs the complete membership relation. It
    /// remains a Whole compile even when its leaves are seed-local.
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
                (intersect
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
        let store = std::sync::Mutex::new(crate::units::InMemoryPolicyUnitStore::new());
        let store: &std::sync::Mutex<dyn crate::units::PolicyUnitStore> = &store;
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
                None,
            ),
            crate::units::IncrementalBaseState::Evaluated,
            crate::units::UnitSnapshots::of(
                crate::units::workspace_snapshot(&workspace)
                    .expect("an analyzed workspace states its content identity"),
            ),
        );
        let (compiled, units) = TypestatePolicyCompiler::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            budget.query_limits(),
            budget.max_selector_results(),
            &cancellation,
            None,
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
                event_set: None,
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
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            budget.query_limits(),
            budget.max_selector_results(),
            &cancellation,
            None,
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
    #[hardwon(
        "a548e3638b8c: the failure-path fix preserves compile and partial evaluation work when typestate projection fails."
    )]
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
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            budget.query_limits(),
            budget.max_selector_results(),
            &cancellation,
            None,
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
            &ProductionTypestateSummaryRepository::new(
                brokk_bifrost_analysis::analyzer::workspace_authority::workspace_memo_attribution(
                    &workspace,
                ),
            ),
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
    #[hardwon("#4271: an overlong typestate failure must retain a bounded diagnostic")]
    fn failed_projection_payload_keeps_overlong_diagnostic_bounded() {
        let message = "m".repeat(crate::finding::MAX_REPORT_PROSE_BYTES + 1);
        let payload = failed_projection_payload(&message, PolicyWorkReport::default());

        assert_eq!(payload.diagnostics.len(), 1);
        let diagnostic = &payload.diagnostics[0];
        assert_eq!(diagnostic.code(), &PolicyDiagnosticCode::EvaluationFailure);
        assert!(diagnostic.message().len() <= crate::finding::MAX_REPORT_PROSE_BYTES);
        assert!(diagnostic.message().ends_with(" [truncated]"));
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
    fn compile_protocol_rejects_invalid_semantic_effect_mappings() {
        let mut spec = minimal_resolved_spec(UnmodeledCallBehavior::Paranoid);
        let event_id = PolicyTypestateEventId::new("close").unwrap();
        spec.automaton.events = vec![
            ResolvedTypestateEventSpec::new(
                event_id,
                ResolvedTypestateEventTrigger::SemanticEvent {
                    event: PolicySemanticEvent::NormalProcedureExit {
                        scope: TypestateExitScope::AnalysisRoot,
                    },
                },
                Vec::new(),
                Vec::new(),
            )
            .with_semantic_effect(Some("test.release".into())),
        ];
        spec.automaton.event_set = Some(crate::definition::TypestateEventSetSpec {
            name: "test.resource".into(),
            version: 1,
            effects: vec!["test.release".into()],
        });
        assert!(compile_protocol(&spec).is_ok());

        let mut invalid = spec.clone();
        invalid.automaton.event_set.as_mut().unwrap().effects = vec!["test.other".into()];
        assert!(matches!(
            compile_protocol(&invalid),
            Err(TypestatePolicyCompileError::InvalidEventSet(
                "semantic-effect-outside-event-set"
            ))
        ));

        let mut invalid = spec.clone();
        invalid.automaton.events[0].semantic_effect = None;
        assert!(matches!(
            compile_protocol(&invalid),
            Err(TypestatePolicyCompileError::InvalidEventSet(
                "event-set-without-mapped-event"
            ))
        ));

        let mut invalid = spec.clone();
        invalid.automaton.events[0].trigger = ResolvedTypestateEventTrigger::Calls {
            selector_path: PolicySelectorPath::new(
                "/analysis/automaton/events/close/calls/selector",
            )
            .unwrap(),
            subject: TypestateCallBinding::Receiver,
            phase: EndpointObservationPhase::AfterNormalReturn,
            argument_condition: Some(TypestateArgumentCondition {
                index: 0,
                equals: true,
            }),
        };
        assert!(matches!(
            compile_protocol(&invalid),
            Err(TypestatePolicyCompileError::InvalidEventSet(
                "conditional-semantic-effect"
            ))
        ));

        let mut invalid = spec;
        invalid.automaton.event_set = None;
        assert!(matches!(
            compile_protocol(&invalid),
            Err(TypestatePolicyCompileError::InvalidEventSet(
                "missing-event-set"
            ))
        ));
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
            .check_admission(SemanticWork {
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
