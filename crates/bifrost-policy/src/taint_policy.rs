//! Production lowering and execution preparation for resolved taint policies.
//!
//! Policy loading owns authoring and composition. This module starts at the
//! closed [`ResolvedTaintPolicySpec`] boundary and lowers only structured,
//! source-backed selector results into the diagnostic-neutral taint engine.

use brokk_bifrost_rust_analysis::{
    RustStdBuiltinCall, RustStdBuiltinTransfer, rust_std_builtin_call,
};
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::hash::Hasher;
use std::ops::Range as ByteRange;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use brokk_bifrost_analysis::analyzer::semantic::partial_flow::rules::{
    ConditionalGuardResult, ConditionalGuardSanitizer, conditional_guard_edge_kills,
    guard_edge_kills,
};

use crate::budget::{PolicyBudget, PolicyBudgetField};
use crate::definition::{
    PolicyId, PolicyPort, PolicySelectorPath, TaintLabel, TaintSanitizerCondition,
    TaintSanitizerKind, TaintSanitizerOperand, TaintSanitizerResult, TaintThreatModel,
    TaintTransferEffect,
};
use crate::evaluator::{PolicyEvaluationContext, TaintPolicyEvaluator};
use crate::finding::{
    AuthoredArmClosureEvidence, BoundedWitness, CertaintyReason, FindingCertainty,
    FindingCompleteness, FindingIncompleteReason, MAX_REPORT_PROSE_BYTES, PolicyDiagnostic,
    PolicyDiagnosticCode, PolicyDiagnosticImpact, PolicyDiagnosticSeverity, PolicyFailureReason,
    PolicyIncompleteReason, PolicyLocationRelationship, PolicyRunCompletion,
    PolicySelectorGapSummary, PolicySourceLocation, ProofMetadata, ProofReason, ProofState,
    RelatedPolicyLocation, ReportValueError, StoreDimensionEvidence, WitnessStep, WitnessStepKind,
    WitnessStepProvenance,
};
use crate::finding::{
    InconclusiveScope, PolicyRunScope, PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit,
};
use crate::finding_identity::{
    AnalysisEventRef, AnalysisFindingId, EvidenceRef, SourceScenarioId, StableSemanticIdentity,
    WitnessId,
};
use crate::future_evidence::{
    TaintFindingAnchor, TaintPolicyProjectionFacts, TaintSourceProjectionFact,
};
use crate::projection::{
    ProjectedFindingReport, TaintEnvelopeIdentity, TaintOriginProjection, TaintPairProjection,
    TaintProjectedFinding, TaintProjectionAuthority, TaintProjectionPayload,
    taint_envelope_identity,
};
use crate::resolved::{
    LoadedPolicy, ResolvedEndpointIdentity, ResolvedPolicySelector, ResolvedTaintAuxiliary,
    ResolvedTaintEndpoint, ResolvedTaintExternalModelDefinition, ResolvedTaintPolicySpec,
    ResolvedTaintSanitizerDefinition, ResolvedTaintSourceDefinition,
    ResolvedTaintTransformDefinition,
};
use crate::selector_compiler::{
    IncompleteTaintSelector, ReceiverBindingApplicability, parameter_name_matches,
    parameter_names_match,
};
use crate::taint_compose_provider::{CompositionMemo, PolicyCompositionProvider};
use crate::{ProductionTaintAnalysisResult, ProductionTaintPhaseMetrics};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    GapOpenness, PreparedWorkspaceDispatchSession, ProcedureRangeLookupStatus,
    abort_paths_run_user_code, classify_gap_openness, procedures_in_artifact,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    CallArgumentMapping, CallArgumentMember, CallBinding, CallBindings, CallSiteHandle,
    CallableReferenceKind, CandidateCoverage, DispatchBoundary, DispatchBoundaryKind,
    DispatchCandidate, DispatchHints, DispatchResult, DurablePortIdentity, EvidenceCompleteness,
    ExactExternalProcedureTarget, IcfgEdgeKind, LengthDelimitedDigest, ObservationPhase,
    ObservedValueType, OracleCallContext, OracleRelationHandle, OracleRelationOwner,
    PreparedWorkspaceDispatchPool, ProcedureHandle, ProcedurePortHandle, ProcedurePortKind,
    ProgramPointHandle, ProgramPointId, ProofStatus, ResolverOwnedExternalCalleeIdentity,
    ReturnedCallableProvenance, RuntimeReadSourceOrigin, SemanticArtifactKey, SemanticBudget,
    SemanticCapability, SemanticEffect, SemanticExecutionBudget, SemanticGapKind,
    SemanticGapSubject, SemanticLanguage, SemanticLocator, SemanticOutcome, SemanticRequest,
    SemanticValueKind, SemanticWork, SourceMappingKind, UnmaterializedExternalTarget, ValueAtPoint,
    ValueFlowSnapshot, ValueHandle, ValueId, WorkspaceIcfgProvider, WorkspaceRelativePath,
    WorkspaceSemanticOracle, authored_procedure_target_identity, record_dispatch_read,
};
use brokk_bifrost_analysis::analyzer::semantic::{DispatchOracle, ValueFlowOracle};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivatedProcedureSummary, ActiveSemanticModelSnapshot, CompiledProcedureSummary,
    CompiledSummaryEffect, ProcedureSummaryMatch, ProcedureSummaryTargetKey,
    ResolvedActiveSemanticModels, SemanticModelMatchDisposition,
    UnmaterializedExternalSummaryCallShapeBinding,
};
use brokk_bifrost_analysis::analyzer::usages::call_shape::call_shapes_in_file;
use brokk_bifrost_analysis::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch_with_source,
};
use brokk_bifrost_analysis::analyzer::{Language, ProjectFile, WorkspaceAnalyzer};
use brokk_bifrost_analysis::path_utils::rel_path_string;
use brokk_bifrost_flow::dataflow::{
    CuratedCallModel, DataflowRequest, ExternalSemanticSummarySet, ExternalSummaryCompatibilityKey,
    ExternalSummaryContentHash, ExternalSummaryModelId, ExternalSummaryTarget, SemanticInputStatus,
    SolverBudget, SolverTermination, SummaryBehaviorKey, SummaryBoundary, SummaryBoundaryKind,
    SummaryContextKey, SummaryEdge, SummaryEffect, SummaryEffectKey, SummaryEvidence, SummaryExit,
    SummaryExitKind, SummaryPort, SummarySchemaVersion, SummarySemanticsVersion, SummaryTransfer,
    SummaryWitness, SummaryWitnessStepKind, WitnessReconstructionLimits, WitnessRetentionLimits,
};
use brokk_bifrost_flow::taint::compose::{
    self, BoundSource, BudgetLane, CompositionBudget, Incompleteness, ProcedureEndpoints,
    compose_taint_batch,
};
use brokk_bifrost_flow::taint::{
    SourceClassId, SourceEventKey, TaintAnalysisPlan, TaintAttributionBudget, TaintAttributionWork,
    TaintBatch, TaintBatchCompatibilityKey, TaintBatchPlanner, TaintClassSet, TaintEdgeFunction,
    TaintFindingCollectionLimits, TaintFindingReport, TaintLocalTransformBinding,
    TaintOriginFindingEvidence, TaintPlanError, TaintPolicyPlan, TaintPropagationSemanticsId,
    TaintSanitizerBinding, TaintSinkBinding, TaintSourceBinding, TaintStoreChannel,
    TaintStoreDimension, TaintStoreReadBinding, TaintStoreWriteBinding, TaintUniverse,
    collect_taint_findings_with_attribution_budget,
};
use brokk_bifrost_flow::value_flow::{
    CallSiteCoverage, ClosureLimits, DispatchStatus, ValueFlowCarrier, ValueFlowCuratedCallModel,
    ValueFlowEdgeKillSpec, ValueFlowEventKey, ValueFlowEventKind, ValueFlowIncompleteCause,
    ValueFlowInput, ValueFlowLocalRuleSpec, ValueFlowObservationPhase, ValueFlowPlan,
    ValueFlowPlanLimits, ValueFlowProvider, ValueFlowReturnedCallable, ValueFlowSinkId,
    ValueFlowSinkSpec, ValueFlowSourceId, ValueFlowSourceSpec, ValueFlowSources,
    ValueFlowSummaryLocationBinding, discover_closure_with,
};
use brokk_bifrost_flow::{
    ExactProcedureSummaryBoundary, ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, bind_compiled_procedure_summaries,
};
use brokk_bifrost_rql::structural::CodeQueryTaintFindingKey;
use brokk_bifrost_rql::structural::search::CodeQueryExecutionScope;
use brokk_bifrost_rql::structural::{
    CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryExecutionLimits,
};

mod candidate;

pub(crate) use candidate::{
    CandidateBinding, CandidateBoundary, CandidatePass, CandidateSite, CandidateSolve,
    project_candidate_witness, solve_flow_candidate,
};

#[derive(Debug, Clone)]
pub(crate) enum TaintPolicyCompileError {
    MissingSelector(String),
    QueryIncomplete {
        completion: CodeQueryCompletion,
        detail: String,
    },
    SemanticProvider(String),
    SemanticUnavailable(String),
    AmbiguousSemanticSite(String),
    /// A `(argument :name ...)` port named a formal the selected call's exactly
    /// resolved target does not declare. The target is proven and its parameter
    /// list is known, so this is an authoring mistake rather than an analysis
    /// limit, and it is reported instead of silently matching nothing (#2496).
    UnknownFormalName {
        name: String,
        target: String,
        declared: Vec<String>,
    },
    UnsupportedBinding(String),
    UnsupportedBarrierEngine(String),
    UnsupportedAuxiliarySemantics(&'static str),
    /// One or both endpoint sets bound no location in the scanned workspace.
    /// The compile is not a failure: the run stays complete and vacuously
    /// clean. The carried sets are what the run reports so a reader can tell a
    /// vacuous verdict from a proven one (#2659).
    EmptyCompiledEndpoints(EmptyEndpointSets),
    Model(String),
    Plan(String),
}

impl fmt::Display for TaintPolicyCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSelector(path) => write!(formatter, "taint selector `{path}` is missing"),
            Self::QueryIncomplete { detail, .. } => {
                write!(
                    formatter,
                    "taint selector did not execute completely: {detail}"
                )
            }
            Self::SemanticProvider(message) => {
                write!(formatter, "taint semantic provider failed: {message}")
            }
            Self::SemanticUnavailable(message) => {
                write!(
                    formatter,
                    "taint semantic binding is unavailable: {message}"
                )
            }
            Self::AmbiguousSemanticSite(message) => {
                write!(formatter, "taint semantic binding is ambiguous: {message}")
            }
            Self::UnknownFormalName {
                name,
                target,
                declared,
            } => {
                write!(
                    formatter,
                    "taint binding names formal `{name}`, which `{target}` does not declare; \
                     its formals are {declared:?}"
                )
            }
            Self::UnsupportedBarrierEngine(reason) => write!(
                formatter,
                "value-type barriers are unsupported on the ICFG taint engine ({reason})"
            ),
            Self::UnsupportedBinding(message) => {
                write!(formatter, "taint binding is unsupported: {message}")
            }
            Self::UnsupportedAuxiliarySemantics(kind) => {
                write!(
                    formatter,
                    "production taint {kind} lowering is not available"
                )
            }
            Self::EmptyCompiledEndpoints(empty) => {
                write!(
                    formatter,
                    "taint policy compiled to an empty endpoint selection: {:?}",
                    empty.named()
                )
            }
            Self::Model(message) => write!(formatter, "taint model compilation failed: {message}"),
            Self::Plan(message) => write!(formatter, "taint plan compilation failed: {message}"),
        }
    }
}

impl std::error::Error for TaintPolicyCompileError {}

pub(crate) struct TaintPolicyCompileFailure {
    pub(crate) error: TaintPolicyCompileError,
    pub(crate) work: PolicyWorkReport,
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledTaintEndpoint {
    pub(crate) endpoint: ResolvedEndpointIdentity,
    pub(crate) event: ValueFlowEventKey,
}

#[derive(Debug, Clone)]
struct CompiledStoreEnd {
    endpoint: ResolvedEndpointIdentity,
    event: ValueFlowEventKey,
    call: CallSiteHandle,
    channel: TaintStoreChannel,
}

/// The engine that answers one compiled taint policy. The rule
/// `select_taint_engine` applies runs once per compile, before any solve. It
/// is not a fallback: a composition that cannot complete reports incomplete
/// and never restarts on the ICFG engine.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TaintEngine {
    Composition,
    Icfg { reason: Box<str> },
}

impl TaintEngine {
    /// The engine name the timing note prints.
    fn name(&self) -> &'static str {
        match self {
            Self::Composition => "composition",
            Self::Icfg { .. } => "icfg",
        }
    }

    /// Why the ICFG engine answers, or `None` for the composition.
    fn reason(&self) -> Option<&str> {
        match self {
            Self::Composition => None,
            Self::Icfg { reason } => Some(reason.as_ref()),
        }
    }

    /// The run output form: `composition`, or `icfg (<reason>)`.
    pub(crate) fn render(&self) -> String {
        match self.reason() {
            None => self.name().to_owned(),
            Some(reason) => format!("{} ({reason})", self.name()),
        }
    }
}

pub(crate) struct CompiledTaintPolicyPlan {
    pub(crate) internal_policy_id: String,
    pub(crate) plan: TaintPolicyPlan,
    pub(crate) engine: TaintEngine,
    /// How this policy's endpoints were scoped against a changed range (spec
    /// `None` when the compile had no range.
    pub(crate) scope: Option<PolicyRunScope>,
    pub(crate) sources: Box<[CompiledTaintEndpoint]>,
    pub(crate) sinks: Box<[CompiledTaintEndpoint]>,
    store_writes: Box<[CompiledStoreEnd]>,
    store_reads: Box<[CompiledStoreEnd]>,
    call_resolution_evidence: Option<TaintCallResolutionEvidence>,
    sanitizer_declines: Vec<SanitizerDecline>,
    /// The kills bound in this region. Ordinary evaluation drops them unread;
    /// a flow candidate (#3686) names the ones a counterfactual path passes.
    kills: Box<[CompiledTaintKill]>,
    /// The policy's bound external models, which a composed plan's provider
    /// reads at each call it crosses. Empty for an ICFG plan, whose value-flow
    /// plan installs them.
    external_models: Arc<[BoundExternalModel]>,
}

#[derive(Debug, Clone)]
struct TaintCallResolutionEvidence {
    call: DurableCallSiteKey,
    path: String,
    location: PolicySourceLocation,
    callee: Option<String>,
    range: ByteRange<usize>,
    status: SemanticInputStatus,
    boundary_status: String,
    resolver_complete: bool,
    reason: Option<String>,
}

/// One bound kill (a flow policy's `kill`, a taint policy's `sanitizer`): the
/// entry that declared it and the program point whose input carrier it clears.
#[derive(Debug, Clone)]
struct CompiledTaintKill {
    endpoint: ResolvedEndpointIdentity,
    point: ProgramPointHandle,
}

enum TaintPolicyCompilation {
    Plans {
        roots: Vec<CompiledTaintPolicyPlan>,
        work: PolicyWorkReport,
        /// One message per selector row the compile refused to bind (#2308).
        /// Non-empty means the run does not cover the whole selection, so it
        /// must not report `Complete`.
        refusals: Vec<RefusalNotice>,
        incomplete_selectors: Vec<IncompleteTaintSelector>,
        authored_selector_summary: bool,
        skipped_region_roots: usize,
    },
    /// A compile whose endpoint selection was empty, so there is nothing to
    /// solve. `empty_endpoints` names the sets that matched nothing; an
    /// incomplete selector still prevents a complete negative verdict.
    Clean {
        work: PolicyWorkReport,
        refusals: Vec<RefusalNotice>,
        incomplete_selectors: Vec<IncompleteTaintSelector>,
        empty_endpoints: EmptyEndpointSets,
        /// Set only for a changed-range answer with no sink in the range
        /// An empty selection leaves both absent.
        engine: Option<TaintEngine>,
        scope: Option<PolicyRunScope>,
    },
}

/// What compiling one policy's endpoints produced. A changed-range compile
/// whose sinks all lie outside the range has no region to analyze: its answer
/// is the empty result, and it still records the engine that gave it.
enum CompiledPolicy {
    Plans(Vec<CompiledTaintPolicyPlan>),
    NoSinkInRange {
        engine: TaintEngine,
        scope: PolicyRunScope,
    },
}

#[derive(Clone)]
struct PreparedTaintPlan {
    policy_id: PolicyId,
    engine: TaintEngine,
    sources: Box<[CompiledTaintEndpoint]>,
    sinks: Box<[CompiledTaintEndpoint]>,
    store_writes: Box<[CompiledStoreEnd]>,
    store_reads: Box<[CompiledStoreEnd]>,
    call_resolution_evidence: Option<TaintCallResolutionEvidence>,
    sanitizer_declines: Vec<SanitizerDecline>,
    external_models: Arc<[BoundExternalModel]>,
    compilation_elapsed: Duration,
    /// The files of every sink the policy compiled, across all its roots.
    /// Every finding of the policy is anchored at one of them, so they are
    /// what a solve that could not finish can have missed findings in
    /// (#5433). Policy-wide rather than this root's, so the scope does not
    /// depend on whether the engine solves one root or all of them.
    sink_files: Arc<InconclusiveScope>,
}

/// The files of every sink one policy compiled, across all its roots, which
/// is where every finding of the policy is anchored (#5433).
fn policy_sink_files(roots: &[CompiledTaintPolicyPlan]) -> Arc<InconclusiveScope> {
    Arc::new(InconclusiveScope::of_files(
        roots
            .iter()
            .flat_map(|compiled| compiled.sinks.iter())
            .map(|sink| sink.event.site().path()),
    ))
}

/// The payload for a compile that produced plans or an empty selection.
///
/// `refusals` carries one message per selector row the compile declined to
/// bind. An empty list is the ordinary case and reports `Complete`. A non-empty
/// list means the compile did not bind part of its own selection, so the run
/// reports a typed capability gap and names every refused row: reporting
/// `Complete` would let a caller read "no finding" as proof about a site that
/// was never analyzed (#2308).
///
/// `empty_endpoints` is `Some` exactly when the compile produced no plan
/// because an endpoint set bound nothing. That does not make the run
/// incomplete -- there was nothing to analyze, and zero findings is the right
/// answer -- but it is reported so a reader can tell a vacuous verdict from a
/// proven one (#2659).
///
/// `endpoint_label` names the endpoint a selector gap belongs to, for the
/// human summary of that gap (see [`selector_endpoint_label`]).
fn compiled_payload(
    policy_id: &PolicyId,
    work: PolicyWorkReport,
    refusals: Vec<RefusalNotice>,
    empty_endpoints: Option<EmptyEndpointSets>,
    authored_selector_summary: bool,
    incomplete_selectors: Vec<IncompleteTaintSelector>,
    endpoint_label: impl Fn(&PolicySelectorPath) -> String,
) -> TaintProjectionPayload {
    let mut diagnostics = empty_endpoints
        .map(|empty| empty_selection_diagnostics(policy_id, empty))
        .unwrap_or_default();
    let source_filtered_by_threat_model =
        empty_endpoints.is_some_and(|empty| empty.source_filtered_by_threat_model);
    let has_incomplete_refusal = refusals
        .iter()
        .any(|refusal| refusal.impact == PolicyDiagnosticImpact::RunIncomplete);
    let refusal_diagnostics = refusals
        .into_iter()
        .map(|refusal| {
            PolicyDiagnostic::new_bounded(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Warning,
                refusal.impact,
                refusal.message,
            )
        })
        .collect::<Vec<_>>();
    if !has_incomplete_refusal
        && incomplete_selectors.is_empty()
        && !source_filtered_by_threat_model
    {
        diagnostics.extend(refusal_diagnostics);
        return TaintProjectionPayload {
            engine: None,
            scope: None,
            projections: Vec::new(),
            completion: if authored_selector_summary {
                PolicyRunCompletion::ProvenBySummary
            } else {
                PolicyRunCompletion::Complete
            },
            diagnostics,
            diagnostics_truncated: false,
            work,
            authored_arm_closures: Vec::new(),
        };
    }
    let mut reasons = Vec::new();
    if has_incomplete_refusal {
        reasons.push(PolicyIncompleteReason::CapabilityIncomplete);
    }
    if !incomplete_selectors.is_empty() {
        reasons.push(PolicyIncompleteReason::PartialDiscovery);
    }
    if source_filtered_by_threat_model {
        reasons.push(PolicyIncompleteReason::CapabilityIncomplete);
    }
    let completion = PolicyRunCompletion::inconclusive(reasons)
        .expect("nonempty selector gaps have canonical reasons");
    diagnostics.extend(refusal_diagnostics);
    diagnostics.extend(incomplete_selectors.into_iter().map(|gap| {
        let diagnostic = PolicyDiagnostic::new_bounded(
            PolicyDiagnosticCode::EvaluationFailure,
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticImpact::RunIncomplete,
            gap.message,
        );
        if gap.discovery.is_empty() {
            return diagnostic;
        }
        let (codes, sites): (Vec<_>, Vec<_>) = gap
            .discovery
            .into_iter()
            .map(|(code, site)| (code.to_owned(), site))
            .unzip();
        diagnostic.with_selector_gap(PolicySelectorGapSummary::new(
            endpoint_label(&gap.path),
            codes,
            sites.into_iter().flatten(),
        ))
    }));
    TaintProjectionPayload {
        engine: None,
        scope: None,
        projections: Vec::new(),
        completion,
        diagnostics,
        diagnostics_truncated: false,
        work,
        authored_arm_closures: Vec::new(),
    }
}

/// The role and display name of the endpoint whose selector is `path`, such
/// as `source ServletRequest.getParameter(String)`. Auxiliary entries have no
/// display name and are named by their entry id.
fn selector_endpoint_label(spec: &ResolvedTaintPolicySpec, path: &PolicySelectorPath) -> String {
    let named = spec
        .sources
        .iter()
        .map(|source| {
            (
                "source",
                &source.definition.display_name,
                &source.definition.selector_path,
            )
        })
        .chain(spec.entry_points.iter().map(|entry| {
            (
                "entry point",
                &entry.definition.display_name,
                &entry.definition.selector_path,
            )
        }))
        .chain(spec.sinks.iter().map(|sink| {
            (
                "sink",
                &sink.definition.display_name,
                &sink.definition.selector_path,
            )
        }))
        .find(|(_, _, selector)| *selector == path)
        .map(|(role, name, _)| format!("{role} {name}"));
    let auxiliary = || {
        spec.sanitizers
            .iter()
            .map(|entry| ("sanitizer", &entry.identity, &entry.selector_path))
            .chain(
                spec.transforms
                    .iter()
                    .map(|entry| ("transform", &entry.identity, &entry.selector_path)),
            )
            .chain(
                spec.external_models
                    .iter()
                    .map(|entry| ("external model", &entry.identity, &entry.selector_path)),
            )
            .chain(
                spec.store_writes
                    .iter()
                    .map(|entry| ("store write", &entry.identity, &entry.selector_path)),
            )
            .chain(
                spec.store_reads
                    .iter()
                    .map(|entry| ("store read", &entry.identity, &entry.selector_path)),
            )
            .find(|(_, _, selector)| *selector == path)
            .map(|(role, identity, _)| {
                let id = match identity {
                    ResolvedEndpointIdentity::Local { entry_id, .. }
                    | ResolvedEndpointIdentity::Catalog { entry_id, .. } => entry_id.as_str(),
                    ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => endpoint_id.as_str(),
                };
                format!("{role} {id}")
            })
    };
    named
        .or_else(auxiliary)
        .unwrap_or_else(|| path.as_str().to_owned())
}

/// One advisory diagnostic per endpoint set that bound nothing (#2659).
///
/// The verdict stays `Complete` with zero findings, because zero findings over
/// an empty selection is the correct answer. What the run must not do is look
/// the same as a run that proved no flow between endpoints it actually found:
/// #2659 saw one policy's kernel selectors name `dfb_source`/`dfb_sink` in a
/// fixture that spells the methods differently, and the resulting clean report
/// was read as a contradiction of a genuine `reached` verdict from a policy
/// whose selectors matched. Both empty sets are named when both are empty.
///
/// The impact is `Advisory` and the severity `Note`: nothing about the run is
/// incomplete, so downgrading the completion would make an honest negative
/// unusable, which is the mistake
/// `production_taint_balanced_negative_completes_without_findings` pins.
fn empty_selection_diagnostics(
    policy_id: &PolicyId,
    empty: EmptyEndpointSets,
) -> Vec<PolicyDiagnostic> {
    let mut diagnostics = if empty.source_filtered_by_threat_model {
        vec![PolicyDiagnostic::new_bounded(
            PolicyDiagnosticCode::EvaluationFailure,
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticImpact::RunIncomplete,
            format!(
                "taint policy `{}` selected no active source after threat-model filtering",
                policy_id.as_str()
            ),
        )]
    } else {
        Vec::new()
    };
    diagnostics.extend(
        empty
            .named()
            .into_iter()
            .filter_map(|set| {
                PolicyDiagnostic::empty_selection(format!(
                    "taint policy `{}` bound no {set} endpoint: its {set} selectors matched no \
                 location in the scanned workspace, so this run reports zero findings \
                 vacuously rather than proving that no flow exists",
                    policy_id.as_str()
                ))
                .ok()
            })
            .collect::<Vec<_>>(),
    );
    diagnostics
}

/// Render one diagnostic per refused selector row, naming the file, the row's
/// byte range, and the distinct call ranges that tied. The complete tie set is
/// in the message so a corpus report says which site could not be named rather
/// than only that some site could not be.
fn refusal_messages(refused: &[RefusedCallSite]) -> Vec<RefusalNotice> {
    refused
        .iter()
        .map(|refusal| {
            // The message names a workspace-relative file, so it renders the
            // path with POSIX separators regardless of the host: a diagnostic
            // is a rendering boundary that needs a stable path spelling.
            let file = refusal.file.to_string().replace('\\', "/");
            let site = format!("{}:{}..{}", file, refusal.span.start, refusal.span.end);
            let message = match &refusal.reason {
                RefusalReason::AmbiguousCallSite(ranges) => format!(
                    "taint semantic binding refused one site: the selector row at {site} \
                     identifies {} distinct semantic call sites {ranges:?}, so it names no \
                     single call",
                    ranges.len(),
                ),
                RefusalReason::NoSemanticCallSite => format!(
                    "taint semantic binding refused one site: the selector row at {site} \
                     does not identify a semantic call site"
                ),
                RefusalReason::NoValueObservation => format!(
                    "taint semantic binding refused one site: the matched source row at {site} \
                     produced no point-sensitive value observation"
                ),
                RefusalReason::UnidentifiedFormal { name, detail } => format!(
                    "taint semantic binding refused one site: the port `(argument :name \
                     \"{name}\")` at {site} does not identify one actual there: {detail}"
                ),
                RefusalReason::MissingOperand {
                    port,
                    arguments,
                    lowering_gap,
                } => format!(
                    "taint semantic binding refused one site: the port `{port}` at {site} \
                     names no operand of the selected call, which has {arguments} argument(s); {}",
                    if *lowering_gap {
                        "the call's lowering leaves an unanswered gap at this site"
                    } else {
                        "the call's lowering records no unanswered operand gap"
                    }
                ),
            };
            RefusalNotice {
                message,
                impact: refusal.impact,
            }
        })
        .collect()
}

/// A missing operand is conclusive only when the selected semantic call and
/// its argument values have no lowering gap that could have dropped it.
fn missing_operand_has_lowering_gap(
    procedure: &ProcedureHandle,
    call: &brokk_bifrost_analysis::analyzer::semantic::SemanticCallSite,
) -> bool {
    let semantics = procedure.semantics();
    let abort_user_code = abort_paths_run_user_code(semantics);
    semantics.gaps().iter().any(|gap| {
        let relevant_subject = gap.point == call.point
            || call
                .arguments
                .iter()
                .any(|argument| gap.subject == SemanticGapSubject::Value(argument.value));
        relevant_subject
            && matches!(
                gap.capability,
                SemanticCapability::Values | SemanticCapability::Calls
            )
            && matches!(
                gap.kind,
                SemanticGapKind::Unknown | SemanticGapKind::Unsupported
            )
            && classify_gap_openness(semantics, gap, abort_user_code) == GapOpenness::Blocked
    })
}

/// Coordinator-owned production adapter.
///
/// Preparation compiles every runnable taint policy before partitioning its
/// plans. Each resulting [`TaintBatchPlanner`] batch is solved once and its
/// retained finding report is projected into every participating policy.
#[derive(Default)]
pub(crate) struct ProductionTaintPolicyEvaluator {
    prepared: Mutex<HashMap<PolicyId, TaintProjectionPayload>>,
    public_findings: Mutex<Vec<brokk_bifrost_rql::structural::CodeQueryTaintFinding>>,
    retained_analyses: Mutex<Vec<Arc<ProductionTaintAnalysisResult>>>,
}

struct TaintExecutionBudget {
    semantic: SemanticBudget,
    solver: SolverBudget,
    remaining_findings: usize,
    remaining_witnesses: usize,
    remaining_witness_steps: usize,
    remaining_witness_expansions: usize,
    remaining_witness_bytes: usize,
    attribution: TaintAttributionBudget,
}

/// The request-wide output lane one batch found already spent.
///
/// Findings and attribution work are request-wide. Evidence-retention lanes
/// are restored per batch (#2208), so they read zero only
/// when the configured budget itself is zero. Either way the lane is a budget,
/// not a broken invariant, so the run says which one ran out (#2356).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExhaustedTaintLane {
    Findings,
    Witnesses,
    WitnessSteps,
    WitnessExpansions,
    WitnessBytes,
}

impl ExhaustedTaintLane {
    const fn label(self) -> &'static str {
        match self {
            Self::Findings => "findings",
            Self::Witnesses => "witnesses",
            Self::WitnessSteps => "witness steps",
            Self::WitnessExpansions => "witness expansions",
            Self::WitnessBytes => "witness bytes",
        }
    }

    /// The findings lane caps how much output the request may produce, which is
    /// exactly `BatchFindingLimit`. A witness lane caps the evidence a report
    /// may retain for that output, which is `ReportRetentionBudget`.
    const fn incomplete_reason(self) -> PolicyIncompleteReason {
        match self {
            Self::Findings => PolicyIncompleteReason::BatchFindingLimit,
            Self::Witnesses | Self::WitnessSteps | Self::WitnessExpansions | Self::WitnessBytes => {
                PolicyIncompleteReason::ReportRetentionBudget
            }
        }
    }

    const fn diagnostic_code(self) -> PolicyDiagnosticCode {
        match self {
            Self::Findings => PolicyDiagnosticCode::BatchFindingLimit,
            Self::Witnesses | Self::WitnessSteps | Self::WitnessExpansions | Self::WitnessBytes => {
                PolicyDiagnosticCode::ReportRetentionBudget
            }
        }
    }
}

/// Why one taint batch produced nothing.
///
/// A drained request-wide lane and a broken invariant are different outcomes
/// and must not share a classification: the first degrades the run to
/// inconclusive and keeps every finding the earlier batches already produced,
/// the second fails the run.
#[derive(Debug)]
enum TaintBatchError {
    BudgetExhausted(ExhaustedTaintLane),
    RefinementTerminated(SolverTermination),
    Internal(String),
}

fn barrier_batch_error(error: brokk_bifrost_flow::taint::IcfgBarrierError) -> TaintBatchError {
    match error {
        brokk_bifrost_flow::taint::IcfgBarrierError::RetentionBudget { .. } => {
            TaintBatchError::BudgetExhausted(ExhaustedTaintLane::WitnessBytes)
        }
        brokk_bifrost_flow::taint::IcfgBarrierError::Terminated(termination) => {
            TaintBatchError::RefinementTerminated(termination)
        }
        error => TaintBatchError::Internal(error.to_string()),
    }
}

impl From<String> for TaintBatchError {
    fn from(message: String) -> Self {
        Self::Internal(message)
    }
}

impl TaintExecutionBudget {
    fn fresh_semantic(budget: &PolicyBudget) -> SemanticBudget {
        SemanticBudget::new(super::selector_compiler::semantic_resident_limits(
            budget.query_limits().semantic,
        ))
        .expect("validated policy semantic limits are positive")
    }

    fn fresh_solver(budget: &PolicyBudget) -> SolverBudget {
        SolverBudget::new(budget.query_limits().value_flow.solver_work)
    }

    fn new(budget: &PolicyBudget) -> Self {
        let limits = budget.query_limits();
        Self {
            semantic: Self::fresh_semantic(budget),
            solver: Self::fresh_solver(budget),
            remaining_findings: budget.max_findings(),
            remaining_witnesses: budget
                .max_findings()
                .saturating_mul(budget.max_witnesses_per_finding()),
            remaining_witness_steps: budget.max_witness_steps(),
            remaining_witness_expansions: limits.value_flow.max_witness_expansions,
            remaining_witness_bytes: budget.max_witness_bytes(),
            attribution: TaintAttributionBudget::new(
                budget.max_findings().saturating_mul(
                    limits
                        .value_flow
                        .max_witness_steps
                        .min(budget.max_witness_steps()),
                ),
                budget
                    .max_findings()
                    .saturating_mul(limits.value_flow.max_witness_expansions),
            ),
        }
    }

    /// Restore the witness-reconstruction lanes to their per-batch starting
    /// budget.
    ///
    /// Witness reconstruction is a per-batch concern: each solved batch rebuilds
    /// evidence only for its own findings. These lanes were threaded as one
    /// request-wide running total, so on a corpus the early batches drained them
    /// and every later batch failed the `solve_and_project_batch` pre-check and
    /// dropped its findings to `not_analyzed` by accumulation (#1935). Resetting
    /// per batch bounds each batch's evidence work on its own; the request-wide
    /// `remaining_findings` still caps total output, so the aggregate stays
    /// bounded. Evidence, not the finding, is what a depleted witness lane
    /// truncates, so this never turns an abstain into a false clean.
    fn reset_per_batch_witness_budget(&mut self, budget: &PolicyBudget) {
        let limits = budget.query_limits();
        self.remaining_witnesses = budget
            .max_findings()
            .saturating_mul(budget.max_witnesses_per_finding());
        self.remaining_witness_steps = budget.max_witness_steps();
        self.remaining_witness_expansions = limits.value_flow.max_witness_expansions;
        self.remaining_witness_bytes = budget.max_witness_bytes();
    }

    /// Restore the semantic-materialization and IFDS solver-work lanes to their
    /// per-batch starting budget.
    ///
    /// These two lanes pay for solving one batch: `semantic` charges the
    /// procedure/value/call-site rows materialized for the batch's regions, and
    /// `solver` charges the IFDS propagation that batch performs. Both are
    /// consumed only inside `solve_and_project_batch`, and each batch is an
    /// independent solve over its own regions, so a running request-wide total
    /// made them a queue-position lottery: on a corpus with many per-region
    /// batches the early batches drained both ledgers and later batches could
    /// not finish their solve, so a real flow in a late region abstained purely
    /// because of where it landed in the batch order (#2208). This is the same
    /// defect and the same remedy as the witness lanes above (#1935).
    ///
    /// `remaining_findings` is deliberately not reset here: it is the cap on
    /// total output, not per-batch work, so the aggregate stays bounded. A
    /// depleted solve lane truncates the solve, which makes require-model taint
    /// abstain rather than report clean, so resetting it can only turn an
    /// abstention into a decision; it can never turn an abstain into a false
    /// clean.
    fn reset_per_batch_solve_budget(&mut self, budget: &PolicyBudget) {
        // Scalar limits reset per batch; the artifact censuses already paid
        // carry over, so a shared artifact is charged once per compile.
        let census = self.semantic.scope_snapshot();
        self.semantic = SemanticBudget::new_child(
            super::selector_compiler::semantic_resident_limits(budget.query_limits().semantic),
            &census,
        );
        self.solver = Self::fresh_solver(budget);
    }
}

impl ProductionTaintPolicyEvaluator {
    pub(crate) fn prepare<'policy>(
        flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
        policies: impl IntoIterator<Item = &'policy LoadedPolicy>,
        workspace: &WorkspaceAnalyzer,
        active_semantic_model_snapshot: Result<Option<Arc<ActiveSemanticModelSnapshot>>, String>,
        cancellation: Option<&CancellationToken>,
        budget: &PolicyBudget,
    ) -> Self {
        let flow_state = flow_state.into();
        Self::prepare_in_range(
            &flow_state,
            policies,
            workspace,
            active_semantic_model_snapshot,
            cancellation,
            budget,
            None,
        )
    }

    /// [`Self::prepare`] for a run that names a changed range: sinks bind only
    /// in `changed`, and `None` binds every sink as `prepare` does.
    pub(crate) fn prepare_in_range<'policy>(
        flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
        policies: impl IntoIterator<Item = &'policy LoadedPolicy>,
        workspace: &WorkspaceAnalyzer,
        active_semantic_model_snapshot: Result<Option<Arc<ActiveSemanticModelSnapshot>>, String>,
        cancellation: Option<&CancellationToken>,
        budget: &PolicyBudget,
        changed: Option<&[PolicyChangedFile]>,
    ) -> Self {
        let flow_state = flow_state.into();
        let uncancelled = CancellationToken::default();
        let cancellation = cancellation.unwrap_or(&uncancelled);
        let policies = policies
            .into_iter()
            .filter(|policy| policy.resolved_taint().is_some())
            .collect::<Vec<_>>();
        let mut payloads = HashMap::with_capacity(policies.len());
        let mut metadata = HashMap::new();
        let mut plans: Vec<(TaintEngine, TaintPolicyPlan)> = Vec::new();
        let mut public_findings = Vec::new();
        let mut retained_analyses = Vec::new();
        let mut execution_budget = TaintExecutionBudget::new(budget);
        // Compilation and propagation are one semantic-model transaction.
        // Retain the exact Arc used to bind modeled summaries rather than
        // rereading analyzer activation when each batch starts its ICFG solve.
        let icfg_active_semantic_model_snapshot = active_semantic_model_snapshot
            .as_ref()
            .ok()
            .and_then(|snapshot| snapshot.as_ref().map(Arc::clone));
        // One ICFG provider serves every batch solve of this policy. Its
        // query-local cache keeps each file's exact dispatch session, so a
        // file is parsed once per policy compile rather than once per solve.
        let icfg_provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            workspace,
            icfg_active_semantic_model_snapshot.clone(),
        );

        for policy in &policies {
            let policy_id = policy.definition().metadata.id.clone();
            let spec = policy
                .resolved_taint()
                .expect("filtered policies retain resolved taint specifications");
            let compilation_started = Instant::now();
            let compilation = match &active_semantic_model_snapshot {
                Ok(snapshot) => TaintPolicyCompiler::new(
                    workspace,
                    &flow_state,
                    snapshot
                        .as_ref()
                        .map(|snapshot| Arc::clone(snapshot.active_models())),
                    budget.query_limits(),
                    budget.max_selector_results(),
                    cancellation,
                )
                .with_active_semantic_model_snapshot(snapshot.clone())
                .with_changed_files(changed)
                .compile(policy, spec),
                Err(message) => Err(Box::new(TaintPolicyCompileFailure {
                    error: TaintPolicyCompileError::Model(message.clone()),
                    work: PolicyWorkReport::default(),
                })),
            };
            let compilation_elapsed = compilation_started.elapsed();
            match compilation {
                Ok(TaintPolicyCompilation::Plans {
                    roots,
                    work,
                    refusals,
                    incomplete_selectors,
                    authored_selector_summary,
                    skipped_region_roots: _,
                }) => {
                    // Every root of one policy shares its engine: the rule
                    // reads the policy's bound endpoints, not one root's region.
                    let engine = roots
                        .first()
                        .map(|compiled| compiled.engine.clone())
                        .expect("a compiled taint policy has at least one root");
                    let scope = roots.first().and_then(|compiled| compiled.scope.clone());
                    brokk_bifrost_analysis::profiling::note_with(|| {
                        format!(
                            "taint.engine policy={} engine={} reason={}",
                            policy_id.as_str(),
                            engine.name(),
                            engine.reason().unwrap_or("-"),
                        )
                    });
                    let mut payload = compiled_payload(
                        &policy_id,
                        work,
                        refusals,
                        None,
                        authored_selector_summary,
                        incomplete_selectors,
                        |path| selector_endpoint_label(spec, path),
                    );
                    payload.engine = Some(engine.clone());
                    payload.scope = scope;
                    payloads.insert(policy_id.clone(), payload);
                    let sink_files = policy_sink_files(&roots);
                    for compiled in roots {
                        metadata.insert(
                            compiled.internal_policy_id.clone(),
                            PreparedTaintPlan {
                                policy_id: policy_id.clone(),
                                engine: compiled.engine.clone(),
                                sources: compiled.sources,
                                sinks: compiled.sinks,
                                store_writes: compiled.store_writes,
                                store_reads: compiled.store_reads,
                                call_resolution_evidence: compiled.call_resolution_evidence,
                                sanitizer_declines: compiled.sanitizer_declines,
                                external_models: compiled.external_models,
                                compilation_elapsed,
                                sink_files: Arc::clone(&sink_files),
                            },
                        );
                        plans.push((compiled.engine, compiled.plan));
                    }
                }
                Ok(TaintPolicyCompilation::Clean {
                    work,
                    refusals,
                    incomplete_selectors,
                    empty_endpoints,
                    engine,
                    scope,
                }) => {
                    let mut payload = compiled_payload(
                        &policy_id,
                        work,
                        refusals,
                        Some(empty_endpoints),
                        false,
                        incomplete_selectors,
                        |path| selector_endpoint_label(spec, path),
                    );
                    payload.engine = engine;
                    payload.scope = scope;
                    payloads.insert(policy_id, payload);
                }
                Err(failure) => {
                    payloads.insert(policy_id, prepared_compile_failure_payload(*failure));
                }
            }
        }

        let batch_planning_started = Instant::now();
        let batches = partition_taint_batches(plans);
        let batch_planning_elapsed = batch_planning_started.elapsed();
        let mut merge = BatchMerge::default();
        match batches {
            Ok(batches) => {
                // Persistence boundaries first: compute what each store read
                // establishes from the writes its channel may alias, across
                // batches, before any batch reports findings. An error here is
                // an evaluation failure for every policy, exactly like a batch
                // planning failure: the store semantics were declared and
                // could not be executed.
                let seeding_attribution_before = execution_budget.attribution.work();
                let seeding = match seed_store_channels(
                    &batches,
                    &metadata,
                    workspace,
                    cancellation,
                    budget,
                    &mut execution_budget,
                    &icfg_provider,
                    &mut payloads,
                    &mut merge,
                ) {
                    Ok(seeding) => seeding,
                    Err(error) => {
                        for (policy_id, payload) in &mut payloads {
                            let mut work = PolicyWorkReport::default();
                            record_attribution_work(
                                &mut work,
                                execution_budget
                                    .attribution
                                    .work()
                                    .since(seeding_attribution_before),
                            )
                            .expect("five attribution counters fit a failed policy work report");
                            *payload = prepared_failure_payload(
                                &format!("taint store seeding failed: {error}"),
                                work,
                            );
                            record_missing_origin_loss(
                                payload,
                                merge.missing_origins.get(policy_id).copied().unwrap_or(0),
                            )
                            .expect("an aggregate source-origin loss is a valid diagnostic");
                        }
                        return Self {
                            prepared: Mutex::new(payloads),
                            public_findings: Mutex::new(public_findings),
                            retained_analyses: Mutex::new(retained_analyses),
                        };
                    }
                };
                // A store-read origin's compiled metadata rows over-approximate
                // (one row per policy source). Narrow each read event's rows to
                // the endpoints that actually contributed classes, so a finding
                // fed across the boundary attributes to real provenance only.
                for (batch_index, batch) in batches.iter().enumerate() {
                    let read_events = batch
                        .analysis()
                        .store_reads()
                        .iter()
                        .filter_map(|read| {
                            batch
                                .analysis()
                                .value_flow()
                                .source(read.source())
                                .map(|spec| (spec.key().clone(), read.source()))
                        })
                        .collect::<Vec<_>>();
                    if read_events.is_empty() {
                        continue;
                    }
                    for internal in batch.policy_ids() {
                        let Some(plan) = metadata.get_mut(internal) else {
                            continue;
                        };
                        let sources = std::mem::take(&mut plan.sources);
                        plan.sources = sources
                            .into_vec()
                            .into_iter()
                            .filter(|row| {
                                let Some((_, source)) =
                                    read_events.iter().find(|(event, _)| *event == row.event)
                                else {
                                    return true;
                                };
                                seeding.seeds[batch_index].iter().any(|seed| {
                                    seed.source == *source
                                        && seed.contributors.contains(&row.endpoint)
                                })
                            })
                            .collect();
                    }
                }
                let store_write_evidence = seeding.write_evidence_by_read(&batches);
                let composition_memo = CompositionMemo::default();
                for (batch_index, batch) in batches.into_iter().enumerate() {
                    let seeds = seeding.seeds[batch_index]
                        .iter()
                        .map(|seed| (seed.source, seed.classes.clone()))
                        .collect::<Vec<_>>();
                    let batch = if seeds.is_empty() {
                        batch
                    } else {
                        match batch.with_seeded_store_reads(&seeds) {
                            Ok(seeded) => seeded,
                            Err(error) => {
                                for internal_id in batch.policy_ids() {
                                    if let Some(plan) = metadata.get(internal_id) {
                                        merge.envelopes.remove(&plan.policy_id);
                                        payloads.insert(
                                            plan.policy_id.clone(),
                                            prepared_failure_payload(
                                                &format!("taint store seeding failed: {error}"),
                                                PolicyWorkReport::default(),
                                            ),
                                        );
                                    }
                                }
                                continue;
                            }
                        }
                    };
                    // A store-fed batch whose seed provenance is uncertain
                    // (an observation solve stayed incomplete) must not
                    // report a complete verdict: a missing class could hide a
                    // real flow behind a clean read.
                    let store_fed_uncertain =
                        seeding.uncertain && !batch.analysis().store_reads().is_empty();
                    let attribution_before = execution_budget.attribution.work();
                    let Err(failure) = solve_and_project_batch(
                        &batch,
                        &flow_state,
                        &seeding.seeds[batch_index],
                        &metadata,
                        &policies,
                        &mut payloads,
                        &mut merge,
                        workspace,
                        cancellation,
                        budget,
                        &mut execution_budget,
                        &mut public_findings,
                        &mut retained_analyses,
                        batch_planning_elapsed,
                        icfg_active_semantic_model_snapshot.clone(),
                        &icfg_provider,
                        &store_write_evidence,
                        &composition_memo,
                    ) else {
                        if store_fed_uncertain {
                            for internal_id in batch.policy_ids() {
                                let Some(plan) = metadata.get(internal_id) else {
                                    continue;
                                };
                                if let Some(payload) = payloads.get_mut(&plan.policy_id) {
                                    downgrade_for_uncertain_store_seed(payload);
                                }
                            }
                        }
                        continue;
                    };
                    let mut failed_policy_ids = HashSet::new();
                    for internal_id in batch.policy_ids() {
                        let Some(plan) = metadata.get(internal_id) else {
                            continue;
                        };
                        if !failed_policy_ids.insert(plan.policy_id.clone()) {
                            continue;
                        }
                        match &failure {
                            // A spent output or evidence lane leaves everything
                            // the earlier batches already produced valid, so the
                            // payload keeps its projections and only says that
                            // it stopped early and which lane stopped it.
                            TaintBatchError::BudgetExhausted(lane) => {
                                if let Some(payload) = payloads.get_mut(&plan.policy_id) {
                                    record_exhausted_lane(payload, *lane);
                                }
                            }
                            TaintBatchError::RefinementTerminated(termination) => {
                                if let Some(payload) = payloads.get_mut(&plan.policy_id) {
                                    record_refinement_termination(payload, *termination);
                                }
                            }
                            TaintBatchError::Internal(message) => {
                                merge.envelopes.remove(&plan.policy_id);
                                payloads.insert(
                                    plan.policy_id.clone(),
                                    prepared_failure_payload(message, PolicyWorkReport::default()),
                                );
                            }
                        }
                        if let Some(payload) = payloads.get_mut(&plan.policy_id) {
                            record_attribution_work(
                                &mut payload.work,
                                execution_budget
                                    .attribution
                                    .work()
                                    .since(attribution_before),
                            )
                            .expect("five attribution counters fit a failed policy work report");
                        }
                    }
                }
            }
            Err(error) => {
                for payload in payloads.values_mut() {
                    *payload = prepared_failure_payload(
                        &format!("taint batch planning failed: {error}"),
                        PolicyWorkReport::default(),
                    );
                }
            }
        }

        for (policy_id, &missing) in &merge.missing_origins {
            if let Some(payload) = payloads.get_mut(policy_id) {
                record_missing_origin_loss(payload, missing)
                    .expect("an aggregate source-origin loss is a valid diagnostic");
            }
        }

        for payload in payloads.values_mut() {
            if !matches!(
                payload.completion,
                PolicyRunCompletion::Complete | PolicyRunCompletion::ProvenBySummary
            ) {
                payload.diagnostics.retain(|diagnostic| {
                    diagnostic.impact() != PolicyDiagnosticImpact::FindingPartial
                });
            }
        }

        Self {
            prepared: Mutex::new(payloads),
            public_findings: Mutex::new(public_findings),
            retained_analyses: Mutex::new(retained_analyses),
        }
    }

    pub(crate) fn take_public_findings(
        &self,
    ) -> Vec<brokk_bifrost_rql::structural::CodeQueryTaintFinding> {
        std::mem::take(
            &mut *self
                .public_findings
                .lock()
                .expect("taint public findings mutex poisoned"),
        )
    }

    pub(crate) fn take_retained_analyses(&self) -> Vec<Arc<ProductionTaintAnalysisResult>> {
        std::mem::take(
            &mut *self
                .retained_analyses
                .lock()
                .expect("taint retained analyses mutex poisoned"),
        )
    }
}

impl super::projection::sealed::TaintAdapter for ProductionTaintPolicyEvaluator {}

impl TaintPolicyEvaluator for ProductionTaintPolicyEvaluator {
    fn evaluate_taint(
        &self,
        _authority: &TaintProjectionAuthority<'_>,
        policy: &LoadedPolicy,
        _spec: &ResolvedTaintPolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> TaintProjectionPayload {
        self.prepared
            .lock()
            .expect("taint prepared payloads mutex poisoned")
            .remove(&policy.definition().metadata.id)
            .unwrap_or_else(|| {
                prepared_failure_payload(
                    "taint policy was not prepared by the policy coordinator",
                    PolicyWorkReport::default(),
                )
            })
    }
}

pub(crate) struct TaintPolicyCompiler<'a> {
    selectors: super::selector_compiler::PolicySelectorSession<'a>,
    /// The immutable activation used by selector semantic rows. Matched-value
    /// keyed reads must revalidate against this same snapshot before entering
    /// the value-flow plan.
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    active_semantic_models: Option<Arc<ResolvedActiveSemanticModels>>,
    /// Selector rows this compile refused to bind because they named no
    /// semantic call or value observation, named ambiguous calls, or lacked
    /// an operand identified by the requested port. Kept per row rather than raised
    /// as a compile failure so one unresolvable row costs its own sites and not
    /// the whole run (#2308).
    refused_sites: Vec<RefusedCallSite>,
    /// Per (selector, formal name), the source spans of the actuals the
    /// analyzer's structural actual-to-formal relation bound to that formal.
    /// It is consulted only where the oracle relation retains no mapping, and
    /// computed once per pair because it costs one extra selector scan.
    named_actuals: HashMap<(PolicySelectorPath, String), NamedActualSpans>,
    /// How many source and sink endpoint locations the compile bound, reported
    /// on every taint run so a raw report says what the policy's endpoint
    /// selectors actually matched in this workspace (#2659).
    bound_endpoints: BoundEndpointCounts,
    store_key_metrics: StoreKeyMetrics,
    /// Whether an endpoint was selected through an authored override contract.
    /// This caps a clean result; it never upgrades an incomplete solve.
    authored_selector_summary: bool,
    /// Analysis roots whose discovery outgrew its per-region budget and were
    /// skipped (#1936). An ordinary run reports the endpoints they held as
    /// unanalyzed files; a flow candidate (#3686) reads the count so that "no
    /// region connects these sites" is never claimed over a skipped region.
    skipped_region_roots: usize,
    /// The two positions a flow candidate asks about (#3686). Only a
    /// candidate pass sets it. Endpoint sites are recorded before regions are
    /// formed, because a site no region pairs with a partner is still bound.
    candidate_probe: Option<&'a mut candidate::CandidateProbe>,
    /// The files a changed-range run binds sinks in. `None` for a
    /// whole-workspace run, which binds every sink.
    changed_files: Option<&'a [PolicyChangedFile]>,
    /// One note per sink selector that could not be sliced to the changed
    /// files and bound the whole workspace instead.
    range_widened: Vec<String>,
    examined_procedures: Vec<PolicySourceLocation>,
    /// How a matched-value port resolves to endpoints: from points-to
    /// observations for the up-front compile, from file-local observations
    /// for the composition's frontier (see `FrontierEndpointBinder::new`).
    matched_values: MatchedValueResolver<'a>,
}

/// A resolver of one selected row's matched value to taint values.
type MatchedValueResolver<'a> = fn(
    &mut TaintPolicyCompiler<'a>,
    SelectedSite,
) -> Result<Vec<ResolvedTaintValue>, TaintPolicyCompileError>;

/// The number of endpoint locations one taint compile bound, per endpoint set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct BoundEndpointCounts {
    sources: usize,
    sinks: usize,
}

/// Counts refer to declared key operands, including reads and writes. They
/// expose the precision opportunity without interpreting a missing finding
/// as proof that a previous finding was a false positive.
#[derive(Debug, Default)]
struct StoreKeyMetrics {
    operands: u64,
    direct_literals: u64,
    recovered: u64,
    unproven: u64,
    budget_hits: u64,
    work: u64,
}

/// Which endpoint set(s) of one taint policy bound no location at all (#2659).
///
/// A policy whose source or sink selectors match nothing compiles to an empty
/// relation, and the solve over it is vacuously clean. The verdict is honest --
/// there is no flow, because there is no endpoint -- but it is indistinguishable
/// from a proven-clean run unless the report says the selection was empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmptyEndpointSets {
    sources: bool,
    sinks: bool,
    source_filtered_by_threat_model: bool,
}

impl EmptyEndpointSets {
    const fn any(self) -> bool {
        self.sources || self.sinks
    }

    /// Whether this empty selection proves that no flow exists, so the
    /// selector gaps in `gaps` cannot change the verdict.
    ///
    /// A finding needs a bound source and a bound sink. A side that bound
    /// nothing while every one of its own selectors finished has nothing to
    /// pair with, so a gap anywhere else (the other side, a sanitizer, a
    /// transform or a model) could only add sites that reach no flow. A side
    /// that is empty because its own selector did not finish proves nothing.
    /// Refused rows are not selector gaps; they still make the run incomplete.
    fn proves_no_flow(
        self,
        spec: &ResolvedTaintPolicySpec,
        gaps: &[IncompleteTaintSelector],
    ) -> bool {
        let has_gap = |path: &PolicySelectorPath| gaps.iter().any(|gap| &gap.path == path);
        let sources_proven_empty = self.sources
            && !spec
                .sources
                .iter()
                .chain(&spec.entry_points)
                .any(|source| has_gap(&source.definition.selector_path));
        let sinks_proven_empty = self.sinks
            && !spec
                .sinks
                .iter()
                .any(|sink| has_gap(&sink.definition.selector_path));
        sources_proven_empty || sinks_proven_empty
    }

    /// Every empty set, source before sink. Both are named when both are
    /// empty: a reader repairing the policy needs the complete list, not the
    /// first mistake the compiler happened to notice.
    fn named(self) -> Vec<&'static str> {
        let mut sets = Vec::new();
        if self.sources {
            sets.push("source");
        }
        if self.sinks {
            sets.push("sink");
        }
        sets
    }
}

pub(crate) type SelectedSite = super::selector_compiler::PolicySelectedSite;

fn threat_model_source_is_active(
    source: &ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>,
    active_models: &[TaintThreatModel],
) -> bool {
    source
        .definition
        .threat_model
        .is_none_or(|model| active_models.contains(&model))
}

/// One callee's formal parameter names, in declaration order. A slot holds
/// every spelling its declaration gives one parameter.
type FormalSlotNames = Arc<[Box<[String]>]>;

/// The source spans of the actuals one selector binds to one formal name.
type NamedActualSpans = Arc<[(ProjectFile, ByteRange<usize>)]>;

/// One selector row that binding refused, with the reason it refused.
struct RefusedCallSite {
    file: ProjectFile,
    /// The selector row's own byte range.
    span: ByteRange<usize>,
    reason: RefusalReason,
    impact: PolicyDiagnosticImpact,
    /// Every procedure that holds a candidate for the refused row. A region
    /// containing none of these cannot contain the refused site.
    procedures: Vec<DurableProcedureKey>,
}

/// A refusal's rendered explanation and its effect on run completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefusalNotice {
    pub(crate) message: String,
    pub(crate) impact: PolicyDiagnosticImpact,
}

/// What `(argument :name ...)` resolved to at one semantic call site.
enum NamedArgumentResolution {
    Bound(NamedArgumentBinding),
    /// The evidence did not identify one actual. The endpoint is refused with
    /// this reason rather than dropped, so the run reports a capability gap.
    Unidentified(String),
}

/// One actual identified by formal name, with the quality of the evidence that
/// identified it. The quality is conjoined into the endpoint exactly like the
/// selector row's own proof and completeness, so a name resolved through an
/// unproven dispatch degrades the endpoint instead of overstating it.
struct NamedArgumentBinding {
    index: u32,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

/// Why one selector row did not become a bound endpoint.
enum RefusalReason {
    /// The row's best-matching candidates name more than one distinct source
    /// call site, so it names no single call (#2308). Carries the tied ranges.
    AmbiguousCallSite(Vec<ByteRange<usize>>),
    /// The selected row has no semantic call to bind (#4919).
    NoSemanticCallSite,
    /// The selected value has no observation at a program point (#4919).
    NoValueObservation,
    /// A `(argument :name ...)` port did not identify exactly one actual at the
    /// selected call, because the callee is unresolved, because the retained
    /// argument binding is open, or because two dispatch candidates map the
    /// formal to different actuals (#2496).
    UnidentifiedFormal { name: String, detail: String },
    /// The selected call has no operand at the declared port: an argument
    /// index past its argument count, or a receiver port on a call without a
    /// receiver. The selector matched a site the port cannot name, so the
    /// site is refused instead of failing the whole compile. Carries the port
    /// as written and the call's argument count.
    MissingOperand {
        port: String,
        arguments: usize,
        lowering_gap: bool,
    },
}

#[derive(Clone)]
pub(crate) struct BoundEndpoint {
    endpoint: ResolvedEndpointIdentity,
    kind: TaintEndpointKind,
    point: ProgramPointHandle,
    /// The phase of `point` at which the bound carrier holds the observed
    /// value. A value the point itself defines holds only after that point's
    /// effects, and the solver strong-updates an assignment target, so an
    /// endpoint observed before the effects of its own defining assignment
    /// would be killed by that assignment.
    phase: ValueFlowObservationPhase,
    carrier: ValueFlowCarrier,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    labels: Box<[TaintLabel]>,
    dispatch_obligations: Box<[CallSiteHandle]>,
    /// The selected row whose evidence the composition's frontier left
    /// unjudged (see [`ResolvedTaintValue::unjudged`]); `None` for every
    /// endpoint the ICFG engine binds.
    unjudged: Option<Arc<SelectedSite>>,
}

/// One sanitizer endpoint pair bound to the same selected call site. The
/// input and output are retained separately so a sanitizer cannot accidentally
/// clear a value from a different operand merely because it produces a result.
#[derive(Clone)]
pub(crate) struct BoundSanitizer {
    input: BoundEndpoint,
    output: BoundEndpoint,
}

/// One policy-local transform bound to an exact selected call. The carrier
/// relation and its evidence live in value flow; the label sets are retained
/// here until the taint function can be built against the region's universe.
#[derive(Clone)]
pub(crate) struct BoundTransform {
    input: BoundEndpoint,
    output: BoundEndpoint,
    removes: Box<[TaintLabel]>,
    adds: Box<[TaintLabel]>,
}

/// One persistence-store write or read end bound to a selected call site: the
/// value carrier that crosses the boundary plus the resolved runtime channel
/// identity linking the two ends. The `endpoint` labels stay empty; the
/// classes a read establishes are computed at evaluation time from the writes
/// its channel may alias.
#[derive(Clone)]
struct BoundStoreEnd {
    endpoint: BoundEndpoint,
    channel: TaintStoreChannel,
    /// The selected call. The declaration models this call's whole value
    /// behavior -- nothing flows through it directly; taint crosses only via
    /// the declared boundary -- so the call receives an empty-transfer
    /// curated model and stops blocking completeness when its own dispatch
    /// cannot be resolved.
    call: CallSiteHandle,
}

/// One policy-declared external model bound to one exact selected call site
/// (#2691).
///
/// The declaration replaces the selected call's analyzed body: discovery does
/// not bind the callee for a modeled call, and the declared transfers run on
/// the caller-side continuation edge as a curated call model. Selection and
/// per-port resolution quality is retained so an unproven or partial
/// declaration degrades the run instead of overstating itself.
#[derive(Clone)]
pub(crate) struct BoundExternalModel {
    /// The declaring entry's stable identity, used for the curated model id
    /// and for deterministic merging when several entries select one call.
    entry: ResolvedEndpointIdentity,
    pub(crate) call: CallSiteHandle,
    transfers: Vec<LoweredModelTransfer>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

/// The declared identity of one field write destination, resolved to a
/// concrete carrier against the finished value-flow plan (#2691): the plan's
/// carrier set is the closed universe of observable locations, so a write
/// whose field no reachable carrier names is a complete no-op, exactly one
/// matching carrier binds the heap port, and several (aliasing disagreement)
/// leave the port unbound so the run degrades instead of guessing.
#[derive(Clone)]
struct ModelFieldDestination {
    name: String,
    /// Caller value ids the written object is known as, from the caller's own
    /// value-copy relations (the argument slot holds a copy of the variable).
    base_values: Vec<brokk_bifrost_analysis::analyzer::semantic::ValueId>,
}

/// One declared transfer after per-call resolution: formal-name argument
/// ports are index-resolved and each port is mapped to the engine's stable
/// summary-port vocabulary. The effect is reduced to the labels the transfer
/// moves and the labels it removes at the seam; the universe complement of
/// the moved set is removed as well when the curated model is built, so a
/// transfer only ever carries its declared labels.
#[derive(Clone)]
struct LoweredModelTransfer {
    from: SummaryPort,
    to: SummaryPort,
    labels: Vec<TaintLabel>,
    removes: Vec<TaintLabel>,
    /// Present exactly when `to` is a field-destination heap port.
    field: Option<ModelFieldDestination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TaintEndpointKind {
    Argument,
    Receiver,
    ReturnValue,
    ConstructorResult,
    LiteralValue,
    MatchedValue,
    Parameter,
}

struct ResolvedTaintValue {
    call: Option<CallSiteHandle>,
    kind: TaintEndpointKind,
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
    carrier: ValueFlowCarrier,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    dispatch_obligations: Box<[CallSiteHandle]>,
    /// Set by the frontier's matched-value resolver for every value it resolves: the
    /// row whose points-to evidence it did not ask for. A source bound from
    /// it carries unknown evidence, judged later from this row (see
    /// [`FrontierEndpointBinder::source_evidence`]). A sanitizer or transform
    /// drops it.
    unjudged: Option<Arc<SelectedSite>>,
}

fn resolved_entry_parameter_value(
    procedure: &ProcedureHandle,
    port: ProcedurePortHandle,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
) -> ResolvedTaintValue {
    let point = procedure
        .point_handle(procedure.semantics().entry_point())
        .expect("validated semantic procedure has its entry point");
    ResolvedTaintValue {
        call: None,
        kind: TaintEndpointKind::Parameter,
        dispatch_obligations: Box::new([]),
        point,
        // Formal parameters are available at entry before local effects.
        phase: ValueFlowObservationPhase::BeforeEffects,
        carrier: ValueFlowCarrier::Port(port),
        proof,
        completeness,
        unjudged: None,
    }
}

struct ResolvedTransferValues {
    input: ResolvedTaintValue,
    output: ResolvedTaintValue,
}

/// The durable identity of one procedure: its owning artifact's validity key
/// and the procedure's dense ID, exactly what `ProcedureHandle::durable_key`
/// returns (#2286).
///
/// A `ProcedureHandle` compares and hashes its owning `Arc<SemanticArtifact>`
/// by pointer, which is right at a provider or oracle boundary and wrong for a
/// compile-scoped memo: the byte-bounded complete-artifact cache can evict a
/// file that a later call resolution re-materializes, and the two handles for
/// one procedure are then unequal. `SemanticArtifactKey` pins the mount, path,
/// language, source revision, adapter semantics version, IR version,
/// configuration, and dependencies, and the dense ID is stable beneath it.
type DurableProcedureKey = (
    SemanticArtifactKey,
    brokk_bifrost_analysis::analyzer::semantic::ProcedureId,
);

/// The durable identity of one call site: its owning procedure's durable key
/// and the caller-local call-site ID.
///
/// `CallSiteId` indexes `ProcedureSemantics::call_sites`, so it is unique only
/// inside one procedure; the procedure's durable key is the scope that makes
/// the pair unique. This is what `CallSiteHandle::durable_key` returns.
type DurableCallSiteKey = (
    DurableProcedureKey,
    brokk_bifrost_analysis::analyzer::semantic::CallSiteId,
);

struct DiscoveredValueFlow {
    root: ProcedureHandle,
    snapshots: Vec<ValueFlowInput<brokk_bifrost_analysis::analyzer::semantic::ValueFlowSnapshot>>,
    bindings: Vec<ValueFlowInput<brokk_bifrost_analysis::analyzer::semantic::CallBindings>>,
    /// Proven returned-callable associations the walk's dispatch answers
    /// published, keyed durably and deduplicated. The plan keeps each
    /// closure's captured environment connected across the call that
    /// returned it (#3470).
    returned_callables: Vec<ValueFlowReturnedCallable>,
    /// Query-local Rust formatting macro calls whose exact standard identity
    /// was proved by ordinary dispatch. They receive the language intrinsic
    /// result-transfer model below, independent of active semantic packs.
    rust_format_result_calls: Vec<(CallSiteHandle, ResolverOwnedExternalCalleeIdentity)>,
    /// Region membership, by durable procedure identity rather than by handle.
    /// A selected source or sink is tested against this set, and its handle can
    /// come from a different materialization than the walk's, so handle
    /// equality would silently drop a region that really does contain the
    /// endpoint (#2289).
    procedures: HashSet<DurableProcedureKey>,
    external_targets: Vec<ExactExternalProcedureTarget>,
    /// Canonical identities of fully-qualified external callees that never
    /// materialize to an artifact, kept separate from `external_targets` so the
    /// materialized-external binding path is unchanged (#1978).
    unmaterialized_external_targets: Vec<UnmaterializedExternalTarget>,
    call_coverage: HashMap<DurableCallSiteKey, CallSiteCoverage>,
    dispatch_boundaries: Vec<DispatchBoundary>,
}

pub(crate) struct CallResolutionDiscoveryEvidence {
    pub(crate) coverage: HashMap<DurableCallSiteKey, CallSiteCoverage>,
    pub(crate) boundaries: Vec<DispatchBoundary>,
}

/// The reason `select_taint_engine` gives when no sink was bound.
const NO_SINKS_REASON: &str = "no-sinks";

/// Query-local changed files and their head-buffer hunks. An explicit file
/// request has no hunk restriction; a diff request always has hunks.
pub(crate) struct PolicyChangedFile {
    pub(crate) file: ProjectFile,
    pub(crate) hunks: Option<Vec<ByteRange<usize>>>,
}

impl PolicyChangedFile {
    fn overlaps(&self, procedure: &ByteRange<usize>) -> bool {
        self.hunks.as_ref().is_none_or(|hunks| {
            hunks.iter().any(|hunk| {
                if hunk.is_empty() {
                    // A pure deletion affects the procedure only at an interior
                    // head position, not a neighboring declaration or module gap.
                    procedure.start < hunk.start && hunk.start < procedure.end
                } else {
                    procedure.start < hunk.end && hunk.start < procedure.end
                }
            })
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
thread_local! { static FORCE_ICFG_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

/// Exercise production ICFG binding and solving without process-global state.
#[cfg(any(test, feature = "test-support"))]
pub fn with_icfg_taint_engine_for_test<T>(run: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            FORCE_ICFG_FOR_TEST.set(self.0);
        }
    }
    let restore = Restore(FORCE_ICFG_FOR_TEST.replace(true));
    let result = run();
    drop(restore);
    result
}

/// Choose the engine of one compiled taint policy. The rule
/// reads the specification and the bound sinks, and the first failing
/// condition in this order is the reason. The order is fixed: conditional sanitizers, store ends,
/// entry points, activation-triggered sources, a flow-candidate pass, the
/// language of every sink, the rows of every sink's blob, then the sink
/// requirement.
///
/// Sources, sanitizers and transforms are not bound before the rule runs:
/// the composition matches them on the frontier, and a match in a blob
/// without rows makes that hop incomplete as any procedure without rows
/// does. A flow-candidate pass needs every source site bound before its
/// regions are chosen, so it keeps the ICFG engine.
fn select_taint_engine(
    workspace: &WorkspaceAnalyzer,
    spec: &ResolvedTaintPolicySpec,
    sinks: &[BoundEndpoint],
    flow_candidate: bool,
) -> Result<TaintEngine, TaintPolicyCompileError> {
    let icfg = |reason: &str| TaintEngine::Icfg {
        reason: reason.into(),
    };
    if spec.sanitizers.iter().any(|entry| {
        matches!(
            entry.definition.kind,
            TaintSanitizerKind::Conditional { .. }
        )
    }) {
        return Ok(icfg("conditional-sanitizers"));
    }
    if !spec.store_writes.is_empty() || !spec.store_reads.is_empty() {
        return Ok(icfg("store-ends"));
    }
    if !spec.entry_points.is_empty() {
        return Ok(icfg("entry-points"));
    }
    // The taint specification has no syntax for an activation trigger, so no
    // source is activation-triggered here. The reason stays in the closed set
    // for a trigger form that the specification may gain.
    if flow_candidate {
        return Ok(icfg("flow-candidate"));
    }
    let mut artifacts = Vec::new();
    let mut seen = HashSet::new();
    for sink in sinks {
        let key = sink.point.procedure().artifact().key();
        if seen.insert(key) {
            artifacts.push(key);
        }
    }
    for key in &artifacts {
        if key.language() != SemanticLanguage::Standard(Language::Rust) {
            return Ok(icfg(&format!("language:{}", key.language().stable_label())));
        }
    }
    for key in &artifacts {
        let rows = workspace
            .has_complete_semantic_ir_rows(key)
            .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?;
        if !rows {
            return Ok(icfg(&format!("no-rows:{}", key.path())));
        }
    }
    if sinks.is_empty() {
        return Ok(icfg(NO_SINKS_REASON));
    }
    #[cfg(any(test, feature = "test-support"))]
    if FORCE_ICFG_FOR_TEST.get() {
        return Ok(icfg("test override"));
    }
    Ok(TaintEngine::Composition)
}

/// Group compiled plans into batches, one engine per batch. The
/// planner keys batches on propagation semantics, which do not name the
/// engine, so the split happens before it.
fn partition_taint_batches(
    plans: Vec<(TaintEngine, TaintPolicyPlan)>,
) -> Result<Vec<TaintBatch>, TaintPlanError> {
    let (composed, icfg): (Vec<_>, Vec<_>) = plans
        .into_iter()
        .partition(|(engine, _)| *engine == TaintEngine::Composition);
    let mut batches =
        TaintBatchPlanner::partition(icfg.into_iter().map(|(_, plan)| plan).collect())?;
    batches.extend(TaintBatchPlanner::partition(
        composed.into_iter().map(|(_, plan)| plan).collect(),
    )?);
    Ok(batches)
}

/// The status a value-flow cause prints. An unsupported input names the
/// missing capability, so a corpus abstention report says which value-flow
/// capability the procedure lacked rather than a bare "unsupported".
fn cause_status_label(cause: &ValueFlowIncompleteCause) -> String {
    match cause.status() {
        Some(status @ SemanticInputStatus::Unsupported { capability }) => {
            format!("{} ({})", status.label(), capability.label())
        }
        Some(status) => status.label().to_owned(),
        None => "incomplete coverage".to_owned(),
    }
}

/// The dotted declaration name of a cause's procedure.
fn cause_procedure_name(cause: &ValueFlowIncompleteCause) -> String {
    cause
        .procedure()
        .semantics()
        .locator()
        .declaration()
        .segments()
        .iter()
        .filter_map(|segment| segment.name())
        .collect::<Vec<_>>()
        .join(".")
}

/// The family and message of a value-flow cause that names no call site: its
/// procedure's semantics are incomplete. The ICFG engine's first cause and the
/// composition's blocked gap both print this text, so both engines name the
/// same family and message.
fn procedure_cause_text(cause: &ValueFlowIncompleteCause, status: &str) -> (String, String) {
    let family = format!(
        "taint discovery is incomplete: {} is {status}",
        cause.label()
    );
    let message = format!(
        "taint discovery is incomplete: {} for {}:{} is {status}",
        cause.label(),
        cause.procedure().semantics().locator().path().as_str(),
        cause_procedure_name(cause),
    );
    (family, message)
}

/// Render a plan cause identically for incomplete runs and partial findings.
fn value_flow_cause_text(
    cause: &ValueFlowIncompleteCause,
    plan: &PreparedTaintPlan,
    metadata: &HashMap<String, PreparedTaintPlan>,
    workspace: &WorkspaceAnalyzer,
) -> Result<(String, String, Option<PolicySourceLocation>), String> {
    let name = cause_procedure_name(cause);
    let status = cause_status_label(cause);
    let (generic_family, generic_detail) = procedure_cause_text(cause, &status);
    let call_resolution_evidence = match cause {
        ValueFlowIncompleteCause::CallResolution { call, .. } => {
            let key = call.durable_key();
            plan.call_resolution_evidence
                .as_ref()
                .filter(|evidence| evidence.call == key)
                .or_else(|| {
                    metadata.values().find_map(|candidate| {
                        candidate
                            .call_resolution_evidence
                            .as_ref()
                            .filter(|evidence| evidence.call == key)
                    })
                })
        }
        _ => None,
    };
    let rust_call_site = match cause {
        ValueFlowIncompleteCause::CallResolution { call, .. }
        | ValueFlowIncompleteCause::CallBinding { call, .. }
        | ValueFlowIncompleteCause::CallBindingCoverage { call, .. } => is_rust_taint_call(call),
        _ => false,
    };
    let family =
        if rust_call_site && matches!(cause, ValueFlowIncompleteCause::CallResolution { .. }) {
            CALL_SITE_EVIDENCE_FAMILY.to_owned()
        } else {
            generic_family
        };
    let (primary, detail) = match cause {
        ValueFlowIncompleteCause::CallResolution { call, .. } => {
            if let Some(evidence) = call_resolution_evidence.filter(|_| rust_call_site) {
                (
                    Some(evidence.location.clone()),
                    call_resolution_detail(evidence),
                )
            } else if rust_call_site {
                let locator = super::semantic_identity::call_site_locator(call);
                (
                    Some(super::semantic_identity::policy_location(
                        workspace, locator,
                    )?),
                    format!(
                        "taint discovery is incomplete at call site {} bytes {}..{}; snapshot input status is {status}; resolver boundary status is unavailable",
                        locator.path().as_str(),
                        locator.anchor().span().start_byte(),
                        locator.anchor().span().end_byte(),
                    ),
                )
            } else {
                let locator = super::semantic_identity::call_site_locator(call);
                (
                    Some(super::semantic_identity::policy_location(
                        workspace, locator,
                    )?),
                    format!(
                        "taint discovery is incomplete: {} for {}:{name} is {status}; this exact call has neither a completely resolved executable target nor an applicable complete external model{}",
                        cause.label(),
                        locator.path().as_str(),
                        // The definition-lookup status and diagnostic kinds in
                        // the resolver arms name why the call stayed
                        // unresolved (#4823).
                        call_resolution_evidence
                            .map(|evidence| format!(
                                "; {}",
                                call_resolution_evidence_text(evidence)
                            ))
                            .unwrap_or_default(),
                    ),
                )
            }
        }
        ValueFlowIncompleteCause::CallBinding { call, .. }
        | ValueFlowIncompleteCause::CallBindingCoverage { call, .. } => {
            let locator = super::semantic_identity::call_site_locator(call);
            if rust_call_site {
                (
                    Some(super::semantic_identity::policy_location(
                        workspace, locator,
                    )?),
                    format!(
                        "taint discovery is incomplete: call binding for {} is {status}; it is not completely covered by executable code or an applicable complete external model",
                        locator.path().as_str(),
                    ),
                )
            } else {
                (
                    Some(super::semantic_identity::policy_location(
                        workspace, locator,
                    )?),
                    format!(
                        "taint discovery is incomplete: {} for {}:{name} is {status}; this exact call binding is not completely covered by executable code or an applicable complete external model",
                        cause.label(),
                        locator.path().as_str(),
                    ),
                )
            }
        }
        _ => (None, generic_detail),
    };
    Ok((family, detail, primary))
}

/// The diagnostic a composed batch gives each of its policy roots: its first
/// incompleteness, reported as the ICFG engine reports its first cause. A
/// reason keyed by a call that the composition dispatched gets the
/// same call-site evidence the ICFG engine builds for that call, so both
/// engines name the same family and the same message.
///
/// The first reason follows the ICFG engine's order. Its plan names the first
/// incomplete procedure snapshot in its procedure order (artifact key,
/// locator, procedure id), before any call binding or endpoint
/// (`first_incomplete_cause`); within one procedure a blocked gap outranks a
/// residual call. So an open procedure is named before any dispatch, caller
/// or interior reason, and the open procedure that sorts first is named. A
/// budget lane or cancellation ends the composition itself, so it is named
/// before everything else.
///
/// The snapshot input status of the first reason is returned beside the
/// diagnostic, when the reason has one: the completion reason reads it as the
/// ICFG engine reads its first cause's status.
fn composition_first_cause(
    workspace: &WorkspaceAnalyzer,
    provider: &PolicyCompositionProvider<'_>,
    reasons: &[Incompleteness],
) -> Result<(Vec<PolicyDiagnostic>, Option<SemanticInputStatus>), TaintBatchError> {
    let stopped = reasons.iter().find(|reason| {
        matches!(
            reason,
            Incompleteness::Budget(_) | Incompleteness::Cancelled
        )
    });
    let open = reasons
        .iter()
        .filter_map(|reason| match reason {
            Incompleteness::Open { procedure, .. } => {
                let handle = provider.served_procedure(procedure);
                Some((
                    (
                        handle.artifact().key().clone(),
                        handle.semantics().locator().clone(),
                        handle.id(),
                    ),
                    reason,
                ))
            }
            _ => None,
        })
        .min_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, reason)| reason);
    // The ICFG engine's plan names an endpoint's selector evidence only after
    // every procedure, call and binding cause, sources before sinks.
    let endpoint_rank = |reason: &Incompleteness| match reason {
        Incompleteness::SourceEvidence { .. } => 1,
        Incompleteness::SinkEvidence { .. } => 2,
        _ => 0,
    };
    let Some(first) = stopped
        .or(open)
        .or_else(|| reasons.iter().min_by_key(|reason| endpoint_rank(reason)))
    else {
        return Ok((Vec::new(), None));
    };
    let first_status = match first {
        Incompleteness::Open { status, .. } => Some(*status),
        Incompleteness::Dispatch { call, .. } => {
            provider.dispatched_call(call).map(|(_, status, _)| status)
        }
        _ => None,
    };
    let (family, message, primary) = composition_cause_text(workspace, provider, first)?;
    let diagnostic = PolicyDiagnostic::try_new_in_family(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        family,
        message,
        primary,
        Vec::new(),
    )
    .ok();
    let mut diagnostics: Vec<PolicyDiagnostic> = diagnostic.into_iter().collect();
    // The ICFG engine gives each analysis root its own first cause, so a run
    // whose roots fail for different reasons names both families. The
    // composition has one root; a source whose evidence is incomplete is
    // named beside a higher-ranked cause of another family.
    if !matches!(first, Incompleteness::SourceEvidence { .. })
        && let Some(Incompleteness::SourceEvidence { point }) = reasons
            .iter()
            .find(|reason| matches!(reason, Incompleteness::SourceEvidence { .. }))
    {
        let (family, message) = source_evidence_text(point);
        diagnostics.extend(
            PolicyDiagnostic::try_new_in_family(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Warning,
                PolicyDiagnosticImpact::RunIncomplete,
                family,
                message,
                None,
                Vec::new(),
            )
            .ok(),
        );
    }
    Ok((diagnostics, first_status))
}

/// Render one composed cause, shared by run and finding diagnostics.
fn composition_cause_text(
    workspace: &WorkspaceAnalyzer,
    provider: &PolicyCompositionProvider<'_>,
    first: &Incompleteness,
) -> Result<(String, String, Option<PolicySourceLocation>), TaintBatchError> {
    // A blocked gap outranks residual calls, as the ICFG engine's plan does.
    // A residual call prints its procedure's snapshot status, as the ICFG
    // engine's `CallResolution` cause does; a dispatch outside an open
    // procedure has no snapshot cause there, so it prints its own status.
    let residual_call = match first {
        Incompleteness::Dispatch { call, .. } => {
            let (_, status, _) = provider
                .dispatched_call(call)
                .expect("the composition records every call a reason names");
            Some((call, status))
        }
        Incompleteness::Open {
            residual,
            blocked: None,
            status,
            ..
        } => residual.first().map(|call| (call, *status)),
        _ => None,
    };
    let call_site = match residual_call {
        Some((call, status)) => call_site_cause(workspace, provider, call, status)?,
        None => None,
    };
    let (family, message, primary) = match (call_site, first) {
        (Some((message, primary)), _) => (CALL_SITE_EVIDENCE_FAMILY.to_owned(), message, primary),
        (
            None,
            Incompleteness::Open {
                blocked: Some(blocked),
                status,
                ..
            },
        ) => {
            let cause = ValueFlowIncompleteCause::SemanticGap {
                gap: blocked.gap.clone(),
                capability: blocked.capability,
                status: *status,
            };
            let (family, message) = procedure_cause_text(&cause, &cause_status_label(&cause));
            (family, message, None)
        }
        // An open procedure with no residual call and no blocked gap is one
        // the ICFG engine blocks without a scoped gap (an unproven relation or
        // an open value-flow capability): its snapshot cause.
        (
            None,
            Incompleteness::Open {
                procedure,
                residual,
                blocked: None,
                status,
                ..
            },
        ) if residual.is_empty() => {
            let procedure = provider.served_procedure(procedure);
            let cause = if status.is_complete() {
                ValueFlowIncompleteCause::SnapshotCoverage { procedure }
            } else {
                ValueFlowIncompleteCause::Snapshot {
                    procedure,
                    status: *status,
                }
            };
            let (family, message) = procedure_cause_text(&cause, &cause_status_label(&cause));
            (family, message, None)
        }
        (None, Incompleteness::SourceEvidence { point }) => {
            let (family, message) = source_evidence_text(point);
            (family, message, None)
        }
        (None, Incompleteness::SinkEvidence { point }) => {
            let cause = ValueFlowIncompleteCause::SinkEvidence {
                point: point.clone(),
            };
            let (family, message) = procedure_cause_text(&cause, &cause_status_label(&cause));
            (family, message, None)
        }
        (None, Incompleteness::Budget(lane)) => (
            "taint_analysis/composition_budget".to_owned(),
            format!(
                "taint composition exhausted its {} lane",
                composition_lane_name(*lane)
            ),
            None,
        ),
        (None, Incompleteness::Cancelled) => (
            "taint_analysis/cancelled".to_owned(),
            "taint composition was cancelled before reaching a fixed point".to_owned(),
            None,
        ),
        (None, other) => (
            format!(
                "taint_analysis/{}",
                PolicyIncompleteReason::PartialDiscovery.label()
            ),
            composition_reason_message(other),
            None,
        ),
    };
    Ok((family, message, primary))
}

/// The family and message the ICFG engine gives a source whose selector
/// evidence is incomplete.
fn source_evidence_text(point: &ProgramPointHandle) -> (String, String) {
    let cause = ValueFlowIncompleteCause::SourceEvidence {
        point: point.clone(),
    };
    procedure_cause_text(&cause, &cause_status_label(&cause))
}

/// The call-site message and location of one call the composition dispatched,
/// printed with the snapshot input `status`, or `None` for a call outside
/// Rust, which keeps the composition's own text.
fn call_site_cause(
    workspace: &WorkspaceAnalyzer,
    provider: &PolicyCompositionProvider<'_>,
    call: &DurableCallSiteKey,
    status: SemanticInputStatus,
) -> Result<Option<(String, Option<PolicySourceLocation>)>, TaintBatchError> {
    let (handle, _, _) = provider
        .dispatched_call(call)
        .expect("the composition records every call a reason names");
    if !is_rust_taint_call(&handle) {
        return Ok(None);
    }
    let evidence = taint_call_resolution_evidence(
        workspace,
        &handle,
        status,
        &provider.call_resolution_discovery(),
    )
    .map_err(|error| TaintBatchError::Internal(error.to_string()))?;
    Ok(Some((
        call_resolution_detail(&evidence),
        Some(evidence.location.clone()),
    )))
}

fn composition_lane_name(lane: BudgetLane) -> &'static str {
    match lane {
        BudgetLane::Procedures => PolicyBudgetField::CompositionProcedures.as_str(),
        BudgetLane::Hops => PolicyBudgetField::CompositionHops.as_str(),
        BudgetLane::CallersPerProcedure => {
            PolicyBudgetField::CompositionCallersPerProcedure.as_str()
        }
    }
}

fn composition_reason_message(reason: &Incompleteness) -> String {
    match reason {
        Incompleteness::Dispatch { call, reason } => format!(
            "taint composition could not resolve the dispatch of call {:?} in {}: {reason}",
            call.1,
            call.0.0.path(),
        ),
        Incompleteness::Callers { procedure, reason } => format!(
            "taint composition could not enumerate the callers of {}: {reason}",
            procedure.0.path(),
        ),
        Incompleteness::Model { call, reason } => format!(
            "taint composition model of call {:?} in {} is incomplete: {reason}",
            call.1,
            call.0.0.path(),
        ),
        Incompleteness::Interior { procedure, reason } => format!(
            "taint composition interior flows of {} are incomplete: {reason}",
            procedure.0.path(),
        ),
        Incompleteness::PartialFlows { procedure, outcome } => format!(
            "taint composition partial flows of {} are {outcome:?}",
            procedure.0.path(),
        ),
        Incompleteness::Open {
            procedure, reason, ..
        } => format!(
            "taint composition found {} open: {reason}",
            procedure.0.path(),
        ),
        Incompleteness::MissingCaptureBinding { procedure, slot } => format!(
            "taint composition found no capture binding for {slot:?} in {}",
            procedure.0.path(),
        ),
        Incompleteness::UnplacedTransfer { procedure, carrier } => format!(
            "taint composition could not place sanitizer or transform carrier {carrier:?} in {}",
            procedure.0.path(),
        ),
        Incompleteness::Endpoints { procedure, reason } => format!(
            "taint composition matched the policy endpoints of {} incompletely: {reason}",
            procedure.0.path(),
        ),
        Incompleteness::Budget(_)
        | Incompleteness::Cancelled
        | Incompleteness::SourceEvidence { .. }
        | Incompleteness::SinkEvidence { .. } => {
            unreachable!("budget, cancellation and endpoint evidence have their own families")
        }
    }
}

fn is_rust_taint_call(call: &CallSiteHandle) -> bool {
    call.procedure().artifact().key().language() == SemanticLanguage::Standard(Language::Rust)
}

/// The family of a Rust call whose dispatch keeps the run incomplete. Both
/// engines name a call-site cause with it, so one message family joins both.
const CALL_SITE_EVIDENCE_FAMILY: &str = "taint discovery is incomplete: call-site evidence";

/// The call-site message of an incomplete Rust call, shared by the ICFG
/// engine's first cause and the composition's first cause.
fn call_resolution_detail(evidence: &TaintCallResolutionEvidence) -> String {
    format!(
        "taint discovery is incomplete: {}",
        call_resolution_evidence_text(evidence)
    )
}

/// The call-site evidence of an incomplete call. Its resolver boundary arms
/// carry the definition-lookup status and diagnostic kinds that left the call
/// unresolved; a call outside Rust appends it to its generic cause (#4823).
fn call_resolution_evidence_text(evidence: &TaintCallResolutionEvidence) -> String {
    let callee = evidence
        .callee
        .as_deref()
        .map_or("<unavailable from call shape>", |callee| callee);
    let resolver_result = if evidence.resolver_complete {
        "the resolver edge is complete"
    } else {
        "the resolver left the call incomplete"
    };
    let reason = evidence
        .reason
        .as_deref()
        .unwrap_or("no call-site semantic-gap row");
    format!(
        "call `{callee}` at {} bytes {}..{} has snapshot input status {}; {resolver_result}; resolver boundary status: {}; call semantic gap: {reason}",
        evidence.path,
        evidence.range.start,
        evidence.range.end,
        evidence.status.label(),
        evidence.boundary_status,
    )
}

fn taint_call_resolution_evidence(
    workspace: &WorkspaceAnalyzer,
    call: &CallSiteHandle,
    status: SemanticInputStatus,
    discovery: &CallResolutionDiscoveryEvidence,
) -> Result<TaintCallResolutionEvidence, TaintPolicyCompileError> {
    let locator = super::semantic_identity::call_site_locator(call);
    let span = locator.anchor().span();
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    );
    let shape = workspace
        .analyzer()
        .structural_fact_providers()
        .into_iter()
        .find_map(|provider| {
            let facts = provider.structural_facts(&file)?;
            call_shapes_in_file(&facts, &file, usize::MAX)
                .into_iter()
                .find(|shape| {
                    shape.outcome.range.start_byte == span.start_byte() as usize
                        && shape.outcome.range.end_byte == span.end_byte() as usize
                })
        });
    let range = shape.as_ref().map_or_else(
        || span.start_byte() as usize..span.end_byte() as usize,
        |shape| shape.outcome.range.start_byte..shape.outcome.range.end_byte,
    );
    let callee = shape.and_then(|shape| shape.outcome.callee_name);
    let coverage = discovery.coverage.get(&call.durable_key());
    let boundaries = discovery
        .boundaries
        .iter()
        .filter(|boundary| {
            boundary.provenance.iter().any(|provenance| {
                matches!(provenance.owner(), OracleRelationOwner::Dispatch(owner) if owner.durable_key() == call.durable_key())
            })
        })
        .map(|boundary| {
            format!(
                "{:?} proof={:?} completeness={:?}",
                boundary.kind, boundary.proof, boundary.completeness
            )
        })
        .collect::<Vec<_>>();
    let entered_targets = coverage.map_or_else(Vec::new, |coverage| {
        coverage
            .entered
            .iter()
            .map(|target| target.semantics().locator().declaration().clone())
            .collect::<Vec<_>>()
    });
    let binding_coverage = coverage.map(|coverage| &coverage.bindings);
    let (boundary_status, resolver_complete) = match coverage {
        Some(CallSiteCoverage {
            dispatch: DispatchStatus::Resolved { status, coverage },
            has_uncovered_boundary,
            truncated,
            ..
        }) => (
            format!(
                "dispatch_status={} candidate_coverage={coverage:?} uncovered_boundary={has_uncovered_boundary} truncated={truncated} arms={boundaries:?}",
                status.label()
            ),
            status.is_complete()
                && *coverage == CandidateCoverage::Exhaustive
                && !has_uncovered_boundary
                && !truncated,
        ),
        Some(CallSiteCoverage {
            dispatch: DispatchStatus::Unavailable { status },
            ..
        }) => (
            format!(
                "dispatch_unavailable={} arms={boundaries:?}",
                status.label()
            ),
            false,
        ),
        Some(CallSiteCoverage {
            dispatch: DispatchStatus::ProviderError { detail },
            ..
        }) => (
            format!("dispatch_provider_error={detail:?} arms={boundaries:?}"),
            false,
        ),
        None => (
            format!("dispatch_coverage_not_retained arms={boundaries:?}"),
            false,
        ),
    };
    let boundary_status = format!(
        "{boundary_status} entered_targets={entered_targets:?} binding_coverage={binding_coverage:?}"
    );
    let reason = call
        .procedure()
        .semantics()
        .gaps()
        .iter()
        .find(|gap| {
            gap.subject == SemanticGapSubject::CallSite(call.id())
                && gap.capability == SemanticCapability::Calls
        })
        .map(|gap| format!("{}: {}", gap.kind.label(), gap.detail));
    let location = super::semantic_identity::policy_location(workspace, locator)
        .map_err(TaintPolicyCompileError::SemanticProvider)?;
    Ok(TaintCallResolutionEvidence {
        call: call.durable_key(),
        path: locator.path().as_str().to_owned(),
        location,
        callee,
        range,
        status,
        boundary_status,
        resolver_complete,
        reason,
    })
}

/// Build source-selective kills for the automatic comparison barriers Rust
/// publishes in its guard facts. The predicate establishes the barrier only
/// on one arm; the other arm retains the source exactly as ordinary value flow
/// would. Policy-authored predicates remain outside this automatic contract.
/// The guard rule itself lives in `partial_flow::rules::guard_edge_kills`.
fn automatic_comparison_guard_edge_kills(
    snapshots: &[ValueFlowInput<ValueFlowSnapshot>],
    source_specs: &mut ValueFlowSources,
) -> Vec<ValueFlowEdgeKillSpec> {
    if source_specs.is_empty() {
        return Vec::new();
    }
    let source_list = source_specs.intern_list(source_specs.ids().collect());
    let mut kills = Vec::new();
    for snapshot in snapshots {
        let procedure = snapshot.value().procedure();
        for kill in guard_edge_kills(procedure) {
            kills.push(ValueFlowEdgeKillSpec {
                point: procedure
                    .point_handle(kill.point)
                    .expect("a guard point names a live semantic point"),
                target: kill.target_point,
                kind: kill.kind,
                carrier: ValueFlowCarrier::from(kill.carrier),
                sources: source_list,
                labels: None,
            });
        }
    }
    kills
}

#[derive(Clone)]
struct SanitizerDecline {
    sanitizer: Box<str>,
    point: ProgramPointHandle,
    target: Option<ProgramPointId>,
    reason: String,
}

struct BoundConditionalSanitizer {
    id: Box<str>,
    procedure: ProcedureHandle,
    guard: ConditionalGuardSanitizer,
    removes: Box<[TaintLabel]>,
    admission: Result<(), String>,
}

fn sanitizer_operand(
    call: &brokk_bifrost_analysis::analyzer::semantic::SemanticCallSite,
    operand: &TaintSanitizerOperand,
) -> Option<ValueId> {
    match operand {
        TaintSanitizerOperand::Receiver => call.receiver,
        TaintSanitizerOperand::Argument { index } => {
            call.arguments.get(*index as usize).map(|arg| arg.value)
        }
    }
}

/// Identity-preserving reaching value, including one dominating local writer.
/// A unique reaching definition must dominate the use; a writer later in a loop
/// can reach its next iteration even though a straight-line call write-back cannot.
/// May-origin edges alone cannot justify a result-of or constant requirement.
fn sanitizer_requirement_origin(
    procedure: &ProcedureHandle,
    mut value: ValueId,
    mut use_point: ProgramPointId,
    request: &mut SemanticRequest<'_>,
) -> Result<ValueId, String> {
    use brokk_bifrost_analysis::analyzer::semantic::cfg_algorithms::{
        self, CfgAlgorithmBudget, CfgAlgorithmRequest, GenKillFacts,
    };
    use brokk_bifrost_analysis::analyzer::semantic::{
        BindingOriginIndex, CaptureSource, ValueFlowKind,
    };
    let semantics = procedure.semantics();
    if semantics
        .value(value)
        .expect("validated value")
        .kind
        .is_constant()
    {
        return Ok(value);
    }
    let origins = BindingOriginIndex::new(procedure);
    let remaining = request.budget.remaining();
    let max_work = remaining.events.saturating_add(remaining.control_edges);
    let mut remaining_work = max_work;
    let mut charge = |amount: usize| {
        if amount > remaining_work || !request.charge_execution_traversal(amount) {
            false
        } else {
            remaining_work -= amount;
            true
        }
    };
    let mut budget = CfgAlgorithmBudget::uniform(max_work);
    let dominance = cfg_algorithms::dominators(
        semantics,
        semantics.entry_point(),
        &mut CfgAlgorithmRequest::new(&mut budget, request.cancellation),
    )
    .map_err(|error| format!("requirement reaching-definition proof declined: {error:?}"))?;
    if !charge(
        budget
            .used()
            .node_visits
            .saturating_add(budget.used().edge_visits),
    ) {
        return Err("requirement reaching-definition proof budget exceeded".into());
    }
    // A source is read before its writer event, or before Invoke for the operand.
    let mut use_event = semantics
        .point(use_point)
        .expect("validated point")
        .events
        .iter()
        .position(|event| matches!(event.effect, SemanticEffect::Invoke { .. }))
        .expect("a sanitizer operand is observed before Invoke");
    struct Writer {
        point: ProgramPointId,
        event: usize,
        source: Option<ValueId>,
        overwrite: bool,
    }
    let mut seen = HashSet::new();
    loop {
        if request.cancellation.is_cancelled() {
            return Err("requirement proof cancelled".into());
        }
        if !charge(1) {
            return Err("requirement proof budget exceeded".into());
        }
        if !seen.insert((value, use_point, use_event)) {
            return Err("requirement has a cyclic binding origin".into());
        }
        let kind = &semantics.value(value).expect("validated value").kind;
        if kind.is_constant() {
            return Ok(value);
        }
        if !charge(semantics.call_sites().len()) {
            return Err("requirement proof budget exceeded".into());
        }
        if let Some(producer) = semantics
            .call_sites()
            .iter()
            .find(|call| call.normal_result_values().any(|result| result == value))
        {
            if producer
                .normal_continuation
                .target()
                .is_some_and(|target| dominance.dominates(semantics, target, use_point))
            {
                return Ok(value);
            }
            return Err("required call result does not dominate its use".into());
        }
        if origins.address_taken_binding_set().contains(&value)
            || semantics
                .captures()
                .iter()
                .any(|capture| match capture.captured {
                    CaptureSource::Value(captured) => captured == value,
                    CaptureSource::Location(location) => {
                        origins.binding_memory_location(value) == Some(location)
                    }
                })
        {
            return Err("requirement binding is address-taken or captured".into());
        }
        let mut writers = Vec::new();
        for point in semantics.points() {
            if !charge(point.events.len()) {
                return Err("requirement proof budget exceeded".into());
            }
            for (index, event) in point.events.iter().enumerate() {
                let (source, overwrite) = match event.effect {
                    SemanticEffect::Assignment {
                        target,
                        value: source,
                    } if target == value => (
                        (!point.assignment_has_transfer_marker(index)).then_some(source),
                        true,
                    ),
                    SemanticEffect::ValueFlow {
                        target,
                        source,
                        kind,
                    } if target == value => {
                        // Assignment's adjacent Local row repeats the same writer.
                        if kind == ValueFlowKind::Local
                            && index > 0
                            && matches!(point.events[index - 1].effect,
                                SemanticEffect::Assignment { target, value: assigned }
                                    if target == value && assigned == source)
                        {
                            continue;
                        }
                        (
                            matches!(
                                kind,
                                ValueFlowKind::Local
                                    | ValueFlowKind::Parameter
                                    | ValueFlowKind::Receiver
                            )
                            .then_some(source),
                            false,
                        )
                    }
                    SemanticEffect::MemoryLoad { result, .. } if result == value => (None, false),
                    _ => continue,
                };
                writers.push(Writer {
                    point: point.id,
                    event: index,
                    source,
                    overwrite,
                });
            }
        }
        if writers.is_empty() {
            return Err("requirement has no unique single-writer origin".into());
        }
        // Bound the dense solver's allocation before constructing its four matrices.
        let words = semantics
            .points()
            .len()
            .saturating_mul(writers.len().div_ceil(64));
        if !charge(words.saturating_mul(4)) {
            return Err("requirement reaching-definition proof budget exceeded".into());
        }
        let mut facts = GenKillFacts::new(semantics.points().len(), writers.len());
        let mut first = 0;
        while first < writers.len() {
            let point = writers[first].point;
            let end = first
                + writers[first..]
                    .iter()
                    .take_while(|writer| writer.point == point)
                    .count();
            let last_overwrite = (first..end).rfind(|&index| writers[index].overwrite);
            if last_overwrite.is_some() {
                if !charge(writers.len()) {
                    return Err("requirement proof budget exceeded".into());
                }
                for killed in 0..writers.len() {
                    facts.record_killed(point.index(), killed);
                }
            }
            // ValueFlow is additive, including receiver write-back. Only a real
            // Assignment kills older definitions. Preserve subsequent additive rows.
            for generated in last_overwrite.unwrap_or(first)..end {
                facts.record_generated(point.index(), generated);
            }
            first = end;
        }
        let before = budget.used();
        let reaching = cfg_algorithms::reaching_definitions(
            semantics,
            semantics.entry_point(),
            &facts,
            &mut CfgAlgorithmRequest::new(&mut budget, request.cancellation),
        )
        .map_err(|error| format!("requirement reaching-definition proof declined: {error:?}"))?;
        let used = budget.used();
        if !charge(
            (used.node_visits - before.node_visits)
                .saturating_add(used.edge_visits - before.edge_visits),
        ) {
            return Err("requirement reaching-definition proof budget exceeded".into());
        }
        let mut candidates = reaching.reaching_in(use_point.index()).collect::<Vec<_>>();
        for (index, writer) in writers
            .iter()
            .enumerate()
            .filter(|(_, writer)| writer.point == use_point && writer.event < use_event)
        {
            if writer.overwrite {
                candidates.clear();
            }
            candidates.push(index);
        }
        // A loop can carry the same definition into its own point before the
        // current execution generates it again. It remains one definition.
        candidates.sort_unstable();
        candidates.dedup();
        let [index] = candidates.as_slice() else {
            return Err("requirement has no unique single-writer origin".into());
        };
        let writer = &writers[*index];
        let source = writer
            .source
            .ok_or("requirement binding has a non-identity transfer")?;
        if !dominance.dominates(semantics, writer.point, use_point) {
            return Err("requirement writer does not dominate the call".into());
        }
        value = source;
        use_point = writer.point;
        use_event = writer.event;
    }
}

fn sanitizer_constant_equals(
    kind: &SemanticValueKind,
    literal: &serde_json::Value,
    language: SemanticLanguage,
) -> Result<bool, String> {
    Ok(match (kind, literal) {
        (SemanticValueKind::Boolean(value), serde_json::Value::Bool(expected)) => value == expected,
        (SemanticValueKind::ConstantString(value), serde_json::Value::String(expected)) => {
            let decoded = match language {
                SemanticLanguage::Standard(language) => {
                    brokk_bifrost_analysis::analyzer::semantic::languages::language_knowledge(
                        language,
                    )
                    .and_then(|knowledge| knowledge.semantic_string_constant_value(value))
                }
                _ => None,
            }
            .ok_or_else(|| {
                format!(
                    "string constant is not decodable for {}",
                    language.stable_label()
                )
            })?;
            decoded == *expected
        }
        (SemanticValueKind::SignedInteger(value), serde_json::Value::Number(expected)) => expected
            .as_i64()
            .map(i128::from)
            .or_else(|| expected.as_u64().map(i128::from))
            .is_some_and(|expected| *value == expected),
        (SemanticValueKind::UnsignedInteger(value), serde_json::Value::Number(expected)) => {
            expected
                .as_u64()
                .is_some_and(|expected| *value == u128::from(expected))
        }
        (SemanticValueKind::FloatingPoint { bits }, serde_json::Value::Number(expected)) => {
            expected
                .as_f64()
                .is_some_and(|expected| f64::from_bits(*bits) == expected)
        }
        _ => false,
    })
}

fn policy_conditioned_guard_edge_kills(
    snapshots: &[ValueFlowInput<ValueFlowSnapshot>],
    source_specs: &mut ValueFlowSources,
    sanitizers: &[BoundConditionalSanitizer],
    universe: &TaintUniverse,
) -> Result<(Vec<ValueFlowEdgeKillSpec>, Vec<SanitizerDecline>), TaintPolicyCompileError> {
    let mut kills = Vec::new();
    let mut declines = Vec::new();
    if sanitizers.is_empty() || source_specs.is_empty() {
        return Ok((kills, declines));
    }
    let sources = source_specs.intern_list(source_specs.ids().collect());
    for snapshot in snapshots {
        let procedure = snapshot.value().procedure();
        let selected = sanitizers
            .iter()
            .filter(|sanitizer| sanitizer.procedure.durable_key() == procedure.durable_key())
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        let guards = selected
            .iter()
            .map(|sanitizer| sanitizer.guard.clone())
            .collect::<Vec<_>>();
        let derived = conditional_guard_edge_kills(procedure, &guards);
        for decline in derived.declines {
            declines.push(SanitizerDecline {
                sanitizer: selected[decline.sanitizer].id.clone(),
                point: procedure
                    .point_handle(decline.point)
                    .expect("validated guard point"),
                target: None,
                reason: decline.reason.into(),
            });
        }
        for derived in derived.kills {
            let sanitizer = selected[derived.sanitizer];
            let point = procedure
                .point_handle(derived.kill.point)
                .expect("validated guard point");
            if let Err(reason) = &sanitizer.admission {
                declines.push(SanitizerDecline {
                    sanitizer: sanitizer.id.clone(),
                    point,
                    target: Some(derived.kill.target_point),
                    reason: reason.clone(),
                });
                continue;
            }
            kills.push(ValueFlowEdgeKillSpec {
                point,
                target: derived.kill.target_point,
                kind: derived.kill.kind,
                carrier: ValueFlowCarrier::from(derived.kill.carrier),
                sources,
                labels: Some(class_set(universe, &sanitizer.removes)?),
            });
        }
    }
    Ok((kills, declines))
}

/// Compile-scoped materialization cache for require-model taint discovery
/// (#1936).
///
/// `discover_value_flow` runs once per root, and the root set includes every
/// procedure of every materialized artifact. A callee subgraph that many roots
/// share was therefore materialized -- and charged against the one shared
/// `SemanticBudget` -- once per root. Total charged work grew with the sum of
/// per-root closure sizes and could pass the semantic ceiling, so the compile
/// abstained.
///
/// This cache lives for the whole compile. It sits in front of the three
/// oracle calls. On a hit, `discover_value_flow` reuses the byte-identical
/// result that a fresh call gives and skips the oracle call, so it also skips
/// that call's budget charge. Each distinct procedure, dispatch, and binding is
/// therefore materialized and charged one time for each compile.
///
/// The cache does not change any plan. Region membership stays a pure per-root
/// forward closure, and each region plan is a pure function of its root,
/// snapshots, bindings, and region-filtered specs. A hit returns the same
/// `(value, status)` that the skipped call produced, so the region result is
/// identical.
///
/// # Durable keys and one canonical artifact instance (#2289)
///
/// Every key here is a *durable* identity -- an artifact validity key plus
/// dense IDs -- and not a handle. A handle compares its owning
/// `Arc<SemanticArtifact>` by pointer, so under artifact-cache eviction a
/// re-materialized procedure missed every one of these maps and re-charged the
/// shared budget for work the compile had already paid for.
///
/// Rekeying alone is not enough, because the cached values *contain* handles: a
/// hit serves the snapshot, dispatch result, and bindings that the first
/// materialization produced. If the walk kept using the second instance's
/// handles, one region's plan would mix instances, and the plan resolves some
/// things by handle. Two of those are load bearing:
/// `ValueFlowPlan::with_limits_and_call_behavior` builds each call's fallback
/// profile from the root and snapshot procedure handles and looks their values
/// up in `carrier_ids`, and it deduplicates that procedure list by handle
/// equality. A root whose own snapshot came from the other instance would lose
/// its fallback inputs and gain a duplicate profile.
///
/// So `canonical_procedure` pins exactly one `Arc<SemanticArtifact>` per
/// artifact key for the whole compile and rewrites every handle the walk
/// touches onto it. That substitution is sound because the artifact cache
/// retains only `SemanticOutcome::Complete` artifacts
/// (`analyzer/semantic/service.rs`, `CompleteSemanticArtifactCache`), so two
/// instances that share a `SemanticArtifactKey` are two complete lowerings of
/// one immutable file with one adapter identity, and are equal row for row.
/// After the rewrite the root, every snapshot, and every call handle in one
/// discovery belong to one instance.
///
/// The handles the walk does not mint stay as the oracle produced them: a
/// `DispatchCandidate` is sealed against its own provenance and cannot be
/// re-anchored, so a binding's callee port handles can name the other instance.
/// Those reach the plan only as carriers, and #1909 made carrier identity
/// durable: `assign_carrier_ids` groups candidates by stable key, checks
/// `denotes_same_entity`, and retains *every* handle that named the carrier, so
/// a lookup resolves through either instance. `append_call_rules` only looks up
/// carriers it contributed itself, so it cannot miss. The one place that does
/// compare a callee handle for equality, `CallResultHandle::new`, is inside the
/// oracle and is only ever given bindings and a snapshot from one oracle call,
/// never from this cache.
#[derive(Default)]
pub(crate) struct DiscoveryMaterializationCache<'a> {
    /// One canonical artifact instance per artifact key, for the whole compile.
    pub(crate) artifacts: RefCell<
        HashMap<
            SemanticArtifactKey,
            Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>,
        >,
    >,
    procedures: RefCell<HashMap<DurableProcedureKey, CachedSemanticOutcome<ValueFlowSnapshot>>>,
    dispatch: RefCell<HashMap<DurableCallSiteKey, CachedSemanticOutcome<DispatchResult>>>,
    bindings: RefCell<
        HashMap<(DurableCallSiteKey, DurableProcedureKey), CachedSemanticOutcome<CallBindings>>,
    >,
    /// Snapshot lookups served from an entry this compile already held.
    procedure_hits: Cell<u64>,
    /// Snapshot lookups with no entry at all, each of which runs the oracle and
    /// charges the budget. This is the number the compile reports as
    /// `taint.semantic_snapshot_materializations`, and it must equal the number
    /// of distinct procedures the compile reached.
    procedure_misses: Cell<u64>,
    /// Procedure visits whose handle named a second materialization of an
    /// artifact this compile had already canonicalized, so the handle was
    /// rewritten onto the canonical instance before any lookup.
    ///
    /// This is the counter that separates a handle-identity miss from a true
    /// one. Keyed on handles, every one of these visits missed all three maps
    /// and re-ran the oracle for the procedure's snapshot, each of its call
    /// sites' dispatch, and each candidate's bindings. Keyed durably they are
    /// hits, so `procedure_misses` counts only genuinely new procedures and the
    /// handle-identity component of it is zero.
    handle_identity_reuses: Cell<u64>,
    /// Exact dispatch sessions, least recently used first, one per artifact key.
    ///
    /// A session parses its file once and then serves every call site in it.
    /// Call sites are visited grouped by file, so a small recency-ordered set
    /// keeps that parse. An uncapped map would hold a parsed tree for every file
    /// a whole-workspace compile touches, for the whole compile, so the set is
    /// capped at `DISPATCH_SESSION_CAP`. It is dropped with the compile. Only
    /// region discovery uses it; the composition's provider has a dispatch pool.
    dispatch_sessions: RefCell<Vec<DispatchSessionEntry<'a>>>,
}

/// Most files whose parsed dispatch syntax one compile retains at once.
const DISPATCH_SESSION_CAP: usize = 16;

struct DispatchSessionEntry<'a> {
    key: SemanticArtifactKey,
    session: PreparedWorkspaceDispatchSession<'a>,
}

#[derive(Clone)]
struct CachedSemanticOutcome<T> {
    value: Option<T>,
    status: SemanticInputStatus,
}

impl<T: Clone> CachedSemanticOutcome<T> {
    fn from_outcome(outcome: &SemanticOutcome<T>) -> Self {
        Self {
            value: outcome.available_value().cloned(),
            status: SemanticInputStatus::from_outcome(outcome),
        }
    }

    /// Replay a cached verdict without replaying work: the oracle call that
    /// populated the cache already charged the compile's budgets.
    fn replay(&self) -> SemanticOutcome<T> {
        let work = SemanticWork::default();
        match self.status {
            SemanticInputStatus::Complete => SemanticOutcome::Complete {
                value: self
                    .value
                    .clone()
                    .expect("a complete semantic outcome carries a value"),
                work,
            },
            SemanticInputStatus::Ambiguous => SemanticOutcome::Ambiguous {
                candidates: self
                    .value
                    .clone()
                    .expect("an ambiguous semantic outcome carries candidates"),
                work,
            },
            SemanticInputStatus::Unknown => SemanticOutcome::Unknown {
                partial: self.value.clone(),
                work,
            },
            SemanticInputStatus::Unsupported { capability } => SemanticOutcome::Unsupported {
                capability,
                partial: self.value.clone(),
                work,
            },
            SemanticInputStatus::Unproven => SemanticOutcome::Unproven {
                partial: self
                    .value
                    .clone()
                    .expect("an unproven semantic outcome carries a partial value"),
                work,
            },
            SemanticInputStatus::ExceededBudget { exceeded } => SemanticOutcome::ExceededBudget {
                partial: self.value.clone(),
                exceeded,
                work,
            },
            SemanticInputStatus::Cancelled => SemanticOutcome::Cancelled {
                partial: self.value.clone(),
                work,
            },
        }
    }

    fn value_input(&self) -> Option<ValueFlowInput<T>> {
        self.value
            .clone()
            .map(|value| ValueFlowInput::new(value, self.status))
    }
}

/// Record one semantic artifact consumed by taint preparation or solving.
///
/// The plan and discovery layers retain the complete semantic artifact key but
/// do not own an analyzer query context. Reuse the same public fingerprint and
/// relative path encoding as the ICFG provider so a preparation cache hit and a
/// cold oracle call name the same replayable input.
fn record_taint_artifact_read(workspace: &WorkspaceAnalyzer, procedure: &ProcedureHandle) {
    record_taint_artifact_key(workspace, procedure.artifact().key());
}

fn record_taint_artifact_key(workspace: &WorkspaceAnalyzer, key: &SemanticArtifactKey) {
    let analyzer = workspace.analyzer();
    if !brokk_bifrost_analysis::analyzer::read_attribution_records_reads(|| {
        analyzer.read_ledger_attached()
    }) {
        return;
    }
    analyzer.record_read(ReadKey::semantic_artifact(key));
}

fn record_taint_plan_artifacts(workspace: &WorkspaceAnalyzer, plan: &TaintAnalysisPlan) {
    if !brokk_bifrost_analysis::analyzer::read_attribution_records_reads(|| {
        workspace.analyzer().read_ledger_attached()
    }) {
        return;
    }
    plan.value_flow()
        .for_each_retained_artifact_key(|key| record_taint_artifact_key(workspace, key));
}

pub(crate) struct PolicyDiscoveryProvider<'a, 'cache> {
    oracle: WorkspaceSemanticOracle<'a>,
    /// The composition's prepared dispatch sessions, one per artifact for the
    /// provider's life, so calls of one file share one source read, one parse
    /// and the batches announced through [`Self::expect_calls`]. `None` for
    /// region discovery, which resolves each call in a session of its own.
    dispatch_pool: Option<PreparedWorkspaceDispatchPool<'a>>,
    execution_budget: SemanticExecutionBudget,
    cache: &'cache DiscoveryMaterializationCache<'a>,
    poison: RefCell<Option<TaintPolicyCompileError>>,
    /// Returned-callable provenance every dispatch answer in this walk
    /// published, in the order the walk saw it. The walk drains this once at
    /// the end, so the vector is scoped to one root's discovery.
    returned_callables: RefCell<Vec<ReturnedCallableProvenance>>,
    rust_format_result_calls: RefCell<Vec<(CallSiteHandle, ResolverOwnedExternalCalleeIdentity)>>,
}

impl<'a, 'cache> PolicyDiscoveryProvider<'a, 'cache> {
    /// A provider over one workspace for one compile. Every answer it caches
    /// lives in `cache`, which the compile owns.
    pub(crate) fn new(
        workspace: &'a WorkspaceAnalyzer,
        execution_budget: SemanticExecutionBudget,
        cache: &'cache DiscoveryMaterializationCache<'a>,
    ) -> Self {
        Self {
            oracle: workspace.semantic_oracle_provider(),
            dispatch_pool: None,
            execution_budget,
            cache,
            poison: RefCell::new(None),
            returned_callables: RefCell::new(Vec::new()),
            rust_format_result_calls: RefCell::new(Vec::new()),
        }
    }

    /// A provider like [`Self::new`] whose dispatches go through one prepared
    /// session per artifact, for the composition engine.
    pub(crate) fn with_dispatch_pool(
        workspace: &'a WorkspaceAnalyzer,
        execution_budget: SemanticExecutionBudget,
        cache: &'cache DiscoveryMaterializationCache<'a>,
    ) -> Self {
        let mut provider = Self::new(workspace, execution_budget, cache);
        provider.dispatch_pool = Some(provider.oracle.prepare_workspace_dispatch_pool());
        provider
    }

    pub(crate) fn prefetch_callers(
        &self,
        sites: &[brokk_bifrost_analysis::analyzer::usages::CallSite],
        request: &SemanticRequest<'_>,
    ) -> Result<(), TaintPolicyCompileError> {
        let pool = self
            .dispatch_pool
            .as_ref()
            .expect("composition uses a dispatch pool");
        if self.execution_budget.work().exhausted {
            pool.discard_prefetched();
            return Ok(());
        }
        pool.prefetch_callers(sites, request).map_err(|error| {
            self.poison(TaintPolicyCompileError::SemanticProvider(error.to_string()))
        })
    }

    /// Announce calls whose dispatch this provider will be asked for, so the
    /// first of them that its file resolves takes the others into its batch.
    /// A call whose answer the compile already holds is not announced.
    pub(crate) fn expect_calls(&self, calls: &[CallSiteHandle]) {
        let pool = self
            .dispatch_pool
            .as_ref()
            .expect("only a provider with a dispatch pool takes call announcements");
        let cached = self.cache.dispatch.borrow();
        pool.expect_calls(
            calls
                .iter()
                .filter(|call| !cached.contains_key(&call.durable_key())),
        );
    }

    /// Take the returned-callable provenance of this walk, deduplicated by
    /// durable identity.
    ///
    /// One provenance row can be published more than once: the compile-wide
    /// dispatch cache replays an answer for every root that reaches the same
    /// call, and a call's answer is also re-read when the walk revisits it.
    /// Rows are keyed on the producing call, the producing callee, the
    /// closure, and the capture slots, so two rows that name the same
    /// association in two materializations of one artifact collapse to one.
    fn take_returned_callables(&self) -> Vec<ReturnedCallableProvenance> {
        let mut seen = HashSet::new();
        let mut rows = Vec::new();
        for row in self.returned_callables.take() {
            let key = (
                row.producer().durable_key(),
                row.producer_callee().durable_key(),
                row.closure().durable_key(),
                row.captures().to_vec(),
            );
            if seen.insert(key) {
                rows.push(row);
            }
        }
        rows
    }

    /// Take standard `format!`/`format_args!` identities observed during this
    /// query's dispatch walk, deduplicated by the call's durable identity.
    fn take_rust_format_result_calls(
        &self,
    ) -> Vec<(CallSiteHandle, ResolverOwnedExternalCalleeIdentity)> {
        let mut seen = HashSet::new();
        let mut rows = Vec::new();
        for row in self.rust_format_result_calls.take() {
            if seen.insert((row.0.durable_key(), row.1.clone())) {
                rows.push(row);
            }
        }
        rows
    }

    fn poison(&self, error: TaintPolicyCompileError) -> TaintPolicyCompileError {
        let mut poison = self.poison.borrow_mut();
        if poison.is_none() {
            *poison = Some(error);
        }
        poison
            .as_ref()
            .expect("the provider poison was just initialized")
            .clone()
    }

    pub(crate) fn poisoned(&self) -> Option<TaintPolicyCompileError> {
        self.poison.borrow().clone()
    }

    fn require_live(&self) -> Result<(), TaintPolicyCompileError> {
        match self.poisoned() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Retain the returned-callable provenance of one dispatch answer.
    ///
    /// The walk records on both the fresh and the cached path: the
    /// compile-wide dispatch cache serves later roots the answer a first root
    /// paid for, and every root's plan needs the association that answer
    /// published. Duplicates collapse when the walk drains the rows.
    fn record_returned_callables(&self, outcome: &SemanticOutcome<DispatchResult>) {
        let Some(result) = outcome.available_value() else {
            return;
        };
        let Some(provenance) = result.returned_callable() else {
            return;
        };
        self.returned_callables
            .borrow_mut()
            .push(provenance.clone());
    }

    /// Record the call's standard format identity when its dispatch proves
    /// one ([`rust_format_result_identity`]).
    fn record_rust_format_result_call(
        &self,
        call: &CallSiteHandle,
        outcome: &SemanticOutcome<DispatchResult>,
    ) {
        if let Some(identity) = rust_format_result_identity(outcome) {
            self.rust_format_result_calls
                .borrow_mut()
                .push((call.clone(), identity.clone()));
        }
    }

    pub(crate) fn require_outcome<T>(
        &self,
        outcome: &SemanticOutcome<T>,
        operation: &str,
    ) -> Result<(), TaintPolicyCompileError> {
        require_uninterrupted_outcome(outcome, operation)
            .and_then(|()| require_discovery_execution_budget(&self.execution_budget, operation))
            .map_err(|error| self.poison(error))
    }
}

/// The standard `format!`/`format_args!` identity one call's dispatch proves,
/// if any. Only a complete, exact query-time macro dispatch answer proves it:
/// the spelling-derived lowerer candidate and a user macro that shadows the
/// prelude cannot satisfy this identity test.
pub(crate) fn rust_format_result_identity(
    outcome: &SemanticOutcome<DispatchResult>,
) -> Option<&ResolverOwnedExternalCalleeIdentity> {
    let dispatch = outcome.available_value()?;
    if dispatch.coverage() != CandidateCoverage::Exhaustive
        || !dispatch.candidates().is_empty()
        || dispatch.boundaries().len() != 1
    {
        return None;
    }
    let boundary = &dispatch.boundaries()[0];
    if boundary.proof != ProofStatus::Proven
        || boundary.completeness != EvidenceCompleteness::Complete
    {
        return None;
    }
    let identity = boundary.external_callee_identity()?;
    (identity.language() == brokk_bifrost_analysis::analyzer::Language::Rust
        && matches!(
            (identity.owner_fqn(), identity.member()),
            ("std" | "core" | "alloc", "format" | "format_args") | ("alloc.fmt", "format")
        ))
    .then_some(identity)
}

impl PolicyDiscoveryProvider<'_, '_> {
    /// Resolve one call through the compile's retained session for its file.
    ///
    /// A new session is opened only when the file has none retained, so the
    /// file is parsed, and its source charged, once per retained session. A
    /// session that lost its entry to the cap is parsed again, and charged again.
    fn resolve_call_in_session(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<
        SemanticOutcome<DispatchResult>,
        brokk_bifrost_analysis::analyzer::semantic::SemanticProviderError,
    > {
        let artifact = call.procedure().artifact();
        let key = artifact.key().clone();
        let mut entry = {
            let mut sessions = self.cache.dispatch_sessions.borrow_mut();
            match sessions.iter().position(|entry| entry.key == key) {
                Some(position) => sessions.remove(position),
                None => DispatchSessionEntry {
                    key,
                    session: self
                        .oracle
                        .prepare_call_dispatch_session(Arc::clone(artifact)),
                },
            }
        };
        let outcome = entry.session.resolve_call(call, request);
        let mut sessions = self.cache.dispatch_sessions.borrow_mut();
        sessions.push(entry);
        if sessions.len() > DISPATCH_SESSION_CAP {
            sessions.remove(0);
        }
        outcome
    }
}

impl ValueFlowProvider for PolicyDiscoveryProvider<'_, '_> {
    type Error = TaintPolicyCompileError;

    fn canonical_procedure(&self, procedure: &ProcedureHandle) -> ProcedureHandle {
        let mut artifacts = self.cache.artifacts.borrow_mut();
        let canonical = artifacts
            .entry(procedure.artifact().key().clone())
            .or_insert_with(|| Arc::clone(procedure.artifact()));
        if Arc::ptr_eq(canonical, procedure.artifact()) {
            return procedure.clone();
        }
        debug_assert_eq!(
            canonical.work(),
            procedure.artifact().work(),
            "two complete lowerings of one artifact key must retain the same rows"
        );
        self.cache
            .handle_identity_reuses
            .set(self.cache.handle_identity_reuses.get().saturating_add(1));
        canonical
            .procedure_handle(procedure.id())
            .expect("one artifact key denotes one procedure table in every materialization")
    }

    fn procedure_snapshot(
        &self,
        procedure: &ProcedureHandle,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<ValueFlowSnapshot>, Self::Error> {
        self.require_live()?;
        record_taint_artifact_read(self.oracle.workspace(), procedure);
        let key = procedure.durable_key();
        if let Some(cached) = self.cache.procedures.borrow().get(&key).cloned() {
            self.cache
                .procedure_hits
                .set(self.cache.procedure_hits.get().saturating_add(1));
            return Ok(cached.replay());
        }

        self.cache
            .procedure_misses
            .set(self.cache.procedure_misses.get().saturating_add(1));
        let outcome = self
            .oracle
            .procedure_relations(
                procedure,
                context,
                &mut request.staged_with_execution_budget(&self.execution_budget),
            )
            .map_err(|error| {
                self.poison(TaintPolicyCompileError::SemanticProvider(error.to_string()))
            })?;
        self.require_outcome(&outcome, "taint value-flow discovery")?;
        if outcome.available_value().is_none() {
            return Err(self.poison(TaintPolicyCompileError::SemanticUnavailable(
                "taint value-flow discovery returned no procedure snapshot".to_owned(),
            )));
        }
        self.cache
            .procedures
            .borrow_mut()
            .insert(key, CachedSemanticOutcome::from_outcome(&outcome));
        Ok(outcome)
    }

    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, Self::Error> {
        self.require_live()?;
        if let Some(pool) = &self.dispatch_pool
            && (self.execution_budget.work().exhausted
                || request.budget.first_refusal().is_some()
                || request.cancellation.is_cancelled()
                || request.cancellation.soft_deadline_passed())
        {
            pool.discard_prefetched();
        }
        record_taint_artifact_read(self.oracle.workspace(), call.procedure());
        let key = call.durable_key();
        if let Some(cached) = self.cache.dispatch.borrow().get(&key).cloned() {
            let outcome = cached.replay();
            record_dispatch_read(self.oracle.workspace(), call, &outcome);
            self.record_returned_callables(&outcome);
            self.record_rust_format_result_call(call, &outcome);
            return Ok(outcome);
        }
        let mut staged = request.staged_with_execution_budget(&self.execution_budget);
        let outcome = match &self.dispatch_pool {
            Some(pool) => pool.resolve_call(call, &mut staged),
            None => self.resolve_call_in_session(call, &mut staged),
        }
        .map_err(|error| {
            self.poison(TaintPolicyCompileError::SemanticProvider(error.to_string()))
        })?;
        if let Some(pool) = &self.dispatch_pool
            && (self.execution_budget.work().exhausted
                || request.budget.first_refusal().is_some()
                || request.cancellation.is_cancelled()
                || request.cancellation.soft_deadline_passed())
        {
            pool.discard_prefetched();
        }
        record_dispatch_read(self.oracle.workspace(), call, &outcome);
        self.require_outcome(&outcome, "taint call dispatch")?;
        self.record_returned_callables(&outcome);
        self.record_rust_format_result_call(call, &outcome);
        self.cache
            .dispatch
            .borrow_mut()
            .insert(key, CachedSemanticOutcome::from_outcome(&outcome));
        Ok(outcome)
    }

    fn call_bindings(
        &self,
        call: &CallSiteHandle,
        candidate: &DispatchCandidate,
        context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallBindings>, Self::Error> {
        self.require_live()?;
        record_taint_artifact_read(self.oracle.workspace(), call.procedure());
        record_taint_artifact_read(self.oracle.workspace(), candidate.target());
        let key = (call.durable_key(), candidate.target().durable_key());
        if let Some(cached) = self.cache.bindings.borrow().get(&key).cloned() {
            return Ok(cached.replay());
        }
        let outcome = self
            .oracle
            .call_bindings(
                call,
                candidate,
                context,
                &mut request.staged_with_execution_budget(&self.execution_budget),
            )
            .map_err(|error| {
                self.poison(TaintPolicyCompileError::SemanticProvider(error.to_string()))
            })?;
        self.require_outcome(&outcome, "taint call binding")?;
        if outcome.available_value().is_some() {
            self.cache
                .bindings
                .borrow_mut()
                .insert(key, CachedSemanticOutcome::from_outcome(&outcome));
        }
        Ok(outcome)
    }
}

struct SelectedSummaryFamily {
    order: usize,
    shard: Arc<brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelShard>,
    language: String,
    root_ids: HashSet<String>,
}

impl<'a> TaintPolicyCompiler<'a> {
    pub(crate) fn new(
        workspace: &'a WorkspaceAnalyzer,
        flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
        active_semantic_models: Option<Arc<ResolvedActiveSemanticModels>>,
        query_limits: CodeQueryExecutionLimits,
        max_selector_results: usize,
        cancellation: &'a CancellationToken,
    ) -> Self {
        let flow_state = flow_state.into();
        Self {
            selectors: super::selector_compiler::PolicySelectorSession::new(
                workspace,
                &flow_state,
                "taint",
                query_limits,
                max_selector_results,
                cancellation,
                // Taint stays a whole-policy unit while its solve crosses
                // funnels nobody names, so its selectors stay whole too.
                CodeQueryExecutionScope::whole_workspace(),
            ),
            active_semantic_model_snapshot: None,
            active_semantic_models,
            refused_sites: Vec::new(),
            named_actuals: HashMap::new(),
            bound_endpoints: BoundEndpointCounts::default(),
            store_key_metrics: StoreKeyMetrics::default(),
            authored_selector_summary: false,
            skipped_region_roots: 0,
            candidate_probe: None,
            changed_files: None,
            range_widened: Vec::new(),
            examined_procedures: Vec::new(),
            matched_values: Self::resolve_matched_value,
        }
    }

    /// Resolve matched values from file-local observations, as the
    /// composition's frontier does.
    fn with_file_local_matched_values(mut self) -> Self {
        self.matched_values = Self::resolve_frontier_matched_value;
        self
    }

    /// Bind sinks only in `files`, or every sink when `None`.
    pub(crate) fn with_changed_files(mut self, files: Option<&'a [PolicyChangedFile]>) -> Self {
        self.changed_files = files;
        self
    }

    pub(crate) fn with_active_semantic_model_snapshot(
        mut self,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        self.active_semantic_models = snapshot
            .as_ref()
            .map(|snapshot| Arc::clone(snapshot.active_models()));
        self.active_semantic_model_snapshot = snapshot;
        self
    }

    fn compile(
        mut self,
        policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
    ) -> Result<TaintPolicyCompilation, Box<TaintPolicyCompileFailure>> {
        let compiled = self.compile_inner(policy, spec).and_then(|compiled| {
            self.selectors
                .record_taint_binding_gaps(policy)
                .map_err(taint_selector_error)?;
            Ok(compiled)
        });
        // Every taint run reports what its endpoint selectors bound, so a raw
        // report distinguishes a proven verdict from one taken over an empty
        // relation without re-running the policy (#2659).
        let mut work = self.selectors.work_report("taint");
        record_compile_metrics(&mut work, self.bound_endpoints);
        for (name, value) in [
            ("taint.store_key_operands", self.store_key_metrics.operands),
            (
                "taint.store_key_direct_literals",
                self.store_key_metrics.direct_literals,
            ),
            (
                "taint.store_key_recovered",
                self.store_key_metrics.recovered,
            ),
            ("taint.store_key_unproven", self.store_key_metrics.unproven),
            (
                "taint.store_key_budget_hits",
                self.store_key_metrics.budget_hits,
            ),
            ("taint.store_key_work", self.store_key_metrics.work),
        ] {
            increment_work_metric(&mut work, name, PolicyWorkUnit::Count, value)
                .expect("bounded store-key metrics fit the taint work report");
        }
        match compiled {
            Ok(CompiledPolicy::Plans(compiled)) => Ok(TaintPolicyCompilation::Plans {
                roots: compiled,
                work,
                refusals: refusal_messages(&self.refused_sites),
                authored_selector_summary: self.authored_selector_summary,
                incomplete_selectors: self.selectors.take_incomplete_taint_selectors(),
                skipped_region_roots: self.skipped_region_roots,
            }),
            Ok(CompiledPolicy::NoSinkInRange { engine, scope }) => {
                Ok(TaintPolicyCompilation::Clean {
                    work,
                    refusals: refusal_messages(&self.refused_sites),
                    // No endpoint set is empty: the sources bound, and the
                    // sinks bound nothing in the range, which claims nothing.
                    empty_endpoints: EmptyEndpointSets {
                        sources: false,
                        sinks: false,
                        source_filtered_by_threat_model: false,
                    },
                    incomplete_selectors: self.selectors.take_incomplete_taint_selectors(),
                    engine: Some(engine),
                    scope: Some(scope),
                })
            }
            Err(TaintPolicyCompileError::EmptyCompiledEndpoints(empty_endpoints)) => {
                let mut incomplete_selectors = self.selectors.take_incomplete_taint_selectors();
                if empty_endpoints.proves_no_flow(spec, &incomplete_selectors) {
                    incomplete_selectors.clear();
                }
                Ok(TaintPolicyCompilation::Clean {
                    work,
                    refusals: refusal_messages(&self.refused_sites),
                    empty_endpoints,
                    incomplete_selectors,
                    engine: None,
                    scope: None,
                })
            }
            Err(error) => Err(Box::new(TaintPolicyCompileFailure { error, work })),
        }
    }

    /// Bind every sink selector of `spec`, in the changed files `range` when it
    /// is given, or in the whole workspace when it is `None`. A
    /// selector whose query cannot be sliced to the files binds the whole
    /// workspace, and its candidates are kept only when their enclosing
    /// procedure overlaps a changed hunk, before operand binding. The reason
    /// for widening selector evaluation is recorded for the run.
    fn bind_sinks(
        &mut self,
        spec: &ResolvedTaintPolicySpec,
        selectors: &HashMap<&PolicySelectorPath, &ResolvedPolicySelector>,
        range: Option<&[PolicyChangedFile]>,
    ) -> Result<Vec<BoundEndpoint>, TaintPolicyCompileError> {
        let mut sinks = Vec::new();
        let files = range.map(|changed| {
            changed
                .iter()
                .map(|changed| changed.file.clone())
                .collect::<Vec<_>>()
        });
        // All ranges come from procedure source mappings. Keep the full
        // per-file range query until binding finishes so a nested unedited
        // procedure cannot borrow its enclosing procedure's scope.
        let mut procedure_ranges = HashMap::new();
        if let Some(changed) = range {
            self.examined_procedures.clear();
            for changed in changed {
                let artifact = self
                    .selectors
                    .materialize(&changed.file)
                    .map_err(taint_selector_error)?;
                let mut ranges = Vec::new();
                for procedure in artifact.procedures() {
                    self.selectors
                        .require_execution_budget("changed procedure ranges")
                        .map_err(taint_selector_error)?;
                    if !self.selectors.execution_budget().charge_traversal(1) {
                        return Err(query_budget_error(
                            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                            "changed procedure ranges exhausted the shared traversal budget",
                        ));
                    }
                    let mapping = procedure
                        .source_mapping(procedure.source())
                        .expect("validated procedure has its source mapping");
                    let span = mapping.locator.anchor().span();
                    let range = span.start_byte() as usize..span.end_byte() as usize;
                    let overlaps = changed.overlaps(&range);
                    if overlaps {
                        self.examined_procedures.push(
                            super::semantic_identity::policy_location(
                                self.selectors.workspace(),
                                &mapping.locator,
                            )
                            .map_err(TaintPolicyCompileError::SemanticUnavailable)?,
                        );
                    }
                    ranges.push((range, overlaps));
                }
                procedure_ranges.insert(rel_path_string(&changed.file), ranges);
            }
            self.examined_procedures.sort();
            self.examined_procedures.dedup();
        }
        for sink in &spec.sinks {
            let _timing = brokk_bifrost_analysis::profiling::scope_with(|| {
                format!("taint.bind_sink[{}]", sink.definition.selector_path)
            });
            let selector = required_selector(selectors, &sink.definition.selector_path)?;
            let port = &sink.definition.dangerous_operand;
            let selected = match range {
                None => self.select(selector, port)?,
                Some(_) => {
                    let (selected, widened) = self
                        .selectors
                        .select_taint_sliced(
                            selector,
                            files.as_deref().expect("a range has sliced files"),
                        )
                        .map_err(taint_selector_error)?;
                    if let Some(reason) = widened {
                        self.range_widened.push(format!(
                            "sink selector `{}` bound the whole workspace: {}",
                            selector.path,
                            reason.stable_label()
                        ));
                    }
                    selected
                }
            };
            for selected in selected {
                if range.is_some() {
                    let enclosing = procedure_ranges
                        .get(&rel_path_string(&selected.file))
                        .and_then(|ranges| {
                            ranges
                                .iter()
                                .filter(|(range, _)| {
                                    range.start <= selected.span.start
                                        && selected.span.end <= range.end
                                })
                                .min_by_key(|(range, _)| range.len())
                        });
                    if !enclosing.is_some_and(|(_, overlaps)| *overlaps) {
                        continue;
                    }
                }
                for resolved in self.resolve_selected_values(selected, selector, port)? {
                    sinks.push(BoundEndpoint {
                        endpoint: sink.identity.clone(),
                        kind: resolved.kind,
                        dispatch_obligations: resolved.dispatch_obligations,
                        point: resolved.point,
                        phase: resolved.phase,
                        carrier: resolved.carrier,
                        proof: resolved.proof,
                        completeness: resolved.completeness,
                        labels: sink.definition.accepts.clone().into_boxed_slice(),
                        unjudged: None,
                    });
                }
            }
        }
        if let Some(files) = range {
            sinks.retain(|sink| {
                let procedure = sink.point.procedure();
                let semantics = procedure.semantics();
                let mapping = semantics
                    .source_mapping(semantics.source())
                    .expect("validated procedure has its source mapping");
                let span = mapping.locator.anchor().span();
                let range = span.start_byte() as usize..span.end_byte() as usize;
                files.iter().any(|changed| {
                    rel_path_string(&changed.file) == mapping.locator.path().as_str()
                        && changed.overlaps(&range)
                })
            });
        }
        Ok(sinks)
    }

    fn compile_inner(
        &mut self,
        policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
    ) -> Result<CompiledPolicy, TaintPolicyCompileError> {
        validate_external_model_entries(&spec.external_models)?;

        let selectors = policy
            .resolved_selectors()
            .iter()
            .map(|selector| (&selector.path, selector))
            .collect::<HashMap<_, _>>();
        let mut all_sources = Vec::new();
        // A changed-range run binds sinks in edited procedures only.
        let mut all_sinks = self.bind_sinks(spec, &selectors, self.changed_files)?;
        // The engine is one rule over the specification
        // and the bound sinks, decided before discovery and any solve, and
        // before any source, sanitizer or transform is bound. The composition
        // engine matches those on the frontier (`FrontierEndpointBinder`); the
        // ICFG engine binds them here.
        let engine = {
            let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.select");
            select_taint_engine(
                self.selectors.workspace(),
                spec,
                &all_sinks,
                self.candidate_probe.is_some(),
            )?
        };
        if !spec.barriers.is_empty()
            && let TaintEngine::Icfg { reason } = &engine
            && reason.as_ref() != NO_SINKS_REASON
        {
            let mut checked = std::collections::HashSet::new();
            for sink in &all_sinks {
                let supported = match sink.point.procedure().artifact().key().language() {
                    SemanticLanguage::Standard(language) if checked.insert(language) => {
                        brokk_bifrost_analysis::analyzer::semantic::open_value_type_barrier_context(
                            language,
                            self.selectors.workspace().analyzer(),
                            self.selectors.cancellation(),
                        )
                        .map_err(|error| {
                            TaintPolicyCompileError::SemanticProvider(error.to_string())
                        })?
                        .is_some()
                    }
                    SemanticLanguage::Standard(_) => true,
                    _ => false,
                };
                if !supported {
                    return Err(TaintPolicyCompileError::UnsupportedBarrierEngine(
                        reason.to_string(),
                    ));
                }
            }
        }
        // A changed-range run is answered by the composition over
        // the sinks in its files. The ICFG engine binds every endpoint, so an
        // ICFG answer rebinds the sinks whole and reports that the range did
        // not narrow it. The rule gives `no-sinks` only after the store, entry
        // point, language and row checks passed, so an empty range with that
        // reason is a composition answer with no region to search. Both are
        // decided before any source is bound, so an empty range binds none.
        let mut scope = None;
        if self.changed_files.is_some() {
            let no_sinks_in_range = all_sinks.is_empty()
                && match &engine {
                    TaintEngine::Composition => true,
                    TaintEngine::Icfg { reason } => reason.as_ref() == NO_SINKS_REASON,
                };
            match &engine {
                _ if no_sinks_in_range => {
                    return Ok(CompiledPolicy::NoSinkInRange {
                        engine: TaintEngine::Composition,
                        scope: PolicyRunScope::changed_range(
                            std::mem::take(&mut self.examined_procedures),
                            std::mem::take(&mut self.range_widened),
                        ),
                    });
                }
                TaintEngine::Composition => {
                    scope = Some(PolicyRunScope::changed_range(
                        std::mem::take(&mut self.examined_procedures),
                        std::mem::take(&mut self.range_widened),
                    ));
                }
                TaintEngine::Icfg { reason } => {
                    scope = Some(PolicyRunScope::workspace(vec![format!(
                        "engine icfg ({reason}) binds every endpoint; the changed range did not narrow it"
                    )]));
                    // The sinks are the first endpoints bound, so the sliced
                    // pass's refusals and notes are all there are.
                    self.refused_sites.clear();
                    self.selectors.truncate_incomplete_taint_selectors(0);
                    self.range_widened.clear();
                    all_sinks = self.bind_sinks(spec, &selectors, None)?;
                }
            }
        }
        // Sanitizers (a taint policy's `sanitizer`, a flow policy's `kill`)
        // bind both ports from one exact selected call. The kill is applied to
        // the input carrier before the call boundary, so only taint arriving
        // through the declared operand is removed. The output remains part of
        // the binding identity and is validated below; resolving it alongside
        // the input prevents a sanitizer from becoming an unconditional kill
        // of a same-named call's result.
        let conditional_sanitizers = self.bind_conditional_sanitizers(spec, &selectors)?;
        let mut all_kills = Vec::new();
        let mut all_transforms = Vec::new();
        if engine != TaintEngine::Composition {
            // Sinks were bound first to decide the engine. Their refusals and
            // incomplete selectors are reported after the sources', in the
            // order binding has always reported them.
            let sink_refusals = std::mem::take(&mut self.refused_sites);
            let sink_incomplete = self.selectors.take_incomplete_taint_selectors();
            for source in spec
                .sources
                .iter()
                .filter(|source| threat_model_source_is_active(source, &spec.threat_models))
            {
                let selector = required_selector(&selectors, &source.definition.selector_path)?;
                for selected in self.select(selector, &source.definition.bind)? {
                    all_sources.extend(self.bind_source(source, selector, selected)?);
                }
            }
            self.refused_sites.extend(sink_refusals);
            self.selectors
                .extend_incomplete_taint_selectors(sink_incomplete);
            for sanitizer in &spec.sanitizers {
                let selector = required_selector(&selectors, &sanitizer.selector_path)?;
                let Some((_, output)) = sanitizer.definition.kind.transfer_ports() else {
                    // Conditional sanitizers are applied by the branch-conditioned kill derivation.
                    continue;
                };
                for selected in self.select(selector, output)? {
                    all_kills.extend(self.bind_sanitizer(sanitizer, selector, selected)?);
                }
            }
            for transform in &spec.transforms {
                let selector = required_selector(&selectors, &transform.selector_path)?;
                for selected in self.select(selector, &transform.definition.output)? {
                    all_transforms.extend(self.bind_transform(transform, selector, selected)?);
                }
            }
        }
        // External models (#2691): each entry declares the transfer semantics
        // of the calls its selector identifies. A bound declaration replaces
        // the call's analyzed body, so binding happens before discovery and the
        // bound call set steers discovery below.
        let mut all_models = Vec::new();
        for model in &spec.external_models {
            let selector = required_selector(&selectors, &model.selector_path)?;
            for selected in self.select(selector, &PolicyPort::ReturnValue)? {
                all_models.extend(self.resolve_selected_model_calls(
                    selected,
                    selector,
                    &model.definition,
                    &model.identity,
                )?);
            }
        }
        sort_bound_external_models(&mut all_models);
        // Entry points (#2692) declare procedures the framework invokes with a
        // tainted formal parameter. Each selected declaration lowers to an
        // ordinary source-shaped endpoint bound at the procedure's own entry
        // point (`BeforeEffects`, port carrier), so the procedure roots its own
        // analysis region and the parameter is a live taint origin even though
        // no analyzed caller exists.
        for entry_point in &spec.entry_points {
            let selector = required_selector(&selectors, &entry_point.definition.selector_path)?;
            let mut bound_ports = HashSet::new();
            for selected in self.select(selector, &entry_point.definition.bind)? {
                for resolved in self
                    .resolve_entry_point_parameter_values(selected, &entry_point.definition.bind)?
                {
                    // One declaration can surface as several selector rows
                    // (a definition node and its binding occurrence); they
                    // name one formal port and must bind it once.
                    let ValueFlowCarrier::Port(port) = &resolved.carrier else {
                        unreachable!("entry-point resolution binds a procedure port carrier")
                    };
                    let identity = DurablePortIdentity::of(port).map_err(|error| {
                        TaintPolicyCompileError::SemanticUnavailable(format!(
                            "entry-point parameter port identity is unavailable: {error}"
                        ))
                    })?;
                    if !bound_ports.insert(identity) {
                        continue;
                    }
                    all_sources.push(BoundEndpoint {
                        endpoint: entry_point.identity.clone(),
                        kind: resolved.kind,
                        dispatch_obligations: resolved.dispatch_obligations,
                        point: resolved.point,
                        phase: resolved.phase,
                        carrier: resolved.carrier,
                        proof: resolved.proof,
                        completeness: resolved.completeness,
                        labels: entry_point.definition.labels.clone().into_boxed_slice(),
                        unjudged: None,
                    });
                }
            }
            // An entry point whose selector matches nothing roots nothing,
            // exactly like a source or sanitizer whose selector matches
            // nothing: one policy commonly serves many workspaces, and only
            // the workspaces that declare the handler synthesize its root.
            // The shared empty-endpoint check below still refuses a policy
            // that bound no source-shaped endpoint at all.
        }
        // Persistence-store ends. A write binds its declared input carrier at
        // the selected call and a read its declared output carrier; the
        // optional key and instance ports resolve into the channel identity
        // that decides which writes reach which reads at evaluation time. An
        // unresolvable dimension joins (whole-store) rather than separating,
        // so nothing here refuses a site over a dimension.
        let mut all_store_writes = Vec::new();
        for write in &spec.store_writes {
            let selector = required_selector(&selectors, &write.selector_path)?;
            if matches!(write.definition.input, PolicyPort::MatchedValue) {
                return Err(TaintPolicyCompileError::UnsupportedBinding(
                    "store-write input must be a call port".to_owned(),
                ));
            }
            for selected in self.select(selector, &write.definition.input)? {
                for resolved in
                    self.resolve_selected_values(selected, selector, &write.definition.input)?
                {
                    let channel = self.resolve_store_channel(
                        write.definition.store.as_str(),
                        write.definition.instance.as_ref(),
                        write.definition.key.as_ref(),
                        &resolved,
                    )?;
                    let call = resolved.call.clone().ok_or_else(|| {
                        TaintPolicyCompileError::UnsupportedBinding(
                            "store-write input must bind a call site".to_owned(),
                        )
                    })?;
                    all_store_writes.push(BoundStoreEnd {
                        endpoint: BoundEndpoint {
                            endpoint: write.identity.clone(),
                            kind: resolved.kind,
                            dispatch_obligations: resolved.dispatch_obligations,
                            point: resolved.point,
                            phase: resolved.phase,
                            carrier: resolved.carrier,
                            proof: resolved.proof,
                            completeness: resolved.completeness,
                            labels: Box::default(),
                            unjudged: None,
                        },
                        channel,
                        call,
                    });
                }
            }
        }
        let mut all_store_reads = Vec::new();
        for read in &spec.store_reads {
            let selector = required_selector(&selectors, &read.selector_path)?;
            if matches!(read.definition.output, PolicyPort::MatchedValue) {
                return Err(TaintPolicyCompileError::UnsupportedBinding(
                    "store-read output must be a call port".to_owned(),
                ));
            }
            for selected in self.select(selector, &read.definition.output)? {
                for resolved in
                    self.resolve_selected_values(selected, selector, &read.definition.output)?
                {
                    let channel = self.resolve_store_channel(
                        read.definition.store.as_str(),
                        read.definition.instance.as_ref(),
                        read.definition.key.as_ref(),
                        &resolved,
                    )?;
                    let call = resolved.call.clone().ok_or_else(|| {
                        TaintPolicyCompileError::UnsupportedBinding(
                            "store-read output must bind a call site".to_owned(),
                        )
                    })?;
                    all_store_reads.push(BoundStoreEnd {
                        endpoint: BoundEndpoint {
                            endpoint: read.identity.clone(),
                            kind: resolved.kind,
                            dispatch_obligations: resolved.dispatch_obligations,
                            point: resolved.point,
                            phase: resolved.phase,
                            carrier: resolved.carrier,
                            proof: resolved.proof,
                            completeness: resolved.completeness,
                            labels: Box::default(),
                            unjudged: None,
                        },
                        channel,
                        call,
                    });
                }
            }
        }
        // An end whose channel aliases no counterpart stays bound: it keeps
        // its region viable and decidable (a read from a store nothing writes
        // is a proven-clean negative, not an abstain), and the evaluation
        // driver simply never seeds it.
        self.bound_endpoints = BoundEndpointCounts {
            sources: all_sources.len(),
            sinks: all_sinks.len(),
        };
        if let Some(probe) = self.candidate_probe.as_deref_mut() {
            probe.record(&all_sources, &all_sinks)?;
        }
        // Both sets are tested before returning, so a policy whose source and
        // sink selectors both match nothing reports both rather than only the
        // first one the compiler happened to reach (#2659).
        // The composition matches sources on the frontier, so only a policy
        // with no active source definition is known to bind none.
        let empty = EmptyEndpointSets {
            sources: match engine {
                TaintEngine::Composition => !spec
                    .sources
                    .iter()
                    .any(|source| threat_model_source_is_active(source, &spec.threat_models)),
                TaintEngine::Icfg { .. } => all_sources.is_empty(),
            },
            // A composed changed-range run's sinks are the ones in its files,
            // so an empty set there is an answer about that range, not an
            // empty selection. An ICFG answer rebound its sinks whole.
            sinks: all_sinks.is_empty()
                && (self.changed_files.is_none() || engine != TaintEngine::Composition),
            source_filtered_by_threat_model: !spec.threat_models.is_empty()
                && !spec.sources.is_empty()
                && spec
                    .sources
                    .iter()
                    .all(|source| !threat_model_source_is_active(source, &spec.threat_models)),
        };
        if empty.any() {
            return Err(TaintPolicyCompileError::EmptyCompiledEndpoints(empty));
        }

        let mut stable_classes = spec
            .sources
            .iter()
            .filter(|source| threat_model_source_is_active(source, &spec.threat_models))
            .flat_map(|source| source.definition.labels.iter())
            .chain(
                spec.sinks
                    .iter()
                    .flat_map(|sink| sink.definition.accepts.iter()),
            )
            .chain(
                spec.sanitizers
                    .iter()
                    .flat_map(|sanitizer| sanitizer.definition.removes.iter()),
            )
            .chain(spec.transforms.iter().flat_map(|transform| {
                transform
                    .definition
                    .removes
                    .iter()
                    .chain(&transform.definition.adds)
            }))
            // Every label an external model mentions joins the universe, so a
            // declared transfer's moved and removed sets resolve to dense
            // classes even when no source currently mints them.
            .chain(spec.external_models.iter().flat_map(|model| {
                model.definition.transfers.iter().flat_map(|transfer| {
                    let effect_labels: &[TaintLabel] = match &transfer.effect {
                        TaintTransferEffect::Propagate => &[],
                        TaintTransferEffect::Sanitize { removes } => removes,
                        TaintTransferEffect::Transform { .. } => {
                            unreachable!("transform effects are refused before endpoint binding")
                        }
                    };
                    transfer.labels.iter().chain(effect_labels.iter())
                })
            }))
            .chain(
                spec.entry_points
                    .iter()
                    .flat_map(|entry_point| entry_point.definition.labels.iter()),
            )
            .map(|label| {
                SourceClassId::new(label.as_str())
                    .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        stable_classes.sort();
        stable_classes.dedup();
        let universe = TaintUniverse::new(stable_classes)
            .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))?;
        // A composed policy discovers no region: its search
        // starts at the bound sinks and reaches everything else on demand.
        if engine == TaintEngine::Composition {
            return self.composed_plans(policy, spec, all_sinks, all_models, &universe, scope);
        }

        let mut roots = all_sources
            .iter()
            .chain(&all_sinks)
            .chain(all_store_writes.iter().map(|end| &end.endpoint))
            .chain(all_store_reads.iter().map(|end| &end.endpoint))
            .map(|endpoint| endpoint.point.procedure().clone())
            .chain(all_kills.iter().flat_map(|kill| {
                [
                    kill.input.point.procedure().clone(),
                    kill.output.point.procedure().clone(),
                ]
            }))
            .chain(all_transforms.iter().flat_map(|transform| {
                [
                    transform.input.point.procedure().clone(),
                    transform.output.point.procedure().clone(),
                ]
            }))
            .chain(
                all_models
                    .iter()
                    .map(|model| model.call.procedure().clone()),
            )
            .chain(
                self.selectors
                    .materialized_artifacts()
                    .flat_map(|artifact| {
                        artifact
                            .procedures()
                            .iter()
                            .filter(|procedure| !procedure.properties().is_synthetic)
                            .map(|procedure| {
                                artifact
                                    .procedure_handle(procedure.id())
                                    .expect("a live artifact owns each retained procedure")
                            })
                    }),
            )
            .collect::<Vec<_>>();
        roots.sort_by(|left, right| left.semantics().locator().cmp(right.semantics().locator()));
        // Deduplicate by durable identity, not by handle: a selected endpoint's
        // procedure and the same procedure enumerated from a materialized
        // artifact can be two handles for one procedure when the artifact cache
        // re-materialized the file in between, and handle equality would then
        // root the same region twice (#2289).
        roots.dedup_by(|left, right| left.durable_key() == right.durable_key());
        let mut discoveries = Vec::with_capacity(roots.len());
        // Calls covered by a bound external model are opaque: their declared
        // transfers are the semantics, so discovery must not bind their callee
        // bodies (#2691).
        let modeled_calls = all_models
            .iter()
            .map(|model| model.call.durable_key())
            .collect::<HashSet<_>>();
        // One cache serves every root in this compile. It charges each shared
        // procedure, dispatch, and binding one time, not one time for each root
        // that reaches it (#1936).
        let materialization = DiscoveryMaterializationCache::default();
        for root in roots {
            // Each region is an independent source-to-sink analysis, so budget
            // it independently rather than accumulating every region's
            // materialization into one shared cap (which makes a corpus abstain
            // by accumulation). The shared `materialization` cache keeps
            // cross-region work amortized, so a region's fresh budget only
            // accounts for the procedures it newly pulls.
            self.selectors.reset_region_semantic_budget();
            match self.discover_value_flow(&root, &modeled_calls, &materialization) {
                Ok(discovery) => discoveries.push(discovery),
                Err(error) if is_region_budget_exhausted(&error) => {
                    // This root's forward closure did not fit its own per-region
                    // budget. `discover_value_flow` errors on exhaustion instead
                    // of truncating, so the region is complete-or-absent: there
                    // is no partial region to solve. Skipping it is honest -- the
                    // root's file simply has no covering region, so any source or
                    // sink it holds reports `not_analyzed`, never a false clean
                    // (the scoreboard already treats an uncovered file as an
                    // abstain). Regions that fit their budget are unaffected, so
                    // one oversized root -- typically a high call-graph entry
                    // whose closure spans the workspace -- no longer aborts the
                    // whole compile and drops every later region (#1936).
                    self.skipped_region_roots = self.skipped_region_roots.saturating_add(1);
                }
                Err(error) => return Err(error),
            }
        }
        self.selectors
            .record_semantic_handle_identity_reuses(materialization.handle_identity_reuses.get());
        // Drop every region that could contain a refused selector row (#2308).
        // A refused row bound no endpoint, so a region holding it is missing an
        // endpoint the policy asked for; solving it anyway could report a clean
        // verdict for a site that was never analyzed. Regions that contain none
        // of the refused row's candidate procedures cannot hold the site, so
        // they keep their verdicts: the refusal costs the sites it affects
        // rather than the whole run.
        if !self.refused_sites.is_empty() {
            let refused = self
                .refused_sites
                .iter()
                .filter(|refusal| refusal.impact == PolicyDiagnosticImpact::RunIncomplete)
                .flat_map(|refusal| refusal.procedures.iter().cloned())
                .collect::<HashSet<_>>();
            discoveries.retain(|discovery| {
                !discovery
                    .procedures
                    .iter()
                    .any(|procedure| refused.contains(procedure))
            });
        }
        // Keep only regions that contain both a selected source and a selected
        // sink: those are the regions where a flow can exist, and each becomes
        // one independent analysis plan below. Binding proceeds per region on
        // purpose (#1935). Workspace-wide name selection spans many files, so
        // requiring every selected source AND sink to land in one shared region
        // aborted the whole compile by construction and abstained with zero
        // findings. A source in one region and a sink in another simply cannot
        // flow, so an endpoint with no co-located partner contributes no
        // finding; it must not suppress a fully-discovered region's verdicts.
        // Within-region incompleteness still degrades honestly: a region whose
        // discovery is partial carries that status into its value-flow plan and
        // reports `Inconclusive`, and require-model still fails closed on a
        // genuinely unmodeled call inside a region.
        // Region membership is tested by durable procedure identity. Building
        // the endpoints' keys once keeps the per-region tests below from
        // cloning one `SemanticArtifactKey` for every endpoint of every region.
        let source_procedures = all_sources
            .iter()
            .map(|endpoint| endpoint.point.procedure().durable_key())
            .collect::<Vec<_>>();
        let sink_procedures = all_sinks
            .iter()
            .map(|endpoint| endpoint.point.procedure().durable_key())
            .collect::<Vec<_>>();
        let kill_procedures = all_kills
            .iter()
            .map(|kill| kill.input.point.procedure().durable_key())
            .collect::<Vec<_>>();
        let transform_procedures = all_transforms
            .iter()
            .map(|transform| transform.input.point.procedure().durable_key())
            .collect::<Vec<_>>();
        let store_write_procedures = all_store_writes
            .iter()
            .map(|end| end.endpoint.point.procedure().durable_key())
            .collect::<Vec<_>>();
        let store_read_procedures = all_store_reads
            .iter()
            .map(|end| end.endpoint.point.procedure().durable_key())
            .collect::<Vec<_>>();
        // A region can host a flow when it contains something that establishes
        // taint (a source, or a store read fed across the boundary) and
        // something that consumes it (a sink, or a store write feeding the
        // boundary). Without stores this is exactly the source-and-sink test;
        // with them, the write region and the read region each stay viable on
        // their own and the evaluation driver links them through the channel.
        let model_procedures = all_models
            .iter()
            .map(|model| model.call.procedure().durable_key())
            .collect::<Vec<_>>();
        let (mut covering_discoveries, mut disconnected_discoveries): (Vec<_>, Vec<_>) =
            discoveries.into_iter().partition(|discovery| {
                let establishes = source_procedures
                    .iter()
                    .chain(&store_read_procedures)
                    .any(|procedure| discovery.procedures.contains(procedure));
                let consumes = sink_procedures
                    .iter()
                    .chain(&store_write_procedures)
                    .any(|procedure| discovery.procedures.contains(procedure));
                establishes && consumes
            });
        if covering_discoveries.is_empty()
            && let Some(first_source) = source_procedures.first()
            && let Some(mut discovery) = disconnected_discoveries
                .iter()
                .position(|discovery| discovery.procedures.contains(first_source))
                .map(|index| disconnected_discoveries.swap_remove(index))
        {
            // The selectors bound real endpoints, but no discovered call region
            // connects them. This is an unresolved-dispatch boundary, not a
            // policy-evaluation failure: mount the disconnected endpoint
            // procedures in one bounded plan so `ValueFlowPlan` can name each
            // unreachable procedure and keep the result typed incomplete
            // (#2834). We add no call binding between them, so this cannot
            // manufacture a path or finding. In particular, a negative sibling
            // stays finding-free, while neither sibling can be read as clean.
            for endpoint in source_procedures.iter().chain(&sink_procedures) {
                if discovery.procedures.insert(endpoint.clone()) {
                    let snapshot = materialization
                        .procedures
                        .borrow()
                        .get(endpoint)
                        .and_then(CachedSemanticOutcome::value_input);
                    let Some(snapshot) = snapshot else {
                        // A skipped budget-exhausted root has no finished
                        // snapshot. Do not turn that absence into a fabricated
                        // mounted procedure; preserve the existing compile
                        // refusal instead.
                        return Err(TaintPolicyCompileError::SemanticUnavailable(
                            "no analysis root contains both a selected source and sink".to_owned(),
                        ));
                    };
                    discovery.snapshots.push(snapshot);
                }
            }
            covering_discoveries.push(discovery);
        }
        let covered = covering_discoveries
            .iter()
            .map(|discovery| discovery.procedures.clone())
            .collect::<Vec<_>>();
        let discoveries = covering_discoveries
            .into_iter()
            .enumerate()
            .filter_map(|(index, discovery)| {
                (!covered.iter().enumerate().any(|(other_index, other)| {
                    index != other_index
                        && discovery.procedures.len() < other.len()
                        && discovery.procedures.is_subset(other)
                }))
                .then_some(discovery)
            })
            .collect::<Vec<_>>();
        let mut compiled = Vec::new();
        for (root_index, discovery) in discoveries.into_iter().enumerate() {
            let root = discovery.root.clone();
            let mut sources = all_sources
                .iter()
                .zip(&source_procedures)
                .filter(|(_, procedure)| discovery.procedures.contains(*procedure))
                .map(|(endpoint, _)| endpoint.clone())
                .collect::<Vec<_>>();
            let mut sinks = all_sinks
                .iter()
                .zip(&sink_procedures)
                .filter(|(_, procedure)| discovery.procedures.contains(*procedure))
                .map(|(endpoint, _)| endpoint.clone())
                .collect::<Vec<_>>();
            let mut kills = all_kills
                .iter()
                .zip(&kill_procedures)
                .filter(|(_, procedure)| discovery.procedures.contains(*procedure))
                .map(|(kill, _)| kill.clone())
                .collect::<Vec<_>>();
            let mut transforms = all_transforms
                .iter()
                .zip(&transform_procedures)
                .filter(|(_, procedure)| discovery.procedures.contains(*procedure))
                .map(|(transform, _)| transform.clone())
                .collect::<Vec<_>>();
            let mut store_writes = all_store_writes
                .iter()
                .zip(&store_write_procedures)
                .filter(|(_, procedure)| discovery.procedures.contains(*procedure))
                .map(|(end, _)| end.clone())
                .collect::<Vec<_>>();
            let mut store_reads = all_store_reads
                .iter()
                .zip(&store_read_procedures)
                .filter(|(_, procedure)| discovery.procedures.contains(*procedure))
                .map(|(end, _)| end.clone())
                .collect::<Vec<_>>();
            let models = all_models
                .iter()
                .zip(&model_procedures)
                .filter(|(_, procedure)| discovery.procedures.contains(*procedure))
                .map(|(model, _)| model.clone())
                .collect::<Vec<_>>();
            sort_bound_endpoints(&mut sources);
            sort_bound_endpoints(&mut sinks);
            sort_bound_sanitizers(&mut kills);
            sort_bound_transforms(&mut transforms);
            sort_bound_store_ends(&mut store_writes);
            sort_bound_store_ends(&mut store_reads);
            // Store ends ride the ordinary source/sink event machinery: a
            // write is an internal value-flow sink observing the written
            // carrier and a read an internal source establishing the returned
            // carrier. Their event ordinals continue after the policy
            // endpoints' so every key stays unique, and every later binding
            // is matched by event key rather than by list position.
            let policy_source_specs = keyed_source_event_specs(&sources, 0)?;
            let read_specs = keyed_source_event_specs(
                &store_reads
                    .iter()
                    .map(|end| end.endpoint.clone())
                    .collect::<Vec<_>>(),
                sources.len(),
            )?;
            // The value-flow carrier universe is assembled from snapshots,
            // call bindings, and endpoint observations. A sanitizer can name
            // an external call's receiver even when its binding payload only
            // publishes the ordinary argument and return carriers. Register
            // both sanitizer ports as auxiliary source observations so their
            // carriers are available to the sanitizer binding; they are kept
            // out of `bind_taint_sources` and therefore never become taint
            // origins.
            let sanitizer_carriers = kills
                .iter()
                .flat_map(|sanitizer| [sanitizer.input.clone(), sanitizer.output.clone()])
                .collect::<Vec<_>>();
            let sanitizer_specs = keyed_source_event_specs(
                &sanitizer_carriers,
                sources.len().saturating_add(store_reads.len()),
            )?;
            let mut source_specs = policy_source_specs.clone();
            source_specs.extend(read_specs.iter().cloned());
            source_specs.extend(sanitizer_specs.iter().cloned());
            let mut sink_specs = keyed_sink_event_specs(&sinks, 0)?;
            let write_specs = keyed_sink_event_specs(
                &store_writes
                    .iter()
                    .map(|end| end.endpoint.clone())
                    .collect::<Vec<_>>(),
                sinks.len(),
            )?;
            sink_specs.extend(write_specs.iter().cloned());
            let rust_format_result_calls = discovery.rust_format_result_calls.clone();
            let (value_flow, call_resolution_discovery, sanitizer_declines) = self
                .build_value_flow_plan(
                    discovery,
                    source_specs.iter().map(|(_, spec)| spec.clone()).collect(),
                    sink_specs.iter().map(|(_, spec)| spec.clone()).collect(),
                    spec.call_modeling.unmodeled,
                    &conditional_sanitizers,
                    &universe,
                )?;
            let value_flow = self.install_bound_external_models(
                value_flow,
                &models,
                &universe,
                &rust_format_result_calls,
            )?;
            // A store declaration models its selected call outright: nothing
            // flows through the call directly, taint crosses only via the
            // declared boundary. The empty-transfer curated model is what
            // states that, and it is what lets an opaque store call (an
            // unresolvable static or dynamic dispatch) stop blocking a
            // complete verdict instead of abstaining the region.
            let mut store_calls: Vec<CallSiteHandle> = Vec::new();
            for end in store_writes.iter().chain(&store_reads) {
                if !store_calls
                    .iter()
                    .any(|call| call.durable_key() == end.call.durable_key())
                {
                    store_calls.push(end.call.clone());
                }
            }
            let value_flow = if store_calls.is_empty() {
                value_flow
            } else {
                let model = store_boundary_call_model()?;
                value_flow
                    .with_curated_call_models(
                        store_calls
                            .into_iter()
                            .map(|call| ValueFlowCuratedCallModel::new(call, model.clone()))
                            .collect(),
                    )
                    .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?
            };
            let value_flow = self.install_rust_std_builtin_models(value_flow)?;
            let local_rules = transforms
                .iter()
                .map(|transform| {
                    ValueFlowLocalRuleSpec::new(
                        transform.output.point.clone(),
                        transform.input.carrier.clone(),
                        transform.output.carrier.clone(),
                        conjoin_proof(&transform.input.proof, &transform.output.proof),
                        conjoin_completeness(
                            &transform.input.completeness,
                            &transform.output.completeness,
                        ),
                    )
                })
                .collect();
            let value_flow = value_flow
                .with_local_rules(local_rules)
                .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
            let taint_sources =
                bind_taint_sources(&value_flow, &universe, &sources, &policy_source_specs)?;
            let taint_sinks =
                bind_taint_sinks(&value_flow, &universe, &sinks, &sink_specs[..sinks.len()])?;
            let taint_sanitizers = bind_taint_sanitizers(&value_flow, &universe, &kills)?;
            let taint_local_transforms =
                bind_taint_local_transforms(&value_flow, &universe, &transforms)?;
            let store_write_bindings = bind_store_writes(&value_flow, &store_writes, &write_specs)?;
            let store_read_bindings = bind_store_reads(&value_flow, &store_reads, &read_specs)?;
            let sanitizer_hash = sanitizer_compatibility_hash(&value_flow, &taint_sanitizers);
            let auxiliary_hash = local_transform_compatibility_hash(
                &value_flow,
                sanitizer_hash,
                &taint_local_transforms,
            );
            let auxiliary_hash = if spec.barriers.is_empty() {
                auxiliary_hash
            } else {
                let mut hasher = DefaultHasher::new();
                hasher.write(b"bifrost-icfg-value-type-barriers-v1");
                hasher.write_u64(auxiliary_hash);
                std::hash::Hash::hash(&policy.definition().metadata.id, &mut hasher);
                for barrier in &spec.barriers {
                    std::hash::Hash::hash(&barrier.id, &mut hasher);
                    std::hash::Hash::hash(&barrier.value_type, &mut hasher);
                }
                hasher.finish()
            };
            let store_hash =
                store_compatibility_hash(&value_flow, &store_write_bindings, &store_read_bindings);
            let analysis = TaintAnalysisPlan::new(
                value_flow,
                universe.clone(),
                taint_sources,
                taint_sinks,
                taint_sanitizers,
                Vec::new(),
            )
            .and_then(|analysis| analysis.with_local_transforms(taint_local_transforms))
            .and_then(|analysis| analysis.with_stores(store_write_bindings, store_read_bindings))
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
            let analysis = analysis.with_value_type_barriers(
                spec.barriers
                    .iter()
                    .map(|barrier| (barrier.id.as_str().into(), barrier.value_type))
                    .collect(),
            );
            let call_resolution_evidence = match analysis.value_flow().first_incomplete_cause() {
                Some(ValueFlowIncompleteCause::CallResolution { call, status }) => {
                    Some(taint_call_resolution_evidence(
                        self.selectors.workspace(),
                        call,
                        *status,
                        &call_resolution_discovery,
                    )?)
                }
                _ => None,
            };
            let internal_policy_id = format!(
                "{}#root-{root_index}",
                policy.definition().metadata.id.as_str()
            );
            let compatibility = TaintBatchCompatibilityKey::with_call_behavior(
                // The value-flow propagation hash deliberately excludes
                // endpoint observations so compatible demand can share a solve,
                // but it also excludes sanitizers and store boundaries, which
                // DO change propagation results. Folding them in is what keeps
                // two policies with different kills or store models in
                // different batches instead of colliding on one key and
                // failing the planner's own equality check.
                TaintPropagationSemanticsId::new(
                    &root.artifact().key().fingerprint(),
                    root.semantics().locator(),
                    value_flow_compatibility_hash(analysis.value_flow()),
                    auxiliary_hash,
                    store_hash,
                ),
                spec.call_modeling.unmodeled,
                universe.hash(),
            );
            let plan = TaintPolicyPlan::new(internal_policy_id.clone(), compatibility, analysis)
                .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
            let mut source_metadata = endpoint_metadata(&sources, &source_specs[..sources.len()]);
            // A store-read origin is attributed back to the policy sources
            // whose labels actually flowed into the boundary: one metadata row
            // per (read event, policy source), filtered at projection time by
            // the observed classes. The read itself is not a policy source, so
            // it never stands alone in a projected finding.
            for (key, _) in &read_specs {
                for source in &spec.sources {
                    source_metadata.push(CompiledTaintEndpoint {
                        endpoint: source.identity.clone(),
                        event: key.clone(),
                    });
                }
            }
            let sink_metadata = endpoint_metadata(&sinks, &sink_specs[..sinks.len()]);
            let store_write_metadata = store_writes
                .iter()
                .zip(&write_specs)
                .map(|(end, (event, _))| CompiledStoreEnd {
                    endpoint: end.endpoint.endpoint.clone(),
                    event: event.clone(),
                    call: end.call.clone(),
                    channel: end.channel.clone(),
                })
                .collect::<Vec<_>>();
            let store_read_metadata = store_reads
                .iter()
                .zip(&read_specs)
                .map(|(end, (event, _))| CompiledStoreEnd {
                    endpoint: end.endpoint.endpoint.clone(),
                    event: event.clone(),
                    call: end.call.clone(),
                    channel: end.channel.clone(),
                })
                .collect::<Vec<_>>();
            compiled.push(CompiledTaintPolicyPlan {
                internal_policy_id,
                plan,
                engine: engine.clone(),
                scope: scope.clone(),
                sources: source_metadata.into_boxed_slice(),
                sinks: sink_metadata.into_boxed_slice(),
                store_writes: store_write_metadata.into_boxed_slice(),
                store_reads: store_read_metadata.into_boxed_slice(),
                call_resolution_evidence,
                sanitizer_declines,
                kills: kills
                    .into_iter()
                    .map(|kill| CompiledTaintKill {
                        endpoint: kill.input.endpoint,
                        point: kill.input.point,
                    })
                    .collect(),
                external_models: Arc::default(),
            });
        }
        if compiled.is_empty() {
            return Err(TaintPolicyCompileError::SemanticUnavailable(
                "no analysis root contains both a selected source and sink".to_owned(),
            ));
        }
        Ok(CompiledPolicy::Plans(compiled))
    }

    /// The plans of a composed policy, built from the
    /// specification and the bound sinks with no region discovered. Sources,
    /// sanitizers and transforms are matched on the frontier, and every
    /// call's models are answered at the call by the composition's provider,
    /// so a plan holds the sinks, the label universe and the unmodeled-call
    /// behavior, and carries the policy's bound external models beside it.
    ///
    /// A refused selector row bound no endpoint, so it costs only its own
    /// site: the refusal leaves the run incomplete, and every other sink, in
    /// the refused row's procedure or not, is composed. The ICFG engine drops
    /// the whole region instead (#2308), because a region's solve would read
    /// as clean over the site it never saw.
    ///
    /// One plan observes every sink up to the value-flow plan's sink limit, so
    /// one batch and one provider serve them all; a plan has one root, which
    /// is the first sink's procedure and names the batch.
    fn composed_plans(
        &self,
        policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
        mut sinks: Vec<BoundEndpoint>,
        models: Vec<BoundExternalModel>,
        universe: &TaintUniverse,
        scope: Option<PolicyRunScope>,
    ) -> Result<CompiledPolicy, TaintPolicyCompileError> {
        assert!(
            !sinks.is_empty(),
            "the engine rule composes only a policy with bound sinks"
        );
        sort_bound_endpoints(&mut sinks);
        let models: Arc<[BoundExternalModel]> = models.into();
        let behavior = spec.call_modeling.unmodeled;
        let plan_error =
            |error: &dyn fmt::Display| TaintPolicyCompileError::Plan(error.to_string());
        // A composed plan matches its own policy's sources, sanitizers and
        // transforms on the frontier, so its batch must hold that
        // policy alone.
        let auxiliary_hash = {
            let mut hasher = DefaultHasher::new();
            hasher.write(b"bifrost-composed-policy-compatibility-v1");
            hasher.write(policy.definition().metadata.id.as_str().as_bytes());
            for barrier in &spec.barriers {
                std::hash::Hash::hash(&barrier.id, &mut hasher);
                std::hash::Hash::hash(&barrier.value_type, &mut hasher);
            }
            hasher.finish()
        };
        let mut compiled = Vec::new();
        for (root_index, sinks) in sinks
            .chunks(ValueFlowPlanLimits::default().max_sinks())
            .enumerate()
        {
            let root = sinks[0].point.procedure().clone();
            let sink_specs = keyed_sink_event_specs(sinks, 0)?;
            let value_flow = ValueFlowPlan::with_call_behavior(
                root.clone(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                sink_specs.iter().map(|(_, spec)| spec.clone()).collect(),
                behavior,
            )
            .map_err(|error| plan_error(&error))?;
            let taint_sinks = bind_taint_sinks(&value_flow, universe, sinks, &sink_specs)?;
            let store_hash = store_compatibility_hash(&value_flow, &[], &[]);
            let analysis = TaintAnalysisPlan::new(
                value_flow,
                universe.clone(),
                Vec::new(),
                taint_sinks,
                Vec::new(),
                Vec::new(),
            )
            .map_err(|error| plan_error(&error))?;
            let internal_policy_id = format!(
                "{}#root-{root_index}",
                policy.definition().metadata.id.as_str()
            );
            let analysis = analysis.with_value_type_barriers(
                spec.barriers
                    .iter()
                    .map(|barrier| (barrier.id.as_str().into(), barrier.value_type))
                    .collect(),
            );
            let compatibility = TaintBatchCompatibilityKey::with_call_behavior(
                TaintPropagationSemanticsId::new(
                    &root.artifact().key().fingerprint(),
                    root.semantics().locator(),
                    value_flow_compatibility_hash(analysis.value_flow()),
                    auxiliary_hash,
                    store_hash,
                ),
                behavior,
                universe.hash(),
            );
            let plan = TaintPolicyPlan::new(internal_policy_id.clone(), compatibility, analysis)
                .map_err(|error| plan_error(&error))?;
            compiled.push(CompiledTaintPolicyPlan {
                internal_policy_id,
                plan,
                engine: TaintEngine::Composition,
                scope: scope.clone(),
                sources: Box::default(),
                sinks: endpoint_metadata(sinks, &sink_specs).into_boxed_slice(),
                store_writes: Box::default(),
                store_reads: Box::default(),
                call_resolution_evidence: None,
                sanitizer_declines: Vec::new(),
                kills: Box::default(),
                external_models: Arc::clone(&models),
            });
        }
        Ok(CompiledPolicy::Plans(compiled))
    }

    fn select(
        &mut self,
        selector: &ResolvedPolicySelector,
        _binding: &PolicyPort,
    ) -> Result<Vec<SelectedSite>, TaintPolicyCompileError> {
        self.selectors
            .select_taint(selector)
            .map_err(taint_selector_error)
    }

    /// The source endpoints one selected row of `source` binds.
    fn bind_source(
        &mut self,
        source: &ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>,
        selector: &ResolvedPolicySelector,
        selected: SelectedSite,
    ) -> Result<Vec<BoundEndpoint>, TaintPolicyCompileError> {
        Ok(self
            .resolve_selected_values(selected, selector, &source.definition.bind)?
            .into_iter()
            .map(|resolved| BoundEndpoint {
                endpoint: source.identity.clone(),
                kind: resolved.kind,
                dispatch_obligations: resolved.dispatch_obligations,
                point: resolved.point,
                phase: resolved.phase,
                carrier: resolved.carrier,
                proof: resolved.proof,
                completeness: resolved.completeness,
                labels: source.definition.labels.clone().into_boxed_slice(),
                unjudged: resolved.unjudged,
            })
            .collect())
    }

    /// Conditional selectors nominate calls only; a failed proof is advisory.
    fn bind_conditional_sanitizers(
        &mut self,
        spec: &ResolvedTaintPolicySpec,
        selectors: &HashMap<&PolicySelectorPath, &ResolvedPolicySelector>,
    ) -> Result<Vec<BoundConditionalSanitizer>, TaintPolicyCompileError> {
        let mut bound = Vec::new();
        let workspace = self.selectors.workspace();
        let cancellation = self.selectors.cancellation();
        let mut contexts = HashMap::new();
        for sanitizer in &spec.sanitizers {
            let TaintSanitizerKind::Conditional {
                when,
                sanitizes,
                requires,
            } = &sanitizer.definition.kind
            else {
                continue;
            };
            let incomplete_before = self.selectors.take_incomplete_taint_selectors();
            let mut result_of_calls = Vec::new();
            for (index, requirement) in requires.iter().enumerate() {
                let mut calls = Vec::new();
                if matches!(requirement.condition, TaintSanitizerCondition::ResultOf(_)) {
                    let path = crate::definition::sanitizer_requirement_selector_path(
                        sanitizer.selector_path.as_str(),
                        index,
                    );
                    let selector = selectors
                        .iter()
                        .find(|(key, _)| key.as_str() == path)
                        .map(|(_, selector)| *selector)
                        .ok_or_else(|| {
                            TaintPolicyCompileError::SemanticUnavailable(format!(
                                "missing sanitizer requirement selector {path}"
                            ))
                        })?;
                    for selected in self.select(selector, &PolicyPort::ReturnValue)? {
                        if let SelectedCallSites::One(sites) =
                            self.selected_semantic_calls(&selected)?
                        {
                            calls.extend(sites.into_iter().map(|(_, call)| call));
                        }
                    }
                }
                result_of_calls.push(calls);
            }
            let selector = required_selector(selectors, &sanitizer.selector_path)?;
            for selected in self.select(selector, &PolicyPort::ReturnValue)? {
                let SelectedCallSites::One(sites) = self.selected_semantic_calls(&selected)? else {
                    continue;
                };
                for (procedure, call_handle) in sites {
                    let call = procedure
                        .semantics()
                        .call_site(call_handle.id())
                        .expect("selected call");
                    let carrier = sanitizer_operand(call, sanitizes);
                    let admission = (|| -> Result<(), String> {
                        let carrier = carrier.ok_or("sanitized carrier operand is absent")?;
                        for (index, requirement) in requires.iter().enumerate() {
                            let operand = sanitizer_operand(call, &requirement.operand)
                                .ok_or("required operand is absent")?;
                            let origin = sanitizer_requirement_origin(
                                &procedure,
                                operand,
                                call.point,
                                &mut self.selectors.semantic_request(),
                            )
                            .map_err(|reason| format!("requires: {reason}"))?;
                            let kind = &procedure
                                .semantics()
                                .value(origin)
                                .expect("proven origin")
                                .kind;
                            match &requirement.condition {
                                TaintSanitizerCondition::Constant if !kind.is_constant() => {
                                    return Err(
                                        "required operand is not a compile-time constant".into()
                                    );
                                }
                                TaintSanitizerCondition::Equals(literal)
                                    if !sanitizer_constant_equals(
                                        kind,
                                        literal,
                                        procedure.artifact().key().language(),
                                    )? =>
                                {
                                    return Err(
                                        "required operand does not equal the authored literal"
                                            .into(),
                                    );
                                }
                                TaintSanitizerCondition::ResultOf(_)
                                    if !result_of_calls[index].iter().any(|matched| {
                                        matched.procedure().durable_key() == procedure.durable_key()
                                            && procedure
                                                .semantics()
                                                .call_site(matched.id())
                                                .expect("matched call")
                                                .normal_result_values()
                                                .any(|result| result == origin)
                                    }) =>
                                {
                                    return Err(
                                        "required operand is not the result of the selected call"
                                            .into(),
                                    );
                                }
                                _ => {}
                            }
                        }
                        let SemanticLanguage::Standard(language) =
                            procedure.artifact().key().language()
                        else {
                            return Err("carrier type undecided: UnsupportedLanguage".into());
                        };
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            contexts.entry(language)
                        {
                            entry.insert(brokk_bifrost_analysis::analyzer::semantic::open_value_type_barrier_context(language, workspace.analyzer(), cancellation)
                                .map_err(|error| format!("carrier type unavailable: {error}"))?);
                        }
                        let Some(support) =
                            brokk_bifrost_analysis::analyzer::languages::language_support(language)
                        else {
                            return Err("carrier type undecided: UnsupportedLanguage".into());
                        };
                        let _binding =
                            brokk_bifrost_analysis::analyzer::semantic::BindingOriginIndex::new(
                                &procedure,
                            )
                            .unique_binding_origin(carrier)
                            .ok_or("carrier has no unique binding origin")?;
                        let observation =
                            brokk_bifrost_analysis::analyzer::semantic::BarrierObservation::new(
                                procedure.point_handle(call.point).expect("call point"),
                                carrier,
                                ObservationPhase::BeforeEffects,
                            );
                        let mut request = self.selectors.semantic_request();
                        if let Some(context) = contexts[&language].as_deref() {
                            request = request.with_value_type_barrier_context(context);
                        }
                        // Shape exclusion is shared. Only nominal types reach the language's immutability hook.
                        match support.observed_value_type(workspace.analyzer(), &observation, &mut request)
                            .map_err(|error| format!("carrier type unavailable: {error}"))? {
                            ObservedValueType::NonNamed(shape) => Err(format!("carrier type is non-named: {shape:?}")),
                            ObservedValueType::Undecided(reason) => Err(format!("carrier type undecided: {reason:?}")),
                            ObservedValueType::Named { canonical } => {
                                if brokk_bifrost_analysis::analyzer::semantic::languages::language_knowledge(language)
                                    .is_some_and(|knowledge| knowledge.declared_type_is_referent_immutable(&canonical)) {
                                    Ok(())
                                } else {
                                    Err(format!("carrier type is not referent-immutable: {canonical}"))
                                }
                            }
                        }
                    })();
                    bound.push(BoundConditionalSanitizer {
                        id: match &sanitizer.identity {
                            ResolvedEndpointIdentity::Local { entry_id, .. }
                            | ResolvedEndpointIdentity::Catalog { entry_id, .. } => {
                                entry_id.as_str()
                            }
                            ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => {
                                endpoint_id.as_str()
                            }
                        }
                        .into(),
                        procedure: procedure.clone(),
                        guard: ConditionalGuardSanitizer {
                            call: call_handle.id(),
                            result_index: when.index,
                            carrier,
                            accepts: match when.result {
                                TaintSanitizerResult::True => ConditionalGuardResult::True,
                                TaintSanitizerResult::False => ConditionalGuardResult::False,
                                TaintSanitizerResult::Nil => ConditionalGuardResult::Nil,
                                TaintSanitizerResult::NonNil => ConditionalGuardResult::NonNil,
                            },
                        },
                        removes: sanitizer.definition.removes.clone().into_boxed_slice(),
                        admission,
                    });
                }
            }
            // Sanitizer proof failures never turn an otherwise complete flow into an incomplete result.
            self.selectors.take_incomplete_taint_selectors();
            self.selectors
                .extend_incomplete_taint_selectors(incomplete_before);
        }
        Ok(bound)
    }

    /// The sanitizers one selected row of `sanitizer` binds.
    fn bind_sanitizer(
        &mut self,
        sanitizer: &ResolvedTaintAuxiliary<ResolvedTaintSanitizerDefinition>,
        selector: &ResolvedPolicySelector,
        selected: SelectedSite,
    ) -> Result<Vec<BoundSanitizer>, TaintPolicyCompileError> {
        let Some((input, output)) = sanitizer.definition.kind.transfer_ports() else {
            // Conditional sanitizers are applied by the branch-conditioned kill derivation.
            return Ok(Vec::new());
        };
        let labels = sanitizer.definition.removes.clone().into_boxed_slice();
        Ok(self
            .resolve_selected_sanitizer_values(selected, selector, input, output)?
            .into_iter()
            .map(|resolved| BoundSanitizer {
                input: BoundEndpoint {
                    endpoint: sanitizer.identity.clone(),
                    kind: resolved.input.kind,
                    dispatch_obligations: resolved.input.dispatch_obligations,
                    point: resolved.input.point,
                    phase: resolved.input.phase,
                    carrier: resolved.input.carrier,
                    proof: resolved.input.proof,
                    completeness: resolved.input.completeness,
                    labels: labels.clone(),
                    unjudged: None,
                },
                output: BoundEndpoint {
                    endpoint: sanitizer.identity.clone(),
                    kind: resolved.output.kind,
                    dispatch_obligations: resolved.output.dispatch_obligations,
                    point: resolved.output.point,
                    phase: resolved.output.phase,
                    carrier: resolved.output.carrier,
                    proof: resolved.output.proof,
                    completeness: resolved.output.completeness,
                    labels: labels.clone(),
                    unjudged: None,
                },
            })
            .collect())
    }

    /// The transforms one selected row of `transform` binds.
    fn bind_transform(
        &mut self,
        transform: &ResolvedTaintAuxiliary<ResolvedTaintTransformDefinition>,
        selector: &ResolvedPolicySelector,
        selected: SelectedSite,
    ) -> Result<Vec<BoundTransform>, TaintPolicyCompileError> {
        Ok(self
            .resolve_selected_transfer_values(
                selected,
                selector,
                &transform.definition.input,
                &transform.definition.output,
            )?
            .into_iter()
            .map(|resolved| BoundTransform {
                input: BoundEndpoint {
                    endpoint: transform.identity.clone(),
                    kind: resolved.input.kind,
                    dispatch_obligations: resolved.input.dispatch_obligations,
                    point: resolved.input.point,
                    phase: resolved.input.phase,
                    carrier: resolved.input.carrier,
                    proof: resolved.input.proof,
                    completeness: resolved.input.completeness,
                    labels: Box::default(),
                    unjudged: None,
                },
                output: BoundEndpoint {
                    endpoint: transform.identity.clone(),
                    kind: resolved.output.kind,
                    dispatch_obligations: resolved.output.dispatch_obligations,
                    point: resolved.output.point,
                    phase: resolved.output.phase,
                    carrier: resolved.output.carrier,
                    proof: resolved.output.proof,
                    completeness: resolved.output.completeness,
                    labels: Box::default(),
                    unjudged: None,
                },
                removes: transform.definition.removes.clone().into_boxed_slice(),
                adds: transform.definition.adds.clone().into_boxed_slice(),
            })
            .collect())
    }

    /// Materialize the selected row's file and classify its semantic call sites.
    fn selected_semantic_calls(
        &mut self,
        selection: &SelectedSite,
    ) -> Result<SelectedCallSites, TaintPolicyCompileError> {
        if selection
            .call_binding
            .as_ref()
            .is_some_and(|row| row.selector_provenance == "authored_summary")
        {
            selection
                .call_binding
                .as_ref()
                .expect("authored selector has a call-binding row")
                .assert_valid_identity();
            self.authored_selector_summary = true;
        }
        let artifact = self
            .selectors
            .materialize(&selection.file)
            .map_err(taint_selector_error)?;
        let lookup = procedures_in_artifact(&artifact, usize::MAX, self.selectors.cancellation());
        match lookup.status {
            ProcedureRangeLookupStatus::Complete => {}
            ProcedureRangeLookupStatus::Cancelled => {
                return Err(TaintPolicyCompileError::QueryIncomplete {
                    completion: CodeQueryCompletion::Cancelled,
                    detail: "taint semantic call binding was cancelled".to_owned(),
                });
            }
            ProcedureRangeLookupStatus::BudgetExhausted => {
                return Err(query_budget_error(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    "taint semantic call binding exhausted the shared traversal budget",
                ));
            }
            ProcedureRangeLookupStatus::SourceChanged => {
                return Err(TaintPolicyCompileError::SemanticUnavailable(
                    "taint semantic call binding observed a changed source snapshot".to_owned(),
                ));
            }
        }
        if !self
            .selectors
            .execution_budget()
            .charge_traversal(lookup.examined)
        {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "taint semantic call binding exhausted the shared traversal budget",
            ));
        }
        Ok(select_call(&lookup.handles, selection))
    }

    /// Keep valid calls and record unsuitable rows without excluding other
    /// endpoints. Ambiguous calls retain their existing region exclusion.
    fn bind_selected_calls(
        &mut self,
        selection: &SelectedSite,
        calls: SelectedCallSites,
    ) -> Option<
        Vec<(
            ProcedureHandle,
            brokk_bifrost_analysis::analyzer::semantic::CallSiteHandle,
        )>,
    > {
        let (reason, procedures) = match calls {
            SelectedCallSites::One(sites) => return Some(sites),
            SelectedCallSites::Missing => (RefusalReason::NoSemanticCallSite, Vec::new()),
            SelectedCallSites::Ambiguous { ranges, procedures } => {
                (RefusalReason::AmbiguousCallSite(ranges), procedures)
            }
        };
        self.refused_sites.push(RefusedCallSite {
            file: selection.file.clone(),
            span: selection.span.clone(),
            reason,
            impact: PolicyDiagnosticImpact::RunIncomplete,
            procedures,
        });
        None
    }

    fn refuse_value_observation(&mut self, selection: &SelectedSite) {
        self.refused_sites.push(RefusedCallSite {
            file: selection.file.clone(),
            span: selection.span.clone(),
            reason: RefusalReason::NoValueObservation,
            impact: PolicyDiagnosticImpact::RunIncomplete,
            // There is no value endpoint to solve. Other endpoints in this
            // procedure keep their findings; the refusal caps run completion.
            procedures: Vec::new(),
        });
    }

    fn resolve_selected_values(
        &mut self,
        mut selection: SelectedSite,
        selector: &ResolvedPolicySelector,
        binding: &PolicyPort,
    ) -> Result<Vec<ResolvedTaintValue>, TaintPolicyCompileError> {
        if matches!(binding, PolicyPort::MatchedValue) {
            if selection
                .call_binding
                .as_ref()
                .is_some_and(|row| row.selector_provenance == "authored_summary")
            {
                selection
                    .call_binding
                    .as_ref()
                    .expect("authored selector has a call-binding row")
                    .assert_valid_identity();
                self.authored_selector_summary = true;
            }
            return (self.matched_values)(self, selection);
        }
        let calls = self.selected_semantic_calls(&selection)?;
        if matches!(calls, SelectedCallSites::Missing) && matches!(binding, PolicyPort::ReturnValue)
        {
            // Preserve the literal-source spelling: only a semantic literal
            // observation can promote a non-call return-value row.
            let refusals_before = self.refused_sites.len();
            let resolved = (self.matched_values)(self, selection.clone())?;
            if !resolved.is_empty()
                && resolved
                    .iter()
                    .all(|value| value.kind == TaintEndpointKind::LiteralValue)
            {
                return Ok(resolved);
            }
            // Report the requested call port's refusal instead of the
            // speculative literal observation's refusal.
            self.refused_sites.truncate(refusals_before);
        }
        let Some(sites) = self.bind_selected_calls(&selection, calls) else {
            return Ok(Vec::new());
        };
        let receiver_sites = if matches!(binding, PolicyPort::Receiver) {
            sites.clone()
        } else if matches!(binding, PolicyPort::ArgumentIndex { index: 0 }) {
            sites
                .iter()
                .filter(|(procedure, call)| {
                    let call = procedure
                        .semantics()
                        .call_site(call.id())
                        .expect("validated semantic call handle resolves");
                    call.arguments.is_empty() && call.receiver.is_some()
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        if !receiver_sites.is_empty() {
            match self
                .selectors
                .receiver_binding_applicability(&receiver_sites)
                .map_err(taint_selector_error)?
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
                    return Err(TaintPolicyCompileError::SemanticUnavailable(
                        "receiver binding remains ambiguous after semantic dispatch refinement"
                            .to_owned(),
                    ));
                }
                ReceiverBindingApplicability::Inconsistent => {
                    return Err(TaintPolicyCompileError::AmbiguousSemanticSite(
                        "semantic lowerings for one selected call disagree whether it has a receiver"
                            .to_owned(),
                    ));
                }
            }
        }
        // One source call site, lowered once per control-flow specialization.
        // Every lowering is a program site the value can reach, so bind all of
        // them; binding one would silently drop the others' paths (#2308).
        let mut resolved = Vec::with_capacity(sites.len());
        for (procedure, call) in &sites {
            // A formal-name port names the callee's parameter list, which the
            // semantic call row does not carry. Resolve it to this call's own
            // actual first, then bind exactly as an index port does, so every
            // port shares one carrier resolver (#2496).
            let named;
            let receiver_port = PolicyPort::Receiver;
            let effective = match binding {
                PolicyPort::ArgumentName { name } => {
                    if let Some(row) = selection.call_binding.as_ref() {
                        let Some(formal_name) = row.formal_name.as_ref() else {
                            self.refused_sites.push(RefusedCallSite {
                                file: selection.file.clone(),
                                span: selection.span.clone(),
                                reason: RefusalReason::UnidentifiedFormal {
                                    name: name.clone(),
                                    detail: "the callee's formal parameter names are unavailable"
                                        .to_owned(),
                                },
                                impact: PolicyDiagnosticImpact::RunIncomplete,
                                procedures: vec![procedure.durable_key()],
                            });
                            continue;
                        };
                        if formal_name != name {
                            return Err(TaintPolicyCompileError::UnsupportedBinding(format!(
                                "selected call-binding row maps formal `{formal_name}`, not requested formal `{name}`"
                            )));
                        }
                        named = PolicyPort::ArgumentIndex {
                            index: u32::try_from(row.actual_index).map_err(|_| {
                                TaintPolicyCompileError::UnsupportedBinding(
                                    "selected actual index does not fit the policy port".to_owned(),
                                )
                            })?,
                        };
                        Some((
                            &named,
                            selection.proof.clone(),
                            selection.completeness.clone(),
                        ))
                    } else {
                        match self.resolve_named_argument(call, name, selector, &selection.file)? {
                            NamedArgumentResolution::Bound(bound) => {
                                named = PolicyPort::ArgumentIndex { index: bound.index };
                                Some((&named, bound.proof, bound.completeness))
                            }
                            NamedArgumentResolution::Unidentified(detail) => {
                                self.refused_sites.push(RefusedCallSite {
                                    file: selection.file.clone(),
                                    span: selection.span.clone(),
                                    reason: RefusalReason::UnidentifiedFormal {
                                        name: name.clone(),
                                        detail,
                                    },
                                    impact: PolicyDiagnosticImpact::RunIncomplete,
                                    procedures: vec![procedure.durable_key()],
                                });
                                None
                            }
                        }
                    }
                }
                PolicyPort::ArgumentIndex { index }
                    if *index == 0
                        && call
                            .procedure()
                            .semantics()
                            .call_site(call.id())
                            .expect("validated semantic call handle resolves")
                            .arguments
                            .is_empty()
                        && call
                            .procedure()
                            .semantics()
                            .call_site(call.id())
                            .expect("validated semantic call handle resolves")
                            .receiver
                            .is_some() =>
                {
                    Some((
                        &receiver_port,
                        selection.proof.clone(),
                        selection.completeness.clone(),
                    ))
                }
                PolicyPort::ArgumentIndex { index }
                    if selection.call_binding.as_ref().is_some_and(|row| {
                        usize::try_from(*index).ok() != Some(row.formal_index)
                    }) =>
                {
                    let row = selection
                        .call_binding
                        .as_ref()
                        .expect("guard established relational call binding");
                    return Err(TaintPolicyCompileError::UnsupportedBinding(format!(
                        "selected call-binding row maps formal index {}, not requested formal index {index}",
                        row.formal_index
                    )));
                }
                PolicyPort::ArgumentIndex { .. } if selection.call_binding.as_ref().is_some() => {
                    let row = selection
                        .call_binding
                        .as_ref()
                        .expect("guard established relational call binding");
                    named = PolicyPort::ArgumentIndex {
                        index: u32::try_from(row.actual_index).map_err(|_| {
                            TaintPolicyCompileError::UnsupportedBinding(
                                "selected actual index does not fit the policy port".to_owned(),
                            )
                        })?,
                    };
                    Some((
                        &named,
                        selection.proof.clone(),
                        selection.completeness.clone(),
                    ))
                }
                _ => Some((binding, ProofStatus::Proven, EvidenceCompleteness::Complete)),
            };
            let Some((port, proof, completeness)) = effective else {
                continue;
            };
            let Some((value, point)) = select_value(procedure, call, &selection.span, port)? else {
                // The selector matched a call that has no operand at this
                // port. Refuse the site rather than guess its operand, as an
                // ambiguous row is refused (#2308).
                let semantic_call = procedure
                    .semantics()
                    .call_site(call.id())
                    .expect("validated call handle resolves");
                let semantic_arguments = semantic_call.arguments.len();
                let lowering_gap = missing_operand_has_lowering_gap(procedure, semantic_call);
                let impact = if lowering_gap {
                    PolicyDiagnosticImpact::RunIncomplete
                } else {
                    PolicyDiagnosticImpact::Advisory
                };
                self.refused_sites.push(RefusedCallSite {
                    file: selection.file.clone(),
                    span: selection.span.clone(),
                    reason: RefusalReason::MissingOperand {
                        port: operand_port_label(port),
                        arguments: semantic_arguments,
                        lowering_gap,
                    },
                    impact,
                    procedures: vec![procedure.durable_key()],
                });
                continue;
            };
            resolved.push(ResolvedTaintValue {
                call: Some(call.clone()),
                dispatch_obligations: selection
                    .call_binding
                    .as_ref()
                    .filter(|row| row.requires_dispatch())
                    .map(|_| call.clone())
                    .into_iter()
                    .collect(),
                kind: taint_endpoint_kind(procedure, call, port),
                point,
                // A call port is a carrier the selected point reads or
                // receives, never one that point's own local effects
                // define: an argument or receiver temporary is assigned at
                // the operand's own point, and a return value is bound at
                // the call's normal continuation.
                phase: ValueFlowObservationPhase::BeforeEffects,
                carrier: ValueFlowCarrier::for_value(value),
                proof: conjoin_proof(&selection.proof, &proof),
                completeness: conjoin_completeness(&selection.completeness, &completeness),
                unjudged: None,
            });
        }
        Ok(resolved)
    }

    /// Resolve both ports from one selector row. The selector gives both
    /// ports the same sites, so equal cardinality is required before pairing;
    /// a missing side is a refusal rather than a one-sided sanitizer effect.
    /// Matched-value ports are supported only as an in-place sanitizer on one
    /// point-sensitive value observation.
    fn resolve_selected_transfer_values(
        &mut self,
        selection: SelectedSite,
        selector: &ResolvedPolicySelector,
        input: &PolicyPort,
        output: &PolicyPort,
    ) -> Result<Vec<ResolvedTransferValues>, TaintPolicyCompileError> {
        if matches!(input, PolicyPort::MatchedValue) || matches!(output, PolicyPort::MatchedValue) {
            return Err(TaintPolicyCompileError::UnsupportedBinding(
                "transform input and output must be call ports".to_owned(),
            ));
        }
        self.resolve_selected_sanitizer_values(selection, selector, input, output)
    }

    fn resolve_selected_sanitizer_values(
        &mut self,
        selection: SelectedSite,
        selector: &ResolvedPolicySelector,
        input: &PolicyPort,
        output: &PolicyPort,
    ) -> Result<Vec<ResolvedTransferValues>, TaintPolicyCompileError> {
        let matched_value_transfer =
            matches!(input, PolicyPort::MatchedValue) || matches!(output, PolicyPort::MatchedValue);
        if matched_value_transfer
            && !(matches!(input, PolicyPort::MatchedValue)
                && matches!(output, PolicyPort::MatchedValue))
        {
            return Err(TaintPolicyCompileError::UnsupportedBinding(
                "transform or sanitizer must use matched-value for both ports or call ports for both ports"
                    .to_owned(),
            ));
        }
        let refusals_before = self.refused_sites.len();
        let inputs = self.resolve_selected_values(selection.clone(), selector, input)?;
        let outputs = self.resolve_selected_values(selection, selector, output)?;
        let row_refused = self.refused_sites[refusals_before..].iter().any(|refusal| {
            matches!(
                refusal.reason,
                RefusalReason::MissingOperand { .. }
                    | RefusalReason::NoSemanticCallSite
                    | RefusalReason::NoValueObservation
            )
        });
        if inputs.is_empty() || inputs.len() != outputs.len() {
            // A refused row has no endpoint for its partner port to pair
            // with. Without a refusal, the mismatch is a binding fault.
            if row_refused {
                return Ok(Vec::new());
            }
            return Err(TaintPolicyCompileError::AmbiguousSemanticSite(
                "transform or sanitizer input and output do not resolve to the same call sites"
                    .to_owned(),
            ));
        }
        let mut resolved = Vec::with_capacity(inputs.len());
        for (input, output) in inputs.into_iter().zip(outputs) {
            let same_site = if matched_value_transfer {
                input.call.is_none()
                    && output.call.is_none()
                    && input.point == output.point
                    && input.phase == output.phase
                    && input.carrier == output.carrier
            } else {
                input.call.as_ref().map(CallSiteHandle::durable_key)
                    == output.call.as_ref().map(CallSiteHandle::durable_key)
            };
            if !same_site {
                return Err(TaintPolicyCompileError::AmbiguousSemanticSite(
                    if matched_value_transfer {
                        "matched-value sanitizer input and output do not identify the same value observation"
                            .to_owned()
                    } else {
                        "transform or sanitizer input and output resolved different call sites"
                            .to_owned()
                    },
                ));
            }
            resolved.push(ResolvedTransferValues { input, output });
        }
        Ok(resolved)
    }

    /// Resolve one store end's runtime channel identity from its declared
    /// dimensions at the selected call. Resolution never refuses a site: a
    /// dimension the analysis cannot prove joins as `Unproven`, which is the
    /// whole-store fallback the public contract documents.
    fn resolve_store_channel(
        &mut self,
        store: &str,
        instance: Option<&PolicyPort>,
        key: Option<&PolicyPort>,
        resolved: &ResolvedTaintValue,
    ) -> Result<TaintStoreChannel, TaintPolicyCompileError> {
        let instance = match instance {
            None => TaintStoreDimension::Undeclared,
            Some(port) => self.resolve_instance_dimension(resolved, port)?,
        };
        let key = match key {
            None => TaintStoreDimension::Undeclared,
            Some(port) => self.resolve_key_dimension(resolved, port)?,
        };
        Ok(TaintStoreChannel::new(store, instance, key))
    }

    /// The dimension ports bind operands of the already-selected call, so
    /// only index and receiver ports are meaningful; a formal-name or result
    /// port here is an authoring error rather than an evidence shortfall.
    fn store_dimension_value(
        &mut self,
        resolved: &ResolvedTaintValue,
        port: &PolicyPort,
    ) -> Result<Option<ValueHandle>, TaintPolicyCompileError> {
        if !matches!(
            port,
            PolicyPort::ArgumentIndex { .. } | PolicyPort::Receiver
        ) {
            return Err(TaintPolicyCompileError::UnsupportedBinding(
                "a store dimension port must be (argument :index N) or receiver".to_owned(),
            ));
        }
        let Some(call) = resolved.call.as_ref() else {
            return Ok(None);
        };
        let procedure = resolved.point.procedure();
        // The span parameter feeds only matched-value ports, which the port
        // check above excludes.
        match select_value(procedure, call, &(0..0), port) {
            Ok(Some((value, _point))) => Ok(Some(value)),
            // A call without the named operand (fewer arguments, or no
            // receiver) leaves the dimension unproven; the join is sound.
            Ok(None) | Err(_) => Ok(None),
        }
    }

    /// Resolve the key before the selected invocation, independently of the
    /// value port's phase (a store read binds its output after the call).
    fn resolve_key_dimension(
        &mut self,
        resolved: &ResolvedTaintValue,
        port: &PolicyPort,
    ) -> Result<TaintStoreDimension, TaintPolicyCompileError> {
        self.store_key_metrics.operands += 1;
        let Some(value) = self.store_dimension_value(resolved, port)? else {
            self.store_key_metrics.unproven += 1;
            return Ok(TaintStoreDimension::Unproven);
        };
        let direct = self.literal_key_dimension(&value);
        if matches!(direct, TaintStoreDimension::Proven(_)) {
            self.store_key_metrics.direct_literals += 1;
            return Ok(direct);
        }
        let procedure = value.procedure();
        let call = resolved
            .call
            .as_ref()
            .expect("a selected store operand has a call");
        let limits =
            brokk_bifrost_analysis::analyzer::semantic::LocalConstantOriginLimits::default();
        let origins = brokk_bifrost_analysis::analyzer::semantic::derive_local_constant_origins(
            self.selectors.workspace(),
            procedure,
            value.id(),
            call.id(),
            limits,
            self.selectors.cancellation(),
        );
        self.store_key_metrics.work += origins.work as u64;
        if origins.cancelled {
            return Err(TaintPolicyCompileError::QueryIncomplete {
                completion: CodeQueryCompletion::Cancelled,
                detail: "store key origin analysis was cancelled".to_owned(),
            });
        }
        self.selectors
            .semantic_budget_mut()
            .charge_work(SemanticWork {
                nested_entries: origins.work,
                source_bytes: origins.source_bytes,
                ..SemanticWork::default()
            });
        self.store_key_metrics.budget_hits += u64::from(origins.budget_exhausted);
        let Some(roots) = origins.roots else {
            self.store_key_metrics.unproven += 1;
            return Ok(TaintStoreDimension::Unproven);
        };
        let mut digests = Vec::with_capacity(roots.len());
        for root in roots {
            let root = procedure
                .value_handle(root)
                .expect("validated constant origin");
            let TaintStoreDimension::Proven(digest) = self.literal_key_dimension(&root) else {
                self.store_key_metrics.unproven += 1;
                return Ok(TaintStoreDimension::Unproven);
            };
            digests.push(digest);
        }
        self.store_key_metrics.recovered += 1;
        Ok(TaintStoreDimension::proven_set(digests))
    }

    /// Hash the existing exact literal representation. Origin analysis returns
    /// semantic values, and never synthesizes or parses a replacement token.
    fn literal_key_dimension(&self, value: &ValueHandle) -> TaintStoreDimension {
        let semantics = value.procedure().semantics();
        let semantic_value = semantics.value(value.id()).expect("validated key value");
        if !semantic_value.kind.is_constant() {
            return TaintStoreDimension::Unproven;
        }
        let mapping = semantics
            .source_mapping(semantic_value.source)
            .expect("validated key source mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return TaintStoreDimension::Unproven;
        }
        let span = mapping.locator.anchor().span();
        let file = ProjectFile::new(
            self.selectors
                .workspace()
                .analyzer()
                .project()
                .root()
                .to_path_buf(),
            mapping.locator.path().as_path(),
        );
        let Some(source) = self.selectors.workspace().analyzer().indexed_source(&file) else {
            return TaintStoreDimension::Unproven;
        };
        let Some(token) = source.get(span.start_byte() as usize..span.end_byte() as usize) else {
            return TaintStoreDimension::Unproven;
        };
        string_literal_key_identity(token)
    }

    /// Bind one external-model selector row to the exact semantic calls it
    /// identifies and lower the entry's transfers for each call (#2691).
    ///
    /// Formal-name argument ports resolve to this call's own actual, exactly
    /// as endpoint ports do, and the resolution quality conjoins into the
    /// bound model so a name resolved through unproven dispatch degrades the
    /// declaration instead of overstating it. A call whose formal cannot be
    /// identified is refused into `refused_sites`, dropping the regions that
    /// could contain it, rather than modeled by guess.
    fn resolve_selected_model_calls(
        &mut self,
        selection: SelectedSite,
        selector: &ResolvedPolicySelector,
        definition: &ResolvedTaintExternalModelDefinition,
        identity: &ResolvedEndpointIdentity,
    ) -> Result<Vec<BoundExternalModel>, TaintPolicyCompileError> {
        let calls = self.selected_semantic_calls(&selection)?;
        let Some(sites) = self.bind_selected_calls(&selection, calls) else {
            return Ok(Vec::new());
        };
        let mut bound = Vec::with_capacity(sites.len());
        'site: for (procedure, call) in &sites {
            let mut proof = selection.proof.clone();
            let mut completeness = selection.completeness.clone();
            let mut transfers = Vec::with_capacity(definition.transfers.len());
            for transfer in &definition.transfers {
                let from = match self.resolve_model_port(
                    &transfer.from,
                    procedure,
                    call,
                    selector,
                    &selection,
                    &mut proof,
                    &mut completeness,
                )? {
                    Some((port, _)) => port,
                    None => continue 'site,
                };
                let (to, field) = match self.resolve_model_port(
                    &transfer.to,
                    procedure,
                    call,
                    selector,
                    &selection,
                    &mut proof,
                    &mut completeness,
                )? {
                    Some(resolved) => resolved,
                    None => continue 'site,
                };
                let removes = match &transfer.effect {
                    TaintTransferEffect::Propagate => Vec::new(),
                    TaintTransferEffect::Sanitize { removes } => removes.clone(),
                    TaintTransferEffect::Transform { .. } => {
                        unreachable!("transform effects are refused before endpoint binding")
                    }
                };
                transfers.push(LoweredModelTransfer {
                    from,
                    to,
                    labels: transfer.labels.clone(),
                    removes,
                    field,
                });
            }
            bound.push(BoundExternalModel {
                entry: identity.clone(),
                call: call.clone(),
                transfers,
                proof,
                completeness,
            });
        }
        Ok(bound)
    }

    /// Map one declared transfer port to the engine's stable summary-port
    /// vocabulary at one selected call. `None` means the port was refused for
    /// this call (recorded in `refused_sites`), so the call stays unmodeled.
    ///
    /// A field destination lowers to a stable heap port plus the declared
    /// field identity; its concrete carrier is decided against the finished
    /// value-flow plan when the model is installed, so the decision ranges
    /// over every location the solve can actually observe.
    #[allow(clippy::too_many_arguments)]
    fn resolve_model_port(
        &mut self,
        port: &PolicyPort,
        procedure: &ProcedureHandle,
        call: &CallSiteHandle,
        selector: &ResolvedPolicySelector,
        selection: &SelectedSite,
        proof: &mut ProofStatus,
        completeness: &mut EvidenceCompleteness,
    ) -> Result<Option<(SummaryPort, Option<ModelFieldDestination>)>, TaintPolicyCompileError> {
        let port = match port {
            PolicyPort::Receiver => SummaryPort::Receiver,
            PolicyPort::ReturnValue => SummaryPort::NormalReturn,
            PolicyPort::ResultIndex { index } => SummaryPort::IndexedNormalReturn(*index),
            PolicyPort::ArgumentIndex { index } => SummaryPort::Parameter(*index),
            PolicyPort::ArgumentName { name } => {
                match self.resolve_named_argument(call, name, selector, &selection.file)? {
                    NamedArgumentResolution::Bound(bound) => {
                        *proof = conjoin_proof(proof, &bound.proof);
                        *completeness = conjoin_completeness(completeness, &bound.completeness);
                        SummaryPort::Parameter(bound.index)
                    }
                    NamedArgumentResolution::Unidentified(detail) => {
                        self.refused_sites.push(RefusedCallSite {
                            file: selection.file.clone(),
                            span: selection.span.clone(),
                            reason: RefusalReason::UnidentifiedFormal {
                                name: name.clone(),
                                detail,
                            },
                            impact: PolicyDiagnosticImpact::RunIncomplete,
                            procedures: vec![procedure.durable_key()],
                        });
                        return Ok(None);
                    }
                }
            }
            PolicyPort::FieldOf { base, name } => {
                let Some((base_port, _)) = self.resolve_model_port(
                    base,
                    procedure,
                    call,
                    selector,
                    selection,
                    proof,
                    completeness,
                )?
                else {
                    return Ok(None);
                };
                let mut key_bytes = Vec::new();
                key_bytes.extend_from_slice(b"bifrost-policy-external-model-field/v1\0");
                key_bytes.extend_from_slice(format!("{base_port:?}").as_bytes());
                key_bytes.push(0);
                key_bytes.extend_from_slice(name.as_bytes());
                let heap = SummaryPort::Heap(
                    brokk_bifrost_flow::dataflow::SummaryLocationKey::hash_bytes(&key_bytes),
                );
                let base_values = self.model_field_base_values(procedure, call, &base_port)?;
                return Ok(Some((
                    heap,
                    Some(ModelFieldDestination {
                        name: name.clone(),
                        base_values,
                    }),
                )));
            }
            PolicyPort::MatchedValue => {
                return Err(TaintPolicyCompileError::UnsupportedBinding(
                    "external-model transfer ports must be call ports".to_owned(),
                ));
            }
        };
        Ok(Some((port, None)))
    }

    /// Every caller value id the object passed at `base` is known as: the
    /// argument slot holds a copy of the caller's variable, so the caller's
    /// own value-to-value relations are closed over backwards from the
    /// argument value with an explicit worklist (stack-safe for large
    /// bodies). Field locations the region can read are rooted at one of
    /// these values.
    fn model_field_base_values(
        &mut self,
        procedure: &ProcedureHandle,
        call: &CallSiteHandle,
        base: &SummaryPort,
    ) -> Result<Vec<brokk_bifrost_analysis::analyzer::semantic::ValueId>, TaintPolicyCompileError>
    {
        let Some(row) = procedure.semantics().call_site(call.id()) else {
            return Ok(Vec::new());
        };
        let base_value = match base {
            SummaryPort::Receiver => row.receiver,
            SummaryPort::Parameter(index) => usize::try_from(*index)
                .ok()
                .and_then(|index| row.arguments.get(index))
                .map(|argument| argument.value),
            _ => None,
        };
        let Some(base_value) = base_value else {
            return Ok(Vec::new());
        };
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        record_taint_artifact_read(self.selectors.workspace(), procedure);
        let outcome = {
            let mut request = self.selectors.semantic_request();
            oracle
                .procedure_relations(procedure, &OracleCallContext::empty(), &mut request)
                .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?
        };
        require_uninterrupted_outcome(&outcome, "external-model field destination")?;
        self.selectors
            .require_execution_budget("external-model field destination")
            .map_err(taint_selector_error)?;
        let Some(snapshot) = outcome.available_value() else {
            return Ok(vec![base_value]);
        };
        let mut equivalent = vec![base_value];
        let mut frontier = vec![base_value];
        while let Some(current) = frontier.pop() {
            for relation in snapshot.relations() {
                let (
                    brokk_bifrost_analysis::analyzer::semantic::ValueFlowEndpoint::Value(source),
                    brokk_bifrost_analysis::analyzer::semantic::ValueFlowEndpoint::Value(target),
                ) = (&relation.source, &relation.target)
                else {
                    continue;
                };
                if target.id() == current && !equivalent.contains(&source.id()) {
                    equivalent.push(source.id());
                    frontier.push(source.id());
                }
            }
        }
        Ok(equivalent)
    }

    /// Materialize the declared name of one field memory-location member from
    /// its declaration anchor in the indexed source. The anchor is the
    /// adapter-validated identity of the field's declaring identifier, so the
    /// slice is a structured name lookup, not a text search.
    fn field_member_name(
        &mut self,
        member: &brokk_bifrost_analysis::analyzer::semantic::ScopedSemanticLocator,
    ) -> Option<String> {
        let locator = member.locator();
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
        let source = self
            .selectors
            .workspace()
            .analyzer()
            .indexed_source(&file)?;
        source
            .get(span.start_byte() as usize..span.end_byte() as usize)
            .map(str::to_owned)
    }

    /// An instance identity is proven when the dimension port's operand
    /// expression resolves, through the reference resolver, to exactly one
    /// declaration: that declaration's stable identity is the identity. Two
    /// reads of one static field or module binding then agree across
    /// procedures, and two distinct declarations separate. A local binder is
    /// procedure-scoped, so it cannot link across procedures and joins; so
    /// does anything the resolver cannot answer uniquely.
    fn resolve_instance_dimension(
        &mut self,
        resolved: &ResolvedTaintValue,
        port: &PolicyPort,
    ) -> Result<TaintStoreDimension, TaintPolicyCompileError> {
        let Some(value) = self.store_dimension_value(resolved, port)? else {
            return Ok(TaintStoreDimension::Unproven);
        };
        let procedure = resolved.point.procedure();
        let semantics = procedure.semantics();
        let Some(semantic_value) = semantics.value(value.id()) else {
            return Ok(TaintStoreDimension::Unproven);
        };
        let Some(mapping) = semantics.source_mapping(semantic_value.source) else {
            return Ok(TaintStoreDimension::Unproven);
        };
        if mapping.kind != SourceMappingKind::Exact {
            return Ok(TaintStoreDimension::Unproven);
        }
        let span = mapping.locator.anchor().span();
        let file = ProjectFile::new(
            self.selectors
                .workspace()
                .analyzer()
                .project()
                .root()
                .to_path_buf(),
            mapping.locator.path().as_path(),
        );
        let Some(source) = self.selectors.workspace().analyzer().indexed_source(&file) else {
            return Ok(TaintStoreDimension::Unproven);
        };
        let outcome = resolve_definition_batch_with_source(
            self.selectors.workspace().analyzer(),
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(span.start_byte() as usize),
                end_byte: Some(span.end_byte() as usize),
            }],
            file,
            Arc::from(source),
        )
        .into_iter()
        .next();
        let Some(outcome) = outcome else {
            return Ok(TaintStoreDimension::Unproven);
        };
        if !matches!(outcome.status, DefinitionLookupStatus::Resolved) {
            return Ok(TaintStoreDimension::Unproven);
        }
        let mut declarations = outcome
            .definitions
            .iter()
            .map(|unit| unit.declaration_id())
            .collect::<Vec<_>>();
        declarations.sort();
        declarations.dedup();
        let [declaration] = declarations.as_slice() else {
            return Ok(TaintStoreDimension::Unproven);
        };
        let mut digest = LengthDelimitedDigest::new(b"bifrost.taint.store-instance.declaration.v1");
        digest.push(declaration.as_str().as_bytes());
        Ok(TaintStoreDimension::Proven(digest.finish()))
    }

    /// The structural route's answer for one whole selector, computed once.
    ///
    /// It costs an extra selector scan, so it is taken only where the oracle
    /// relation retained no mapping.
    fn named_actuals(
        &mut self,
        selector: &ResolvedPolicySelector,
        name: &str,
    ) -> Result<NamedActualSpans, TaintPolicyCompileError> {
        let key = (selector.path.clone(), name.to_owned());
        if let Some(cached) = self.named_actuals.get(&key) {
            return Ok(Arc::clone(cached));
        }
        let actuals: NamedActualSpans = self
            .selectors
            .select_named_actuals(selector, name)
            .map_err(taint_selector_error)?
            .into();
        self.named_actuals.insert(key, Arc::clone(&actuals));
        Ok(actuals)
    }

    /// Resolve `(argument :name ...)` to the ordinal of the actual this call
    /// passes to that formal, with the quality of the evidence that mapped it.
    ///
    /// The semantic call row records operands, never formals, so the answer
    /// comes from a caller/callee binding relation. Two of them are read, in
    /// order.
    ///
    /// The oracle's dispatch-aware `CallBindings` is the authoritative one. It
    /// maps a positional actual to a `ProcedurePortKind::Parameter` ordinal of
    /// an exact dispatch target, and the name of that ordinal comes from the
    /// target's own declaration, so it carries per-candidate proof and
    /// completeness. It says nothing about a keyword actual: the semantic row
    /// records `ArgumentDomain::Keyword` but not which keyword, so the oracle's
    /// producer retains no mapping for `put(value=x)`.
    ///
    /// The analyzer's structural actual-to-formal relation -- what
    /// `(call-input :parameter-name ...)` publishes -- reads the label from the
    /// call's own syntax and answers that case. A binding taken from it is
    /// neither proven nor complete, because this seam cannot re-derive the
    /// relation's own dispatch evidence.
    ///
    /// Whichever relation answers, the whole resolved candidate set has to
    /// agree before the port binds. One candidate's mapping is one candidate's
    /// evidence; a sibling that maps the formal elsewhere, declares no formal
    /// of that name, or whose declaration this seam could not read leaves the
    /// actual unidentified rather than letting the confident candidate, or a
    /// keyword label at the call site, stand for the call.
    ///
    /// Nothing here fails silently. An exactly resolved target that does not
    /// declare the formal is a typed error; every other shortfall -- an
    /// unresolved callee, an open argument group, a candidate set that does not
    /// agree, a declaration that could not be read -- either degrades the
    /// endpoint's proof and completeness or refuses the row with a named
    /// diagnostic.
    fn resolve_named_argument(
        &mut self,
        call: &CallSiteHandle,
        name: &str,
        selector: &ResolvedPolicySelector,
        file: &ProjectFile,
    ) -> Result<NamedArgumentResolution, TaintPolicyCompileError> {
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        record_taint_artifact_read(self.selectors.workspace(), call.procedure());
        let dispatch = {
            let mut request = self.selectors.semantic_request();
            oracle
                .resolve_call(call, &mut request)
                .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?
        };
        record_dispatch_read(self.selectors.workspace(), call, &dispatch);
        require_uninterrupted_outcome(&dispatch, "formal-name dispatch")?;
        self.selectors
            .require_execution_budget("formal-name dispatch")
            .map_err(taint_selector_error)?;
        // Dispatch quality is the first half of the endpoint's evidence. An
        // unproven or non-exhaustive answer still names candidates worth
        // consulting; it just cannot make the resulting endpoint proven.
        let mut proof = ProofStatus::Proven;
        let mut completeness = EvidenceCompleteness::Complete;
        if !dispatch.is_complete() {
            completeness =
                EvidenceCompleteness::Partial("formal-name dispatch did not complete".into());
        }
        // A callee that does not resolve leaves the oracle nothing to say. It
        // is not a decision, so it does not return here: the structural
        // relation below still reads a keyword label off the call's own syntax,
        // and that is the whole Python case.
        let candidates = dispatch
            .available_value()
            .map(|dispatch| {
                if dispatch.coverage() != CandidateCoverage::Exhaustive {
                    completeness = EvidenceCompleteness::Partial(
                        "formal-name dispatch coverage is not exhaustive".into(),
                    );
                }
                dispatch.candidates().to_vec()
            })
            .unwrap_or_default();
        if candidates.is_empty() {
            proof = ProofStatus::Unproven("the callee of this call does not resolve".into());
            completeness =
                EvidenceCompleteness::Partial("formal-name binding has no resolved callee".into());
        }
        // An exact target set is what makes "this formal does not exist" a
        // statement about the code rather than about the analysis.
        let exact = !candidates.is_empty()
            && dispatch
                .available_value()
                .is_some_and(|dispatch| dispatch.coverage() == CandidateCoverage::Exhaustive)
            && candidates
                .iter()
                .all(|candidate| matches!(candidate.proof(), ProofStatus::Proven));
        let mut index: Option<u32> = None;
        // A name binds this call only if the whole resolved candidate set says
        // so. What one candidate declares is that candidate's evidence, not the
        // call's, so the loop below gathers facts about the set and the
        // refusals after it are stated over the set:
        //
        // - `read_formals`: some candidate's parameter list was read at all. A
        //   declaration nobody could parse is an evidence gap, and must not be
        //   reported as "the target has no such formal".
        // - `declares_formal`: some candidate declares a formal of this name.
        // - `known_nondeclared_candidate`: some candidate's list was read and
        //   does not declare it.
        // - `formal_names_unavailable`: some candidate has a parameter whose
        //   semantic IR does not publish one unique name. This seam may neither
        //   bind that candidate by ordinal nor report the requested name absent.
        // - `mapped_candidates`: how many candidates mapped the name onto the
        //   single actual `index` holds. Anything short of every candidate is
        //   a set that does not agree.
        //
        // A keyword mapping is the one route exempt from all of this: it states
        // the formal's name itself, so it binds without consulting any table.
        let mut read_formals = false;
        let mut declares_formal = false;
        let mut known_nondeclared_candidate = false;
        let mut formal_names_unavailable = false;
        let mut declared = Vec::new();
        let mut mapped_candidates = 0_usize;
        for candidate in &candidates {
            if let ProofStatus::Unproven(reason) = candidate.proof() {
                proof = ProofStatus::Unproven(reason.clone());
            }
            if let EvidenceCompleteness::Partial(reason) = candidate.completeness() {
                completeness = EvidenceCompleteness::Partial(reason.clone());
            }
            let names = self.formal_ir_names(candidate.target())?;
            if let Some(names) = &names {
                read_formals = true;
                let candidate_declares = names.iter().any(|slot| parameter_names_match(slot, name));
                if candidate_declares {
                    declares_formal = true;
                } else {
                    known_nondeclared_candidate = true;
                    if declared.is_empty() {
                        declared = names
                            .iter()
                            .map(|slot| slot.first().cloned().unwrap_or_default())
                            .collect();
                    }
                }
            } else {
                formal_names_unavailable = true;
            }
            record_taint_artifact_read(self.selectors.workspace(), call.procedure());
            record_taint_artifact_read(self.selectors.workspace(), candidate.target());
            let bindings = {
                let mut request = self.selectors.semantic_request();
                oracle
                    .call_bindings(call, candidate, &OracleCallContext::empty(), &mut request)
                    .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?
            };
            require_uninterrupted_outcome(&bindings, "formal-name argument binding")?;
            self.selectors
                .require_execution_budget("formal-name argument binding")
                .map_err(taint_selector_error)?;
            if !bindings.is_complete() {
                completeness = EvidenceCompleteness::Partial(
                    "formal-name argument binding did not complete".into(),
                );
            }
            let Some(bindings) = bindings.available_value() else {
                return Ok(NamedArgumentResolution::Unidentified(
                    "the caller/callee argument relation is unavailable".to_owned(),
                ));
            };
            if bindings.coverage() != CandidateCoverage::Exhaustive {
                completeness = EvidenceCompleteness::Partial(
                    "formal-name argument coverage is not exhaustive".into(),
                );
            }
            let mut mapped = Vec::new();
            for binding in bindings.bindings() {
                let CallBinding::ArgumentGroup(group) = binding else {
                    continue;
                };
                if group.coverage() != CandidateCoverage::Exhaustive {
                    completeness = EvidenceCompleteness::Partial(
                        "formal-name binding crosses an open argument group".into(),
                    );
                }
                for mapping in group.mappings() {
                    if !self.mapping_names_formal(mapping.value(), name, names.as_deref()) {
                        continue;
                    }
                    if let ProofStatus::Unproven(reason) = mapping.proof() {
                        proof = ProofStatus::Unproven(reason.clone());
                    }
                    if let EvidenceCompleteness::Partial(reason) = mapping.completeness() {
                        completeness = EvidenceCompleteness::Partial(reason.clone());
                    }
                    mapped.push(mapping.value().source_index());
                }
            }
            mapped.sort_unstable();
            mapped.dedup();
            match mapped.as_slice() {
                [] => {}
                [only] => match index {
                    None => {
                        index = Some(*only);
                        mapped_candidates = mapped_candidates.saturating_add(1);
                    }
                    Some(previous) if previous == *only => {
                        mapped_candidates = mapped_candidates.saturating_add(1);
                    }
                    Some(previous) => {
                        return Ok(NamedArgumentResolution::Unidentified(format!(
                            "dispatch candidates map it to argument {previous} and argument \
                             {only}"
                        )));
                    }
                },
                many => {
                    return Ok(NamedArgumentResolution::Unidentified(format!(
                        "one target maps it to {} actuals {many:?}",
                        many.len()
                    )));
                }
            }
        }
        // Agreement is the binding condition. A sibling candidate that declares
        // no such formal, or that maps the name nowhere, leaves this call's
        // actual unidentified however confidently another candidate answered.
        // The non-declaring case is reported first because it is the cause the
        // author can act on; the count is what catches the rest, including a
        // candidate whose table was withheld and so mapped nothing.
        if index.is_some() && known_nondeclared_candidate {
            return Ok(NamedArgumentResolution::Unidentified(
                "a dispatch candidate does not declare the named formal".to_owned(),
            ));
        }
        if index.is_some() && mapped_candidates != candidates.len() {
            return Ok(NamedArgumentResolution::Unidentified(
                "dispatch candidates do not all map the formal to one actual".to_owned(),
            ));
        }
        // An unresolved or incomplete candidate can still retain no semantic
        // binding for an actual. In that bounded case, consult the analyzer's
        // structural actual-to-formal relation. This is the same relation
        // `(call-input :parameter-name ...)` publishes, and a binding taken
        // from it is complete only up to that relation.
        let index = match index {
            Some(index) => Some(index),
            None => {
                let actuals = self.named_actuals(selector, name)?;
                let actuals = actuals
                    .iter()
                    .filter(|(actual_file, _)| actual_file == file)
                    .map(|(_, span)| span.clone())
                    .collect::<Vec<_>>();
                let matched = self.structural_named_argument(call, &actuals);
                // The structural relation reads a label off this call's syntax
                // and knows nothing about the callee. That is enough when the
                // candidate set's declarations are understood, and it is not
                // enough to overrule them: a candidate that does not declare
                // the formal, or whose table was withheld, is a fact about the
                // target that a label at the call site cannot answer.
                if matched.is_some() && (known_nondeclared_candidate || formal_names_unavailable) {
                    return Ok(NamedArgumentResolution::Unidentified(
                        if known_nondeclared_candidate {
                            "a dispatch candidate does not declare the named formal".to_owned()
                        } else {
                            "a dispatch candidate's formal names are unavailable".to_owned()
                        },
                    ));
                }
                if matched.is_some() {
                    proof = ProofStatus::Unproven(
                        "formal-name binding rests on the structural actual-to-formal relation"
                            .into(),
                    );
                    completeness = EvidenceCompleteness::Partial(
                        "formal-name binding rests on the structural actual-to-formal relation"
                            .into(),
                    );
                }
                matched
            }
        };
        let Some(index) = index else {
            // Exactly one proven target, its parameter list read, and no
            // formal of that name: the policy names something that is not
            // there. Say so rather than quietly binding nothing (#2496).
            if exact && read_formals && !formal_names_unavailable && !declares_formal {
                let target = candidates
                    .first()
                    .map(|candidate| format!("{:?}", candidate.target().semantics().locator()))
                    .unwrap_or_default();
                return Err(TaintPolicyCompileError::UnknownFormalName {
                    name: name.to_owned(),
                    target,
                    declared,
                });
            }
            return Ok(NamedArgumentResolution::Unidentified(
                if candidates.is_empty() {
                    "the callee does not resolve here, and no actual at this call is written \
                     with that formal's name"
                        .to_owned()
                } else {
                    "no retained argument binding reaches that formal".to_owned()
                },
            ));
        };
        Ok(NamedArgumentResolution::Bound(NamedArgumentBinding {
            index,
            proof,
            completeness,
        }))
    }

    /// The ordinal of this call's own operand that the structural
    /// actual-to-formal relation bound to the requested formal.
    ///
    /// `actuals` holds every such operand of the whole selector, because a row
    /// carries only its own span. Intersecting it with this call's operand
    /// spans is what keeps a nested call's actual out: `store.put(wrap(value))`
    /// contains the inner call's `value` operand inside the outer call's span,
    /// but only `wrap(value)` is an operand of the outer call.
    fn structural_named_argument(
        &self,
        call: &CallSiteHandle,
        actuals: &[ByteRange<usize>],
    ) -> Option<u32> {
        if actuals.is_empty() {
            return None;
        }
        let semantics = call.procedure().semantics();
        let row = semantics.call_site(call.id())?;
        let mut matched = Vec::new();
        for (index, argument) in row.arguments.iter().enumerate() {
            let Some(value) = semantics.value(argument.value) else {
                continue;
            };
            let Some(mapping) = semantics.source_mapping(value.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            let operand = span.start_byte() as usize..span.end_byte() as usize;
            if actuals
                .iter()
                .any(|actual| actual.start <= operand.start && actual.end >= operand.end)
            {
                matched.push(u32::try_from(index).ok()?);
            }
        }
        match matched.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
    }

    /// Whether one retained actual-to-formal mapping reaches the named formal.
    ///
    /// A positional actual states an ordinal, and the name of that ordinal is a
    /// property of the resolved target's semantic parameter row. A keyword
    /// mapping states the formal's name directly.
    fn mapping_names_formal(
        &self,
        mapping: &CallArgumentMapping,
        name: &str,
        formals: Option<&[Box<[String]>]>,
    ) -> bool {
        if let CallArgumentMember::Keyword(keyword) = mapping.member()
            && parameter_name_matches(keyword, name)
        {
            return true;
        }
        let ProcedurePortKind::Parameter { ordinal } = mapping.formal().kind() else {
            return false;
        };
        formals
            .and_then(|formals| formals.get(ordinal as usize))
            .is_some_and(|slot| parameter_names_match(slot, name))
    }

    /// The formal parameter names of one callee, indexed by the parameter
    /// ordinal a `call_binding` row names.
    ///
    /// Names come directly from the parameter rows that define the oracle's
    /// procedure ports. `None` means at least one parameter has no unique name;
    /// that is an evidence shortfall, never a decision that a formal is absent.
    fn formal_ir_names(
        &self,
        procedure: &ProcedureHandle,
    ) -> Result<Option<FormalSlotNames>, TaintPolicyCompileError> {
        let semantics = procedure.semantics();
        let mut names: Vec<Box<[String]>> = Vec::new();
        for value in semantics.values() {
            let SemanticValueKind::Parameter { ordinal, name, .. } = &value.kind else {
                continue;
            };
            let Some(name) = name else {
                return Ok(None);
            };
            let ordinal = *ordinal as usize;
            if names.len() <= ordinal {
                names.resize(ordinal + 1, Box::default());
            }
            names[ordinal] = vec![name.to_string()].into_boxed_slice();
        }
        if names.iter().any(|slot| slot.is_empty()) {
            return Ok(None);
        }
        Ok(Some(names.into()))
    }

    fn resolve_matched_value(
        &mut self,
        selection: SelectedSite,
    ) -> Result<Vec<ResolvedTaintValue>, TaintPolicyCompileError> {
        if let Some(parameter) = selection.decorated_parameter.clone() {
            return self.resolve_decorated_parameter_value(selection, parameter);
        }
        let dispatch_calls = if selection
            .call_binding
            .as_ref()
            .is_some_and(|row| row.requires_dispatch())
        {
            let calls = self.selected_semantic_calls(&selection)?;
            let Some(sites) = self.bind_selected_calls(&selection, calls) else {
                return Ok(Vec::new());
            };
            sites.into_iter().map(|(_, call)| call).collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let workspace = self.selectors.workspace();
        let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
            workspace,
            self.active_semantic_model_snapshot.clone(),
            DispatchHints::empty(),
        );
        let (outcome, source_observation_complete) = {
            let mut request = self.selectors.semantic_request();
            if let Some(endpoint) = selection.runtime_keyed_read.as_ref() {
                let outcome = oracle
                    .pointees_for_keyed_read(endpoint, &mut request)
                    .map_err(|error| {
                        TaintPolicyCompileError::SemanticProvider(error.to_string())
                    })?;
                let source_observation_complete =
                    matches!(outcome, SemanticOutcome::Complete { .. })
                        && outcome.available_value().is_some_and(|result| {
                            result.coverage() == CandidateCoverage::Exhaustive
                        });
                let values = outcome.map(|result| {
                    result
                        .observations()
                        .iter()
                        .map(|observation| observation.query().clone())
                        .collect::<Vec<_>>()
                        .into_boxed_slice()
                });
                (values, source_observation_complete)
            } else {
                if selection.runtime_keyed_read_row {
                    if selection.runtime_keyed_read_conclusive_exclusion {
                        return Ok(Vec::new());
                    }
                    return Err(TaintPolicyCompileError::SemanticUnavailable(
                        "runtime keyed-read selector produced incomplete endpoint evidence"
                            .to_owned(),
                    ));
                }
                let outcome = oracle
                    .value_observations_at_source(
                        &selection.file,
                        super::selector_compiler::source_range(&selection.span),
                        &mut request,
                    )
                    .map_err(|error| {
                        TaintPolicyCompileError::SemanticProvider(error.to_string())
                    })?;
                let source_observation_complete =
                    matches!(outcome, SemanticOutcome::Complete { .. });
                (outcome, source_observation_complete)
            }
        };
        require_uninterrupted_outcome(&outcome, "taint matched source binding")?;
        self.selectors
            .require_execution_budget("taint matched source binding")
            .map_err(taint_selector_error)?;
        let Some(result) = outcome.available_value() else {
            if selection.occurrence_role
                == Some(brokk_bifrost_analysis::analyzer::structural::OccurrenceRole::Binder)
                && matches!(outcome, SemanticOutcome::Unknown { .. })
            {
                return Ok(Vec::new());
            }
            self.refuse_value_observation(&selection);
            return Ok(Vec::new());
        };
        if let Some(observation) = result.first() {
            self.selectors.remember_artifact(
                selection.file.clone(),
                Arc::clone(observation.point().procedure().artifact()),
            );
        }
        let endpoint_quality = selection.runtime_keyed_read.as_ref().map(|endpoint| {
            if endpoint.source_origin != RuntimeReadSourceOrigin::PristineRuntimeInput {
                return (
                    ProofStatus::Unproven(
                        "runtime keyed-read source origin is not pristine runtime input".into(),
                    ),
                    EvidenceCompleteness::Partial(
                        "runtime keyed-read source origin is not eligible for matched-value".into(),
                    ),
                );
            }
            (endpoint.proof.clone(), endpoint.completeness.clone())
        });
        // A matched source is the value read at this selected point. Which
        // object a formal base aliases does not change what flows from the
        // read; aliasing for kills and sanitizers is the flow solver's question.
        // The points-to objects were never consumed here, and establishing a
        // formal's identity needs every caller, which dynamic dispatch cannot
        // provide. The file-local projection is therefore the source evidence.
        let proof = if source_observation_complete {
            endpoint_quality.as_ref().map_or_else(
                || selection.proof.clone(),
                |(proof, _)| conjoin_proof(&selection.proof, proof),
            )
        } else {
            let proof = conjoin_proof(
                &selection.proof,
                &ProofStatus::Unproven("matched source observation is not proven".into()),
            );
            endpoint_quality
                .as_ref()
                .map_or(proof.clone(), |(endpoint_proof, _)| {
                    conjoin_proof(&proof, endpoint_proof)
                })
        };
        let completeness = if source_observation_complete {
            endpoint_quality.as_ref().map_or_else(
                || selection.completeness.clone(),
                |(_, endpoint_completeness)| {
                    conjoin_completeness(&selection.completeness, endpoint_completeness)
                },
            )
        } else {
            let completeness = conjoin_completeness(
                &selection.completeness,
                &EvidenceCompleteness::Partial(
                    "matched source observation coverage is not exhaustive".into(),
                ),
            );
            endpoint_quality
                .as_ref()
                .map_or(completeness.clone(), |(_, endpoint_completeness)| {
                    conjoin_completeness(&completeness, endpoint_completeness)
                })
        };
        Ok(result
            .iter()
            .map(|observation| {
                matched_value_endpoint(
                    observation,
                    &dispatch_calls,
                    proof.clone(),
                    completeness.clone(),
                )
            })
            .collect())
    }

    /// Resolve a matched value on the composition's frontier from the
    /// file-local value observations at the selected range.
    ///
    /// The up-front path, [`Self::resolve_matched_value`], asks for the
    /// points-to set of every observation and keeps only the observations
    /// that have one; for a value traced to a formal that means every caller
    /// of the procedure, then theirs. The composition never reads that set:
    /// a frontier endpoint is the value or parameter port at its point, and
    /// its quality comes from the path the search composes through it. So
    /// this resolver asks no heap question and keeps every observation. Its
    /// proof and completeness are those of the selected row and of the
    /// projection itself (a truncated or incompletely materialized
    /// projection is unproven and partial).
    ///
    /// Every value it resolves, a literal included, records its row in
    /// `unjudged`. A source bound from it carries unknown evidence, and the
    /// composition judges that evidence with the ICFG engine's own
    /// resolution, [`Self::resolve_matched_value`], only for a source on a
    /// reported path ([`FrontierEndpointBinder::source_evidence`]). A
    /// matched-value sanitizer or transform keeps the proof and completeness
    /// computed here: the search needs a sanitizer's proof to evaluate labels
    /// along a path, so it cannot defer it.
    fn resolve_frontier_matched_value(
        &mut self,
        selection: SelectedSite,
    ) -> Result<Vec<ResolvedTaintValue>, TaintPolicyCompileError> {
        if let Some(parameter) = selection.decorated_parameter.clone() {
            return self.resolve_decorated_parameter_value(selection, parameter);
        }
        assert!(
            selection.runtime_keyed_read.is_none() && !selection.runtime_keyed_read_row,
            "a runtime keyed read is a JavaScript, TypeScript or Python row; the composition's frontier visits Rust procedures only"
        );
        let dispatch_calls = if selection
            .call_binding
            .as_ref()
            .is_some_and(|row| row.requires_dispatch())
        {
            let calls = self.selected_semantic_calls(&selection)?;
            let Some(sites) = self.bind_selected_calls(&selection, calls) else {
                return Ok(Vec::new());
            };
            sites.into_iter().map(|(_, call)| call).collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let workspace = self.selectors.workspace();
        let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
            workspace,
            self.active_semantic_model_snapshot.clone(),
            DispatchHints::empty(),
        );
        let outcome = {
            let mut request = self.selectors.semantic_request();
            oracle
                .value_observations_at_source(
                    &selection.file,
                    super::selector_compiler::source_range(&selection.span),
                    &mut request,
                )
                .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?
        };
        require_uninterrupted_outcome(&outcome, "taint matched source binding")?;
        self.selectors
            .require_execution_budget("taint matched source binding")
            .map_err(taint_selector_error)?;
        let Some(observations) = outcome.available_value() else {
            if selection.occurrence_role
                == Some(brokk_bifrost_analysis::analyzer::structural::OccurrenceRole::Binder)
                && matches!(outcome, SemanticOutcome::Unknown { .. })
            {
                return Ok(Vec::new());
            }
            self.refuse_value_observation(&selection);
            return Ok(Vec::new());
        };
        if let Some(observation) = observations.first() {
            self.selectors.remember_artifact(
                selection.file.clone(),
                Arc::clone(observation.point().procedure().artifact()),
            );
        }
        let (proof, completeness) = if matches!(outcome, SemanticOutcome::Complete { .. }) {
            (selection.proof.clone(), selection.completeness.clone())
        } else {
            (
                conjoin_proof(
                    &selection.proof,
                    &ProofStatus::Unproven("matched value observations are not proven".into()),
                ),
                conjoin_completeness(
                    &selection.completeness,
                    &EvidenceCompleteness::Partial(
                        "matched value observations are incomplete".into(),
                    ),
                ),
            )
        };
        let unjudged = Arc::new(selection);
        Ok(observations
            .iter()
            .map(|observation| {
                let mut value = matched_value_endpoint(
                    observation,
                    &dispatch_calls,
                    proof.clone(),
                    completeness.clone(),
                );
                value.unjudged = Some(Arc::clone(&unjudged));
                value
            })
            .collect())
    }

    fn resolve_decorated_parameter_value(
        &mut self,
        selection: SelectedSite,
        parameter: super::selector_compiler::PolicyDecoratedParameterSelection,
    ) -> Result<Vec<ResolvedTaintValue>, TaintPolicyCompileError> {
        let artifact = self
            .selectors
            .materialize_with_artifact_continuation(&selection.file)
            .map_err(taint_selector_error)?;
        let procedure_id = artifact
            .procedure_id(parameter.value_locator.procedure_locator())
            .ok_or_else(|| {
                TaintPolicyCompileError::SemanticUnavailable(
                    "decorated parameter procedure is absent from the retained semantic artifact"
                        .to_owned(),
                )
            })?;
        let procedure = artifact
            .procedure_handle(procedure_id)
            .expect("semantic artifact procedure ID must resolve to a scoped handle");
        parameter
            .value_locator
            .validate_owner(&procedure)
            .map_err(|error| {
                TaintPolicyCompileError::SemanticUnavailable(format!(
                    "decorated parameter semantic identity is stale: {error}"
                ))
            })?;
        let value = procedure
            .value_handle(parameter.value_locator.id())
            .ok_or_else(|| {
                TaintPolicyCompileError::SemanticUnavailable(
                    "decorated parameter value is absent from its semantic procedure".to_owned(),
                )
            })?;
        let value_row = procedure
            .semantics()
            .value(value.id())
            .expect("validated semantic value handle resolves to its row");
        let SemanticValueKind::Parameter { ordinal, .. } = value_row.kind else {
            return Err(TaintPolicyCompileError::SemanticUnavailable(
                "decorated parameter identity resolved to a non-parameter semantic value"
                    .to_owned(),
            ));
        };
        let port = ProcedurePortHandle::parameter(procedure.clone(), ordinal).map_err(|error| {
            TaintPolicyCompileError::SemanticUnavailable(format!(
                "decorated parameter has no matching procedure port: {error}"
            ))
        })?;
        let durable_port = DurablePortIdentity::of(&port).map_err(|error| {
            TaintPolicyCompileError::SemanticUnavailable(format!(
                "decorated parameter port identity is unavailable: {error}"
            ))
        })?;
        if durable_port != parameter.port {
            return Err(TaintPolicyCompileError::SemanticUnavailable(
                "decorated parameter value and retained procedure port disagree".to_owned(),
            ));
        }
        Ok(vec![resolved_entry_parameter_value(
            &procedure,
            port,
            selection.proof,
            selection.completeness,
        )])
    }

    /// Resolve one selected entry-point declaration row to its own procedure's
    /// formal-parameter port (#2692).
    ///
    /// The row selects a *declaration*, not a call, so the procedure is found
    /// by its declared source range: an exact range match wins, otherwise the
    /// smallest declaration that fully encloses the selected node (a selector
    /// may match the name or an annotated sub-node of the declaration). A
    /// nested callable inside the selected declaration never encloses it, so
    /// it cannot be chosen. The bound value is the formal at the procedure's
    /// entry point before any local effect, exactly like a decorated-parameter
    /// source, so ordinary local value-flow rules carry it into the body.
    fn resolve_entry_point_parameter_values(
        &mut self,
        selection: SelectedSite,
        parameter: &PolicyPort,
    ) -> Result<Vec<ResolvedTaintValue>, TaintPolicyCompileError> {
        let artifact = self
            .selectors
            .materialize_with_artifact_continuation(&selection.file)
            .map_err(taint_selector_error)?;
        let lookup = procedures_in_artifact(&artifact, usize::MAX, self.selectors.cancellation());
        match lookup.status {
            ProcedureRangeLookupStatus::Complete => {}
            ProcedureRangeLookupStatus::Cancelled => {
                return Err(TaintPolicyCompileError::QueryIncomplete {
                    completion: CodeQueryCompletion::Cancelled,
                    detail: "entry-point declaration binding was cancelled".to_owned(),
                });
            }
            ProcedureRangeLookupStatus::BudgetExhausted => {
                return Err(query_budget_error(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    "entry-point declaration binding exhausted the shared traversal budget",
                ));
            }
            ProcedureRangeLookupStatus::SourceChanged => {
                return Err(TaintPolicyCompileError::SemanticUnavailable(
                    "entry-point declaration binding observed a changed source snapshot".to_owned(),
                ));
            }
        }
        if !self
            .selectors
            .execution_budget()
            .charge_traversal(lookup.examined)
        {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "entry-point declaration binding exhausted the shared traversal budget",
            ));
        }
        let mut candidates = Vec::new();
        for procedure in &lookup.handles {
            let semantics = procedure.semantics();
            let Some(mapping) = semantics.source_mapping(semantics.source()) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            let range = span.start_byte() as usize..span.end_byte() as usize;
            let exact = range == selection.span;
            let enclosing = range.start <= selection.span.start && range.end >= selection.span.end;
            if exact || enclosing {
                candidates.push((!exact, range.len(), range.start, procedure.clone()));
            }
        }
        candidates.sort_by(|left, right| {
            (left.0, left.1, left.2, left.3.semantics().locator()).cmp(&(
                right.0,
                right.1,
                right.2,
                right.3.semantics().locator(),
            ))
        });
        let Some((inexact, length, _, procedure)) = candidates.first() else {
            return Err(TaintPolicyCompileError::SemanticUnavailable(
                "selected entry-point row does not identify a procedure declaration".to_owned(),
            ));
        };
        let mut tied = candidates
            .iter()
            .filter(|candidate| (candidate.0, candidate.1) == (*inexact, *length))
            .map(|candidate| candidate.3.durable_key())
            .collect::<Vec<_>>();
        tied.dedup();
        if tied.len() > 1 {
            return Err(TaintPolicyCompileError::AmbiguousSemanticSite(
                "selected entry-point row names more than one procedure declaration".to_owned(),
            ));
        }
        let ordinal = match parameter {
            PolicyPort::ArgumentIndex { index } => *index,
            PolicyPort::ArgumentName { name } => {
                let Some(formals) = self.formal_ir_names(procedure)? else {
                    return Err(TaintPolicyCompileError::SemanticUnavailable(
                        "entry-point formal parameter names are unavailable for the selected declaration".to_owned(),
                    ));
                };
                let matched = formals
                    .iter()
                    .enumerate()
                    .filter(|(_, slot)| parameter_names_match(slot, name))
                    .map(|(ordinal, _)| ordinal)
                    .collect::<Vec<_>>();
                match matched.as_slice() {
                    [ordinal] => u32::try_from(*ordinal)
                        .expect("formal parameter ordinals fit the semantic port width"),
                    [] => {
                        return Err(TaintPolicyCompileError::Model(format!(
                            "entry-point parameter `{name}` does not name a formal of the selected declaration; formals: {formals:?}"
                        )));
                    }
                    _ => {
                        return Err(TaintPolicyCompileError::AmbiguousSemanticSite(format!(
                            "entry-point parameter `{name}` names more than one formal of the selected declaration"
                        )));
                    }
                }
            }
            PolicyPort::MatchedValue
            | PolicyPort::Receiver
            | PolicyPort::ReturnValue
            | PolicyPort::ResultIndex { .. }
            | PolicyPort::FieldOf { .. } => {
                unreachable!("entry-point parameter decoding admits only argument ports")
            }
        };
        let port = ProcedurePortHandle::parameter(procedure.clone(), ordinal).map_err(|error| {
            TaintPolicyCompileError::Model(format!(
                "entry-point parameter {ordinal} has no matching procedure port on the selected declaration: {error}"
            ))
        })?;
        Ok(vec![resolved_entry_parameter_value(
            procedure,
            port,
            selection.proof,
            selection.completeness,
        )])
    }

    fn discover_value_flow(
        &mut self,
        root: &ProcedureHandle,
        modeled_calls: &HashSet<DurableCallSiteKey>,
        cache: &DiscoveryMaterializationCache<'a>,
    ) -> Result<DiscoveredValueFlow, TaintPolicyCompileError> {
        let workspace = self.selectors.workspace();
        let cancellation = self.selectors.cancellation();
        let provider = PolicyDiscoveryProvider::new(
            workspace,
            self.selectors.execution_budget().clone(),
            cache,
        );
        // Anchor the returned root to the same compile-wide artifact instance
        // the provider uses for every procedure the shared walk touches.
        let root = provider.canonical_procedure(root);
        let misses_before = cache.procedure_misses.get();
        let discovered = discover_closure_with(
            &provider,
            &root,
            ClosureLimits {
                max_procedures: usize::MAX,
            },
            self.selectors.semantic_budget_mut(),
            cancellation,
        );
        let poisoned = provider.poisoned();
        let newly_materialized = cache.procedure_misses.get().saturating_sub(misses_before);
        self.selectors
            .record_semantic_snapshot_materializations(newly_materialized);
        if let Some(error) = poisoned {
            return Err(error);
        }
        let discovered = discovered?;
        let returned_callables = provider
            .take_returned_callables()
            .into_iter()
            .map(|row| {
                ValueFlowReturnedCallable::new(
                    row.producer().clone(),
                    row.producer_callee().clone(),
                    row.closure().clone(),
                    row.captures().to_vec(),
                )
            })
            .collect();
        let rust_format_result_calls = provider.take_rust_format_result_calls();

        let mut seen_external_targets = HashSet::new();
        let mut seen_unmaterialized_targets = HashSet::new();
        let mut external_targets = Vec::new();
        let mut unmaterialized_external_targets = Vec::new();
        for boundary in &discovered.boundaries {
            if let Some(target) = boundary.exact_external_target()
                && seen_external_targets.insert(target.clone())
            {
                external_targets.push(target.clone());
            }
            if let Some(target) = boundary.unmaterialized_external_target()
                && seen_unmaterialized_targets.insert(target.clone())
            {
                unmaterialized_external_targets.push(target.clone());
            }
        }
        let procedures = discovered
            .procedures
            .iter()
            .map(ProcedureHandle::durable_key)
            .collect();
        let bindings = discovered
            .bindings
            .into_iter()
            .filter(|binding| !modeled_calls.contains(&binding.value().call().durable_key()))
            .collect();
        Ok(DiscoveredValueFlow {
            root,
            snapshots: discovered.snapshots,
            bindings,
            returned_callables,
            rust_format_result_calls,
            procedures,
            external_targets,
            unmaterialized_external_targets,
            call_coverage: discovered.coverage.into_iter().collect(),
            dispatch_boundaries: discovered.boundaries,
        })
    }

    fn build_value_flow_plan(
        &mut self,
        discovery: DiscoveredValueFlow,
        source_specs: Vec<ValueFlowSourceSpec>,
        sink_specs: Vec<ValueFlowSinkSpec>,
        call_behavior: brokk_bifrost_flow::dataflow::UnmodeledCallBehavior,
        conditional_sanitizers: &[BoundConditionalSanitizer],
        universe: &TaintUniverse,
    ) -> Result<
        (
            ValueFlowPlan,
            CallResolutionDiscoveryEvidence,
            Vec<SanitizerDecline>,
        ),
        TaintPolicyCompileError,
    > {
        let DiscoveredValueFlow {
            root,
            snapshots,
            bindings,
            returned_callables,
            external_targets,
            unmaterialized_external_targets,
            call_coverage,
            dispatch_boundaries,
            ..
        } = discovery;
        let external_summaries = self.bind_external_summaries(
            &external_targets,
            &unmaterialized_external_targets,
            root.artifact().key(),
            call_behavior,
        )?;
        let mut source_specs = ValueFlowSources::from(source_specs);
        let mut edge_kills = automatic_comparison_guard_edge_kills(&snapshots, &mut source_specs);
        let (conditional_kills, sanitizer_declines) = policy_conditioned_guard_edge_kills(
            &snapshots,
            &mut source_specs,
            conditional_sanitizers,
            universe,
        )?;
        edge_kills.extend(conditional_kills);
        let mut resolved_external_calls = exact_python_external_resolution_calls(
            &call_coverage,
            &dispatch_boundaries,
            external_summaries.as_ref(),
        );
        resolved_external_calls.extend(exact_rust_builtin_macro_resolution_calls(
            &call_coverage,
            &dispatch_boundaries,
        ));
        let plan = ValueFlowPlan::with_call_behavior_and_edge_kills_and_resolved_external_calls(
            root,
            snapshots,
            bindings,
            source_specs,
            sink_specs,
            edge_kills,
            call_behavior,
            resolved_external_calls,
        )
        .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
        let plan = plan
            .with_returned_callable_captures(returned_callables)
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
        let plan = match external_summaries {
            Some(summaries) => plan
                .with_external_summaries(summaries)
                .map_err(|error| TaintPolicyCompileError::Plan(error.to_string())),
            None => Ok(plan),
        }?;
        Ok((
            plan,
            CallResolutionDiscoveryEvidence {
                coverage: call_coverage,
                boundaries: dispatch_boundaries,
            },
            sanitizer_declines,
        ))
    }

    fn bind_external_summaries(
        &self,
        targets: &[ExactExternalProcedureTarget],
        unmaterialized: &[UnmaterializedExternalTarget],
        root_artifact: &SemanticArtifactKey,
        call_behavior: brokk_bifrost_flow::dataflow::UnmodeledCallBehavior,
    ) -> Result<Option<ExternalSemanticSummarySet>, TaintPolicyCompileError> {
        let Some(active) = &self.active_semantic_models else {
            return Ok(None);
        };
        let dependencies = root_artifact.dependencies();
        let compatibility = ExternalSummaryCompatibilityKey::new(
            SummarySchemaVersion::CURRENT,
            SummarySemanticsVersion::hash_bytes(b"bifrost.production-value-flow.semantic-pack.v1"),
            SummaryContextKey::hash_bytes(b"bifrost.production-value-flow.empty-call-context.v1"),
            SummaryBehaviorKey::hash_bytes(b"bifrost.production-value-flow.external-boundary.v1")
                .with_unmodeled_call_behavior(call_behavior),
            dependencies,
            call_behavior,
        );
        let mut families = HashMap::<usize, SelectedSummaryFamily>::new();
        for target in targets {
            let matched = active.procedure_summaries_for(ProcedureSummaryTargetKey::new(
                target.artifact().language().semantic_pack_label(),
                target.artifact().path().as_str(),
                target.symbol(),
                target.has_receiver(),
                target.parameter_count(),
            ));
            match matched.disposition {
                SemanticModelMatchDisposition::Empty => continue,
                SemanticModelMatchDisposition::Conflict => {
                    return Err(TaintPolicyCompileError::Model(format!(
                        "conflicting activated procedure summaries target {}:{}",
                        target.artifact().path().as_str(),
                        target.symbol()
                    )));
                }
                SemanticModelMatchDisposition::Unique => {}
            }
            let [selected] = matched.records.as_slice() else {
                return Err(TaintPolicyCompileError::Model(
                    "unique procedure-summary lookup returned a non-unique record set".to_owned(),
                ));
            };
            let family_key = Arc::as_ptr(&selected.shard) as usize;
            let family = families
                .entry(family_key)
                .or_insert_with(|| SelectedSummaryFamily {
                    order: active.procedure_summary_shard_order(&selected.shard),
                    shard: Arc::clone(&selected.shard),
                    language: selected.shard.manifest.language.clone(),
                    root_ids: HashSet::new(),
                });
            family.root_ids.insert(selected.record.id.clone());
        }
        if families.is_empty() && unmaterialized.is_empty() {
            return Ok(None);
        }

        let mut families = families.into_values().collect::<Vec<_>>();
        families.sort_unstable_by_key(|family| family.order);
        let mut lowered = Vec::new();
        let mut unmaterialized_bindings = Vec::new();
        for family in families {
            let payload = active.procedure_summary_family(
                &family.shard,
                family.root_ids.iter().map(String::as_str),
            );
            let by_id = payload
                .iter()
                .map(|summary| (summary.id.as_str(), summary))
                .collect::<HashMap<_, _>>();
            let mut pending = family.root_ids.into_iter().collect::<Vec<_>>();
            pending.sort_unstable_by(|left, right| right.cmp(left));
            let mut selected_ids = HashSet::new();
            while let Some(id) = pending.pop() {
                if !selected_ids.insert(id.clone()) {
                    continue;
                }
                let summary = by_id.get(id.as_str()).ok_or_else(|| {
                    TaintPolicyCompileError::Model(format!(
                        "activated procedure-summary dependency `{id}` is missing from its payload"
                    ))
                })?;
                for effect in &summary.effects {
                    match effect {
                        CompiledSummaryEffect::Call { callee, .. } => pending.push(callee.clone()),
                        CompiledSummaryEffect::AmbiguousCall { candidates, .. } => {
                            pending.extend(candidates.iter().cloned());
                        }
                        CompiledSummaryEffect::Allocation { .. }
                        | CompiledSummaryEffect::Escape { .. }
                        | CompiledSummaryEffect::UnknownCall { .. }
                        | CompiledSummaryEffect::UnknownCallBoundary { .. }
                        | CompiledSummaryEffect::Sanitize { .. } => {}
                    }
                }
            }
            let summaries = payload
                .iter()
                .filter(|summary| selected_ids.contains(&summary.id))
                .cloned()
                .collect::<Vec<_>>();
            let mut bindings = Vec::with_capacity(summaries.len());
            for summary in &summaries {
                let mut exact = targets
                    .iter()
                    .filter(|target| {
                        target.artifact().language().semantic_pack_label() == family.language
                            && target.artifact().path().as_str() == summary.target.path
                            && target.symbol() == summary.target.symbol
                            && target.has_receiver() == summary.target.has_receiver
                            && target.parameter_count() == summary.target.parameter_count
                    })
                    .collect::<Vec<_>>();
                exact.sort_unstable_by(|left, right| {
                    left.artifact()
                        .mount()
                        .cmp(&right.artifact().mount())
                        .then_with(|| left.procedure().cmp(right.procedure()))
                });
                exact.dedup();
                let [target] = exact.as_slice() else {
                    return Err(TaintPolicyCompileError::Model(format!(
                        "procedure summary `{}` dependency closure lacks one exact external target descriptor",
                        summary.id
                    )));
                };
                let receiver = summary
                    .target
                    .has_receiver
                    .then_some(ExactProcedureSummaryReceiver);
                let parameters = (0..summary.target.parameter_count)
                    .map(ExactProcedureSummaryParameter::new)
                    .collect();
                bindings.push(ExactProcedureSummaryTargetBinding::new(
                    summary.id.clone(),
                    summary.target.clone(),
                    target.artifact().clone(),
                    target.procedure().clone(),
                    ExactProcedureSummaryBoundary::new(receiver, parameters),
                ));
            }
            let set = bind_compiled_procedure_summaries(&summaries, bindings, compatibility)
                .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))?;
            lowered.extend(set.entries().map(|(_target, summary)| summary.clone()));
        }

        // #1978: bind activated summaries to fully-qualified external callees that
        // never materialize. They select a summary by canonical identity
        // (language, owner FQN, member, arity, has_receiver) rather than by
        // artifact path or parameter-typed symbol, and anchor the lowered summary
        // to the boundary's synthetic locator so it applies at solve time. The
        // materialized-external binding above is untouched.
        let mut unmaterialized_families = HashMap::<usize, SelectedSummaryFamily>::new();
        for target in unmaterialized {
            let matched = active.procedure_summaries_for_external_target(target);
            let Some(selected) = select_unmaterialized_flow_summary(&matched)? else {
                continue;
            };
            let family_key = Arc::as_ptr(&selected.shard) as usize;
            let family = unmaterialized_families
                .entry(family_key)
                .or_insert_with(|| SelectedSummaryFamily {
                    order: active.procedure_summary_shard_order(&selected.shard),
                    shard: Arc::clone(&selected.shard),
                    language: selected.shard.manifest.language.clone(),
                    root_ids: HashSet::new(),
                });
            family.root_ids.insert(selected.record.id.clone());
        }
        let mut unmaterialized_families = unmaterialized_families.into_values().collect::<Vec<_>>();
        unmaterialized_families.sort_unstable_by_key(|family| family.order);
        for family in unmaterialized_families {
            let payload = active.procedure_summary_family(
                &family.shard,
                family.root_ids.iter().map(String::as_str),
            );
            let by_id = payload
                .iter()
                .map(|summary| (summary.id.as_str(), summary))
                .collect::<HashMap<_, _>>();
            let mut pending = family.root_ids.into_iter().collect::<Vec<_>>();
            pending.sort_unstable_by(|left, right| right.cmp(left));
            let mut selected_ids = HashSet::new();
            while let Some(id) = pending.pop() {
                if !selected_ids.insert(id.clone()) {
                    continue;
                }
                let summary = by_id.get(id.as_str()).ok_or_else(|| {
                    TaintPolicyCompileError::Model(format!(
                        "activated procedure-summary dependency `{id}` is missing from its payload"
                    ))
                })?;
                for effect in &summary.effects {
                    match effect {
                        CompiledSummaryEffect::Call { callee, .. } => pending.push(callee.clone()),
                        CompiledSummaryEffect::AmbiguousCall { candidates, .. } => {
                            pending.extend(candidates.iter().cloned());
                        }
                        CompiledSummaryEffect::Allocation { .. }
                        | CompiledSummaryEffect::Escape { .. }
                        | CompiledSummaryEffect::UnknownCall { .. }
                        | CompiledSummaryEffect::UnknownCallBoundary { .. }
                        | CompiledSummaryEffect::Sanitize { .. } => {}
                    }
                }
            }
            let summaries = payload
                .iter()
                .filter(|summary| selected_ids.contains(&summary.id))
                .cloned()
                .collect::<Vec<_>>();
            let mut bindings = Vec::with_capacity(summaries.len());
            let mut bindings_by_summary_target = BTreeMap::<
                ExternalSummaryTarget,
                Vec<UnmaterializedExternalSummaryCallShapeBinding>,
            >::new();
            for summary in &summaries {
                // Re-match this closure summary at every resolver-owned actual
                // arity. Each lowered record gets one stable internal identity
                // beneath the declaration's shared formal call shape; exact
                // actual-arity locators become query-scoped aliases only after
                // the active matcher confirms this record wins that shape.
                let binding_error = || {
                    TaintPolicyCompileError::Model(format!(
                        "unmaterialized procedure summary `{}` dependency closure lacks one external target identity",
                        summary.id
                    ))
                };
                let Some((owner, member)) = authored_procedure_target_identity(
                    &summary.target.path,
                    &summary.target.symbol,
                ) else {
                    return Err(binding_error());
                };
                let candidates = unmaterialized.iter().filter(|target| {
                    target.language().semantic_pack_label() == family.language
                        && target.has_receiver() == summary.target.has_receiver
                        && owner == target.owner_fqn()
                        && member == target.member()
                });
                let mut applicable = Vec::new();
                for target in candidates {
                    let matched = active.procedure_summaries_for_external_target(target);
                    let Some(selected) = select_unmaterialized_flow_summary(&matched)? else {
                        continue;
                    };
                    if Arc::ptr_eq(&selected.shard, &family.shard)
                        && selected.record.model_id == summary.model_id
                        && selected.record.id == summary.id
                    {
                        let binding = selected
                            .bind_unmaterialized_call_shape(target)
                            .ok_or_else(binding_error)?;
                        applicable.push((target, binding));
                    }
                }
                // Calls with the same resolver-owned target locator share one
                // semantic alias even when their argument value IDs differ.
                applicable.sort_unstable_by(|left, right| {
                    left.1.actual_locator().cmp(right.1.actual_locator())
                });
                applicable
                    .dedup_by(|left, right| left.1.actual_locator() == right.1.actual_locator());
                let Some((target, first_binding)) = applicable.first() else {
                    return Err(binding_error());
                };
                let receiver = summary
                    .target
                    .has_receiver
                    .then_some(ExactProcedureSummaryReceiver);
                let parameters = (0..summary.target.parameter_count)
                    .map(ExactProcedureSummaryParameter::new)
                    .collect();
                let formal_locator = first_binding.formal_locator().clone();
                let summary_locator = ExternalSummaryTarget::internal_summary_locator(
                    &formal_locator,
                    &summary.model_id,
                )
                .expect("validated external model id yields one internal procedure locator");
                let summary_target = ExternalSummaryTarget::from_locator(&summary_locator)
                    .expect("internal external-summary identity is a procedure locator");
                bindings.push(ExactProcedureSummaryTargetBinding::new(
                    summary.id.clone(),
                    summary.target.clone(),
                    target.provenance_artifact_key(root_artifact),
                    summary_locator,
                    ExactProcedureSummaryBoundary::new(receiver, parameters),
                ));
                let retained = bindings_by_summary_target
                    .entry(summary_target)
                    .or_default();
                for (_target, binding) in applicable {
                    debug_assert_eq!(binding.formal_locator(), &formal_locator);
                    retained.push(binding);
                }
            }
            let set = bind_compiled_procedure_summaries(&summaries, bindings, compatibility)
                .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))?;
            for (summary_target, summary) in set.entries() {
                let bindings = bindings_by_summary_target
                    .get(summary_target)
                    .ok_or_else(|| {
                    TaintPolicyCompileError::Model(format!(
                        "lowered procedure summary at `{}:{:?}` lacks resolver-owned target aliases",
                        summary_target.path().as_str(),
                        summary_target.declaration()
                    ))
                })?;
                unmaterialized_bindings.extend(
                    bindings
                        .iter()
                        .cloned()
                        .map(|binding| (binding, summary.clone())),
                );
            }
        }

        if lowered.is_empty() && unmaterialized_bindings.is_empty() {
            return Ok(None);
        }
        ExternalSemanticSummarySet::try_new_with_unmaterialized_call_shape_bindings(
            lowered,
            unmaterialized_bindings,
            compatibility,
        )
        .map(Some)
        .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))
    }
}

pub(crate) fn exact_python_external_resolution_calls(
    coverage: &HashMap<DurableCallSiteKey, CallSiteCoverage>,
    boundaries: &[DispatchBoundary],
    summaries: Option<&ExternalSemanticSummarySet>,
) -> Vec<CallSiteHandle> {
    let mut calls = HashMap::<DurableCallSiteKey, CallSiteHandle>::new();
    for boundary in boundaries {
        if !is_exact_python_constructor_boundary(boundary)
            && !is_exact_python_modeled_receiver_method_boundary(boundary, summaries)
        {
            continue;
        }
        for call in boundary
            .provenance
            .iter()
            .filter_map(|provenance| match provenance.owner() {
                OracleRelationOwner::Dispatch(call) => Some(call),
                _ => None,
            })
        {
            calls.insert(call.durable_key(), call.clone());
        }
    }

    calls
        .into_values()
        .filter(|call| {
            let call_boundaries = boundaries
                .iter()
                .filter(|boundary| {
                    boundary.provenance.iter().any(|provenance| {
                        matches!(provenance.owner(), OracleRelationOwner::Dispatch(owner) if owner == call)
                    })
                })
                .collect::<Vec<_>>();
            let exact_constructor = call_boundaries
                .iter()
                .all(|boundary| is_exact_python_constructor_boundary(boundary));
            let exact_modeled_method = call_boundaries.iter().all(|boundary| {
                is_exact_python_modeled_receiver_method_boundary(boundary, summaries)
            });
            if call_boundaries.is_empty() || !(exact_constructor || exact_modeled_method) {
                return false;
            }
            let Some(CallSiteCoverage {
                dispatch: DispatchStatus::Resolved {
                    status,
                    coverage: candidate_coverage,
                },
                has_uncovered_boundary,
                truncated: false,
                bindings,
                ..
            }) = coverage.get(&call.durable_key())
            else {
                return false;
            };
            if !status.is_complete()
                || *candidate_coverage != CandidateCoverage::Exhaustive
                || !bindings.is_empty()
                || (*has_uncovered_boundary && !exact_modeled_method)
            {
                return false;
            }
            true
        })
        .collect()
}

pub(crate) fn exact_rust_builtin_macro_resolution_calls(
    coverage: &HashMap<DurableCallSiteKey, CallSiteCoverage>,
    boundaries: &[DispatchBoundary],
) -> Vec<CallSiteHandle> {
    let is_complete_builtin_target = |boundary: &DispatchBoundary| {
        let Some(identity) = boundary.external_callee_identity() else {
            return false;
        };
        let Some(target) = boundary.unmaterialized_external_target() else {
            return false;
        };
        let known_identity = identity.language() == Language::Rust
            && matches!(
                (identity.owner_fqn(), identity.member()),
                (
                    "std" | "core" | "alloc",
                    "format"
                        | "format_args"
                        | "print"
                        | "println"
                        | "eprint"
                        | "eprintln"
                        | "write"
                        | "writeln"
                        | "panic"
                ) | ("alloc.fmt", "format")
                    | ("core.panicking", "panic_fmt" | "assert_failed")
                    | ("std.io.stdio", "_print" | "_eprint")
                    | ("core", "matches")
                    | ("alloc", "vec")
            );
        known_identity
            && target.language() == SemanticLanguage::Standard(Language::Rust)
            && target.owner_fqn() == identity.owner_fqn()
            && target.member() == identity.member()
            && matches!(&boundary.kind, DispatchBoundaryKind::External(Some(locator)) if locator == target.locator())
            && matches!(&boundary.proof, ProofStatus::Proven)
            && matches!(&boundary.completeness, EvidenceCompleteness::Complete)
    };
    let mut calls = HashMap::<DurableCallSiteKey, CallSiteHandle>::new();
    for boundary in boundaries
        .iter()
        .filter(|boundary| is_complete_builtin_target(boundary))
    {
        for call in boundary
            .provenance
            .iter()
            .filter_map(|provenance| match provenance.owner() {
                OracleRelationOwner::Dispatch(call) => Some(call),
                _ => None,
            })
        {
            calls.insert(call.durable_key(), call.clone());
        }
    }
    calls
        .into_values()
        .filter(|call| {
            let call_boundaries = boundaries
                .iter()
                .filter(|boundary| {
                    boundary.provenance.iter().any(|provenance| {
                        matches!(provenance.owner(), OracleRelationOwner::Dispatch(owner) if owner == call)
                    })
                })
                .collect::<Vec<_>>();
            if call_boundaries.is_empty()
                || !call_boundaries
                    .iter()
                    .all(|boundary| is_complete_builtin_target(boundary))
            {
                return false;
            }
            matches!(
                coverage.get(&call.durable_key()),
                Some(CallSiteCoverage {
                    dispatch: DispatchStatus::Resolved {
                        status,
                        coverage: CandidateCoverage::Exhaustive,
                    },
                    has_uncovered_boundary: false,
                    truncated: false,
                    bindings,
                    ..
                }) if status.is_complete() && bindings.is_empty()
            )
        })
        .collect()
}

fn is_exact_python_modeled_receiver_method_boundary(
    boundary: &DispatchBoundary,
    summaries: Option<&ExternalSemanticSummarySet>,
) -> bool {
    let Some(identity) = boundary.external_callee_identity() else {
        return false;
    };
    let Some(target) = boundary.unmaterialized_external_target() else {
        return false;
    };
    identity.language() == Language::Python
        && target.language() == SemanticLanguage::Standard(Language::Python)
        && target.has_resolver_owned_call_shape()
        && target.has_receiver()
        && target.owner_fqn() == identity.owner_fqn()
        && target.member() == identity.member()
        && matches!(&boundary.kind, DispatchBoundaryKind::External(Some(locator)) if locator == target.locator())
        && matches!(&boundary.proof, ProofStatus::Proven)
        && summaries
            .and_then(|summaries| summaries.summary_for(target.locator()))
            .is_some_and(|summary| summary.completeness().is_complete())
}

fn is_exact_python_constructor_boundary(boundary: &DispatchBoundary) -> bool {
    let Some(identity) = boundary.external_callee_identity() else {
        return false;
    };
    let Some(target) = boundary.unmaterialized_external_target() else {
        return false;
    };
    identity.language() == Language::Python
        && target.language() == SemanticLanguage::Standard(Language::Python)
        && target.has_resolver_owned_call_shape()
        && target.has_receiver()
        && target.member() == "__init__"
        && target.owner_fqn() == format!("{}.{}", identity.owner_fqn(), identity.member())
        && matches!(&boundary.kind, DispatchBoundaryKind::External(Some(locator)) if locator == target.locator())
        && matches!(&boundary.proof, ProofStatus::Proven)
        && matches!(&boundary.completeness, EvidenceCompleteness::Complete)
}

fn select_unmaterialized_flow_summary(
    matched: &ProcedureSummaryMatch,
) -> Result<Option<&ActivatedProcedureSummary>, TaintPolicyCompileError> {
    if matched.applicability
        == brokk_bifrost_analysis::analyzer::semantic_model::ProcedureSummaryApplicability::Incomplete
    {
        // Keep the unresolved call boundary and any partial findings. An
        // existing model with incomplete applicability cannot close it.
        return Ok(None);
    }
    match matched.disposition {
        SemanticModelMatchDisposition::Empty if matched.records.is_empty() => Ok(None),
        SemanticModelMatchDisposition::Empty => Err(TaintPolicyCompileError::Model(
            "empty unmaterialized procedure-summary lookup returned records".to_owned(),
        )),
        SemanticModelMatchDisposition::Unique => {
            let [selected] = matched.records.as_slice() else {
                return Err(TaintPolicyCompileError::Model(
                    "unique unmaterialized procedure-summary lookup returned a non-unique record set"
                        .to_owned(),
                ));
            };
            Ok(Some(selected))
        }
        SemanticModelMatchDisposition::Conflict => {
            // Several activated summaries collapse to the same unmaterialized
            // identity because parameter types are unrecoverable, so overloads
            // like StringBuilder.append(String), append(Object), and
            // append(char[]) share one key. When every candidate models the
            // same flow-observable claim, choosing one is exact for this
            // consumer. A disagreement remains unmodeled so require-model
            // abstains.
            let Some((first, rest)) = matched.records.split_first() else {
                return Err(TaintPolicyCompileError::Model(
                    "conflicting unmaterialized procedure-summary lookup returned no records"
                        .to_owned(),
                ));
            };
            if rest.is_empty() {
                return Err(TaintPolicyCompileError::Model(
                    "conflicting unmaterialized procedure-summary lookup returned one record"
                        .to_owned(),
                ));
            }
            let identical = rest
                .iter()
                .all(|other| unmaterialized_flow_claims_agree(&other.record, &first.record));
            Ok(identical.then_some(first))
        }
    }
}

fn unmaterialized_flow_claims_agree(
    left: &CompiledProcedureSummary,
    right: &CompiledProcedureSummary,
) -> bool {
    left.completeness == right.completeness
        && left.covers_overrides == right.covers_overrides
        && left.normal_result_count == right.normal_result_count
        && left.locations == right.locations
        && left.transfers == right.transfers
        && left.effects == right.effects
}

/// Keep a store-fed run from reporting a complete verdict when its seed
/// provenance is uncertain: an observation solve over a write region stayed
/// incomplete, so a class may be missing from the seed and a clean read is
/// not a proven negative.
fn downgrade_for_uncertain_store_seed(payload: &mut TaintProjectionPayload) {
    if !matches!(payload.completion, PolicyRunCompletion::Complete) {
        return;
    }
    if let Ok(completion) =
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery])
    {
        payload.completion = completion;
    }
    if let Ok(diagnostic) = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        "a persistence-store observation solve stayed incomplete, so store-fed \
         verdicts cannot be proven complete"
            .to_owned(),
        None,
        Vec::new(),
    ) {
        payload.diagnostics.push(diagnostic);
    }
}

/// The store-read seeds one fixpoint computed for a batch list, plus whether
/// any observation solve stayed incomplete (in which case a class may be
/// missing from a seed and no store-fed verdict may be reported complete).
struct StoreSeeding {
    /// Per batch: each seeded read's source id, the classes crossing the
    /// boundary, and the policy source endpoints those classes came from.
    seeds: Vec<Vec<StoreReadSeed>>,
    uncertain: bool,
}

#[derive(Clone, PartialEq)]
struct StoreReadSeed {
    source: ValueFlowSourceId,
    event: ValueFlowEventKey,
    classes: TaintClassSet,
    contributors: BTreeSet<ResolvedEndpointIdentity>,
    crossings: Vec<StoreCrossingProvenance>,
    /// The write call sites that fed this read's channel, and the origin sites
    /// whose values those writes persisted, so a store-fed finding can name the
    /// write-to-read edge it crossed instead of presenting the read as an
    /// unexplained origin.
    write_sites: BTreeSet<brokk_bifrost_analysis::analyzer::semantic::SemanticLocator>,
    write_origin_sites: BTreeSet<brokk_bifrost_analysis::analyzer::semantic::SemanticLocator>,
}

#[derive(Clone, PartialEq)]
struct StoreCrossingProvenance {
    source_endpoint: ResolvedEndpointIdentity,
    source_to_write: Option<SummaryWitness>,
    write_endpoint: ResolvedEndpointIdentity,
    write_call: CallSiteHandle,
    read_endpoint: ResolvedEndpointIdentity,
    read_call: CallSiteHandle,
    write_channel: TaintStoreChannel,
    read_channel: TaintStoreChannel,
}

#[derive(Clone)]
struct ObservedStoreWrite {
    policy_id: PolicyId,
    source_endpoint: ResolvedEndpointIdentity,
    source_to_write: Option<SummaryWitness>,
    endpoint: ResolvedEndpointIdentity,
    call: CallSiteHandle,
    channel: TaintStoreChannel,
}

/// The write-side evidence of one seeded store read: the write call sites that
/// fed the read's channel, and the origin sites whose values those writes
/// persisted. Keyed by the read's own origin event key so the projection can
/// attach it to a store-fed origin.
type StoreWriteEvidenceByRead = HashMap<
    ValueFlowEventKey,
    (
        BTreeSet<brokk_bifrost_analysis::analyzer::semantic::SemanticLocator>,
        BTreeSet<brokk_bifrost_analysis::analyzer::semantic::SemanticLocator>,
    ),
>;

impl StoreSeeding {
    fn empty(batches: usize) -> Self {
        Self {
            seeds: vec![Vec::new(); batches],
            uncertain: false,
        }
    }

    /// Collect the write-side evidence of every seeded read by its origin key.
    fn write_evidence_by_read(&self, batches: &[TaintBatch]) -> StoreWriteEvidenceByRead {
        let mut evidence = HashMap::new();
        for (batch_index, seeds) in self.seeds.iter().enumerate() {
            let batch = &batches[batch_index];
            for seed in seeds {
                let Some(read) = batch
                    .analysis()
                    .store_reads()
                    .iter()
                    .find(|read| read.source() == seed.source)
                else {
                    continue;
                };
                let Some(spec) = batch.analysis().value_flow().source(read.source()) else {
                    continue;
                };
                evidence.insert(
                    spec.key().clone(),
                    (seed.write_sites.clone(), seed.write_origin_sites.clone()),
                );
            }
        }
        evidence
    }
}

/// Compute the classes each store read establishes by iterating observation
/// solves to a fixpoint: solve every batch that declares store writes with
/// its writes bound as observation sinks, union the classes observed at each
/// write into its channel, seed every read whose channel a write's may alias,
/// and repeat until no seed grows. Store names are policy-local, so a write
/// and a read link only when their batches share a policy.
///
/// Termination: seed class sets grow monotonically inside finite universes,
/// so the loop is bounded by the total class count.
#[allow(clippy::too_many_arguments)]
fn seed_store_channels(
    batches: &[TaintBatch],
    metadata: &HashMap<String, PreparedTaintPlan>,
    workspace: &WorkspaceAnalyzer,
    cancellation: &CancellationToken,
    budget: &PolicyBudget,
    execution_budget: &mut TaintExecutionBudget,
    icfg_provider: &WorkspaceIcfgProvider<'_>,
    payloads: &mut HashMap<PolicyId, TaintProjectionPayload>,
    merge: &mut BatchMerge,
) -> Result<StoreSeeding, String> {
    let mut seeding = StoreSeeding::empty(batches.len());
    let has_writes = batches
        .iter()
        .any(|batch| !batch.analysis().store_writes().is_empty());
    let has_reads = batches
        .iter()
        .any(|batch| !batch.analysis().store_reads().is_empty());
    if !has_writes || !has_reads {
        return Ok(seeding);
    }
    // A batch names its members by internal per-root plan id; the store
    // linkage is policy-local, so map each back to its owning policy id.
    let batch_policy_ids = batches
        .iter()
        .map(|batch| {
            batch
                .policy_ids()
                .filter_map(|internal| metadata.get(internal).map(|plan| &plan.policy_id))
                .collect::<HashSet<_>>()
        })
        .collect::<Vec<_>>();
    let mut write_classes = batches
        .iter()
        .map(|batch| {
            vec![batch.analysis().universe().empty_set(); batch.analysis().store_writes().len()]
        })
        .collect::<Vec<_>>();
    let mut observed_writes = batches
        .iter()
        .map(|batch| vec![Vec::<ObservedStoreWrite>::new(); batch.analysis().store_writes().len()])
        .collect::<Vec<_>>();
    let mut write_sites = batches
        .iter()
        .map(|batch| {
            vec![
                BTreeSet::<brokk_bifrost_analysis::analyzer::semantic::SemanticLocator>::new();
                batch.analysis().store_writes().len()
            ]
        })
        .collect::<Vec<_>>();
    let mut write_origin_sites = write_sites.clone();
    // Per batch, the compiled metadata's origin-event-to-endpoint rows, for
    // attributing an observed write back to the policy sources that fed it.
    let batch_origin_endpoints = batches
        .iter()
        .map(|batch| {
            let mut rows: Vec<(&PolicyId, &ValueFlowEventKey, &ResolvedEndpointIdentity)> =
                Vec::new();
            for internal in batch.policy_ids() {
                if let Some(plan) = metadata.get(internal) {
                    for row in plan.sources.iter() {
                        rows.push((&plan.policy_id, &row.event, &row.endpoint));
                    }
                }
            }
            rows
        })
        .collect::<Vec<_>>();
    // Origin evidence is what attributes an observed write back to its policy
    // sources, and it is reconstructed from retained witnesses, so the
    // observation solves retain witnesses under the same limits the
    // projection path uses.
    let value_flow_limits = budget.query_limits().value_flow;
    let witness_retention = WitnessRetentionLimits::best_effort(
        1,
        value_flow_limits.max_retained_relations,
        value_flow_limits.max_retained_bytes,
    )
    .map_err(|error| error.to_string())?;
    let witness_limits = WitnessReconstructionLimits::new(
        value_flow_limits
            .max_witness_steps
            .min(budget.max_witness_steps()),
        value_flow_limits.max_witness_expansions,
    )
    .map_err(|error| error.to_string())?;
    let collection_limits = TaintFindingCollectionLimits::new(
        usize::MAX / 2,
        usize::MAX / 2,
        usize::MAX / 2,
        usize::MAX / 2,
        usize::MAX / 2,
    )
    .map_err(|error| error.to_string())?;
    let class_bound: usize = batches
        .iter()
        .map(|batch| batch.analysis().universe().classes().len())
        .sum();
    let semantic_limits = budget.query_limits().semantic;
    let barrier_services = batches
        .iter()
        .map(|batch| {
            (!batch.analysis().value_type_barriers().is_empty()).then(|| {
                crate::taint_barriers::ValueTypeBarrierService::new(
                    workspace,
                    SemanticExecutionBudget::new(semantic_limits.max_materialized_files),
                )
            })
        })
        .collect::<Vec<_>>();
    for iteration in 0.. {
        assert!(
            iteration <= class_bound.saturating_add(2),
            "store seeding must reach its fixpoint within the class bound"
        );
        let mut changed = false;
        for (index, batch) in batches.iter().enumerate() {
            if batch.analysis().store_writes().is_empty() {
                continue;
            }
            let seeds = seeding.seeds[index]
                .iter()
                .map(|seed| (seed.source, seed.classes.clone()))
                .collect::<Vec<_>>();
            let observation = batch
                .analysis()
                .with_seeded_store_reads(&seeds)
                .and_then(|analysis| analysis.with_store_write_observations())
                .map_err(|error| error.to_string())?;
            execution_budget.reset_per_batch_solve_budget(budget);
            let mut request = DataflowRequest::new(&mut execution_budget.solver, cancellation);
            record_taint_plan_artifacts(workspace, &observation);
            let attribution_before = execution_budget.attribution.work();
            let report = if observation.value_type_barriers().is_empty() {
                let result = brokk_bifrost_flow::taint::solve_taint_batch_with_witnesses(
                    observation.value_flow().root(),
                    icfg_provider,
                    &observation,
                    witness_retention,
                    &mut execution_budget.semantic,
                    &mut request,
                )
                .map_err(|error| error.to_string())?;
                collect_taint_findings_with_attribution_budget(
                    &observation,
                    result,
                    64,
                    witness_limits,
                    collection_limits,
                    &mut execution_budget.attribution,
                )
                .map_err(|error| error.to_string())?
            } else {
                let session = brokk_bifrost_flow::taint::IcfgBarrierSession::discover(
                    observation.value_flow().root(),
                    icfg_provider,
                    &observation,
                    witness_retention,
                    &mut execution_budget.semantic,
                    &mut request,
                    64,
                    witness_limits,
                    collection_limits,
                    &mut execution_budget.attribution,
                )
                .map_err(|error| error.to_string())?;
                let service = barrier_services[index]
                    .as_ref()
                    .expect("a barrier observation batch retains its native service");
                let mut semantic_request =
                    SemanticRequest::new(&mut execution_budget.semantic, cancellation);
                match session.refine(&observation, &mut request, |value, predicate| {
                    service
                        .classify(value, predicate, &mut semantic_request)
                        .map_err(|error| error.to_string().into())
                }) {
                    Ok(outcome) => outcome.report,
                    Err(
                        error @ (brokk_bifrost_flow::taint::IcfgBarrierError::Terminated(_)
                        | brokk_bifrost_flow::taint::IcfgBarrierError::RetentionBudget {
                            ..
                        }),
                    ) => {
                        brokk_bifrost_analysis::profiling::note_with(|| {
                            format!("taint.store.barriers.incomplete {error}")
                        });
                        let attribution = execution_budget
                            .attribution
                            .work()
                            .since(attribution_before);
                        for policy_id in &batch_policy_ids[index] {
                            let payload = payloads
                                .get_mut(*policy_id)
                                .expect("a store observation batch has a compiled policy payload");
                            record_attribution_work(&mut payload.work, attribution)?;
                        }
                        seeding.uncertain = true;
                        return Ok(seeding);
                    }
                    Err(error) => return Err(error.to_string()),
                }
            };
            let attribution = report.attribution_work();
            let missing = report
                .findings()
                .iter()
                .filter(|finding| finding.origins().evidence().is_empty())
                .count();
            for policy_id in &batch_policy_ids[index] {
                let payload = payloads
                    .get_mut(*policy_id)
                    .expect("a store observation batch has a compiled policy payload");
                record_attribution_work(&mut payload.work, attribution)?;
                let total = merge
                    .missing_origins
                    .entry((*policy_id).clone())
                    .or_default();
                *total = total.saturating_add(missing);
            }
            if !report.is_complete() {
                seeding.uncertain = true;
            }
            for finding in report.findings() {
                let Some(write_index) = batch.analysis().store_writes().iter().position(|write| {
                    batch
                        .analysis()
                        .value_flow()
                        .sink(write.sink())
                        .is_some_and(|spec| spec.key() == finding.key().sink())
                }) else {
                    continue;
                };
                let write_event = batch
                    .analysis()
                    .value_flow()
                    .sink(batch.analysis().store_writes()[write_index].sink())
                    .expect("a bound store write retains its value-flow sink")
                    .key();
                let merged = write_classes[index][write_index].union(finding.classes());
                if merged != write_classes[index][write_index] {
                    write_classes[index][write_index] = merged;
                    changed = true;
                }
                write_sites[index][write_index].insert(finding.key().sink().site().clone());
                for origin in finding.origins().evidence() {
                    let key = origin.origin().value_flow_key();
                    write_origin_sites[index][write_index].insert(key.site().clone());
                    for (policy_id, event, endpoint) in &batch_origin_endpoints[index] {
                        if *event != key {
                            continue;
                        }
                        for internal in batch.policy_ids() {
                            let Some(plan) = metadata.get(internal) else {
                                continue;
                            };
                            if &plan.policy_id != *policy_id {
                                continue;
                            }
                            for write in plan
                                .store_writes
                                .iter()
                                .filter(|write| &write.event == write_event)
                            {
                                let observed = ObservedStoreWrite {
                                    policy_id: (*policy_id).clone(),
                                    source_endpoint: (*endpoint).clone(),
                                    source_to_write: origin
                                        .witnesses()
                                        .iter()
                                        .find(|witness| !witness.steps().is_empty())
                                        .map(|witness| witness.as_ref().clone()),
                                    endpoint: write.endpoint.clone(),
                                    call: write.call.clone(),
                                    channel: write.channel.clone(),
                                };
                                if !observed_writes[index][write_index].iter().any(|retained| {
                                    retained.policy_id == observed.policy_id
                                        && retained.source_endpoint == observed.source_endpoint
                                        && retained.endpoint == observed.endpoint
                                        && retained.call.durable_key()
                                            == observed.call.durable_key()
                                }) {
                                    observed_writes[index][write_index].push(observed);
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        for (read_index, read_batch) in batches.iter().enumerate() {
            let mut next = Vec::new();
            for read in read_batch.analysis().store_reads() {
                let mut classes = read_batch.analysis().universe().empty_set();
                let mut contributors = BTreeSet::new();
                let mut crossings = Vec::new();
                let mut read_write_sites = BTreeSet::new();
                let mut read_write_origin_sites = BTreeSet::new();
                let read_event = read_batch
                    .analysis()
                    .value_flow()
                    .source(read.source())
                    .expect("a bound store read retains its value-flow source")
                    .key();
                for (write_index, write_batch) in batches.iter().enumerate() {
                    if batch_policy_ids[read_index].is_disjoint(&batch_policy_ids[write_index]) {
                        continue;
                    }
                    for (position, write) in
                        write_batch.analysis().store_writes().iter().enumerate()
                    {
                        if !write.channel().may_alias(read.channel()) {
                            continue;
                        }
                        assert_eq!(
                            write_batch.analysis().universe().hash(),
                            read_batch.analysis().universe().hash(),
                            "batches of one policy share one taint universe"
                        );
                        classes = classes.union(&write_classes[write_index][position]);
                        for observed in &observed_writes[write_index][position] {
                            contributors.insert(observed.source_endpoint.clone());
                            for internal in read_batch.policy_ids() {
                                let Some(plan) = metadata.get(internal) else {
                                    continue;
                                };
                                if plan.policy_id != observed.policy_id {
                                    continue;
                                }
                                for read_metadata in plan
                                    .store_reads
                                    .iter()
                                    .filter(|candidate| &candidate.event == read_event)
                                {
                                    if observed.channel.may_alias(&read_metadata.channel) {
                                        crossings.push(StoreCrossingProvenance {
                                            source_endpoint: observed.source_endpoint.clone(),
                                            source_to_write: observed.source_to_write.clone(),
                                            write_endpoint: observed.endpoint.clone(),
                                            write_call: observed.call.clone(),
                                            read_endpoint: read_metadata.endpoint.clone(),
                                            read_call: read_metadata.call.clone(),
                                            write_channel: observed.channel.clone(),
                                            read_channel: read_metadata.channel.clone(),
                                        });
                                    }
                                }
                            }
                        }
                        read_write_sites.extend(write_sites[write_index][position].iter().cloned());
                        read_write_origin_sites
                            .extend(write_origin_sites[write_index][position].iter().cloned());
                    }
                }
                if !classes.is_empty() {
                    crossings.sort_by(|left, right| {
                        left.source_endpoint
                            .cmp(&right.source_endpoint)
                            .then_with(|| left.write_endpoint.cmp(&right.write_endpoint))
                            .then_with(|| left.read_endpoint.cmp(&right.read_endpoint))
                            .then_with(|| {
                                left.write_call
                                    .durable_key()
                                    .cmp(&right.write_call.durable_key())
                            })
                            .then_with(|| {
                                left.read_call
                                    .durable_key()
                                    .cmp(&right.read_call.durable_key())
                            })
                    });
                    crossings.dedup();
                    next.push(StoreReadSeed {
                        source: read.source(),
                        event: read_event.clone(),
                        classes,
                        contributors,
                        crossings,
                        write_sites: read_write_sites,
                        write_origin_sites: read_write_origin_sites,
                    });
                }
            }
            next.sort_by_key(|seed| seed.source);
            if next != seeding.seeds[read_index] {
                seeding.seeds[read_index] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(seeding)
}

/// One batch's report, its timing, and what its composition found incomplete.
struct BatchReport {
    barrier_notes: Vec<compose::ValueTypeBarrierFindingNotes>,
    barrier_pairs: Vec<compose::ValueTypeBarrierPairEvidence>,
    report: TaintFindingReport,
    propagation_elapsed: Duration,
    reconstruction_elapsed: Duration,
    /// Present for a composed batch that is incomplete: the diagnostic its
    /// first incompleteness renders. Each policy root of the batch receives it.
    composition_diagnostics: Vec<PolicyDiagnostic>,
    composition_finding_diagnostics: Vec<PolicyDiagnostic>,
    /// The snapshot input status of a composed batch's first incompleteness,
    /// when it has one. The completion reason reads it.
    composition_status: Option<SemanticInputStatus>,
    /// The origin metadata of the sources a composed batch matched on the
    /// frontier. The compile bound none of them, so the projection reads
    /// these beside the compiled ones.
    frontier_sources: Vec<CompiledTaintEndpoint>,
    /// Per-row frontier refusals retained independently of the first cause.
    composition_refusals: Vec<PolicyDiagnostic>,
}

/// The engine of a batch. Every policy of one batch shares its engine, because
/// the batch planner partitions by engine first.
fn batch_engine<'m>(
    batch: &TaintBatch,
    metadata: &'m HashMap<String, PreparedTaintPlan>,
) -> &'m TaintEngine {
    let internal = batch
        .policy_ids()
        .next()
        .expect("a taint batch holds at least one policy");
    &metadata
        .get(internal)
        .expect("a batch policy has compiled metadata")
        .engine
}

/// The first request-wide output or evidence lane that is spent, if any.
fn first_exhausted_taint_lane(
    execution_budget: &TaintExecutionBudget,
) -> Option<ExhaustedTaintLane> {
    [
        (
            ExhaustedTaintLane::Findings,
            execution_budget.remaining_findings,
        ),
        (
            ExhaustedTaintLane::Witnesses,
            execution_budget.remaining_witnesses,
        ),
        (
            ExhaustedTaintLane::WitnessSteps,
            execution_budget.remaining_witness_steps,
        ),
        (
            ExhaustedTaintLane::WitnessExpansions,
            execution_budget.remaining_witness_expansions,
        ),
        (
            ExhaustedTaintLane::WitnessBytes,
            execution_budget.remaining_witness_bytes,
        ),
    ]
    .into_iter()
    .find_map(|(lane, remaining)| (remaining == 0).then_some(lane))
}

/// Solve one batch on the ICFG engine and collect its findings.
fn solve_icfg_batch(
    batch: &TaintBatch,
    workspace: &WorkspaceAnalyzer,
    cancellation: &CancellationToken,
    budget: &PolicyBudget,
    execution_budget: &mut TaintExecutionBudget,
    icfg_provider: &WorkspaceIcfgProvider<'_>,
    barriers: &[(Box<str>, crate::definition::ValueTypePredicate)],
) -> Result<BatchReport, TaintBatchError> {
    let limits = budget.query_limits();
    let value_flow_limits = limits.value_flow;
    let witness_retention = WitnessRetentionLimits::best_effort(
        1,
        value_flow_limits.max_retained_relations,
        value_flow_limits.max_retained_bytes,
    )
    .map_err(|error| error.to_string())?;
    let mut request = DataflowRequest::new(&mut execution_budget.solver, cancellation);
    record_taint_plan_artifacts(workspace, batch.analysis());
    let propagation_started = Instant::now();
    if !barriers.is_empty() {
        let witness_limits = WitnessReconstructionLimits::new(
            value_flow_limits
                .max_witness_steps
                .min(budget.max_witness_steps()),
            value_flow_limits.max_witness_expansions,
        )
        .map_err(|error| error.to_string())?;
        let collection = TaintFindingCollectionLimits::new(
            execution_budget.remaining_findings,
            execution_budget.remaining_witnesses,
            execution_budget.remaining_witness_steps,
            execution_budget.remaining_witness_expansions,
            execution_budget.remaining_witness_bytes,
        )
        .map_err(|error| error.to_string())?;
        let session = brokk_bifrost_flow::taint::IcfgBarrierSession::discover(
            batch.analysis().value_flow().root(),
            icfg_provider,
            batch.analysis(),
            witness_retention,
            &mut execution_budget.semantic,
            &mut request,
            budget.max_origins_per_finding(),
            witness_limits,
            collection,
            &mut execution_budget.attribution,
        )
        .map_err(barrier_batch_error)?;
        let reconstruction_started = Instant::now();
        let semantic = budget.query_limits().semantic;
        let service = crate::taint_barriers::ValueTypeBarrierService::new(
            workspace,
            SemanticExecutionBudget::new(semantic.max_materialized_files),
        );
        let mut semantic_request =
            SemanticRequest::new(&mut execution_budget.semantic, cancellation);
        let outcome = session
            .refine(batch.analysis(), &mut request, |observation, predicate| {
                service
                    .classify(observation, predicate, &mut semantic_request)
                    .map_err(|error| error.to_string().into())
            })
            .map_err(barrier_batch_error)?;
        brokk_bifrost_analysis::profiling::note_with(|| {
            format!(
                "taint.icfg.barriers.counts classifier_calls={} pairs={}",
                service.checks(),
                outcome.barrier_pairs.len()
            )
        });
        return Ok(BatchReport {
            report: outcome.report,
            barrier_pairs: outcome.barrier_pairs,
            barrier_notes: outcome.barrier_notes,
            propagation_elapsed: propagation_started.elapsed(),
            reconstruction_elapsed: reconstruction_started.elapsed(),
            composition_diagnostics: Vec::new(),
            composition_finding_diagnostics: Vec::new(),
            composition_refusals: Vec::new(),
            composition_status: None,
            frontier_sources: Vec::new(),
        });
    }
    let result = brokk_bifrost_flow::taint::solve_taint_batch_with_witnesses(
        batch.analysis().value_flow().root(),
        icfg_provider,
        batch.analysis(),
        witness_retention,
        &mut execution_budget.semantic,
        &mut request,
    )
    .map_err(|error| error.to_string())?;
    let propagation_elapsed = propagation_started.elapsed();
    let witness_limits = WitnessReconstructionLimits::new(
        value_flow_limits
            .max_witness_steps
            .min(budget.max_witness_steps()),
        value_flow_limits.max_witness_expansions,
    )
    .map_err(|error| error.to_string())?;
    if let Some(lane) = first_exhausted_taint_lane(execution_budget) {
        return Err(TaintBatchError::BudgetExhausted(lane));
    }
    let collection = TaintFindingCollectionLimits::new(
        execution_budget.remaining_findings,
        execution_budget.remaining_witnesses,
        execution_budget.remaining_witness_steps,
        execution_budget.remaining_witness_expansions,
        execution_budget.remaining_witness_bytes,
    )
    .map_err(|error| error.to_string())?;
    let reconstruction_started = Instant::now();
    let report = collect_taint_findings_with_attribution_budget(
        batch.analysis(),
        result,
        budget.max_origins_per_finding(),
        witness_limits,
        collection,
        &mut execution_budget.attribution,
    )
    .map_err(|error| error.to_string())?;
    let reconstruction_elapsed = reconstruction_started.elapsed();
    Ok(BatchReport {
        barrier_notes: Vec::new(),
        barrier_pairs: Vec::new(),
        report,
        propagation_elapsed,
        reconstruction_elapsed,
        composition_diagnostics: Vec::new(),
        composition_finding_diagnostics: Vec::new(),
        composition_refusals: Vec::new(),
        composition_status: None,
        frontier_sources: Vec::new(),
    })
}

/// A source, sanitizer or transform selector of one policy, by its index in
/// the policy's specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FrontierSelector {
    Source(usize),
    Sanitizer(usize),
    Transform(usize),
}

/// One endpoint a frontier selector bound.
#[derive(Clone)]
pub(crate) enum FrontierEndpoint {
    Source(BoundEndpoint),
    Sanitizer(BoundSanitizer),
    Transform(BoundTransform),
}

impl FrontierEndpoint {
    /// The procedure the endpoint lies in. A sanitizer's or transform's two
    /// ports are bound at one call, so they lie in one procedure.
    pub(crate) fn procedure(&self) -> DurableProcedureKey {
        let (input, output) = match self {
            Self::Source(endpoint) => (endpoint, endpoint),
            Self::Sanitizer(sanitizer) => (&sanitizer.input, &sanitizer.output),
            Self::Transform(transform) => (&transform.input, &transform.output),
        };
        let procedure = input.point.procedure().durable_key();
        debug_assert_eq!(procedure, output.point.procedure().durable_key());
        procedure
    }
}

/// One frontier selection's endpoints, incompleteness, and per-row refusals.
/// Refusals also stay separate so an earlier composition cause cannot hide
/// their row-specific diagnostics (#4919).
pub(crate) struct FrontierBindings {
    pub(crate) endpoints: Vec<FrontierEndpoint>,
    pub(crate) gaps: Vec<String>,
    pub(crate) refusals: Vec<RefusalNotice>,
}

/// What the composition needs to match one policy's sources, sanitizers and
/// transforms on the frontier: the policy's selectors and
/// definitions, and a compiler whose binding code turns a selected row into
/// endpoints exactly as the up-front binding of the ICFG engine does. The
/// provider decides which blob to evaluate a selector on and memoizes; this
/// value selects and binds.
pub(crate) struct FrontierEndpointBinder<'a> {
    compiler: TaintPolicyCompiler<'a>,
    policy: &'a LoadedPolicy,
    spec: &'a ResolvedTaintPolicySpec,
    universe: TaintUniverse,
    /// The analyzed files, which a sliced selector's callers, dispatch and
    /// references still answer over.
    workspace_files: Vec<ProjectFile>,
}

impl<'a> FrontierEndpointBinder<'a> {
    /// `compiler` is a fresh compiler over the workspace the policy runs on;
    /// its selector session and binding state serve the frontier alone.
    pub(crate) fn new(
        compiler: TaintPolicyCompiler<'a>,
        policy: &'a LoadedPolicy,
        spec: &'a ResolvedTaintPolicySpec,
        universe: TaintUniverse,
    ) -> Self {
        let workspace = compiler.selectors.workspace();
        Self {
            compiler: compiler.with_file_local_matched_values(),
            policy,
            spec,
            universe,
            workspace_files: workspace.analyzer().analyzed_files(),
        }
    }

    /// The policy whose endpoints this binder matches.
    pub(crate) fn policy_id(&self) -> &PolicyId {
        &self.policy.definition().metadata.id
    }

    pub(crate) fn barriers(&self) -> Vec<(Box<str>, crate::definition::ValueTypePredicate)> {
        self.spec
            .barriers
            .iter()
            .map(|barrier| (barrier.id.as_str().into(), barrier.value_type))
            .collect()
    }

    pub(crate) fn analysis_type(&self) -> crate::definition::PolicyAnalysisType {
        self.policy.definition().analysis.analysis_type()
    }

    /// Every selector the frontier matches: the active sources, then the
    /// sanitizers, then the transforms.
    pub(crate) fn selectors(&self) -> Vec<FrontierSelector> {
        let spec = self.spec;
        spec.sources
            .iter()
            .enumerate()
            .filter(|(_, source)| threat_model_source_is_active(source, &spec.threat_models))
            .map(|(index, _)| FrontierSelector::Source(index))
            // Conditional sanitizers are applied by the branch-conditioned kill derivation.
            .chain(
                spec.sanitizers
                    .iter()
                    .enumerate()
                    .filter(|(_, sanitizer)| sanitizer.definition.kind.transfer_ports().is_some())
                    .map(|(index, _)| FrontierSelector::Sanitizer(index)),
            )
            .chain((0..spec.transforms.len()).map(FrontierSelector::Transform))
            .collect()
    }

    fn selector(
        &self,
        selector: FrontierSelector,
    ) -> Result<&'a ResolvedPolicySelector, TaintPolicyCompileError> {
        let spec = self.spec;
        let path = match selector {
            FrontierSelector::Source(index) => &spec.sources[index].definition.selector_path,
            FrontierSelector::Sanitizer(index) => &spec.sanitizers[index].selector_path,
            FrontierSelector::Transform(index) => &spec.transforms[index].selector_path,
        };
        self.policy
            .resolved_selectors()
            .iter()
            .find(|selector| &selector.path == path)
            .ok_or_else(|| TaintPolicyCompileError::MissingSelector(path.as_str().to_owned()))
    }

    /// Why the selector's query cannot be evaluated on one blob, or `None`
    /// when it can. A relational selector has no query to slice.
    pub(crate) fn widen_reason(
        &self,
        selector: FrontierSelector,
    ) -> Result<Option<crate::units::WidenReason>, TaintPolicyCompileError> {
        Ok(match self.selector(selector)?.as_query() {
            Some((_, query)) => crate::unit_execution::frontier_slicing_widen_reason(query),
            None => Some(crate::units::WidenReason::PlanCrossesSeeds),
        })
    }

    /// The rows the selector selects with its seed enumeration narrowed to
    /// `file`.
    pub(crate) fn select_in_file(
        &mut self,
        selector: FrontierSelector,
        file: &ProjectFile,
    ) -> Result<Vec<SelectedSite>, TaintPolicyCompileError> {
        let resolved = self.selector(selector)?;
        self.compiler
            .selectors
            .select_taint_in_file(resolved, file, &self.workspace_files)
            .map_err(taint_selector_error)
    }

    /// The rows the selector selects over the whole workspace.
    pub(crate) fn select_workspace(
        &mut self,
        selector: FrontierSelector,
    ) -> Result<Vec<SelectedSite>, TaintPolicyCompileError> {
        let resolved = self.selector(selector)?;
        self.compiler
            .selectors
            .select_taint(resolved)
            .map_err(taint_selector_error)
    }

    /// The authored summaries the active semantic models hold for the
    /// external targets one call's dispatch boundaries name, bound as the
    /// compile binds a region's (`bind_external_summaries`) with the call's
    /// artifact as the root. `None` when no summary applies.
    pub(crate) fn external_summaries(
        &self,
        targets: &[ExactExternalProcedureTarget],
        unmaterialized: &[UnmaterializedExternalTarget],
        artifact: &SemanticArtifactKey,
        call_behavior: brokk_bifrost_flow::dataflow::UnmodeledCallBehavior,
    ) -> Result<Option<ExternalSemanticSummarySet>, TaintPolicyCompileError> {
        self.compiler
            .bind_external_summaries(targets, unmaterialized, artifact, call_behavior)
    }

    /// Bind selected rows of one selector with the compile's binding code.
    /// Returns the endpoints and every reason the selection or the binding
    /// may have missed one: refused rows and selector evaluations that did
    /// not finish.
    pub(crate) fn bind(
        &mut self,
        selector: FrontierSelector,
        sites: Vec<SelectedSite>,
    ) -> Result<FrontierBindings, TaintPolicyCompileError> {
        let resolved = self.selector(selector)?;
        let spec = self.spec;
        let mut endpoints = Vec::new();
        for site in sites {
            match selector {
                FrontierSelector::Source(index) => endpoints.extend(
                    self.compiler
                        .bind_source(&spec.sources[index], resolved, site)?
                        .into_iter()
                        .map(FrontierEndpoint::Source),
                ),
                FrontierSelector::Sanitizer(index) => endpoints.extend(
                    self.compiler
                        .bind_sanitizer(&spec.sanitizers[index], resolved, site)?
                        .into_iter()
                        .map(FrontierEndpoint::Sanitizer),
                ),
                FrontierSelector::Transform(index) => endpoints.extend(
                    self.compiler
                        .bind_transform(&spec.transforms[index], resolved, site)?
                        .into_iter()
                        .map(FrontierEndpoint::Transform),
                ),
            }
        }
        let refusals = refusal_messages(&std::mem::take(&mut self.compiler.refused_sites));
        let mut gaps = refusals
            .iter()
            .filter(|refusal| refusal.impact == PolicyDiagnosticImpact::RunIncomplete)
            .map(|refusal| refusal.message.clone())
            .collect::<Vec<_>>();
        gaps.extend(
            self.compiler
                .selectors
                .take_incomplete_taint_selectors()
                .into_iter()
                .map(|gap| gap.message),
        );
        Ok(FrontierBindings {
            endpoints,
            gaps,
            refusals,
        })
    }

    /// The evidence the ICFG engine would give a frontier matched-value
    /// source bound from `selection`: its own matched-value resolution, which
    /// asks points-to for the coverage of the matched value. The frontier
    /// binds the source without that question, so the
    /// composition asks it here, once per source that reaches a sink.
    ///
    /// A row that points-to resolves to no observation binds no source in the
    /// ICFG engine; the composition has already found a flow from it, so the
    /// evidence is neither proven nor complete.
    pub(crate) fn source_evidence(
        &mut self,
        selection: &SelectedSite,
    ) -> Result<compose::HopQuality, TaintPolicyCompileError> {
        let refusals = self.compiler.refused_sites.len();
        let resolved = self.compiler.resolve_matched_value(selection.clone());
        // The frontier's own resolution of the same row already reported its
        // refusals.
        self.compiler.refused_sites.truncate(refusals);
        let resolved = resolved?;
        let Some(first) = resolved.first() else {
            return Ok(compose::HopQuality::UNCERTAIN);
        };
        debug_assert!(
            resolved
                .iter()
                .all(|value| value.proof == first.proof && value.completeness == first.completeness),
            "the observations of one selected row share its evidence"
        );
        Ok(compose::HopQuality::new(
            matches!(first.proof, ProofStatus::Proven),
            matches!(first.completeness, EvidenceCompleteness::Complete),
        ))
    }

    /// The endpoints of one procedure in the composition's terms, the origin
    /// metadata of its sources, and the sources whose evidence is unknown.
    /// Sources are ordered and their events minted as the compile orders and
    /// mints them, with ordinals counted within the procedure; sanitizers
    /// acting at one point and carrier pair are merged as the compile merges
    /// them.
    pub(crate) fn procedure_endpoints(
        &self,
        endpoints: Vec<FrontierEndpoint>,
    ) -> Result<
        (
            ProcedureEndpoints,
            Vec<CompiledTaintEndpoint>,
            Vec<UnjudgedSource>,
        ),
        TaintPolicyCompileError,
    > {
        let mut sources = Vec::new();
        let mut sanitizers = Vec::new();
        let mut transforms = Vec::new();
        for endpoint in endpoints {
            match endpoint {
                FrontierEndpoint::Source(source) => sources.push(source),
                FrontierEndpoint::Sanitizer(sanitizer) => sanitizers.push(sanitizer),
                FrontierEndpoint::Transform(transform) => transforms.push(transform),
            }
        }
        sort_bound_endpoints(&mut sources);
        sort_bound_sanitizers(&mut sanitizers);
        sort_bound_transforms(&mut transforms);
        let specs = keyed_source_event_specs(&sources, 0)?;
        let metadata = endpoint_metadata(&sources, &specs);
        let mut answer = ProcedureEndpoints::none();
        let mut unjudged = Vec::new();
        for (source, (key, _)) in sources.iter().zip(specs) {
            let origin = SourceEventKey::new(key);
            let evidence = match &source.unjudged {
                Some(selection) => {
                    unjudged.push(UnjudgedSource {
                        origin: origin.clone(),
                        identity: source.endpoint.clone(),
                        selection: Arc::clone(selection),
                    });
                    compose::EndpointEvidence::Unknown
                }
                None => compose::EndpointEvidence::Known(compose::HopQuality::new(
                    matches!(source.proof, ProofStatus::Proven),
                    matches!(source.completeness, EvidenceCompleteness::Complete),
                )),
            };
            answer.sources.push(BoundSource {
                point: source.point.clone(),
                phase: source.phase,
                carrier: source.carrier.clone(),
                classes: class_set(&self.universe, &source.labels)?,
                origin,
                evidence,
            });
        }
        for slot in sanitizer_slots(&self.universe, &sanitizers)? {
            answer.sanitizers.push(compose::BoundSanitizer {
                point: slot.point,
                input: slot.input,
                output: slot.output,
                removed: slot.removed,
                proven: slot.proven,
                resolved: slot.complete,
            });
        }
        for transform in transforms {
            let removed = class_set(&self.universe, &transform.removes)?;
            let added = class_set(&self.universe, &transform.adds)?;
            let certain = matches!(
                conjoin_proof(&transform.input.proof, &transform.output.proof),
                ProofStatus::Proven
            ) && matches!(
                conjoin_completeness(
                    &transform.input.completeness,
                    &transform.output.completeness,
                ),
                EvidenceCompleteness::Complete
            );
            answer.transforms.push(compose::BoundTransform {
                point: transform.output.point.clone(),
                input: transform.input.carrier,
                output: transform.output.carrier,
                function: TaintEdgeFunction::kill(&removed)
                    .compose(&TaintEdgeFunction::generate(&added)),
                uncertain: !certain,
            });
        }
        Ok((answer, metadata, unjudged))
    }
}

/// A frontier source bound without its points-to evidence: the selected row
/// to judge it from, and the identity that keys the judgment. The memo of one
/// policy run is keyed by the endpoint and the row's site.
pub(crate) struct UnjudgedSource {
    pub(crate) origin: SourceEventKey,
    pub(crate) identity: ResolvedEndpointIdentity,
    pub(crate) selection: Arc<SelectedSite>,
}

/// Answer one batch by composition over the partial flows. An
/// incomplete composition stays incomplete: nothing here reruns the batch on
/// the ICFG engine.
#[allow(clippy::too_many_arguments)]
fn compose_batch(
    batch: &TaintBatch,
    flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
    metadata: &HashMap<String, PreparedTaintPlan>,
    policies: &[&LoadedPolicy],
    workspace: &WorkspaceAnalyzer,
    cancellation: &CancellationToken,
    budget: &PolicyBudget,
    execution_budget: &mut TaintExecutionBudget,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    composition_memo: &CompositionMemo,
) -> Result<BatchReport, TaintBatchError> {
    let flow_state = flow_state.into();
    // A composed plan's compatibility names its policy, so its batch holds
    // that one policy, whose sources, sanitizers and transforms the frontier
    // matches.
    let [internal] = batch.policy_ids().collect::<Vec<_>>()[..] else {
        unreachable!("a composed batch holds one policy");
    };
    let prepared = metadata
        .get(internal)
        .expect("a batch policy has compiled metadata");
    let policy_id = &prepared.policy_id;
    let policy = policies
        .iter()
        .copied()
        .find(|policy| &policy.definition().metadata.id == policy_id)
        .expect("a composed policy is a member of its coordinator batch");
    let spec = policy
        .resolved_taint()
        .expect("a composed policy is a taint policy");
    let composition_budget = CompositionBudget {
        max_procedures: budget.max_composition_procedures(),
        max_hops: budget.max_composition_hops(),
        max_callers_per_procedure: budget.max_composition_callers_per_procedure(),
    };
    let semantic = budget.query_limits().semantic;
    let cache = DiscoveryMaterializationCache::default();
    let provider = {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.compose.bind");
        PolicyCompositionProvider::new(
            workspace,
            SemanticExecutionBudget::new(semantic.max_materialized_files),
            &cache,
            batch.analysis(),
            &prepared.external_models,
            composition_budget.max_callers_per_procedure,
            FrontierEndpointBinder::new(
                TaintPolicyCompiler::new(
                    workspace,
                    &flow_state,
                    active_semantic_model_snapshot
                        .as_ref()
                        .map(|snapshot| Arc::clone(snapshot.active_models())),
                    budget.query_limits(),
                    budget.max_selector_results(),
                    cancellation,
                )
                .with_active_semantic_model_snapshot(active_semantic_model_snapshot),
                policy,
                spec,
                batch.analysis().universe().clone(),
            ),
            composition_memo,
        )
    };
    let propagation_started = Instant::now();
    let outcome = {
        let mut request = SemanticRequest::new(&mut execution_budget.semantic, cancellation);
        compose_taint_batch(
            batch.analysis(),
            &provider,
            composition_budget,
            &mut request,
        )
    };
    let propagation_elapsed = propagation_started.elapsed();
    if let Some(failure) = provider.failure() {
        return Err(TaintBatchError::Internal(failure.to_string()));
    }
    let outcome = outcome.map_err(|error| error.to_string())?;
    let (partial_flows_read, partial_flows_computed) = provider.partial_flow_counts();
    let (barrier_checks, barrier_fixpoints, barrier_procedures) = provider.barrier_work_counts();
    // The provider dispatches each distinct call once per run, whether the
    // search or the openness refinement asked first.
    let dispatches = provider.dispatches_made();
    let endpoint_widened = provider.endpoint_widened();
    brokk_bifrost_analysis::profiling::note_with(|| {
        let excluded_callers = provider.excluded_callers();
        format!(
            "taint.compose.counts candidate_pairs={} strict_replays={} barrier_checks={barrier_checks} barrier_fixpoints={barrier_fixpoints} barrier_procedures={barrier_procedures} supports={} edges={} chop_procedures={} extra_proof_lookups={} changed_edge_qualities={} policies={:?} procedures={} hops={} dispatches={} callers={} inactive_callers={} excluded_callers={:?} partial_flows_read={partial_flows_read} partial_flows_computed={partial_flows_computed} endpoint_evaluations={} source_evidence_resolved={} endpoint_widened={} widened_selectors={:?} incomplete={:?} abstained={:?}",
            outcome.stats.baseline_candidate_pairs,
            outcome.stats.strict_replays,
            outcome.stats.recorded_supports,
            outcome.stats.recorded_edges,
            outcome.stats.chop_procedures,
            outcome.stats.extra_proof_lookups,
            outcome.stats.changed_edge_qualities,
            batch.policy_ids().collect::<Vec<_>>(),
            outcome.stats.procedures,
            outcome.stats.hops,
            dispatches,
            outcome.stats.callers,
            excluded_callers.len(),
            &*excluded_callers,
            provider.endpoint_evaluations(),
            provider.source_evidence_resolved(),
            endpoint_widened.len(),
            endpoint_widened,
            outcome.incompleteness,
            outcome.abstained,
        )
    });
    let (composition_diagnostics, composition_status) =
        composition_first_cause(workspace, &provider, &outcome.incompleteness)?;
    let mut composition_finding_diagnostics = Vec::new();
    if outcome.report.is_complete() || outcome.report.is_proven_by_authored_summaries() {
        for cause in &outcome.finding_incompleteness {
            let (family, message, primary) = composition_cause_text(workspace, &provider, cause)?;
            if let Ok(diagnostic) = PolicyDiagnostic::try_new_in_family(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Warning,
                PolicyDiagnosticImpact::FindingPartial,
                family,
                message,
                primary,
                Vec::new(),
            ) {
                composition_finding_diagnostics.push(diagnostic);
            }
        }
    }
    if let Some(lane) = first_exhausted_taint_lane(execution_budget) {
        return Err(TaintBatchError::BudgetExhausted(lane));
    }
    if outcome.report.findings().len() > execution_budget.remaining_findings {
        return Err(TaintBatchError::BudgetExhausted(
            ExhaustedTaintLane::Findings,
        ));
    }
    let composition_refusals = provider
        .refusal_messages()
        .into_iter()
        .map(|refusal| {
            PolicyDiagnostic::new_bounded(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Warning,
                refusal.impact,
                refusal.message,
            )
        })
        .collect();
    Ok(BatchReport {
        barrier_notes: outcome.barrier_notes,
        barrier_pairs: outcome.barrier_pairs,
        report: outcome.report,
        propagation_elapsed,
        reconstruction_elapsed: Duration::ZERO,
        composition_diagnostics,
        composition_finding_diagnostics,
        composition_refusals,
        composition_status,
        frontier_sources: provider.frontier_sources(),
    })
}

#[allow(clippy::too_many_arguments)]
fn solve_and_project_batch(
    batch: &TaintBatch,
    flow_state: impl Into<brokk_bifrost_rql::SemanticFlowResources> + Clone,
    store_seeds: &[StoreReadSeed],
    metadata: &HashMap<String, PreparedTaintPlan>,
    policies: &[&LoadedPolicy],
    payloads: &mut HashMap<PolicyId, TaintProjectionPayload>,
    merge: &mut BatchMerge,
    workspace: &WorkspaceAnalyzer,
    cancellation: &CancellationToken,
    budget: &PolicyBudget,
    execution_budget: &mut TaintExecutionBudget,
    public_findings: &mut Vec<brokk_bifrost_rql::structural::CodeQueryTaintFinding>,
    retained_analyses: &mut Vec<Arc<ProductionTaintAnalysisResult>>,
    batch_planning_elapsed: Duration,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    icfg_provider: &WorkspaceIcfgProvider<'_>,
    store_write_evidence: &StoreWriteEvidenceByRead,
    composition_memo: &CompositionMemo,
) -> Result<(), TaintBatchError> {
    let flow_state = flow_state.into();
    // Each batch solves its own regions and reconstructs evidence only for its
    // own findings, so give it a fresh solve and witness budget instead of the
    // request-wide remainder a corpus would have already drained (#1935 for the
    // witness lanes, #2208 for the semantic and solver lanes).
    // `remaining_findings` is deliberately not reset: it stays the request-wide
    // cap on total output.
    execution_budget.reset_per_batch_witness_budget(budget);
    execution_budget.reset_per_batch_solve_budget(budget);
    let engine = batch_engine(batch, metadata);
    let BatchReport {
        barrier_notes,
        barrier_pairs,
        report,
        propagation_elapsed,
        reconstruction_elapsed,
        composition_diagnostics,
        composition_finding_diagnostics,
        composition_refusals,
        composition_status,
        frontier_sources,
    } = match engine {
        TaintEngine::Icfg { .. } => solve_icfg_batch(
            batch,
            workspace,
            cancellation,
            budget,
            execution_budget,
            icfg_provider,
            batch.analysis().value_type_barriers(),
        )?,
        TaintEngine::Composition => compose_batch(
            batch,
            &flow_state,
            metadata,
            policies,
            workspace,
            cancellation,
            budget,
            execution_budget,
            active_semantic_model_snapshot,
            composition_memo,
        )?,
    };
    let attribution = report.attribution_work();
    execution_budget.remaining_findings = execution_budget
        .remaining_findings
        .saturating_sub(report.findings().len());
    execution_budget.remaining_witnesses = execution_budget
        .remaining_witnesses
        .saturating_sub(report.retained_witnesses());
    execution_budget.remaining_witness_steps = execution_budget
        .remaining_witness_steps
        .saturating_sub(report.retained_witness_steps());
    execution_budget.remaining_witness_expansions = execution_budget
        .remaining_witness_expansions
        .saturating_sub(report.witness_expansions());
    execution_budget.remaining_witness_bytes = execution_budget
        .remaining_witness_bytes
        .saturating_sub(report.retained_witness_bytes());
    let projection_limits = brokk_bifrost_rql::structural::CodeQueryTaintProjectionLimits::new(
        budget.max_origins_per_finding(),
        budget.max_witnesses_per_finding(),
        budget.max_witness_steps(),
        budget.max_witness_bytes(),
    );
    let mut retained = ProductionTaintAnalysisResult::new(
        Arc::new(batch.analysis().clone()),
        Arc::new(report),
        *batch.compatibility(),
        brokk_bifrost_flow::taint::TaintProjectionLimits::new(
            budget.max_origins_per_finding(),
            budget.max_witnesses_per_finding(),
            budget.max_witness_steps(),
            budget.max_witness_bytes(),
        ),
    );
    debug_assert!(retained.plan_report_match());
    retained.set_frontier_sources(frontier_sources.iter().map(|source| source.event.clone()));
    let standalone_projection_started = Instant::now();
    let projected_findings = brokk_bifrost_rql::structural::project_taint_finding_report(
        workspace,
        retained.plan(),
        retained.report(),
        retained.projection_scope(),
        projection_limits,
    )
    .map_err(|error| error.to_string())?;
    let standalone_projection_elapsed = standalone_projection_started.elapsed();
    retained
        .set_registration_digest(&projected_findings)
        .map_err(|error| error.to_string())?;
    let policy_projection_started = Instant::now();
    for projection in batch.projections() {
        let compiled = metadata
            .get(projection.policy_id())
            .ok_or_else(|| "taint batch projection has no compiled policy metadata".to_owned())?;
        // The sources a composition matched on the frontier attribute its
        // findings' origins exactly as compiled sources do.
        let extended;
        let plan = if frontier_sources.is_empty() {
            compiled
        } else {
            let mut sources = compiled.sources.to_vec();
            sources.extend(frontier_sources.iter().cloned());
            extended = PreparedTaintPlan {
                sources: sources.into_boxed_slice(),
                ..compiled.clone()
            };
            &extended
        };
        let policy = policies
            .iter()
            .copied()
            .find(|policy| policy.definition().metadata.id == plan.policy_id)
            .ok_or_else(|| {
                "compiled taint policy is absent from the coordinator batch".to_owned()
            })?;
        let spec = policy
            .resolved_taint()
            .ok_or_else(|| "compiled taint policy lost its resolved specification".to_owned())?;
        let mut dropped_for_missing_origins = 0usize;
        let projected = project_policy_findings(
            workspace,
            policy,
            spec,
            plan,
            retained.plan().universe(),
            retained.report(),
            store_seeds,
            budget,
            &mut dropped_for_missing_origins,
            store_write_evidence,
            &barrier_notes,
            &barrier_pairs,
        )?;
        let has_partial_finding = projected.iter().any(|projection| {
            projection.pairs.iter().any(|pair| {
                matches!(
                    pair.report.completeness,
                    FindingCompleteness::Partial { .. }
                )
            })
        });
        let payload = payloads
            .get_mut(&plan.policy_id)
            .ok_or_else(|| "compiled taint policy has no prepared payload".to_owned())?;
        // One batch solves each root's closure, so a sink reachable from two
        // roots yields the same envelope from two batches; keep the first copy.
        // Not at plan time: one sink in two plans with different source sets
        // has two identities, and both must survive. Duplicates within one
        // batch still reach validate_taint_batch.
        let identities = merge.envelopes.entry(plan.policy_id.clone()).or_default();
        let mut fresh = Vec::with_capacity(projected.len());
        for projection in projected {
            let identity = taint_envelope_identity(&plan.policy_id, &projection);
            if !identities.contains(&identity) {
                fresh.push((identity, projection));
            }
        }
        for (identity, projection) in fresh {
            identities.insert(identity);
            payload.projections.push(projection);
        }
        if !composition_refusals.is_empty() {
            let mut reasons = match &payload.completion {
                PolicyRunCompletion::Inconclusive { reasons, .. } => reasons.clone(),
                _ => Vec::new(),
            };
            reasons.push(PolicyIncompleteReason::CapabilityIncomplete);
            payload.completion =
                PolicyRunCompletion::inconclusive(reasons).map_err(|error| error.to_string())?;
            payload
                .diagnostics
                .extend(composition_refusals.iter().cloned());
        }
        // A composed batch's first incompleteness is the run's diagnostic for
        // this root. The completion below already downgrades the run.
        payload
            .diagnostics
            .extend(composition_diagnostics.iter().cloned());
        // Both counters were already published at zero by
        // `record_compile_metrics`, so this raises existing metrics and never
        // adds a name. See that function for why the name set has to be fixed.
        increment_work_metric(
            &mut payload.work,
            "taint.propagation_solves",
            PolicyWorkUnit::Count,
            1,
        )?;
        increment_work_metric(
            &mut payload.work,
            "taint.propagation_shared_memberships",
            PolicyWorkUnit::Count,
            u64::try_from(batch.projections().len().saturating_sub(1)).unwrap_or(u64::MAX),
        )?;
        record_attribution_work(&mut payload.work, attribution)?;
        let total = merge
            .missing_origins
            .entry(plan.policy_id.clone())
            .or_default();
        *total = total.saturating_add(dropped_for_missing_origins);
        if !retained.report().is_complete()
            && matches!(
                payload.completion,
                PolicyRunCompletion::Complete
                    | PolicyRunCompletion::ProvenBySummary
                    | PolicyRunCompletion::Inconclusive { .. }
            )
        {
            if retained.report().is_proven_by_authored_summaries() {
                // The run terminates precisely, but every open boundary was
                // closed by an authored-complete external summary, not by
                // derived proof (#1916). Only lower `Complete` to this tier;
                // never lift a genuine `Inconclusive` from an earlier batch.
                if matches!(payload.completion, PolicyRunCompletion::Complete) {
                    payload.completion = PolicyRunCompletion::ProvenBySummary;
                }
                if matches!(payload.completion, PolicyRunCompletion::ProvenBySummary) {
                    payload
                        .authored_arm_closures
                        .extend(policy_authored_arm_closures(retained.report()));
                    payload.authored_arm_closures.sort();
                    payload.authored_arm_closures.dedup();
                }
            } else {
                // Keep the first path-relevant cause the plan retained (#1952):
                // an unavailable capability stays a typed capability reason and
                // the diagnostic names the input that opened the run instead of
                // collapsing everything into a bare partial-discovery verdict.
                // A composed plan holds only its sinks, so its cause is the
                // composition's own first incompleteness, whose diagnostic was
                // pushed above.
                let (cause, status) = match engine {
                    TaintEngine::Composition => (None, composition_status),
                    TaintEngine::Icfg { .. } => {
                        let cause = batch.analysis().value_flow().first_incomplete_cause();
                        (cause, cause.and_then(ValueFlowIncompleteCause::status))
                    }
                };
                let reason = match retained.report().result().termination() {
                    SolverTermination::Cancelled => PolicyIncompleteReason::Cancelled,
                    SolverTermination::FixedPoint | SolverTermination::ExceededBudget(_) => {
                        match status {
                            Some(SemanticInputStatus::Unsupported { .. }) => {
                                PolicyIncompleteReason::CapabilityIncomplete
                            }
                            _ => PolicyIncompleteReason::PartialDiscovery,
                        }
                    }
                };
                let sinks = InconclusiveScope::clone(&plan.sink_files);
                let (mut reasons, scope) = match &payload.completion {
                    PolicyRunCompletion::Inconclusive { reasons, scope } => {
                        (reasons.clone(), scope.clone().union(sinks))
                    }
                    _ => (Vec::new(), sinks),
                };
                reasons.push(reason);
                payload.completion = PolicyRunCompletion::inconclusive_in(reasons, scope)
                    .map_err(|error| error.to_string())?;
                payload.authored_arm_closures.clear();
                if let Some(cause) = cause {
                    let (family, detail, primary) =
                        value_flow_cause_text(cause, plan, metadata, workspace)?;
                    // The family names only the repeating cause. A corpus
                    // produces one of these per procedure, so without a family
                    // the per-policy diagnostic cap kept the first 256 by sort
                    // order and hid every later cause (#2356).
                    if let Ok(diagnostic) = PolicyDiagnostic::try_new_in_family(
                        PolicyDiagnosticCode::EvaluationFailure,
                        PolicyDiagnosticSeverity::Warning,
                        PolicyDiagnosticImpact::RunIncomplete,
                        family,
                        detail,
                        primary,
                        Vec::new(),
                    ) {
                        payload.diagnostics.push(diagnostic);
                    }
                }
                ensure_taint_incomplete_diagnostic(payload, retained.report(), workspace);
            }
        }
        if matches!(
            payload.completion,
            PolicyRunCompletion::Complete | PolicyRunCompletion::ProvenBySummary
        ) && has_partial_finding
        {
            match engine {
                TaintEngine::Composition => {
                    for diagnostic in &composition_finding_diagnostics {
                        if !payload.diagnostics.contains(diagnostic) {
                            payload.diagnostics.push(diagnostic.clone());
                        }
                    }
                }
                TaintEngine::Icfg { .. } => {
                    if let Some(cause) = batch.analysis().value_flow().first_incomplete_cause() {
                        let (family, message, primary) =
                            value_flow_cause_text(cause, plan, metadata, workspace)?;
                        if let Ok(diagnostic) = PolicyDiagnostic::try_new_in_family(
                            PolicyDiagnosticCode::EvaluationFailure,
                            PolicyDiagnosticSeverity::Warning,
                            PolicyDiagnosticImpact::FindingPartial,
                            family,
                            message,
                            primary,
                            Vec::new(),
                        ) && !payload.diagnostics.contains(&diagnostic)
                        {
                            payload.diagnostics.push(diagnostic);
                        }
                    }
                }
            }
        }
    }
    let policy_projection_elapsed = policy_projection_started.elapsed();
    let mut compiled_policy_ids = HashSet::new();
    let plan_discovery_and_summary_binding = batch
        .projections()
        .iter()
        .filter_map(|projection| metadata.get(projection.policy_id()))
        .filter(|plan| compiled_policy_ids.insert(&plan.policy_id))
        .map(|plan| plan.compilation_elapsed)
        .fold(Duration::ZERO, |total, elapsed| {
            total.saturating_add(elapsed)
        });
    retained.set_phase_metrics(ProductionTaintPhaseMetrics::new(
        plan_discovery_and_summary_binding,
        batch_planning_elapsed,
        propagation_elapsed,
        reconstruction_elapsed,
        standalone_projection_elapsed,
        policy_projection_elapsed,
        batch.projections().len(),
        1,
    ));
    let retained = Arc::new(retained);
    // The public findings come from this batch's own report, so a leak that two
    // roots reach is reported once per root here as well. Compare against
    // earlier batches only, as the envelope merge does.
    let mut fresh_public = Vec::with_capacity(projected_findings.len());
    for finding in projected_findings {
        let key = finding.content_key();
        if !merge.public.contains(&key) {
            fresh_public.push((key, finding));
        }
    }
    for (key, finding) in fresh_public {
        merge.public.insert(key);
        public_findings.push(finding);
    }
    retained_analyses.push(retained);
    Ok(())
}

/// Preserve a machine-readable reason when solver-derived incompleteness has no
/// plan-time [`ValueFlowIncompleteCause`]. Recursive calls are the important
/// example: the plan can be structurally complete while the fixed-point result
/// retains an open coverage boundary. Before #2838 those runs carried only
/// `completion.reasons = [partial_discovery]`, with no diagnostic family at all.
///
/// A fixed point keeps the three coverage totals and names the first rows of
/// each coverage category with their locations and proof or completeness
/// reasons (#3644). Rows are projected lazily, so a cancelled or
/// budget-exhausted solve resolves no locations.
fn ensure_taint_incomplete_diagnostic(
    payload: &mut TaintProjectionPayload,
    report: &TaintFindingReport,
    workspace: &WorkspaceAnalyzer,
) {
    if payload
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.impact() == PolicyDiagnosticImpact::RunIncomplete)
    {
        return;
    }
    let PolicyRunCompletion::Inconclusive { reasons, .. } = &payload.completion else {
        return;
    };
    let reason = reasons
        .first()
        .copied()
        .expect("validated inconclusive completion has a reason");
    let coverage = report.result().coverage();
    let diagnostic = taint_incomplete_diagnostic(
        report.result().termination(),
        reason,
        coverage
            .unproven_edges()
            .iter()
            .map(|edge| CoverageRow::edge(workspace, edge)),
        coverage
            .partial_edges()
            .iter()
            .map(|edge| CoverageRow::edge(workspace, edge)),
        coverage
            .boundaries()
            .iter()
            .map(|boundary| CoverageRow::boundary(workspace, boundary)),
    );
    payload.diagnostics.push(diagnostic);
}

/// Coverage rows a fixed-point warning names from each category, taken in
/// the order `SummaryCoverage` already holds them.
const FIXED_POINT_ROWS_PER_CATEGORY: usize = 3;
/// Bytes one rendered coverage row keeps, truncation marker included.
const FIXED_POINT_ROW_BYTES: usize = 400;
/// Bytes one retained proof or completeness reason keeps inside a row,
/// truncation marker included, so a long proof reason cannot push the
/// completeness reason out of its row.
const FIXED_POINT_REASON_BYTES: usize = 120;
/// Upper bounds, with every count at `usize::MAX` digits, of the totals
/// sentence and of one category's omitted-count clause.
const FIXED_POINT_TOTALS_BYTES: usize = 200;
const FIXED_POINT_OMITTED_BYTES: usize = 64;
const MAX_FIXED_POINT_PROVENANCE: usize = 3;
const COVERAGE_ROW_TRUNCATION: &str = " [truncated]";

const _: () = assert!(FIXED_POINT_ROW_BYTES > COVERAGE_ROW_TRUNCATION.len());
const _: () = assert!(FIXED_POINT_REASON_BYTES > COVERAGE_ROW_TRUNCATION.len());
// Three categories of at most three rows, each behind a "; " separator, and
// one omitted-count clause per category fit the report prose bound for any
// coverage, so the diagnostic below cannot be rejected for its length.
const _: () = assert!(
    FIXED_POINT_TOTALS_BYTES
        + 3 * (FIXED_POINT_ROWS_PER_CATEGORY * (2 + FIXED_POINT_ROW_BYTES)
            + FIXED_POINT_OMITTED_BYTES)
        <= MAX_REPORT_PROSE_BYTES
);

/// One retained coverage row, projected for the fixed-point warning.
///
/// The program point, origin call site, and dispatch target are resolved to
/// report locations; the kind, reasons, and provenance are borrowed from the
/// coverage. Rendering reads only these fields and needs no workspace.
struct CoverageRow<'a> {
    location: PolicySourceLocation,
    kind: CoverageRowKind<'a>,
    origin: Option<PolicySourceLocation>,
    proof: Option<&'a ProofStatus>,
    completeness: Option<&'a EvidenceCompleteness>,
    provenance: &'a [OracleRelationHandle],
}

enum CoverageRowKind<'a> {
    Edge(IcfgEdgeKind),
    Boundary {
        kind: &'a SummaryBoundaryKind,
        /// The exact target a dispatch boundary names, when it names one.
        target: Option<PolicySourceLocation>,
    },
}

impl<'a> CoverageRow<'a> {
    /// An unproven or partial edge, located at its source point.
    fn edge(workspace: &WorkspaceAnalyzer, edge: &'a SummaryEdge) -> Self {
        Self {
            location: coverage_location(
                workspace,
                super::semantic_identity::program_point_locator(edge.source()),
            ),
            kind: CoverageRowKind::Edge(edge.kind()),
            origin: edge.origin().map(|call| {
                coverage_location(workspace, super::semantic_identity::call_site_locator(call))
            }),
            proof: Some(edge.proof()),
            completeness: Some(edge.completeness()),
            provenance: &[],
        }
    }

    /// An open boundary, located at its program point.
    fn boundary(workspace: &WorkspaceAnalyzer, boundary: &'a SummaryBoundary) -> Self {
        let target = match boundary.kind() {
            SummaryBoundaryKind::Dispatch(dispatch) => dispatch
                .target_locator()
                .map(|target| coverage_location(workspace, target)),
            SummaryBoundaryKind::Semantic(_)
            | SummaryBoundaryKind::Limit(_)
            | SummaryBoundaryKind::Continuation { .. } => None,
        };
        Self {
            location: coverage_location(
                workspace,
                super::semantic_identity::program_point_locator(boundary.at()),
            ),
            kind: CoverageRowKind::Boundary {
                kind: boundary.kind(),
                target,
            },
            origin: boundary.origin().map(|call| {
                coverage_location(workspace, super::semantic_identity::call_site_locator(call))
            }),
            proof: boundary.proof(),
            completeness: boundary.completeness(),
            provenance: boundary.provenance(),
        }
    }
}

/// The report location of one coverage locator. A location that cannot be
/// built keeps its row, named by the locator's path alone, rather than
/// dropping the row or the warning.
fn coverage_location(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> PolicySourceLocation {
    super::semantic_identity::policy_location(workspace, locator)
        .unwrap_or_else(|_| PolicySourceLocation::artifact(locator.path().clone()))
}

fn taint_incomplete_diagnostic<'a>(
    termination: SolverTermination,
    reason: PolicyIncompleteReason,
    unproven_edges: impl ExactSizeIterator<Item = CoverageRow<'a>>,
    partial_edges: impl ExactSizeIterator<Item = CoverageRow<'a>>,
    boundaries: impl ExactSizeIterator<Item = CoverageRow<'a>>,
) -> PolicyDiagnostic {
    let (family, message, primary, related) = match termination {
        SolverTermination::FixedPoint => {
            let mut message = format!(
                "taint analysis is incomplete after reaching a fixed point: {} unproven edge(s), {} partial edge(s), and {} open boundary row(s)",
                unproven_edges.len(),
                partial_edges.len(),
                boundaries.len(),
            );
            debug_assert!(message.len() <= FIXED_POINT_TOTALS_BYTES);
            let mut locations = Vec::new();
            push_coverage_category(
                &mut message,
                &mut locations,
                "unproven edge",
                unproven_edges,
            );
            push_coverage_category(&mut message, &mut locations, "partial edge", partial_edges);
            push_coverage_category(
                &mut message,
                &mut locations,
                "open boundary row",
                boundaries,
            );
            let primary = locations.first().cloned();
            let related = locations
                .into_iter()
                .filter_map(|location| {
                    // A location too large to keep as evidence stays named in
                    // the message.
                    RelatedPolicyLocation::try_new(
                        PolicyLocationRelationship::Evidence,
                        location,
                        Vec::new(),
                    )
                    .ok()
                })
                .collect();
            (
                format!("taint_analysis/{}", reason.label()),
                message,
                primary,
                related,
            )
        }
        SolverTermination::Cancelled => (
            "taint_analysis/cancelled".to_owned(),
            "taint analysis was cancelled before reaching a fixed point".to_owned(),
            None,
            Vec::new(),
        ),
        SolverTermination::ExceededBudget(exceeded) => (
            format!(
                "taint_analysis/solver_budget/{}",
                exceeded.dimension().label()
            ),
            exceeded.to_string(),
            None,
            Vec::new(),
        ),
    };
    PolicyDiagnostic::try_new_in_family(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        family,
        message,
        primary,
        related,
    )
    .expect("taint incompleteness diagnostic is bounded by construction")
}

/// Append the first rows of one coverage category and, when rows remain,
/// the exact count of the ones left out.
///
/// The summary solve already ordered and deduplicated each category, so a
/// long unproven list never hides the partial edges or the open boundaries.
/// Rows past the first `FIXED_POINT_ROWS_PER_CATEGORY` are never projected.
fn push_coverage_category<'a>(
    message: &mut String,
    locations: &mut Vec<PolicySourceLocation>,
    category: &str,
    rows: impl ExactSizeIterator<Item = CoverageRow<'a>>,
) {
    let total = rows.len();
    for row in rows.take(FIXED_POINT_ROWS_PER_CATEGORY) {
        message.push_str("; ");
        message.push_str(&render_coverage_row(category, &row));
        locations.push(row.location);
    }
    let omitted = total.saturating_sub(FIXED_POINT_ROWS_PER_CATEGORY);
    if omitted > 0 {
        let clause = format!("; omitted {omitted} {category}(s)");
        debug_assert!(clause.len() <= FIXED_POINT_OMITTED_BYTES);
        message.push_str(&clause);
    }
}

fn render_coverage_row(category: &str, row: &CoverageRow<'_>) -> String {
    let kind = match &row.kind {
        CoverageRowKind::Edge(kind) => Cow::Borrowed(kind.label()),
        CoverageRowKind::Boundary { kind, .. } => Cow::Owned(boundary_kind_detail(kind)),
    };
    let mut text = format!("{category} {kind} at {}", location_text(&row.location));
    if let Some(origin) = &row.origin {
        text.push_str(" origin=");
        text.push_str(&location_text(origin));
    }
    if let CoverageRowKind::Boundary {
        target: Some(target),
        ..
    } = &row.kind
    {
        text.push_str(" target=");
        text.push_str(&location_text(target));
    }
    if let Some(proof) = row.proof {
        text.push_str(" proof=");
        text.push_str(proof.label());
        if let ProofStatus::Unproven(reason) = proof {
            push_coverage_reason(&mut text, reason);
        }
    }
    if let Some(completeness) = row.completeness {
        text.push_str(" completeness=");
        text.push_str(completeness.label());
        if let EvidenceCompleteness::Partial(reason) = completeness {
            push_coverage_reason(&mut text, reason);
        }
    }
    push_provenance(&mut text, row.provenance);
    bound_coverage_row(text)
}

/// `path:line:column` from the location's display region, as the human
/// report writes locations; a path-only location is its path.
fn location_text(location: &PolicySourceLocation) -> String {
    match location.region() {
        Some(region) => format!(
            "{}:{}:{}",
            location.path(),
            region.start_line(),
            region.start_column()
        ),
        None => location.path().to_owned(),
    }
}

fn boundary_kind_detail(kind: &SummaryBoundaryKind) -> String {
    match kind {
        SummaryBoundaryKind::Semantic(status) => {
            let mut text = format!("semantic:{}", status.label());
            if let Some(capability) = status.unsupported_capability() {
                text.push_str(" (");
                text.push_str(capability.label());
                text.push(')');
            }
            if let Some(exceeded) = status.budget_exceeded() {
                text.push_str(" (");
                text.push_str(&exceeded.to_string());
                text.push(')');
            }
            text
        }
        SummaryBoundaryKind::Dispatch(dispatch) => match dispatch {
            DispatchBoundaryKind::Deferred { kind, .. } => {
                format!("dispatch:{} {}", dispatch.label(), kind.label())
            }
            DispatchBoundaryKind::External(_)
            | DispatchBoundaryKind::Unmaterialized(_)
            | DispatchBoundaryKind::Unresolved
            | DispatchBoundaryKind::Truncated => format!("dispatch:{}", dispatch.label()),
        },
        SummaryBoundaryKind::Limit(limit) => format!("limit:{}", limit.label()),
        SummaryBoundaryKind::Continuation { kind, state } => {
            format!("continuation:{}:{}", kind.label(), state.label())
        }
    }
}

fn push_provenance(text: &mut String, provenance: &[OracleRelationHandle]) {
    if provenance.is_empty() {
        return;
    }
    text.push_str(" provenance=");
    let shown = provenance.len().min(MAX_FIXED_POINT_PROVENANCE);
    for (index, relation) in provenance[..shown].iter().enumerate() {
        if index > 0 {
            text.push(',');
        }
        text.push_str(relation.record().kind().label());
        text.push('#');
        text.push_str(&relation.id().get().to_string());
    }
    let omitted = provenance.len() - shown;
    if omitted > 0 {
        text.push_str(",+");
        text.push_str(&omitted.to_string());
    }
}

/// Append one retained proof or completeness reason in parentheses, cut at
/// `FIXED_POINT_REASON_BYTES` on a char boundary with a marker.
fn push_coverage_reason(text: &mut String, reason: &str) {
    text.push_str(" (");
    if reason.len() <= FIXED_POINT_REASON_BYTES {
        text.push_str(reason);
    } else {
        let boundary =
            reason.floor_char_boundary(FIXED_POINT_REASON_BYTES - COVERAGE_ROW_TRUNCATION.len());
        text.push_str(&reason[..boundary]);
        text.push_str(COVERAGE_ROW_TRUNCATION);
    }
    text.push(')');
}

fn bound_coverage_row(mut text: String) -> String {
    if text.len() <= FIXED_POINT_ROW_BYTES {
        return text;
    }
    let boundary = text.floor_char_boundary(FIXED_POINT_ROW_BYTES - COVERAGE_ROW_TRUNCATION.len());
    text.truncate(boundary);
    text.push_str(COVERAGE_ROW_TRUNCATION);
    debug_assert!(text.len() <= FIXED_POINT_ROW_BYTES);
    text
}

/// Publish every metric name a compiled taint run reports: the compile's bound
/// endpoint counts, and the propagation counters seeded at zero for the solve
/// to raise.
///
/// Reported unconditionally, including the zeros: a permanent zero is exactly
/// the signal a reader of a raw benchmark artifact needs, because it says the
/// policy's selectors bound nothing here rather than that the analysis found
/// nothing (#2659).
///
/// State that the batches of one solve share when they merge into the run.
///
/// Each batch solves one root's closure, so a sink reachable from two roots is
/// projected by two batches, each with the same leak. The merge keeps the first
/// copy of each leak in every output it feeds.
#[derive(Default)]
struct BatchMerge {
    /// Envelope identities per policy. Kept equal to the identities of that
    /// policy's `payload.projections`: every path that replaces a payload
    /// inside the batch loop clears its entry.
    envelopes: HashMap<PolicyId, HashSet<TaintEnvelopeIdentity>>,
    /// Content keys of public findings that an earlier batch emitted.
    public: HashSet<CodeQueryTaintFindingKey>,
    missing_origins: HashMap<PolicyId, usize>,
}

fn record_attribution_work(
    work: &mut PolicyWorkReport,
    attribution: TaintAttributionWork,
) -> Result<(), String> {
    for (name, value) in [
        ("taint.attribution_attempts", attribution.attempts),
        ("taint.attribution_steps", attribution.steps),
        ("taint.attribution_expansions", attribution.expansions),
        (
            "taint.attribution_candidate_exhaustions",
            attribution.candidate_exhaustions,
        ),
        (
            "taint.attribution_run_exhaustions",
            usize::from(attribution.run_exhausted),
        ),
    ] {
        increment_work_metric(
            work,
            name,
            PolicyWorkUnit::Count,
            u64::try_from(value).unwrap_or(u64::MAX),
        )?;
    }
    Ok(())
}

fn record_missing_origin_loss(
    payload: &mut TaintProjectionPayload,
    dropped_for_missing_origins: usize,
) -> Result<(), String> {
    if dropped_for_missing_origins == 0 {
        return Ok(());
    }
    // This loss is independent of other gaps. Preserve their reasons,
    // and never promote failed, unsupported or not-run terminal states.
    match &mut payload.completion {
        PolicyRunCompletion::Complete | PolicyRunCompletion::ProvenBySummary => {
            payload.completion =
                PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery])
                    .map_err(|error| error.to_string())?;
        }
        PolicyRunCompletion::Inconclusive { reasons, scope } => {
            reasons.push(PolicyIncompleteReason::PartialDiscovery);
            reasons.sort();
            reasons.dedup();
            *scope = InconclusiveScope::Run;
        }
        _ => {}
    }
    if matches!(payload.completion, PolicyRunCompletion::Inconclusive { .. }) {
        payload.authored_arm_closures.clear();
    }
    // Exactly one aggregate per policy, even across solved batches.
    // Its family survives diagnostic-cap folding in truncation metadata.
    const FAMILY: &str = "taint_missing_origin_evidence";
    payload.diagnostics.push(PolicyDiagnostic::try_new_in_family(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        FAMILY,
        format!(
            "{dropped_for_missing_origins} candidate finding(s) retained no source origin evidence and could not be projected"
        ),
        None,
        Vec::new(),
    ).map_err(|error| error.to_string())?
        .with_family_count(u64::try_from(dropped_for_missing_origins).unwrap_or(u64::MAX)));
    Ok(())
}

/// Seeding the propagation counters here, rather than letting the solve
/// introduce their names, keeps the metric *name* set a function of the policy
/// family alone. Retention accounting sums metric name capacities
/// (`PolicyWorkReport::retained_size` feeds `PolicyRun`'s), and the evaluator's
/// retention search decides how many findings a run keeps from that size, so a
/// name set that depended on whether a batch was solved would make the retained
/// finding set depend on it too. Incremental and full evaluations must produce
/// byte-identical reports.
fn record_compile_metrics(work: &mut PolicyWorkReport, counts: BoundEndpointCounts) {
    for (name, value) in [
        (
            "taint.compiled_source_endpoints",
            u64::try_from(counts.sources).unwrap_or(u64::MAX),
        ),
        (
            "taint.compiled_sink_endpoints",
            u64::try_from(counts.sinks).unwrap_or(u64::MAX),
        ),
        ("taint.propagation_solves", 0),
        ("taint.propagation_shared_memberships", 0),
        ("taint.attribution_attempts", 0),
        ("taint.attribution_steps", 0),
        ("taint.attribution_expansions", 0),
        ("taint.attribution_candidate_exhaustions", 0),
        ("taint.attribution_run_exhaustions", 0),
    ] {
        increment_work_metric(work, name, PolicyWorkUnit::Count, value)
            .expect("compile-time metrics fit the taint work report");
    }
}

fn increment_work_metric(
    work: &mut PolicyWorkReport,
    name: &str,
    unit: PolicyWorkUnit,
    increment: u64,
) -> Result<(), String> {
    let mut metrics = work.metrics().to_vec();
    if let Some(existing) = metrics.iter_mut().find(|metric| metric.name() == name) {
        let value = existing.value().saturating_add(increment);
        *existing =
            PolicyWorkMetric::try_new(name, unit, value).map_err(|error| error.to_string())?;
    } else {
        metrics.push(
            PolicyWorkMetric::try_new(name, unit, increment).map_err(|error| error.to_string())?,
        );
    }
    *work = PolicyWorkReport::try_new(
        work.scanned_files(),
        work.scanned_source_bytes(),
        work.fact_nodes(),
        work.pipeline_rows(),
        work.examined_references(),
        work.retained_findings(),
        work.omitted_findings_lower_bound(),
        work.retained_report_bytes(),
        metrics,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn value_flow_compatibility_hash(plan: &ValueFlowPlan) -> u64 {
    let mut hasher = DefaultHasher::new();
    plan.propagation_semantics_hash(&mut hasher);
    hasher.finish()
}

struct ProjectedSourceGroup<'a> {
    source: &'a ResolvedTaintEndpoint<ResolvedTaintSourceDefinition>,
    origins: Vec<&'a TaintOriginFindingEvidence>,
    findings: Vec<&'a brokk_bifrost_flow::taint::TaintFinding>,
    /// Labels minted by the source and retained as origin evidence.
    labels: Vec<TaintLabel>,
    /// Labels those source values carry at the sink after transforms.
    reached_labels: Vec<TaintLabel>,
}

/// The place one projected taint finding reports: one declared sink endpoint at
/// one place in the source.
///
/// "One place in the source" is the file, the enclosing declaration, and the
/// anchor's byte span. It deliberately excludes the anchor's *occurrence*
/// counter, which is what distinguishes several lowerings of one written call
/// from one another (#2308).
///
/// The field order is the sort order, and it matters: sorting groups the sites
/// that share one endpoint, file, and enclosing declaration into one run,
/// ordered by source position. That run is what `site_ordinals` numbers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReportedSinkSite {
    endpoint: ResolvedEndpointIdentity,
    path: WorkspaceRelativePath,
    declaration: String,
    span_start: u32,
    span_end: u32,
}

/// Where one value-flow sink event is reported, or `None` when the event
/// belongs to another policy in the shared batch.
fn reported_sink_site(
    plan: &PreparedTaintPlan,
    event: &ValueFlowEventKey,
) -> Option<Result<ReportedSinkSite, String>> {
    let compiled = plan.sinks.iter().find(|sink| &sink.event == event)?;
    let locator = event.site();
    let span = locator.anchor().span();
    Some(
        canonical_locator_identity(locator).map(|declaration| ReportedSinkSite {
            endpoint: compiled.endpoint.clone(),
            path: locator.path().clone(),
            declaration,
            span_start: span.start_byte(),
            span_end: span.end_byte(),
        }),
    )
}

/// Number each reported sink site within the run of sites that share its
/// endpoint, file, and enclosing declaration, in source order.
///
/// `sites` must already be sorted, which is what puts each such run together.
fn site_ordinals(sites: &[ReportedSinkSite]) -> Vec<u32> {
    let mut ordinals = Vec::with_capacity(sites.len());
    let mut ordinal = 0;
    for (index, site) in sites.iter().enumerate() {
        if index > 0 {
            let previous = &sites[index - 1];
            let same_declaration = previous.endpoint == site.endpoint
                && previous.path == site.path
                && previous.declaration == site.declaration;
            ordinal = if same_declaration { ordinal + 1 } else { 0 };
        }
        ordinals.push(ordinal);
    }
    ordinals
}

/// Select whole evidence packets after the public finding group is known.
/// A strict-surviving pair excludes every lenient-only origin in that group.
fn select_barrier_evidence<'a, K: Eq, T>(
    pairs: Vec<(K, &'a T, Option<&'a T>)>,
) -> Vec<(K, &'a T, bool)> {
    let strict_groups = pairs
        .iter()
        .filter(|(_, _, strict)| strict.is_some())
        .map(|(group, _, _)| group)
        .collect::<Vec<_>>();
    let selected = pairs
        .iter()
        .map(|(group, lenient, strict)| {
            if strict_groups.contains(&group) {
                strict.map(|evidence| (evidence, true))
            } else {
                Some((*lenient, false))
            }
        })
        .collect::<Vec<_>>();
    pairs
        .into_iter()
        .zip(selected)
        .filter_map(|((group, _, _), selected)| {
            selected.map(|(evidence, strict)| (group, evidence, strict))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn project_policy_findings(
    workspace: &WorkspaceAnalyzer,
    policy: &LoadedPolicy,
    spec: &ResolvedTaintPolicySpec,
    plan: &PreparedTaintPlan,
    universe: &TaintUniverse,
    report: &TaintFindingReport,
    store_seeds: &[StoreReadSeed],
    budget: &PolicyBudget,
    dropped_for_missing_origins: &mut usize,
    store_write_evidence: &StoreWriteEvidenceByRead,
    barrier_notes: &[compose::ValueTypeBarrierFindingNotes],
    barrier_pairs: &[compose::ValueTypeBarrierPairEvidence],
) -> Result<Vec<TaintProjectedFinding>, String> {
    // The projection authority validates each envelope against the *effective*
    // report limits, which are the policy's own report options capped by the
    // host budget (`EffectiveReportLimits` in `projection.rs`). The adapter has
    // to project inside the same limits or its envelope is rejected wholesale
    // and the finding is lost. Merging a sink's events into one finding (below)
    // makes that reachable, because one finding now carries every event's
    // origins and witnesses.
    let report_options = &policy.definition().report;
    // The host budget is only the ceiling. A witness is validated against the
    // *effective* limit, so projecting to the ceiling produced witnesses the
    // authority rejected, and the rejection dropped the whole finding (#2356).
    let witness_limits = EffectiveWitnessLimits {
        steps: report_options
            .witness
            .max_steps
            .min(budget.max_witness_steps()),
        bytes: report_options
            .witness
            .max_bytes
            .min(budget.max_witness_bytes()),
    };
    let mut projected = Vec::new();
    // One projected finding per declared sink endpoint per *place in the
    // source*, rather than per value-flow event key.
    //
    // One written call can be lowered into several program points, and each gets
    // its own event key: Java specializes a `finally` body once per completion
    // route out of the guarded region, so `out.write(x)` written once inside one
    // becomes several events sharing one anchor span and differing only in the
    // anchor's occurrence counter (#2308). Those events are one place in the
    // source and carry one finding identity, so emitting an envelope for each
    // makes several envelopes claim it -- which the projection authority rejects
    // as an internal invariant violation, failing the whole run.
    //
    // Grouping by the site reports the one finding they describe, carrying every
    // route's origins and witnesses. It groups no more than that: two calls
    // written at different places keep their own findings and their own reported
    // locations.
    let strict_by_lenient = barrier_pairs
        .iter()
        .flat_map(|pair| {
            let strict = pair
                .strict
                .as_ref()
                .and_then(|report| report.findings().first());
            pair.lenient
                .findings()
                .iter()
                .map(move |lenient| (std::ptr::from_ref(lenient), strict))
        })
        .collect::<HashMap<_, _>>();
    let mut reported_sinks = Vec::<ReportedSinkSite>::new();
    for candidate in report.findings() {
        let Some(reported_sink) = reported_sink_site(plan, candidate.key().sink()) else {
            continue;
        };
        let reported_sink = reported_sink?;
        if !reported_sinks.contains(&reported_sink) {
            reported_sinks.push(reported_sink);
        }
    }
    // Sorting is what makes the site ordinals below a property of the source
    // rather than of the order the solver happened to retain its findings in.
    reported_sinks.sort();
    let sink_site_ordinals = site_ordinals(&reported_sinks);
    for (reported_sink, sink_site_ordinal) in reported_sinks.iter().zip(sink_site_ordinals) {
        let mut strict_sources = Vec::new();
        let sink_findings = if spec.barriers.is_empty() {
            report.findings().iter().collect::<Vec<_>>()
        } else {
            barrier_pairs
                .iter()
                .flat_map(|pair| pair.lenient.findings())
                .collect::<Vec<_>>()
        }
        .into_iter()
        .filter(|finding| {
            reported_sink_site(plan, finding.key().sink())
                .and_then(Result::ok)
                .is_some_and(|site| &site == reported_sink)
        })
        .collect::<Vec<_>>();
        let Some(finding) = sink_findings.iter().copied().max_by_key(|finding| {
            (
                finding.is_proven(),
                finding.is_complete(),
                finding.origins().is_complete(),
            )
        }) else {
            continue;
        };
        let Some(compiled_sink) = plan
            .sinks
            .iter()
            .find(|sink| &sink.event == finding.key().sink())
        else {
            continue;
        };
        let sink = spec
            .sinks
            .iter()
            .find(|sink| sink.identity == compiled_sink.endpoint)
            .ok_or_else(|| "compiled taint sink is absent from the loaded policy".to_owned())?;
        let mut groups = Vec::<ProjectedSourceGroup<'_>>::new();
        for finding in &sink_findings {
            for origin in finding.origins().evidence() {
                // A policy source's event has exactly one metadata row. A
                // store-read origin keeps one row per contributing policy
                // source (the seeding fixpoint narrowed the compiled rows to
                // real provenance), and one origin row attributes to exactly
                // one source: the projection authority rejects one scenario
                // identity claimed by two endpoints, so the first source
                // whose labels the observed classes satisfy claims the row.
                for compiled_source in plan
                    .sources
                    .iter()
                    .filter(|source| &source.event == origin.origin().value_flow_key())
                {
                    // A finding's origin endpoint is either a declared source
                    // or a declared entry point; both resolve as source-shaped
                    // endpoints (#2692).
                    let source = spec
                        .sources
                        .iter()
                        .chain(spec.entry_points.iter())
                        .find(|source| source.identity == compiled_source.endpoint)
                        .ok_or_else(|| {
                            "compiled taint source is absent from the loaded policy".to_owned()
                        })?;
                    let labels = stable_taint_labels(universe, origin.classes())?
                        .into_iter()
                        .filter(|label| source.definition.labels.contains(label))
                        .collect::<Vec<_>>();
                    let reached_labels = stable_taint_labels(universe, origin.reached_classes())?
                        .into_iter()
                        .filter(|label| {
                            spec.authorizes_reached_label(&source.definition, label)
                                && sink.definition.accepts.contains(label)
                        })
                        .collect::<Vec<_>>();
                    if labels.is_empty() || reached_labels.is_empty() {
                        continue;
                    }
                    match groups
                        .iter_mut()
                        .find(|group| group.source.identity == source.identity)
                    {
                        Some(group) => {
                            // Retain every fact-local evidence row. Rows for the
                            // same source occurrence can carry distinct bounded
                            // witnesses or contributing class subsets; later
                            // projection deduplicates only the public origin row.
                            group.origins.push(origin);
                            if !group.findings.contains(finding) {
                                group.findings.push(finding);
                            }
                            group.labels.extend(labels);
                            group.labels.sort();
                            group.labels.dedup();
                            group.reached_labels.extend(reached_labels);
                            group.reached_labels.sort();
                            group.reached_labels.dedup();
                        }
                        None => groups.push(ProjectedSourceGroup {
                            source,
                            origins: vec![origin],
                            findings: vec![finding],
                            labels,
                            reached_labels,
                        }),
                    }
                    break;
                }
            }
        }
        if groups.is_empty() {
            // A finding with no retained origin evidence cannot be projected
            // at all; that is an evidence-retention defect, not a clean
            // absence, so the caller must not report a complete run over it.
            // A finding whose retained origins simply belong to another
            // policy in the shared batch is not this policy's finding.
            if finding.origins().evidence().is_empty() {
                *dropped_for_missing_origins = dropped_for_missing_origins.saturating_add(1);
            }
            continue;
        }
        groups.sort_by(|left, right| left.source.identity.cmp(&right.source.identity));
        if !spec.barriers.is_empty() {
            for group in &mut groups {
                let candidates = group
                    .findings
                    .iter()
                    .map(|lenient| {
                        let strict = strict_by_lenient
                            .get(&std::ptr::from_ref(*lenient))
                            .expect("every barrier finding retains its concrete pair evidence");
                        ((), *lenient, *strict)
                    })
                    .collect();
                let selected = select_barrier_evidence(candidates);
                if !selected.iter().any(|(_, _, strict)| *strict) {
                    continue;
                }
                strict_sources.push(group.source.identity.clone());
                group.findings = selected
                    .into_iter()
                    .map(|(_, finding, _)| finding)
                    .collect();
                group.origins = group
                    .findings
                    .iter()
                    .flat_map(|finding| finding.origins().evidence())
                    .filter(|origin| {
                        group
                            .origins
                            .iter()
                            .any(|lenient| lenient.origin() == origin.origin())
                    })
                    .collect();
                group.labels.clear();
                group.reached_labels.clear();
                for origin in &group.origins {
                    group.labels.extend(
                        stable_taint_labels(universe, origin.classes())?
                            .into_iter()
                            .filter(|label| group.source.definition.labels.contains(label)),
                    );
                    group.reached_labels.extend(
                        stable_taint_labels(universe, origin.reached_classes())?
                            .into_iter()
                            .filter(|label| {
                                spec.authorizes_reached_label(&group.source.definition, label)
                                    && sink.definition.accepts.contains(label)
                            }),
                    );
                }
                group.labels.sort();
                group.labels.dedup();
                group.reached_labels.sort();
                group.reached_labels.dedup();
            }
        }

        let sink_locator = finding.key().sink().site();
        let sink_key = super::semantic_identity::semantic_site_key(workspace, sink_locator);
        let sink_identity = StableSemanticIdentity::canonical_ast_identity(
            sink_locator.language().config_label(),
            sink_locator.path().clone(),
            canonical_locator_identity(sink_locator)?,
        )
        .map_err(|error| error.to_string())?;
        let sink_ref =
            AnalysisEventRef::try_new("bifrost", &sink_key).map_err(|error| error.to_string())?;
        let primary = super::semantic_identity::policy_location(workspace, sink_locator)?;
        let mut source_facts = Vec::new();
        let mut pairs = Vec::new();
        for group in &groups {
            let mut scenarios = source_scenarios(workspace, group)?;
            scenarios.sort();
            scenarios.dedup();
            let scenario_hash =
                super::cvss::SourceScenarioSetHash::try_from_scenarios(scenarios.clone())
                    .map_err(|error| error.to_string())?;
            for label in &group.labels {
                source_facts.push(
                    TaintSourceProjectionFact::try_new_with_threat_model(
                        group.source.identity.clone(),
                        group.source.semantic_hash,
                        group.source.analysis_projection_hash,
                        group.source.definition.display_name.clone(),
                        group.source.definition.threat_model,
                        group.source.definition.categories.clone(),
                        label.clone(),
                        group.source.definition.evidence.clone(),
                        scenarios.clone(),
                        taint_evidence_ref(&group.source.identity, label, &scenarios)?,
                    )
                    .map_err(|error| error.to_string())?,
                );
            }
            let anchor = TaintFindingAnchor::strong(
                sink_identity.clone(),
                sink_site_ordinal,
                group.source.analysis_projection_hash,
                sink.analysis_projection_hash,
                scenario_hash,
            )
            .map_err(|error| error.to_string())?;
            let pair_key = super::semantic_identity::stable_hex(
                format!(
                    "{sink_key}:{:?}:{:?}",
                    group.source.analysis_projection_hash, sink.analysis_projection_hash
                )
                .as_bytes(),
            );
            let fixed_point = report.result().termination().is_fixed_point();
            let (origins, origins_omitted) = project_taint_origins(
                workspace,
                universe,
                group,
                fixed_point,
                report_options
                    .origins_per_finding
                    .min(budget.max_origins_per_finding()),
            )?;
            let origins_truncated = group
                .findings
                .iter()
                .any(|finding| finding.origins().origin_truncated())
                || origins_omitted > 0;
            // One certain origin establishes the finding even when another
            // grouped origin is unproven (#5597). Each origin reports its own
            // certainty, so a definite finding does not claim every origin is
            // proven. Completeness keeps the every-origin rule.
            let pair_proven = (group.findings.iter().all(|finding| finding.is_proven())
                && report.result().is_complete())
                || group
                    .origins
                    .iter()
                    .any(|origin| origin_is_certain(group, origin, fixed_point));
            let pair_closures = group
                .origins
                .iter()
                .flat_map(|origin| origin.authored_arm_closures().iter().cloned())
                .collect::<Vec<_>>();
            let pair_finding_incomplete =
                group.findings.iter().any(|finding| !finding.is_complete());
            let pair_witness_incomplete = group.findings.iter().any(|finding| {
                finding.origins().witness_truncated() || finding.origins().witness_unavailable()
            });
            let (mut projected_report, witness_refs) = project_taint_report(
                workspace,
                group,
                store_crossings_for_group(store_seeds, group),
                &pair_key,
                &primary,
                pair_proven,
                pair_finding_incomplete,
                origins_truncated,
                pair_witness_incomplete,
                report_options
                    .witnesses_per_finding
                    .min(budget.max_witnesses_per_finding()),
                witness_limits,
                budget,
                &pair_closures,
                store_write_evidence,
            )?;
            for notes in barrier_notes.iter().filter(|notes| {
                !strict_sources.contains(&group.source.identity)
                    && group
                        .origins
                        .iter()
                        .any(|origin| origin.origin() == &notes.source)
                    && group
                        .findings
                        .iter()
                        .any(|finding| finding.key().sink() == &notes.sink)
            }) {
                for check in &notes.checks {
                    projected_report
                        .value_type_barrier_notes
                        .push(crate::ValueTypeBarrierNote::from_check(workspace, check)?);
                }
                if notes.omitted_lower_bound > 0 {
                    projected_report.value_type_barrier_notes.note_omitted();
                }
            }
            for decline in &plan.sanitizer_declines {
                // A decline explains a witnessed flow through this decision, not
                // an unrelated sink or the opposite accepting arm.
                if !group
                    .origins
                    .iter()
                    .flat_map(|origin| origin.witnesses())
                    .any(|witness| {
                        witness.steps().iter().any(|step| {
                            step.source().procedure().durable_key()
                                == decline.point.procedure().durable_key()
                                && step.source().id() == decline.point.id()
                                && decline.target.is_none_or(|target| {
                                    step.target().is_some_and(|point| point.id() == target)
                                })
                        })
                    })
                {
                    continue;
                }
                let mapping = decline
                    .point
                    .procedure()
                    .semantics()
                    .source_mapping(
                        decline
                            .point
                            .procedure()
                            .semantics()
                            .point(decline.point.id())
                            .expect("guard point")
                            .source,
                    )
                    .expect("guard mapping");
                let related = RelatedPolicyLocation::try_new(
                    PolicyLocationRelationship::Evidence,
                    super::semantic_identity::policy_location(workspace, &mapping.locator)?,
                    Vec::new(),
                )
                .and_then(|location| {
                    location.with_label(format!(
                        "sanitizer {} declined: {}",
                        decline.sanitizer, decline.reason
                    ))
                })
                .map_err(|error| error.to_string())?;
                if projected_report.related.contains(&related) {
                    continue;
                }
                if projected_report.related.len() >= budget.max_related_locations_per_finding() {
                    projected_report.related_truncated = true;
                    projected_report.omitted_related_locations_lower_bound += 1;
                    continue;
                }
                projected_report.related.push(related);
            }
            let witness_refs_truncated = projected_report.witnesses_truncated;
            pairs.push(TaintPairProjection {
                source_endpoint: group.source.identity.clone(),
                analysis_finding_id: AnalysisFindingId::try_new("bifrost", &pair_key)
                    .map_err(|error| error.to_string())?,
                anchor,
                sink: sink_ref.clone(),
                reached_labels: group.reached_labels.clone(),
                origins,
                origins_truncated,
                witness_refs,
                witness_refs_truncated,
                report: projected_report,
            });
        }
        let reached_labels = groups
            .iter()
            .flat_map(|group| group.reached_labels.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let facts = TaintPolicyProjectionFacts::try_new(
            sink.identity.clone(),
            sink.semantic_hash,
            sink.analysis_projection_hash,
            sink.definition.display_name.clone(),
            sink.definition.categories.clone(),
            sink.definition.tags.clone(),
            sink.definition.impacts.clone(),
            reached_labels,
            source_facts,
            budget,
        )
        .map_err(|error| error.to_string())?;
        projected.push(TaintProjectedFinding { facts, pairs });
    }
    Ok(projected)
}

/// The declaration path and role a locator sits in.
///
/// This names the *enclosing declaration*, so every sink call written inside
/// one procedure shares it. What separates those calls from one another is the
/// site ordinal that `TaintFindingAnchor::strong` carries; a positional handle
/// cannot live in a semantic key, which `validate_semantic_key` rejects as a
/// dense handle.
fn canonical_locator_identity(
    locator: &brokk_bifrost_analysis::analyzer::semantic::SemanticLocator,
) -> Result<String, String> {
    let mut segments = locator
        .declaration()
        .segments()
        .iter()
        .map(|segment| {
            (
                segment.kind().stable_label().to_owned(),
                segment.name().map(str::to_owned),
            )
        })
        .collect::<Vec<_>>();
    segments.push((locator.role().stable_label().to_owned(), None));
    serde_json::to_string(&segments).map_err(|error| error.to_string())
}

fn stable_taint_labels(
    universe: &TaintUniverse,
    classes: &TaintClassSet,
) -> Result<Vec<TaintLabel>, String> {
    universe
        .stable_classes(classes)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|class| TaintLabel::new(class.as_str()).map_err(|error| error.to_string()))
        .collect()
}

fn source_scenarios(
    workspace: &WorkspaceAnalyzer,
    group: &ProjectedSourceGroup<'_>,
) -> Result<Vec<SourceScenarioId>, String> {
    let mut scenarios = group
        .origins
        .iter()
        .map(|origin| source_scenario(workspace, origin))
        .collect::<Result<Vec<_>, _>>()?;
    scenarios.sort();
    scenarios.dedup();
    Ok(scenarios)
}

fn source_scenario(
    workspace: &WorkspaceAnalyzer,
    origin: &TaintOriginFindingEvidence,
) -> Result<SourceScenarioId, String> {
    let event = origin.origin().value_flow_key();
    let site = super::semantic_identity::semantic_site_key(workspace, event.site());
    let key = format!("{site}:source-event:{}", event.ordinal());
    SourceScenarioId::try_new("bifrost", key).map_err(|error| error.to_string())
}

fn taint_evidence_ref(
    endpoint: &ResolvedEndpointIdentity,
    label: &TaintLabel,
    scenarios: &[SourceScenarioId],
) -> Result<EvidenceRef, String> {
    let key = super::semantic_identity::stable_hex(
        format!("{endpoint:?}:{label:?}:{scenarios:?}").as_bytes(),
    );
    EvidenceRef::try_new("bifrost", key).map_err(|error| error.to_string())
}

fn project_taint_origins(
    workspace: &WorkspaceAnalyzer,
    universe: &TaintUniverse,
    group: &ProjectedSourceGroup<'_>,
    fixed_point: bool,
    limit: usize,
) -> Result<(Vec<TaintOriginProjection>, usize), String> {
    let scenarios = source_scenarios(workspace, group)?;
    let mut origins = Vec::new();
    for origin in &group.origins {
        let scenario = source_scenario(workspace, origin)?;
        let labels = stable_taint_labels(universe, origin.classes())?;
        let certainty = if origin_is_certain(group, origin, fixed_point) {
            FindingCertainty::Definite
        } else {
            FindingCertainty::possible(vec![
                CertaintyReason::analyzer_ambiguity("taint-uncertain-origin-path")
                    .map_err(|error| error.to_string())?,
            ])
            .map_err(|error| error.to_string())?
        };
        for label in labels
            .into_iter()
            .filter(|label| group.labels.contains(label))
        {
            origins.push(TaintOriginProjection {
                source_endpoint: group.source.identity.clone(),
                source_label: label.clone(),
                source_threat_model: group.source.definition.threat_model,
                source_evidence: group.source.definition.evidence.clone(),
                primary: super::semantic_identity::policy_location(
                    workspace,
                    origin.origin().value_flow_key().site(),
                )?,
                scenario_id: scenario.clone(),
                evidence_refs: vec![taint_evidence_ref(
                    &group.source.identity,
                    &label,
                    &scenarios,
                )?],
                certainty: certainty.clone(),
            });
        }
    }
    origins.sort_by(|left, right| {
        left.source_label
            .cmp(&right.source_label)
            .then_with(|| left.scenario_id.cmp(&right.scenario_id))
    });
    // Several evidence rows can name one source occurrence; the occurrence is
    // certain when any of its rows is, independent of row order.
    origins.dedup_by(|later, kept| {
        let duplicate =
            later.source_label == kept.source_label && later.scenario_id == kept.scenario_id;
        if duplicate && later.certainty == FindingCertainty::Definite {
            kept.certainty = FindingCertainty::Definite;
        }
        duplicate
    });
    let omitted = origins.len().saturating_sub(limit);
    origins.truncate(limit);
    Ok((origins, omitted))
}

/// An origin is certain when its own path is proven and complete at every hop,
/// the search reached a fixed point, and every finding at this sink meeting
/// that retains the origin is proven. One proven finding can carry an origin's
/// certain path while a sibling finding meets the sink with an uncertain fact
/// for the same origin, such as through an unproven transform selection
/// (#3138); the origin then stays uncertain. A sibling finding for another
/// origin does not affect it (#5597).
fn origin_is_certain(
    group: &ProjectedSourceGroup<'_>,
    origin: &TaintOriginFindingEvidence,
    fixed_point: bool,
) -> bool {
    fixed_point
        && origin.has_certain_path()
        && group
            .findings
            .iter()
            .filter(|finding| {
                finding
                    .origins()
                    .evidence()
                    .iter()
                    .any(|retained| retained.origin() == origin.origin())
            })
            .all(|finding| finding.is_proven())
}

fn policy_authored_arm_closures(report: &TaintFindingReport) -> Vec<AuthoredArmClosureEvidence> {
    policy_authored_arm_closures_from(report.authored_arm_closures())
}

fn policy_authored_arm_closures_from(
    closures: &[brokk_bifrost_flow::value_flow::AuthoredArmClosure],
) -> Vec<AuthoredArmClosureEvidence> {
    let mut evidence = closures
        .iter()
        .filter_map(|closure| {
            AuthoredArmClosureEvidence::try_new(
                closure.origin().model().as_str(),
                closure.origin().content().to_string(),
                closure.origin().contract_version(),
            )
            .ok()
        })
        .collect::<Vec<_>>();
    evidence.sort();
    evidence.dedup();
    evidence
}

#[allow(clippy::too_many_arguments)]
fn project_taint_report(
    workspace: &WorkspaceAnalyzer,
    group: &ProjectedSourceGroup<'_>,
    store_crossings: Vec<&StoreCrossingProvenance>,
    finding_key: &str,
    primary: &crate::finding::PolicySourceLocation,
    proven: bool,
    finding_incomplete: bool,
    origins_truncated: bool,
    witness_incomplete: bool,
    witness_limit: usize,
    witness_limits: EffectiveWitnessLimits,
    budget: &PolicyBudget,
    authored_arm_closures: &[brokk_bifrost_flow::value_flow::AuthoredArmClosure],
    store_write_evidence: &StoreWriteEvidenceByRead,
) -> Result<(ProjectedFindingReport, Vec<WitnessId>), String> {
    let certainty = if proven {
        FindingCertainty::Definite
    } else {
        FindingCertainty::possible(vec![
            CertaintyReason::analyzer_ambiguity("taint-unproven-path")
                .map_err(|error| error.to_string())?,
        ])
        .map_err(|error| error.to_string())?
    };
    let mut incomplete = Vec::new();
    if finding_incomplete {
        incomplete.push(FindingIncompleteReason::ProofPartial);
    }
    if origins_truncated {
        incomplete.push(FindingIncompleteReason::OriginsTruncated);
    }
    if witness_incomplete {
        incomplete.push(FindingIncompleteReason::WitnessTruncated);
    }
    let ProjectedTaintWitnesses {
        witnesses,
        witness_refs,
        omitted: omitted_witnesses,
        display_path,
    } = project_taint_witnesses(
        workspace,
        group,
        store_crossings,
        finding_key,
        finding_incomplete || origins_truncated || witness_incomplete,
        witness_limit,
        witness_limits,
    )?;
    if omitted_witnesses > 0 || witnesses.iter().any(BoundedWitness::truncated) {
        incomplete.push(FindingIncompleteReason::WitnessTruncated);
    }
    incomplete.sort();
    incomplete.dedup();
    let completeness = if incomplete.is_empty() {
        FindingCompleteness::Complete
    } else {
        FindingCompleteness::partial(incomplete).map_err(|error| error.to_string())?
    };
    let mut proof_reasons = vec![ProofReason::DataflowWitness];
    proof_reasons.extend(
        policy_authored_arm_closures_from(authored_arm_closures)
            .into_iter()
            .map(|closure| closure.to_proof_reason()),
    );
    let proof = ProofMetadata::try_new(
        if proven {
            ProofState::Proven
        } else {
            ProofState::Unproven
        },
        proof_reasons,
        Vec::new(),
    )
    .map_err(|error| error.to_string())?;
    let related_limit = budget.max_related_locations_per_finding();
    let mut related = Vec::new();
    let mut omitted_related = 0_u64;
    for origin in &group.origins {
        let location = super::semantic_identity::policy_location(
            workspace,
            origin.origin().value_flow_key().site(),
        )?;
        super::projection::retain_related_location(
            &mut related,
            primary,
            PolicyLocationRelationship::Source,
            location,
            related_limit,
            &mut omitted_related,
        )?;
    }
    // A store-fed origin carries the write-to-read edge it crossed: the write
    // call sites that fed its channel, and the origin sites whose values those
    // writes persisted. The read stays the origin; these name what fed it.
    for origin in &group.origins {
        let Some((write_sites, write_origin_sites)) =
            store_write_evidence.get(origin.origin().value_flow_key())
        else {
            continue;
        };
        for (relationship, sites) in [
            (PolicyLocationRelationship::StoreWrite, write_sites),
            (PolicyLocationRelationship::Origin, write_origin_sites),
        ] {
            for site in sites {
                let location = super::semantic_identity::policy_location(workspace, site)?;
                super::projection::retain_related_location(
                    &mut related,
                    primary,
                    relationship,
                    location,
                    related_limit,
                    &mut omitted_related,
                )?;
            }
        }
    }
    Ok((
        ProjectedFindingReport {
            value_type_barrier_notes: Default::default(),
            primary: primary.clone(),
            certainty,
            completeness,
            related,
            related_truncated: omitted_related > 0,
            omitted_related_locations_lower_bound: omitted_related,
            evidence_refs_truncated: false,
            omitted_evidence_refs_lower_bound: 0,
            proof,
            witnesses,
            witnesses_truncated: omitted_witnesses > 0,
            omitted_witnesses_lower_bound: u64::try_from(omitted_witnesses).unwrap_or(u64::MAX),
            display_path,
        },
        witness_refs,
    ))
}

/// The policy witness vocabulary for one step of a taint solver witness.
fn taint_witness_step_kind(kind: &SummaryWitnessStepKind) -> (WitnessStepKind, &'static str) {
    match kind {
        SummaryWitnessStepKind::Seed => (WitnessStepKind::Source, "taint source"),
        SummaryWitnessStepKind::Edge(_) => (WitnessStepKind::Propagation, "taint propagation"),
        SummaryWitnessStepKind::EndSummaryGap(_) => {
            (WitnessStepKind::Return, "taint summary boundary")
        }
    }
}

struct ProjectedTaintWitnesses {
    witnesses: Vec<BoundedWitness>,
    witness_refs: Vec<WitnessId>,
    omitted: usize,
    display_path: Option<crate::display_path::TaintDisplayPath>,
}

/// The step and byte bounds one projected witness must respect: the policy's
/// authored report options capped by the host budget, which is exactly what
/// `EffectiveReportLimits` in `projection.rs` validates against.
#[derive(Debug, Clone, Copy)]
struct EffectiveWitnessLimits {
    steps: usize,
    bytes: usize,
}

fn project_taint_witnesses(
    workspace: &WorkspaceAnalyzer,
    group: &ProjectedSourceGroup<'_>,
    store_crossings: Vec<&StoreCrossingProvenance>,
    finding_key: &str,
    finding_incomplete: bool,
    witness_limit: usize,
    witness_limits: EffectiveWitnessLimits,
) -> Result<ProjectedTaintWitnesses, String> {
    let mut retained = Vec::<(&TaintOriginFindingEvidence, &SummaryWitness)>::new();
    for origin in &group.origins {
        for witness in origin.witnesses() {
            let witness = witness.as_ref();
            if !retained
                .iter()
                .any(|(_, retained_witness)| *retained_witness == witness)
            {
                retained.push((origin, witness));
            }
        }
    }
    let retained_limit = retained.len().min(witness_limit);
    let mut omitted = retained.len().saturating_sub(retained_limit);
    let mut witnesses = Vec::new();
    let mut witness_refs = Vec::new();
    let mut display_candidates = Vec::new();
    let sink_locator = group
        .findings
        .first()
        .expect("a projected source group has a finding")
        .key()
        .sink()
        .site();
    for (index, (origin, witness)) in retained.into_iter().take(retained_limit).enumerate() {
        let id_key =
            super::semantic_identity::stable_hex(format!("{finding_key}:{index}").as_bytes());
        let id = WitnessId::try_new("bifrost", id_key).map_err(|error| error.to_string())?;
        let projected = super::witness_projection::project_summary_witness(
            workspace,
            witness,
            id.clone(),
            witness_limits.steps,
            witness_limits.bytes,
            taint_witness_step_kind,
        )?;
        let Some(mut projected) = projected else {
            omitted = omitted.saturating_add(1);
            continue;
        };
        if let Some(crossing) = store_crossings
            .iter()
            .find(|crossing| crossing.source_endpoint == group.source.identity)
        {
            projected =
                project_store_crossing_witness(workspace, projected, crossing, witness_limits)?;
        }
        display_candidates.push(crate::display_path::project_taint_display_candidate(
            workspace,
            origin.origin().value_flow_key().site(),
            sink_locator,
            id.clone(),
            witness,
            finding_incomplete,
        )?);
        witnesses.push(projected);
        witness_refs.push(id);
    }
    Ok(ProjectedTaintWitnesses {
        witnesses,
        witness_refs,
        omitted,
        display_path: crate::display_path::select_taint_display_path(
            display_candidates,
            u64::try_from(omitted).unwrap_or(u64::MAX),
        ),
    })
}

fn store_crossings_for_group<'a>(
    seeds: &'a [StoreReadSeed],
    group: &ProjectedSourceGroup<'_>,
) -> Vec<&'a StoreCrossingProvenance> {
    let origin_events = group
        .origins
        .iter()
        .map(|origin| origin.origin().value_flow_key())
        .collect::<HashSet<_>>();
    seeds
        .iter()
        .filter(|seed| origin_events.contains(&seed.event))
        .flat_map(|seed| seed.crossings.iter())
        .filter(|crossing| crossing.source_endpoint == group.source.identity)
        .collect()
}

fn store_dimension_evidence(dimension: &TaintStoreDimension) -> StoreDimensionEvidence {
    match dimension {
        TaintStoreDimension::Undeclared => StoreDimensionEvidence::Undeclared,
        TaintStoreDimension::Unproven => StoreDimensionEvidence::Unproven,
        TaintStoreDimension::Proven(identity) => StoreDimensionEvidence::Proven {
            identities: vec![identity.to_string()],
        },
        TaintStoreDimension::ProvenSet(identities) => StoreDimensionEvidence::Proven {
            identities: identities
                .digests()
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
    }
}

fn project_store_crossing_witness(
    workspace: &WorkspaceAnalyzer,
    downstream: BoundedWitness,
    crossing: &StoreCrossingProvenance,
    limits: EffectiveWitnessLimits,
) -> Result<BoundedWitness, String> {
    let mut omitted = downstream.omitted_steps_lower_bound();
    let mut steps = if let Some(upstream) = crossing.source_to_write.as_ref() {
        let projected = super::witness_projection::project_summary_witness_steps(
            workspace,
            upstream,
            downstream.id(),
            limits.steps,
            limits.bytes,
            taint_witness_step_kind,
        )?;
        omitted = omitted
            .saturating_add(u64::try_from(upstream.omitted_steps_lower_bound()).unwrap_or(u64::MAX))
            .saturating_add(
                u64::try_from(upstream.steps().len().saturating_sub(projected.len()))
                    .unwrap_or(u64::MAX),
            );
        projected
    } else {
        omitted = omitted.saturating_add(1);
        Vec::new()
    };
    steps.push(
        WitnessStep::try_new(
            WitnessStepKind::StoreWrite,
            Some(super::semantic_identity::policy_location(
                workspace,
                super::semantic_identity::call_site_locator(&crossing.write_call),
            )?),
            "declared store write",
            Vec::new(),
        )
        .map_err(|error| error.to_string())?,
    );
    steps.push(
        WitnessStep::try_new_with_provenance(
            WitnessStepKind::DeclaredStore,
            None,
            "policy-declared store edge",
            Vec::new(),
            Some(WitnessStepProvenance::DeclaredStore {
                write_model: crossing.write_endpoint.clone(),
                read_model: crossing.read_endpoint.clone(),
                store: crossing.read_channel.store().to_owned(),
                write_instance: store_dimension_evidence(crossing.write_channel.instance()),
                write_key: store_dimension_evidence(crossing.write_channel.key()),
                read_instance: store_dimension_evidence(crossing.read_channel.instance()),
                read_key: store_dimension_evidence(crossing.read_channel.key()),
            }),
        )
        .map_err(|error| error.to_string())?,
    );
    steps.push(
        WitnessStep::try_new(
            WitnessStepKind::StoreRead,
            Some(super::semantic_identity::policy_location(
                workspace,
                super::semantic_identity::call_site_locator(&crossing.read_call),
            )?),
            "declared store read",
            Vec::new(),
        )
        .map_err(|error| error.to_string())?,
    );
    steps.extend(downstream.steps().iter().skip(1).cloned());
    while steps.len() > limits.steps {
        let Some(index) = compressible_store_witness_step(&steps) else {
            return mark_store_crossing_unavailable(downstream);
        };
        steps.remove(index);
        omitted = omitted.saturating_add(1);
    }
    loop {
        match BoundedWitness::try_new(downstream.id().clone(), steps.clone(), omitted > 0, omitted)
        {
            Ok(candidate)
                if usize::try_from(candidate.retained_bytes()).unwrap_or(usize::MAX)
                    <= limits.bytes =>
            {
                return Ok(candidate);
            }
            Ok(_)
            | Err(ReportValueError::TooManyBytes {
                field: "witness", ..
            }) => {}
            Err(error) => return Err(error.to_string()),
        }
        let Some(index) = compressible_store_witness_step(&steps) else {
            return mark_store_crossing_unavailable(downstream);
        };
        steps.remove(index);
        omitted = omitted.saturating_add(1);
    }
}

fn compressible_store_witness_step(steps: &[WitnessStep]) -> Option<usize> {
    steps.iter().enumerate().find_map(|(index, step)| {
        (index + 1 < steps.len()
            && matches!(
                step.kind(),
                WitnessStepKind::Propagation | WitnessStepKind::Return
            ))
        .then_some(index)
    })
}

fn mark_store_crossing_unavailable(downstream: BoundedWitness) -> Result<BoundedWitness, String> {
    BoundedWitness::try_new(
        downstream.id().clone(),
        downstream.steps().to_vec(),
        true,
        downstream.omitted_steps_lower_bound().saturating_add(1),
    )
    .map_err(|error| error.to_string())
}

/// Degrade one payload for a request-wide lane that ran out mid-run.
///
/// Before #2356 the caller replaced the payload with a failed one, so a corpus
/// large enough to spend the request-wide finding cap reported
/// `Failed { reasons: [InternalInvariant] }` and threw away every finding the
/// earlier batches had already projected. Exhausting a declared budget is a
/// normal, honest outcome: the findings stay, the run becomes inconclusive, and
/// the diagnostic names the lane.
fn record_exhausted_lane(payload: &mut TaintProjectionPayload, lane: ExhaustedTaintLane) {
    // A run that already failed or is unsupported cannot be made more
    // reliable by a budget note, and its completion forbids an incomplete
    // diagnostic impact.
    if !payload
        .completion
        .mark_inconclusive(lane.incomplete_reason())
    {
        return;
    }
    payload.authored_arm_closures.clear();
    let Ok(diagnostic) = PolicyDiagnostic::try_new_in_family(
        lane.diagnostic_code(),
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        format!("taint request-wide budget is exhausted: {}", lane.label()),
        format!("taint request-wide budget is exhausted: {}", lane.label()),
        None,
        Vec::new(),
    ) else {
        return;
    };
    if !payload.diagnostics.contains(&diagnostic) {
        payload.diagnostics.push(diagnostic);
    }
}

/// Keep cancellation and replay budget boundaries honest on both evaluation
/// and the explicit candidate route, preserving earlier batch projections.
fn record_refinement_termination(
    payload: &mut TaintProjectionPayload,
    termination: SolverTermination,
) -> PolicyIncompleteReason {
    debug_assert!(!termination.is_fixed_point());
    let reason = if matches!(termination, SolverTermination::Cancelled) {
        PolicyIncompleteReason::Cancelled
    } else {
        PolicyIncompleteReason::PartialDiscovery
    };
    let mut reasons = match &payload.completion {
        PolicyRunCompletion::Inconclusive { reasons, .. } => reasons.clone(),
        PolicyRunCompletion::NotRun { .. }
        | PolicyRunCompletion::Unsupported { .. }
        | PolicyRunCompletion::Failed { .. } => return reason,
        _ => Vec::new(),
    };
    reasons.push(reason);
    reasons.sort();
    reasons.dedup();
    payload.completion =
        PolicyRunCompletion::inconclusive(reasons).expect("incomplete reasons are canonical");
    payload.authored_arm_closures.clear();
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        format!("ICFG value-type barrier refinement stopped: {termination:?}"),
        None,
        Vec::new(),
    )
    .expect("a refinement diagnostic is nonempty");
    if !payload.diagnostics.contains(&diagnostic) {
        payload.diagnostics.push(diagnostic);
    }
    reason
}

fn prepared_failure_payload(message: &str, work: PolicyWorkReport) -> TaintProjectionPayload {
    let completion = PolicyRunCompletion::failed(vec![PolicyFailureReason::InternalInvariant])
        .expect("one failure reason is canonical");
    TaintProjectionPayload {
        engine: None,
        scope: None,
        projections: Vec::new(),
        completion,
        diagnostics: vec![super::projection::failed_projection_diagnostic(message)],
        diagnostics_truncated: false,
        work,
        authored_arm_closures: Vec::new(),
    }
}

fn prepared_compile_failure_payload(failure: TaintPolicyCompileFailure) -> TaintProjectionPayload {
    let TaintPolicyCompileFailure { error, work } = failure;
    let message = error.to_string();
    if matches!(error, TaintPolicyCompileError::UnsupportedBarrierEngine(_)) {
        return TaintProjectionPayload {
            engine: None,
            scope: None,
            projections: Vec::new(),
            completion: PolicyRunCompletion::Unsupported {
                capability: crate::finding::PolicyCapability::TaintEvaluation,
            },
            diagnostics: vec![PolicyDiagnostic::new_bounded(
                PolicyDiagnosticCode::UnsupportedAnalysis,
                PolicyDiagnosticSeverity::Warning,
                PolicyDiagnosticImpact::RunUnsupported,
                message,
            )],
            diagnostics_truncated: false,
            work,
            authored_arm_closures: Vec::new(),
        };
    }
    let incomplete = match &error {
        TaintPolicyCompileError::QueryIncomplete { completion, .. } => {
            let reason = if matches!(completion, CodeQueryCompletion::Cancelled) {
                PolicyIncompleteReason::Cancelled
            } else {
                PolicyIncompleteReason::PartialDiscovery
            };
            Some(reason)
        }
        TaintPolicyCompileError::SemanticUnavailable(_)
        | TaintPolicyCompileError::AmbiguousSemanticSite(_)
        | TaintPolicyCompileError::UnknownFormalName { .. }
        | TaintPolicyCompileError::UnsupportedBinding(_)
        | TaintPolicyCompileError::UnsupportedAuxiliarySemantics(_) => {
            Some(PolicyIncompleteReason::CapabilityIncomplete)
        }
        TaintPolicyCompileError::UnsupportedBarrierEngine(_) => {
            unreachable!("unsupported engines return above")
        }
        TaintPolicyCompileError::MissingSelector(_)
        | TaintPolicyCompileError::SemanticProvider(_)
        | TaintPolicyCompileError::Model(_)
        | TaintPolicyCompileError::Plan(_) => None,
        TaintPolicyCompileError::EmptyCompiledEndpoints(_) => {
            unreachable!("empty endpoint selections are handled as clean compilations")
        }
    };
    let Some(reason) = incomplete else {
        return prepared_failure_payload(&message, work);
    };
    let completion = PolicyRunCompletion::inconclusive(vec![reason])
        .expect("one incomplete reason is canonical");
    // Bounded, not validated: the QueryIncomplete detail joins every
    // underlying query diagnostic, and dropping it for length is what made
    // the #2779 xss refusal ship 455 Inconclusive cases with an empty
    // diagnostics list.
    let diagnostic = Some(PolicyDiagnostic::new_bounded(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        message,
    ));
    TaintProjectionPayload {
        engine: None,
        scope: None,
        projections: Vec::new(),
        completion,
        diagnostics: diagnostic.into_iter().collect(),
        diagnostics_truncated: false,
        work,
        authored_arm_closures: Vec::new(),
    }
}

fn required_selector<'a>(
    selectors: &HashMap<&PolicySelectorPath, &'a ResolvedPolicySelector>,
    path: &PolicySelectorPath,
) -> Result<&'a ResolvedPolicySelector, TaintPolicyCompileError> {
    super::selector_compiler::find_resolved_selector(selectors, path)
        .ok_or_else(|| TaintPolicyCompileError::MissingSelector(path.as_str().to_owned()))
}

/// One tied candidate for a selector row: the semantic call site, the source
/// range its anchor covers, and the procedure that holds it.
struct CallCandidate {
    /// Sorts exact anchor matches before merely enclosing ones.
    inexact: bool,
    range: ByteRange<usize>,
    procedure: ProcedureHandle,
    handle: brokk_bifrost_analysis::analyzer::semantic::CallSiteHandle,
}

fn semantic_call_is_constructor(
    procedure: &ProcedureHandle,
    call_handle: &brokk_bifrost_analysis::analyzer::semantic::CallSiteHandle,
) -> bool {
    procedure
        .semantics()
        .callable_selection_events(call_handle.id())
        .iter()
        .any(|(_, _, event)| {
            matches!(&event.effect,
            SemanticEffect::CallableReference { callable, .. }
                | SemanticEffect::CallableCreation { callable, .. }
                if callable.kind == CallableReferenceKind::Constructor)
        })
}

fn taint_endpoint_kind(
    procedure: &ProcedureHandle,
    call: &brokk_bifrost_analysis::analyzer::semantic::CallSiteHandle,
    binding: &PolicyPort,
) -> TaintEndpointKind {
    match binding {
        PolicyPort::Receiver => TaintEndpointKind::Receiver,
        PolicyPort::ReturnValue | PolicyPort::ResultIndex { .. }
            if semantic_call_is_constructor(procedure, call) =>
        {
            TaintEndpointKind::ConstructorResult
        }
        PolicyPort::ReturnValue | PolicyPort::ResultIndex { .. } => TaintEndpointKind::ReturnValue,
        PolicyPort::ArgumentIndex { .. } => TaintEndpointKind::Argument,
        PolicyPort::ArgumentName { .. } => {
            unreachable!("formal-name ports resolve to an ordinal before endpoint classification")
        }
        PolicyPort::MatchedValue => TaintEndpointKind::MatchedValue,
        PolicyPort::FieldOf { .. } => {
            unreachable!("field ports are not executable taint endpoint bindings")
        }
    }
}

/// What one selector row names in the semantic model.
enum SelectedCallSites {
    /// No semantic call matches the row; it may still name a literal source.
    Missing,
    /// One source call site. The vector holds every semantic call site that
    /// lowers it, which is more than one whenever the lowering specializes the
    /// surrounding code per control-flow route.
    One(
        Vec<(
            ProcedureHandle,
            brokk_bifrost_analysis::analyzer::semantic::CallSiteHandle,
        )>,
    ),
    /// More than one distinct source call site ties for best match, so the row
    /// does not identify a single site and binding refuses it.
    Ambiguous {
        /// The tied source ranges, in ascending order, for the diagnostic.
        ranges: Vec<ByteRange<usize>>,
        /// Durable identity of every procedure holding a tied candidate. A
        /// region that contains none of these cannot contain the refused site,
        /// so this is what bounds the refusal to the sites it really affects.
        procedures: Vec<DurableProcedureKey>,
    },
}

/// Bind one selector row to the semantic call sites it identifies.
///
/// The primary identity is exact source-anchor equality between the selector
/// row and a call site's own anchor; this is what binds Ruby calls with and
/// without parentheses, whose structural rows and semantic call anchors share
/// one node (#1953). A call whose anchor strictly encloses the row is a
/// secondary candidate for adapters whose rows sit inside the call expression.
/// No candidate is a per-row refusal, unless a literal source can bind it.
///
/// Equal-rank candidates are not automatically an ambiguity (#2308). A call
/// site is anchored at its call expression, so tied candidates that share one
/// source range are one call in the source, lowered more than once. Java's
/// `finally` body is the case that matters at corpus scale: the lowering emits
/// one specialization of the cleanup body per completion route out of the
/// guarded region (`crates/bifrost-analysis/src/analyzer/java/semantic/control.rs`,
/// `try_statement` and `route`), so `out.write(x)` written once inside a
/// `finally` becomes two call sites with the identical anchor. Both are real
/// program sites the value can reach, so binding takes all of them rather than
/// picking one path or refusing the row.
///
/// Tied candidates that carry *different* source ranges are a genuine
/// ambiguity: the row's evidence names no single call, and binding refuses it
/// rather than guess.
fn select_call(procedures: &[ProcedureHandle], selection: &SelectedSite) -> SelectedCallSites {
    let selected_call_span = selection
        .call_binding
        .as_ref()
        .map_or(&selection.span, |binding| {
            binding.assert_valid_identity();
            &binding.call_span
        });
    let mut candidates = Vec::new();
    for procedure in procedures {
        for call in procedure.semantics().call_sites() {
            let mapping = procedure
                .semantics()
                .source_mapping(call.source)
                .expect("validated semantic call has a source mapping");
            let span = mapping.locator.anchor().span();
            let call_range = span.start_byte() as usize..span.end_byte() as usize;
            let exact = call_range == *selected_call_span;
            let enclosing = call_range.start <= selected_call_span.start
                && call_range.end >= selected_call_span.end;
            if exact || enclosing {
                let handle = procedure
                    .call_site_handle(call.id)
                    .expect("validated semantic call has a scoped handle");
                candidates.push(CallCandidate {
                    inexact: !exact,
                    range: call_range,
                    procedure: procedure.clone(),
                    handle,
                });
            }
        }
    }
    candidates.sort_by(|left, right| {
        (
            left.inexact,
            left.range.len(),
            left.range.start,
            left.procedure.semantics().locator(),
            left.handle.id(),
        )
            .cmp(&(
                right.inexact,
                right.range.len(),
                right.range.start,
                right.procedure.semantics().locator(),
                right.handle.id(),
            ))
    });
    let Some(best) = candidates.first() else {
        return SelectedCallSites::Missing;
    };
    let rank = (best.inexact, best.range.len());
    let tied = candidates
        .iter()
        .filter(|candidate| (candidate.inexact, candidate.range.len()) == rank)
        .collect::<Vec<_>>();
    let mut ranges = tied
        .iter()
        .map(|candidate| candidate.range.clone())
        .collect::<Vec<_>>();
    ranges.dedup();
    if ranges.len() > 1 {
        let mut procedures = tied
            .iter()
            .map(|candidate| candidate.procedure.durable_key())
            .collect::<Vec<_>>();
        procedures.dedup();
        return SelectedCallSites::Ambiguous { ranges, procedures };
    }
    SelectedCallSites::One(
        tied.into_iter()
            .map(|candidate| (candidate.procedure.clone(), candidate.handle.clone()))
            .collect(),
    )
}

/// The value and observation point a port names at one selected call. `None`
/// means the call has no operand for a receiver or argument port, so the port
/// names nothing there; the caller refuses that site.
fn select_value(
    procedure: &ProcedureHandle,
    call_handle: &brokk_bifrost_analysis::analyzer::semantic::CallSiteHandle,
    selected_span: &ByteRange<usize>,
    binding: &PolicyPort,
) -> Result<Option<(ValueHandle, ProgramPointHandle)>, TaintPolicyCompileError> {
    let call = procedure
        .semantics()
        .call_site(call_handle.id())
        .expect("validated call handle resolves");
    let value_id = match binding {
        PolicyPort::MatchedValue => {
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
                return Err(TaintPolicyCompileError::AmbiguousSemanticSite(
                    "matched-value binding does not identify exactly one semantic value".to_owned(),
                ));
            }
            matching[0].id
        }
        PolicyPort::Receiver => match call.receiver {
            Some(receiver) => receiver,
            None => return Ok(None),
        },
        PolicyPort::ReturnValue => call.result.ok_or_else(|| {
            TaintPolicyCompileError::SemanticUnavailable(
                "return-value binding selected a call without a normal result".to_owned(),
            )
        })?,
        PolicyPort::ResultIndex { index } => call
            .normal_result(usize::try_from(*index).map_err(|_| {
                TaintPolicyCompileError::UnsupportedBinding(
                    "result index does not fit this platform".to_owned(),
                )
            })?)
            .ok_or_else(|| {
                TaintPolicyCompileError::SemanticUnavailable(format!(
                    "selected call has no normal result at index {index}"
                ))
            })?,
        PolicyPort::ArgumentIndex { index } => {
            let position = usize::try_from(*index).map_err(|_| {
                TaintPolicyCompileError::UnsupportedBinding(
                    "argument index does not fit this platform".to_owned(),
                )
            })?;
            match call.arguments.get(position) {
                Some(argument) => argument.value,
                None => return Ok(None),
            }
        }
        PolicyPort::ArgumentName { .. } => {
            unreachable!("formal-name ports resolve to an ordinal before carrier selection")
        }
        PolicyPort::FieldOf { .. } => {
            return Err(TaintPolicyCompileError::UnsupportedBinding(
                "field ports are only valid as external-model transfer destinations".to_owned(),
            ));
        }
    };
    let point_id = if matches!(
        binding,
        PolicyPort::ReturnValue | PolicyPort::ResultIndex { .. }
    ) {
        // A zero-argument return source can be the receiver of an enclosing
        // call, whose invocation point precedes the nested expression's
        // normal continuation in the Rust lowering. Observe the returned
        // value at its call point so that the enclosing receiver boundary can
        // carry it through the reviewed summary. Calls with arguments keep
        // the ordinary post-call observation, which prevents their own input
        // effects from seeing a value before the invocation completes.
        if call.arguments.is_empty() {
            Some(call.point)
        } else {
            call.normal_continuation.target()
        }
    } else {
        Some(call.point)
    }
    .ok_or_else(|| {
        TaintPolicyCompileError::SemanticUnavailable(
            "selected call has no requested observation continuation".to_owned(),
        )
    })?;
    let value = procedure
        .value_handle(value_id)
        .expect("validated call value has a scoped handle");
    let point = procedure
        .point_handle(point_id)
        .expect("validated call point has a scoped handle");
    Ok(Some((value, point)))
}

/// The port as the policy writes it, for a refusal that names a missing
/// operand. Only receiver and argument ports can name a missing operand.
fn operand_port_label(port: &PolicyPort) -> String {
    match port {
        PolicyPort::Receiver => "receiver".to_owned(),
        PolicyPort::ArgumentIndex { index } => format!("(argument :index {index})"),
        _ => unreachable!("only receiver and argument ports can name a missing operand"),
    }
}

fn conjoin_proof(left: &ProofStatus, right: &ProofStatus) -> ProofStatus {
    match (left, right) {
        (ProofStatus::Proven, ProofStatus::Proven) => ProofStatus::Proven,
        (ProofStatus::Unproven(reason), _) | (_, ProofStatus::Unproven(reason)) => {
            ProofStatus::Unproven(reason.clone())
        }
    }
}

fn conjoin_completeness(
    left: &EvidenceCompleteness,
    right: &EvidenceCompleteness,
) -> EvidenceCompleteness {
    match (left, right) {
        (EvidenceCompleteness::Complete, EvidenceCompleteness::Complete) => {
            EvidenceCompleteness::Complete
        }
        (EvidenceCompleteness::Partial(reason), _) | (_, EvidenceCompleteness::Partial(reason)) => {
            EvidenceCompleteness::Partial(reason.clone())
        }
    }
}

/// Project one semantic observation phase onto the value-flow solver's phase.
/// The two enumerations describe the same instant of one program point, so the
/// bridge is total and no endpoint has to choose a phase the oracle did not
/// state.
const fn value_flow_phase(phase: ObservationPhase) -> ValueFlowObservationPhase {
    match phase {
        ObservationPhase::BeforeEffects => ValueFlowObservationPhase::BeforeEffects,
        ObservationPhase::AfterEffects => ValueFlowObservationPhase::AfterEffects,
    }
}

fn cmp_bound_endpoint_site(left: &BoundEndpoint, right: &BoundEndpoint) -> std::cmp::Ordering {
    left.point
        .procedure()
        .semantics()
        .locator()
        .cmp(right.point.procedure().semantics().locator())
        .then_with(|| left.point.id().cmp(&right.point.id()))
}

fn cmp_bound_endpoint(left: &BoundEndpoint, right: &BoundEndpoint) -> std::cmp::Ordering {
    cmp_bound_endpoint_site(left, right)
        .then_with(|| left.endpoint.cmp(&right.endpoint))
        .then_with(|| left.kind.cmp(&right.kind))
}

fn sort_bound_endpoints(endpoints: &mut [BoundEndpoint]) {
    endpoints.sort_by(cmp_bound_endpoint);
}

fn sort_bound_sanitizers(sanitizers: &mut [BoundSanitizer]) {
    sanitizers.sort_by(|left, right| {
        cmp_bound_endpoint(&left.input, &right.input)
            .then_with(|| left.output.point.id().cmp(&right.output.point.id()))
    });
}

fn sort_bound_transforms(transforms: &mut [BoundTransform]) {
    transforms.sort_by(|left, right| {
        cmp_bound_endpoint_site(&left.output, &right.output)
            .then_with(|| left.input.endpoint.cmp(&right.input.endpoint))
            .then_with(|| left.input.point.id().cmp(&right.input.point.id()))
    });
}

/// Sort bound external models by call identity, then by declaring entry, so
/// per-call grouping and every derived hash input is deterministic.
fn sort_bound_external_models(models: &mut [BoundExternalModel]) {
    models.sort_by(|left, right| {
        left.call
            .procedure()
            .semantics()
            .locator()
            .cmp(right.call.procedure().semantics().locator())
            .then_with(|| left.call.id().cmp(&right.call.id()))
            .then_with(|| left.entry.cmp(&right.entry))
    });
}

/// Refuse the external-model shapes this compiler does not lower, before any
/// selector runs, so an unsupported declaration is a loud typed failure and
/// never a silently inert stanza (#2691).
///
/// External-model transform effects (the broader propagator contract of
/// #2689) stay refused. Policy-local `:transforms` lower separately onto exact
/// local carrier relations.
fn validate_external_model_entries(
    models: &[ResolvedTaintAuxiliary<ResolvedTaintExternalModelDefinition>],
) -> Result<(), TaintPolicyCompileError> {
    for model in models {
        for transfer in &model.definition.transfers {
            if matches!(transfer.effect, TaintTransferEffect::Transform { .. }) {
                return Err(TaintPolicyCompileError::UnsupportedAuxiliarySemantics(
                    "external-model transform-effect",
                ));
            }
            match &transfer.from {
                PolicyPort::ArgumentIndex { .. }
                | PolicyPort::ArgumentName { .. }
                | PolicyPort::Receiver => {}
                PolicyPort::ReturnValue
                | PolicyPort::ResultIndex { .. }
                | PolicyPort::MatchedValue
                | PolicyPort::FieldOf { .. } => {
                    return Err(TaintPolicyCompileError::UnsupportedBinding(
                        "external-model transfer :from must be a call input port (argument or receiver)"
                            .to_owned(),
                    ));
                }
            }
            if matches!(transfer.to, PolicyPort::MatchedValue) {
                return Err(TaintPolicyCompileError::UnsupportedBinding(
                    "external-model transfer ports must be call ports".to_owned(),
                ));
            }
            if let PolicyPort::FieldOf { base, .. } = &transfer.to
                && !matches!(
                    base.as_ref(),
                    PolicyPort::Receiver
                        | PolicyPort::ArgumentIndex { .. }
                        | PolicyPort::ArgumentName { .. }
                )
            {
                return Err(TaintPolicyCompileError::UnsupportedBinding(
                    "a field base must be an argument or the receiver".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// The curated-model identity string for one declaring entry. Deterministic
/// and collision-free across local and catalog entries because each arm keeps
/// its own prefix and the component identifiers are validated identifiers.
fn external_model_entry_name(identity: &ResolvedEndpointIdentity) -> String {
    match identity {
        ResolvedEndpointIdentity::Local {
            policy_id,
            entry_id,
        } => format!("policy:{}/{}", policy_id.as_str(), entry_id.as_str()),
        ResolvedEndpointIdentity::Catalog { catalog, entry_id } => format!(
            "catalog:{}@{}/{}",
            catalog.name.as_str(),
            catalog.version,
            entry_id.as_str()
        ),
        ResolvedEndpointIdentity::MatchEndpoint { endpoint_id } => {
            format!("match:{}", endpoint_id.as_str())
        }
    }
}

/// Resolve one field destination against the finished plan's closed carrier
/// set. `Bind` is exactly one observable location, `Unobservable` means no
/// carrier in the solve names the field on the written object (the write is
/// a complete no-op), and `Ambiguous` (several matching carriers) leaves the
/// heap port unbound so the run degrades instead of guessing.
enum FieldDestinationResolution {
    Bind(ValueFlowCarrier),
    Unobservable,
    Ambiguous,
}

impl<'a> TaintPolicyCompiler<'a> {
    /// Install the in-code Rust std operations as curated call models
    /// (#3757): `str::to_owned` and `str::len` carry the receiver to the
    /// result, `Ok`, `Err`, and `Some` carry their argument, and
    /// `String::new()` returns a fresh value. They are Bifrost-authored
    /// language-library facts applied only where the resolver, or the
    /// literal receiver's structure, proves the std identity, so they model
    /// the call at the derived tier. A call another model already owns keeps
    /// that model.
    fn install_rust_std_builtin_models(
        &mut self,
        plan: ValueFlowPlan,
    ) -> Result<ValueFlowPlan, TaintPolicyCompileError> {
        let workspace = self.selectors.workspace();
        let mut models = Vec::new();
        let mut modeled = HashSet::new();
        for procedure in plan.mounted_procedures() {
            for row in procedure.semantics().call_sites() {
                let Some(call) = procedure.call_site_handle(row.id) else {
                    continue;
                };
                if plan.has_curated_call_model(&call) || !modeled.insert(call.clone()) {
                    continue;
                }
                let Some(builtin) = rust_std_builtin_call(workspace, &call)
                    .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?
                else {
                    continue;
                };
                models.push(ValueFlowCuratedCallModel::new(
                    call,
                    rust_std_builtin_model(&builtin)?,
                ));
            }
        }
        if models.is_empty() {
            return Ok(plan);
        }
        plan.with_curated_call_models(models)
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))
    }

    /// Install one curated call model per modeled call site (#2691), merged
    /// as [`ExternalCallSeams`] describes.
    fn install_bound_external_models(
        &mut self,
        plan: ValueFlowPlan,
        models: &[BoundExternalModel],
        universe: &TaintUniverse,
        rust_format_result_calls: &[(CallSiteHandle, ResolverOwnedExternalCalleeIdentity)],
    ) -> Result<ValueFlowPlan, TaintPolicyCompileError> {
        if models.is_empty() && rust_format_result_calls.is_empty() {
            return Ok(plan);
        }
        // `models` is sorted by call identity, so equal calls are adjacent.
        let mut grouped: Vec<(
            CallSiteHandle,
            Vec<&BoundExternalModel>,
            Option<ResolverOwnedExternalCalleeIdentity>,
        )> = Vec::new();
        for model in models {
            match grouped.last_mut() {
                Some((call, group, _)) if call.durable_key() == model.call.durable_key() => {
                    group.push(model);
                }
                _ => grouped.push((model.call.clone(), vec![model], None)),
            }
        }
        for (call, identity) in rust_format_result_calls {
            if let Some((_, _, recorded_identity)) = grouped
                .iter_mut()
                .find(|(candidate, _, _)| candidate.durable_key() == call.durable_key())
            {
                if let Some(recorded_identity) = recorded_identity {
                    assert_eq!(recorded_identity, identity);
                } else {
                    *recorded_identity = Some(identity.clone());
                }
            } else {
                grouped.push((call.clone(), Vec::new(), Some(identity.clone())));
            }
        }
        grouped.sort_by(|left, right| {
            left.0
                .procedure()
                .semantics()
                .locator()
                .cmp(right.0.procedure().semantics().locator())
                .then_with(|| left.0.id().cmp(&right.0.id()))
        });
        let mut curated = Vec::with_capacity(grouped.len());
        let mut location_bindings = Vec::new();
        for (call, group, rust_format_identity) in grouped {
            let mut seams =
                ExternalCallSeams::new(&call, &group, rust_format_identity.as_ref(), universe);
            // Decide every field destination against the plan's closed
            // carrier set before the model is built, so an unobservable write
            // drops out of the model entirely and the rest stays complete.
            let mut dropped_ports = Vec::new();
            for ((_, to), (_, field)) in &seams.moved {
                let Some(field) = field else { continue };
                match self.resolve_field_destination(&plan, &call, field)? {
                    FieldDestinationResolution::Bind(carrier) => {
                        location_bindings.push(ValueFlowSummaryLocationBinding::new(
                            call.clone(),
                            to.clone(),
                            carrier,
                        ));
                    }
                    FieldDestinationResolution::Unobservable => dropped_ports.push(to.clone()),
                    FieldDestinationResolution::Ambiguous => {}
                }
            }
            seams.moved.retain(|(_, to), _| !dropped_ports.contains(to));
            curated.push(ValueFlowCuratedCallModel::new(call, seams.model(universe)?));
        }
        let plan = plan
            .with_curated_call_models(curated)
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
        if location_bindings.is_empty() {
            return Ok(plan);
        }
        plan.with_summary_location_bindings(location_bindings)
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))
    }

    /// Match one declared field destination against every location carrier
    /// the plan retained: the last access selector must be a field whose
    /// declared name matches, and the path root must be one of the caller
    /// values the written object is known as at the modeled call.
    fn resolve_field_destination(
        &mut self,
        plan: &ValueFlowPlan,
        call: &CallSiteHandle,
        field: &ModelFieldDestination,
    ) -> Result<FieldDestinationResolution, TaintPolicyCompileError> {
        let procedure_key = call.procedure().durable_key();
        let mut matched: Vec<&ValueFlowCarrier> = Vec::new();
        for carrier in plan.carriers() {
            let ValueFlowCarrier::Location(location) = carrier else {
                continue;
            };
            let path = location.path();
            let Some(brokk_bifrost_analysis::analyzer::semantic::AccessSelector::Field(member)) =
                path.selectors().last()
            else {
                continue;
            };
            let brokk_bifrost_analysis::analyzer::semantic::AccessPathRoot::Value(root) =
                path.root()
            else {
                continue;
            };
            if root.procedure().durable_key() != procedure_key
                || !field.base_values.contains(&root.id())
            {
                continue;
            }
            if self.field_member_name(member).as_deref() != Some(field.name.as_str()) {
                continue;
            }
            if !matched.contains(&carrier) {
                matched.push(carrier);
            }
        }
        Ok(match matched.as_slice() {
            [] => FieldDestinationResolution::Unobservable,
            [carrier] => FieldDestinationResolution::Bind((*carrier).clone()),
            _ => FieldDestinationResolution::Ambiguous,
        })
    }
}

/// The curated model of one reviewed Rust std operation (#3757).
pub(crate) fn rust_std_builtin_model(
    builtin: &RustStdBuiltinCall,
) -> Result<CuratedCallModel, TaintPolicyCompileError> {
    let plan_error = |error: &dyn fmt::Display| TaintPolicyCompileError::Plan(error.to_string());
    let evidence =
        SummaryEvidence::from_semantic(&ProofStatus::Proven, &EvidenceCompleteness::Complete)
            .map_err(|e| plan_error(&e))?;
    let input = match builtin.transfer {
        RustStdBuiltinTransfer::ReceiverToResult => Some(SummaryPort::Receiver),
        RustStdBuiltinTransfer::ArgumentToResult => Some(SummaryPort::Parameter(0)),
        RustStdBuiltinTransfer::FreshResult => None,
    };
    let transfers = input
        .map(|input| {
            SummaryTransfer::try_new(
                input,
                SummaryExit::try_new(SummaryExitKind::Normal, SummaryPort::NormalReturn)
                    .map_err(|e| plan_error(&e))?,
                evidence.clone(),
            )
            .map_err(|e| plan_error(&e))
        })
        .transpose()?
        .into_iter()
        .collect();
    let mut content = b"bifrost-rust-std-builtin/v1\0".to_vec();
    content.extend_from_slice(builtin.operation.as_bytes());
    content.extend_from_slice(format!("\0{:?}", builtin.transfer).as_bytes());
    CuratedCallModel::try_new(
        ExternalSummaryModelId::new(format!("bifrost.rust-std#{}", builtin.operation))
            .map_err(|e| plan_error(&e))?,
        ExternalSummaryContentHash::hash_bytes(&content),
        transfers,
    )
    .map_err(|e| plan_error(&e))
}

/// One label set a modeled call moves across one port pair, and the field
/// destination of the pair's output when it writes a field.
type ExternalSeam<'model> = (BTreeSet<&'model str>, Option<&'model ModelFieldDestination>);

/// The merged declarations of the external models bound to one call (#2691),
/// with the call's standard format identity when its dispatch proves one.
///
/// Several entries selecting one call merge into one model: per port pair
/// the moved label set is the union of every declaration that moves the
/// label and does not remove it, and the model removes everything else in
/// the universe at that seam, so a transfer only ever carries its declared
/// labels and an explicit `(sanitize :removes ...)` no-flow declaration
/// carries none. The whole group's selection quality conjoins into every
/// transfer's evidence, so an unproven or partial selection keeps the run
/// from completing while the declared semantics still apply.
pub(crate) struct ExternalCallSeams<'model> {
    names: Vec<String>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    moved: BTreeMap<(SummaryPort, SummaryPort), ExternalSeam<'model>>,
}

impl<'model> ExternalCallSeams<'model> {
    pub(crate) fn new(
        call: &CallSiteHandle,
        group: &[&'model BoundExternalModel],
        rust_format_identity: Option<&ResolverOwnedExternalCalleeIdentity>,
        universe: &'model TaintUniverse,
    ) -> Self {
        let mut proof = ProofStatus::Proven;
        let mut completeness = EvidenceCompleteness::Complete;
        let mut names =
            Vec::with_capacity(group.len() + usize::from(rust_format_identity.is_some()));
        let mut moved: BTreeMap<(SummaryPort, SummaryPort), ExternalSeam<'model>> = BTreeMap::new();
        for model in group {
            proof = conjoin_proof(&proof, &model.proof);
            completeness = conjoin_completeness(&completeness, &model.completeness);
            names.push(external_model_entry_name(&model.entry));
            for transfer in &model.transfers {
                let seam = moved
                    .entry((transfer.from.clone(), transfer.to.clone()))
                    .or_default();
                for label in &transfer.labels {
                    if !transfer.removes.contains(label) {
                        seam.0.insert(label.as_str());
                    }
                }
                if seam.1.is_none() {
                    seam.1 = transfer.field.as_ref();
                }
            }
        }
        if let Some(identity) = rust_format_identity {
            assert_eq!(
                identity.language(),
                brokk_bifrost_analysis::analyzer::Language::Rust
            );
            assert!(matches!(
                identity.owner_fqn(),
                "std" | "core" | "alloc" | "alloc.fmt"
            ));
            assert!(matches!(identity.member(), "format" | "format_args"));
            names.push(format!(
                "bifrost.intrinsic.rust-format.{}.{}",
                identity.owner_fqn(),
                identity.member()
            ));
            let semantic_call = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("the dispatched call belongs to its retained procedure");
            for index in 0..semantic_call.arguments.len() {
                let seam = moved
                    .entry((
                        SummaryPort::Parameter(
                            u32::try_from(index).expect("semantic call argument index fits u32"),
                        ),
                        SummaryPort::NormalReturn,
                    ))
                    .or_default();
                seam.0
                    .extend(universe.classes().iter().map(|class| class.as_str()));
            }
        }
        names.sort_unstable();
        names.dedup();
        Self {
            names,
            proof,
            completeness,
            moved,
        }
    }

    /// The curated model of these seams.
    pub(crate) fn model(
        &self,
        universe: &TaintUniverse,
    ) -> Result<CuratedCallModel, TaintPolicyCompileError> {
        let plan_error =
            |error: &dyn fmt::Display| TaintPolicyCompileError::Plan(error.to_string());
        let evidence = SummaryEvidence::from_semantic(&self.proof, &self.completeness)
            .map_err(|e| plan_error(&e))?;
        let mut content = Vec::new();
        content.extend_from_slice(b"bifrost-policy-external-model/v1\0");
        for name in &self.names {
            content.extend_from_slice(name.as_bytes());
            content.push(0);
        }
        let mut transfers = Vec::with_capacity(self.moved.len());
        let mut effects = Vec::with_capacity(self.moved.len());
        for ((from, to), (seam, _)) in &self.moved {
            content.extend_from_slice(format!("{from:?}->{to:?}:").as_bytes());
            for label in seam.iter() {
                content.extend_from_slice(label.as_bytes());
                content.push(0);
            }
            content.push(b'\n');
            transfers.push(
                SummaryTransfer::try_new(
                    from.clone(),
                    SummaryExit::try_new(SummaryExitKind::Normal, to.clone())
                        .map_err(|e| plan_error(&e))?,
                    evidence.clone(),
                )
                .map_err(|e| plan_error(&e))?,
            );
            let removed = universe
                .classes()
                .iter()
                .map(|class| class.as_str())
                .filter(|class| !seam.contains(class))
                .collect::<Vec<_>>();
            if !removed.is_empty() {
                effects.push(SummaryEffect::new(
                    SummaryEffectKey::sanitize(from.clone(), to.clone(), removed),
                    evidence.clone(),
                ));
            }
        }
        match &self.proof {
            ProofStatus::Proven => content.extend_from_slice(b"proven\0"),
            ProofStatus::Unproven(reason) => {
                content.extend_from_slice(b"unproven:");
                content.extend_from_slice(reason.as_bytes());
                content.push(0);
            }
        }
        match &self.completeness {
            EvidenceCompleteness::Complete => content.extend_from_slice(b"complete\0"),
            EvidenceCompleteness::Partial(reason) => {
                content.extend_from_slice(b"partial:");
                content.extend_from_slice(reason.as_bytes());
                content.push(0);
            }
        }
        CuratedCallModel::try_new_with_effects(
            ExternalSummaryModelId::new(self.names.join("+")).map_err(|e| plan_error(&e))?,
            ExternalSummaryContentHash::hash_bytes(&content),
            transfers,
            effects,
        )
        .map_err(|e| plan_error(&e))
    }
}

/// The one curated call model every store-selected call receives: no direct
/// transfers, so the call's whole value behavior is the declared boundary.
fn store_boundary_call_model()
-> Result<brokk_bifrost_flow::dataflow::CuratedCallModel, TaintPolicyCompileError> {
    let model =
        brokk_bifrost_flow::dataflow::ExternalSummaryModelId::new("bifrost.policy.store-boundary")
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
    brokk_bifrost_flow::dataflow::CuratedCallModel::try_new(
        model,
        brokk_bifrost_flow::dataflow::ExternalSummaryContentHash::hash_bytes(
            b"bifrost.policy.store-boundary.empty-transfers.v1",
        ),
        Vec::new(),
    )
    .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))
}

/// The proven identity of a plain string-literal key token, or the join.
///
/// The token must be one quote-delimited literal whose content carries no
/// escape and no embedded quote; the content bytes are then the identity, so
/// `'k'` and `"k"` agree while `"a"` and `"b"` separate. Any other spelling
/// (an escape, a prefix, a template, a non-string constant) stays unproven:
/// separating on it could split two spellings of one runtime value, which
/// would be unsound, while joining only costs precision.
fn string_literal_key_identity(token: &str) -> TaintStoreDimension {
    let bytes = token.as_bytes();
    if bytes.len() >= 2 {
        let quote = bytes[0];
        if (quote == b'"' || quote == b'\'') && bytes[bytes.len() - 1] == quote {
            let content = &bytes[1..bytes.len() - 1];
            if !content.contains(&b'\\') && !content.contains(&quote) {
                let mut digest = LengthDelimitedDigest::new(b"bifrost.taint.store-key.string.v1");
                digest.push(content);
                return TaintStoreDimension::Proven(digest.finish());
            }
        }
    }
    TaintStoreDimension::Unproven
}

fn sort_bound_store_ends(ends: &mut [BoundStoreEnd]) {
    ends.sort_by(|left, right| {
        cmp_bound_endpoint(&left.endpoint, &right.endpoint)
            .then_with(|| left.channel.cmp(&right.channel))
    });
}

/// Hash the persistence-store semantics one region compiled, keyed on event
/// keys rather than dense IDs, mirroring `sanitizer_compatibility_hash`: two
/// policies may share a propagation solve only when their store models agree,
/// because a seeded store read changes the classes the solve establishes.
fn store_compatibility_hash(
    value_flow: &ValueFlowPlan,
    writes: &[TaintStoreWriteBinding],
    reads: &[TaintStoreReadBinding],
) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write_usize(writes.len());
    for write in writes {
        if let Some(spec) = value_flow.sink(write.sink()) {
            std::hash::Hash::hash(spec.key(), &mut hasher);
        }
        std::hash::Hash::hash(write.channel(), &mut hasher);
        hasher.write_u8(u8::from(write.is_complete()));
    }
    hasher.write_usize(reads.len());
    for read in reads {
        if let Some(spec) = value_flow.source(read.source()) {
            std::hash::Hash::hash(spec.key(), &mut hasher);
        }
        std::hash::Hash::hash(read.channel(), &mut hasher);
        hasher.write_u8(u8::from(read.is_complete()));
    }
    hasher.finish()
}

/// Mint the value-flow source specs for a bound endpoint list, keeping each
/// endpoint's minted event key beside its spec. Ordinals start at `offset` so
/// the policy endpoints and the store ends they share a plan with never
/// collide on one `(point, ordinal, kind)` key.
fn keyed_source_event_specs(
    endpoints: &[BoundEndpoint],
    offset: usize,
) -> Result<Vec<(ValueFlowEventKey, ValueFlowSourceSpec)>, TaintPolicyCompileError> {
    keyed_event_specs(
        endpoints,
        offset,
        "source",
        ValueFlowEventKind::Source,
        |endpoint, key| {
            let spec = ValueFlowSourceSpec::new(
                key,
                endpoint.point.clone(),
                endpoint.phase,
                endpoint.carrier.clone(),
                endpoint.proof.clone(),
                endpoint.completeness.clone(),
            );
            spec.requiring_dispatches(endpoint.dispatch_obligations.clone())
        },
    )
}

fn keyed_sink_event_specs(
    endpoints: &[BoundEndpoint],
    offset: usize,
) -> Result<Vec<(ValueFlowEventKey, ValueFlowSinkSpec)>, TaintPolicyCompileError> {
    keyed_event_specs(
        endpoints,
        offset,
        "sink",
        ValueFlowEventKind::Sink,
        |endpoint, key| {
            let spec = ValueFlowSinkSpec::new(
                key,
                endpoint.point.clone(),
                endpoint.phase,
                endpoint.carrier.clone(),
                endpoint.proof.clone(),
                endpoint.completeness.clone(),
            );
            spec.requiring_dispatches(endpoint.dispatch_obligations.clone())
        },
    )
}

fn keyed_event_specs<T>(
    endpoints: &[BoundEndpoint],
    offset: usize,
    kind_name: &str,
    kind: ValueFlowEventKind,
    mut make_spec: impl FnMut(&BoundEndpoint, ValueFlowEventKey) -> T,
) -> Result<Vec<(ValueFlowEventKey, T)>, TaintPolicyCompileError> {
    endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| {
            let ordinal = u32::try_from(offset + index).map_err(|_| {
                TaintPolicyCompileError::Plan(format!("taint {kind_name} ordinal overflow"))
            })?;
            let key = ValueFlowEventKey::at_point(&endpoint.point, ordinal, kind)
                .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
            let spec = make_spec(endpoint, key.clone());
            Ok((key, spec))
        })
        .collect()
}

fn source_id_for_event(
    value_flow: &ValueFlowPlan,
    key: &ValueFlowEventKey,
) -> Result<ValueFlowSourceId, TaintPolicyCompileError> {
    event_id_for_key(
        value_flow.sources().map(|(id, spec)| (id, spec.key())),
        key,
        "source",
    )
}

fn sink_id_for_event(
    value_flow: &ValueFlowPlan,
    key: &ValueFlowEventKey,
) -> Result<ValueFlowSinkId, TaintPolicyCompileError> {
    event_id_for_key(
        value_flow.sinks().map(|(id, spec)| (id, spec.key())),
        key,
        "sink",
    )
}

fn event_id_for_key<'a, I, Id>(
    events: I,
    key: &ValueFlowEventKey,
    kind: &str,
) -> Result<Id, TaintPolicyCompileError>
where
    I: IntoIterator<Item = (Id, &'a ValueFlowEventKey)>,
{
    events
        .into_iter()
        .find_map(|(id, event_key)| (event_key == key).then_some(id))
        .ok_or_else(|| {
            TaintPolicyCompileError::Plan(format!(
                "compiled taint {kind} event is absent from the value-flow plan"
            ))
        })
}

fn class_set(
    universe: &TaintUniverse,
    labels: &[TaintLabel],
) -> Result<TaintClassSet, TaintPolicyCompileError> {
    let stable = labels
        .iter()
        .map(|label| {
            SourceClassId::new(label.as_str())
                .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    universe
        .class_set(stable.iter())
        .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))
}

fn bind_taint_sources(
    value_flow: &ValueFlowPlan,
    universe: &TaintUniverse,
    endpoints: &[BoundEndpoint],
    specs: &[(ValueFlowEventKey, ValueFlowSourceSpec)],
) -> Result<Vec<TaintSourceBinding>, TaintPolicyCompileError> {
    bind_taint_endpoints(endpoints, specs, "source", |endpoint, key| {
        Ok(TaintSourceBinding::new(
            source_id_for_event(value_flow, key)?,
            class_set(universe, &endpoint.labels)?,
            SourceEventKey::new(key.clone()),
        ))
    })
}

fn bind_taint_sinks(
    value_flow: &ValueFlowPlan,
    universe: &TaintUniverse,
    endpoints: &[BoundEndpoint],
    specs: &[(ValueFlowEventKey, ValueFlowSinkSpec)],
) -> Result<Vec<TaintSinkBinding>, TaintPolicyCompileError> {
    bind_taint_endpoints(endpoints, specs, "sink", |endpoint, key| {
        Ok(TaintSinkBinding::new(
            sink_id_for_event(value_flow, key)?,
            class_set(universe, &endpoint.labels)?,
        ))
    })
}

fn bind_taint_endpoints<T, Spec>(
    endpoints: &[BoundEndpoint],
    specs: &[(ValueFlowEventKey, Spec)],
    kind: &str,
    mut bind: impl FnMut(&BoundEndpoint, &ValueFlowEventKey) -> Result<T, TaintPolicyCompileError>,
) -> Result<Vec<T>, TaintPolicyCompileError> {
    assert_eq!(
        endpoints.len(),
        specs.len(),
        "every bound {kind} endpoint minted exactly one event spec"
    );
    endpoints
        .iter()
        .zip(specs)
        .map(|(endpoint, (key, _))| bind(endpoint, key))
        .collect()
}

/// Lower the region's bound store ends into plan bindings by their minted
/// event keys. Completeness follows the carrier resolution: a partially
/// evidenced end still flows (the join direction) but blocks a complete
/// verdict downstream.
fn bind_store_writes(
    value_flow: &ValueFlowPlan,
    ends: &[BoundStoreEnd],
    specs: &[(ValueFlowEventKey, ValueFlowSinkSpec)],
) -> Result<Vec<TaintStoreWriteBinding>, TaintPolicyCompileError> {
    bind_store_ends(ends, specs, "write", |end, key, complete| {
        Ok(TaintStoreWriteBinding::new(
            sink_id_for_event(value_flow, key)?,
            end.channel.clone(),
            complete,
        ))
    })
}

fn bind_store_reads(
    value_flow: &ValueFlowPlan,
    ends: &[BoundStoreEnd],
    specs: &[(ValueFlowEventKey, ValueFlowSourceSpec)],
) -> Result<Vec<TaintStoreReadBinding>, TaintPolicyCompileError> {
    bind_store_ends(ends, specs, "read", |end, key, complete| {
        Ok(TaintStoreReadBinding::new(
            source_id_for_event(value_flow, key)?,
            end.channel.clone(),
            complete,
        ))
    })
}

fn bind_store_ends<T, Spec>(
    ends: &[BoundStoreEnd],
    specs: &[(ValueFlowEventKey, Spec)],
    kind: &str,
    mut bind: impl FnMut(&BoundStoreEnd, &ValueFlowEventKey, bool) -> Result<T, TaintPolicyCompileError>,
) -> Result<Vec<T>, TaintPolicyCompileError> {
    assert_eq!(
        ends.len(),
        specs.len(),
        "every bound store {kind} minted exactly one event spec"
    );
    ends.iter()
        .zip(specs)
        .map(|(end, (key, _))| {
            let complete = matches!(end.endpoint.proof, ProofStatus::Proven)
                && matches!(end.endpoint.completeness, EvidenceCompleteness::Complete);
            bind(end, key, complete)
        })
        .collect()
}

/// Lower the region's bound sanitizer pairs into per-input-carrier taint kill
/// functions. One `(point, phase, input-carrier, output-carrier)` slot carries
/// at most one binding. The output carrier is retained and validated as part
/// of the exact input/output contract, while applying the kill to the input is
/// what keeps a wrong tainted operand from being cleared by the sanitizer call.
/// One sanitizer effect at one point and phase on one input and output
/// carrier: the union of the classes every sanitizer bound there removes, and
/// whether all of them are proven and complete.
struct SanitizerSlot {
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
    input: ValueFlowCarrier,
    output: ValueFlowCarrier,
    removed: TaintClassSet,
    proven: bool,
    complete: bool,
}

/// Merge bound sanitizers that act at one point, phase and carrier pair.
fn sanitizer_slots(
    universe: &TaintUniverse,
    sanitizers: &[BoundSanitizer],
) -> Result<Vec<SanitizerSlot>, TaintPolicyCompileError> {
    let mut slots: Vec<SanitizerSlot> = Vec::new();
    for sanitizer in sanitizers {
        let removed = class_set(universe, &sanitizer.input.labels)?;
        let proven = matches!(sanitizer.input.proof, ProofStatus::Proven)
            && matches!(sanitizer.output.proof, ProofStatus::Proven);
        let complete = proven
            && matches!(sanitizer.input.completeness, EvidenceCompleteness::Complete)
            && matches!(
                sanitizer.output.completeness,
                EvidenceCompleteness::Complete
            );
        match slots.iter_mut().find(|slot| {
            slot.point == sanitizer.input.point
                && slot.phase == sanitizer.input.phase
                && slot.input == sanitizer.input.carrier
                && slot.output == sanitizer.output.carrier
        }) {
            Some(slot) => {
                slot.removed = slot.removed.union(&removed);
                slot.proven &= proven;
                slot.complete &= complete;
            }
            None => slots.push(SanitizerSlot {
                point: sanitizer.input.point.clone(),
                phase: sanitizer.input.phase,
                input: sanitizer.input.carrier.clone(),
                output: sanitizer.output.carrier.clone(),
                removed,
                proven,
                complete,
            }),
        }
    }
    Ok(slots)
}

fn bind_taint_sanitizers(
    value_flow: &ValueFlowPlan,
    universe: &TaintUniverse,
    sanitizers: &[BoundSanitizer],
) -> Result<Vec<TaintSanitizerBinding>, TaintPolicyCompileError> {
    sanitizer_slots(universe, sanitizers)?
        .into_iter()
        .map(|slot| {
            let input = value_flow.carrier_id(&slot.input).ok_or_else(|| {
                TaintPolicyCompileError::Plan(
                    "sanitizer input carrier is absent from the value-flow plan".to_owned(),
                )
            })?;
            let output = value_flow.carrier_id(&slot.output).ok_or_else(|| {
                TaintPolicyCompileError::Plan(
                    "sanitizer output carrier is absent from the value-flow plan".to_owned(),
                )
            })?;
            let SanitizerSlot {
                point,
                phase,
                removed,
                proven,
                complete,
                ..
            } = slot;
            Ok(if complete {
                TaintSanitizerBinding::resolved_with_output(point, phase, 0, input, output, removed)
            } else if proven {
                TaintSanitizerBinding::proven_incomplete_with_output(
                    point, phase, 0, input, output, removed,
                )
            } else {
                TaintSanitizerBinding::unresolved_with_output(
                    point, phase, 0, input, output, removed,
                )
            })
        })
        .collect()
}

fn bind_taint_local_transforms(
    value_flow: &ValueFlowPlan,
    universe: &TaintUniverse,
    transforms: &[BoundTransform],
) -> Result<Vec<TaintLocalTransformBinding>, TaintPolicyCompileError> {
    transforms
        .iter()
        .map(|transform| {
            let input = value_flow
                .carrier_id(&transform.input.carrier)
                .ok_or_else(|| {
                    TaintPolicyCompileError::Plan(
                        "transform input carrier is absent from the value-flow plan".to_owned(),
                    )
                })?;
            let output = value_flow
                .carrier_id(&transform.output.carrier)
                .ok_or_else(|| {
                    TaintPolicyCompileError::Plan(
                        "transform output carrier is absent from the value-flow plan".to_owned(),
                    )
                })?;
            let removed = class_set(universe, &transform.removes)?;
            let added = class_set(universe, &transform.adds)?;
            let function =
                TaintEdgeFunction::kill(&removed).compose(&TaintEdgeFunction::generate(&added));
            Ok(TaintLocalTransformBinding::new(
                transform.output.point.clone(),
                input,
                output,
                function,
            ))
        })
        .collect()
}

/// Hash the kill semantics one region compiled, keyed on carrier *keys* rather
/// than dense carrier IDs so two policies over the same region agree exactly
/// when the batch planner's own sanitizer equality would.
fn sanitizer_compatibility_hash(
    value_flow: &ValueFlowPlan,
    sanitizers: &[TaintSanitizerBinding],
) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write_usize(sanitizers.len());
    for binding in sanitizers {
        std::hash::Hash::hash(binding.point(), &mut hasher);
        std::hash::Hash::hash(&binding.phase(), &mut hasher);
        hasher.write_u32(binding.event_index());
        if let Some(key) = value_flow.carrier_key(binding.carrier()) {
            std::hash::Hash::hash(key, &mut hasher);
        }
        if let Some(key) = value_flow.carrier_key(binding.output()) {
            std::hash::Hash::hash(key, &mut hasher);
        }
        std::hash::Hash::hash(binding.removed(), &mut hasher);
        hasher.write_u8(u8::from(binding.is_proven()));
        hasher.write_u8(u8::from(binding.is_resolved()));
    }
    hasher.finish()
}

/// Add policy-local label rewriting to the existing sanitizer compatibility
/// component without rotating identities for policies that declare no local
/// transform.
fn local_transform_compatibility_hash(
    value_flow: &ValueFlowPlan,
    sanitizer_hash: u64,
    transforms: &[TaintLocalTransformBinding],
) -> u64 {
    if transforms.is_empty() {
        return sanitizer_hash;
    }
    let mut hasher = DefaultHasher::new();
    hasher.write(b"bifrost-policy-local-transform-compatibility-v1");
    hasher.write_u64(sanitizer_hash);
    hasher.write_usize(transforms.len());
    for binding in transforms {
        std::hash::Hash::hash(binding.point(), &mut hasher);
        if let Some(key) = value_flow.carrier_key(binding.input()) {
            std::hash::Hash::hash(key, &mut hasher);
        }
        if let Some(key) = value_flow.carrier_key(binding.output()) {
            std::hash::Hash::hash(key, &mut hasher);
        }
        std::hash::Hash::hash(binding.function(), &mut hasher);
    }
    hasher.finish()
}

/// The taint value one matched-value observation binds: a parameter's
/// observation binds its procedure port at the entry point, any other value
/// binds itself at its point, a constant as a literal.
fn matched_value_endpoint(
    observation: &ValueAtPoint,
    dispatch_calls: &[CallSiteHandle],
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
) -> ResolvedTaintValue {
    let value = observation.value();
    let procedure = value.procedure().clone();
    let parameter_ordinal =
        procedure
            .semantics()
            .value(value.id())
            .and_then(|row| match &row.kind {
                SemanticValueKind::Parameter { ordinal, .. } => Some(*ordinal),
                _ => None,
            });
    let (point, phase, carrier) = match parameter_ordinal {
        Some(ordinal) => {
            let port = ProcedurePortHandle::parameter(procedure.clone(), ordinal)
                .expect("semantic parameter value has a matching procedure port");
            let point = procedure
                .point_handle(procedure.semantics().entry_point())
                .expect("semantic procedure has an entry point handle");
            (
                point,
                ValueFlowObservationPhase::BeforeEffects,
                ValueFlowCarrier::Port(port),
            )
        }
        None => (
            observation.point().clone(),
            // Keep the phase the oracle attached to the observation. A
            // matched value is usually the one the point defines, so the
            // observation holds after that point's effects; binding it
            // before them lets the defining assignment's strong update
            // kill the endpoint at its own site.
            value_flow_phase(observation.phase()),
            ValueFlowCarrier::for_value(value.clone()),
        ),
    };
    let kind = match &carrier {
        ValueFlowCarrier::Value(value)
            if procedure.semantics().value(value.id()).is_some_and(|row| {
                matches!(
                    row.kind,
                    SemanticValueKind::Constant | SemanticValueKind::ConstantString(_)
                )
            }) =>
        {
            TaintEndpointKind::LiteralValue
        }
        _ => TaintEndpointKind::MatchedValue,
    };
    ResolvedTaintValue {
        call: None,
        dispatch_obligations: dispatch_calls
            .iter()
            .filter(|call| call.procedure() == &procedure)
            .cloned()
            .collect(),
        kind,
        point,
        phase,
        carrier,
        proof,
        completeness,
        unjudged: None,
    }
}

fn endpoint_metadata<Spec>(
    endpoints: &[BoundEndpoint],
    specs: &[(ValueFlowEventKey, Spec)],
) -> Vec<CompiledTaintEndpoint> {
    assert_eq!(
        endpoints.len(),
        specs.len(),
        "every bound endpoint minted exactly one event spec"
    );
    endpoints
        .iter()
        .zip(specs)
        .map(|(endpoint, (key, _))| CompiledTaintEndpoint {
            endpoint: endpoint.endpoint.clone(),
            event: key.clone(),
        })
        .collect()
}

fn require_uninterrupted_outcome<T>(
    outcome: &brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome<T>,
    operation: &str,
) -> Result<(), TaintPolicyCompileError> {
    super::selector_compiler::semantic_outcome_failure(outcome, operation)
        .map_or(Ok(()), |(completion, detail)| {
            Err(TaintPolicyCompileError::QueryIncomplete { completion, detail })
        })
}

fn require_discovery_execution_budget(
    budget: &SemanticExecutionBudget,
    operation: &str,
) -> Result<(), TaintPolicyCompileError> {
    super::selector_compiler::semantic_execution_budget_failure(budget, operation).map_or(
        Ok(()),
        |detail| {
            Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                detail,
            ))
        },
    )
}

fn query_budget_error(
    code: CodeQueryDiagnosticCode,
    detail: impl Into<String>,
) -> TaintPolicyCompileError {
    TaintPolicyCompileError::QueryIncomplete {
        completion: super::selector_compiler::incomplete_code_query_completion(code),
        detail: detail.into(),
    }
}

/// True when a compile error is a per-region semantic-budget exhaustion, the one
/// error the discovery loop recovers from by skipping the oversized root rather
/// than aborting the whole compile (#1936). Every other error still propagates.
fn is_region_budget_exhausted(error: &TaintPolicyCompileError) -> bool {
    matches!(
        error,
        TaintPolicyCompileError::QueryIncomplete {
            completion: CodeQueryCompletion::Incomplete { codes },
            ..
        } if codes.contains(&CodeQueryDiagnosticCode::SemanticBudgetExhausted)
    )
}

fn taint_selector_error(
    error: super::selector_compiler::PolicySelectorSessionError,
) -> TaintPolicyCompileError {
    match error {
        super::selector_compiler::PolicySelectorSessionError::Incomplete { completion, detail } => {
            TaintPolicyCompileError::QueryIncomplete { completion, detail }
        }
        super::selector_compiler::PolicySelectorSessionError::Unavailable(detail) => {
            TaintPolicyCompileError::SemanticUnavailable(detail)
        }
        super::selector_compiler::PolicySelectorSessionError::Provider(detail) => {
            TaintPolicyCompileError::SemanticProvider(detail)
        }
        // A taint compile hands its session no units, so nothing in it can ask
        // to be compiled again (taint is `WholePolicyFamily`).
        super::selector_compiler::PolicySelectorSessionError::Widen(reason) => unreachable!(
            "a taint selector session has no units and cannot widen: {}",
            reason.stable_label()
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use brokk_bifrost_test_macros::hardwon;

    use super::{
        DiscoveryMaterializationCache, ProductionTaintPolicyEvaluator, TaintEngine,
        TaintExecutionBudget, TaintPolicyCompilation, TaintPolicyCompiler, compiled_payload,
        sanitizer_constant_equals,
    };
    use crate::budget::PolicyBudget;
    use crate::coordinator::{
        PolicyEvaluationInput, PolicyEvaluationOptions, PolicySemanticModelContext,
        evaluate_policy_inputs_with_analyzer_and_semantic_models, evaluate_policy_source,
    };
    use crate::definition::PolicyId;
    use crate::evaluator::{DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator};
    use crate::finding::{
        PolicyDiagnostic, PolicyDiagnosticImpact, PolicyDiagnosticSeverity, PolicyIncompleteReason,
        PolicyRunCompletion, PolicyWorkMetric, PolicyWorkReport,
    };
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::registry::PolicyRegistry;
    use crate::source::PolicySourceIdentity;
    use crate::suppression::PolicyEvaluationDate;
    use brokk_bifrost_analysis::CancellationToken;
    use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, ReadKey, ReadLedger};
    use brokk_bifrost_analysis::analyzer::semantic::{
        DispatchBoundaryKind, EvidenceCompleteness, IcfgEdgeKind, IcfgLimitKind, ProcedureHandle,
        ProofStatus, SemanticArtifact, SemanticBudget, SemanticLanguage, SemanticRequest,
        SemanticValueKind, SemanticWork,
    };
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
        SemanticModelActivationRequest, SemanticPackCatalog, SessionPackSource,
        SessionPackSourceKind, SourceFormat, compile_source,
    };
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, AnalyzerQueryScope, FilesystemProject, Language, Project, WorkspaceAnalyzer,
    };
    use brokk_bifrost_flow::dataflow::{SolverWork, SummaryBoundaryKind};
    use brokk_bifrost_rql::structural::{CodeQueryExecutionLimits, CodeQuerySemanticLimits};

    #[test]
    fn semantic_string_labels_do_not_satisfy_literal_requirements() {
        let error = sanitizer_constant_equals(
            &SemanticValueKind::ConstantString("Eq".into()),
            &serde_json::json!("Eq"),
            SemanticLanguage::Standard(Language::Rust),
        )
        .expect_err("Rust's synthetic keys are not decoded literals");
        assert_eq!(error, "string constant is not decodable for rust");
    }

    #[test]
    fn barrier_projection_selects_strict_origins_within_the_public_group() {
        // S1 and S2 are occurrences of the same declared source endpoint.
        // Their concrete pairs collapse to one public finding. Only S2 has
        // a strict witness, so S1's labels, quality and notes must not leak.
        #[derive(Debug, PartialEq)]
        struct Evidence {
            origins: &'static [&'static str],
            notes: &'static [&'static str],
        }
        let s1 = Evidence {
            origins: &["S1"],
            notes: &["U: unknown type"],
        };
        let s2 = Evidence {
            origins: &["S2"],
            notes: &[],
        };
        let u1 = Evidence {
            origins: &["U1"],
            notes: &["U1: unknown type"],
        };
        let u2 = Evidence {
            origins: &["U2"],
            notes: &["U2: ambiguous type"],
        };
        let selected = super::select_barrier_evidence(vec![
            ("mixed", &s1, None),
            ("mixed", &s2, Some(&s2)),
            ("all-undecided", &u1, None),
            ("all-undecided", &u2, None),
        ]);
        let mixed = selected
            .iter()
            .filter(|(group, _, _)| *group == "mixed")
            .collect::<Vec<_>>();
        assert_eq!(mixed.len(), 1);
        assert_eq!(mixed[0].1.origins, &["S2"]);
        assert!(mixed[0].1.notes.is_empty());
        assert!(mixed[0].2);
        let undecided = selected
            .iter()
            .filter(|(group, _, _)| *group == "all-undecided")
            .collect::<Vec<_>>();
        assert_eq!(
            undecided
                .iter()
                .flat_map(|(_, evidence, _)| evidence.origins.iter().copied())
                .collect::<Vec<_>>(),
            ["U1", "U2"]
        );
        assert_eq!(
            undecided
                .iter()
                .flat_map(|(_, evidence, _)| evidence.notes.iter().copied())
                .collect::<Vec<_>>(),
            ["U1: unknown type", "U2: ambiguous type"]
        );
        assert!(undecided.iter().all(|(_, _, strict)| !strict));
    }

    #[test]
    #[hardwon("#2838: recursive-carry runs were inconclusive without a diagnostic family")]
    fn solver_incompleteness_diagnostics_have_stable_typed_families() {
        let proof = ProofStatus::Unproven("unproven".into());
        let gap = EvidenceCompleteness::Partial("partial".into());
        let limit = SummaryBoundaryKind::Limit(IcfgLimitKind::CallDepth);
        let edges = |count: u64| {
            (1..=count)
                .map(|line| {
                    coverage_rows::edge(
                        IcfgEdgeKind::NormalReturn,
                        coverage_rows::at("handler.js", line),
                        &proof,
                        &gap,
                    )
                })
                .collect::<Vec<_>>()
        };
        let boundaries = (1..=3)
            .map(|line| {
                coverage_rows::boundary(
                    &limit,
                    coverage_rows::at("handler.js", line),
                    Some(&proof),
                    None,
                )
            })
            .collect::<Vec<_>>();
        let fixed_point = super::taint_incomplete_diagnostic(
            super::SolverTermination::FixedPoint,
            PolicyIncompleteReason::PartialDiscovery,
            edges(1).into_iter(),
            edges(2).into_iter(),
            boundaries.into_iter(),
        );
        assert_eq!(fixed_point.family(), "taint_analysis/partial_discovery");
        assert_eq!(
            fixed_point.impact(),
            super::PolicyDiagnosticImpact::RunIncomplete
        );
        assert!(fixed_point.message().contains("1 unproven edge(s)"));
        assert!(fixed_point.message().contains("2 partial edge(s)"));
        assert!(fixed_point.message().contains("3 open boundary row(s)"));

        let cancelled = super::taint_incomplete_diagnostic(
            super::SolverTermination::Cancelled,
            PolicyIncompleteReason::Cancelled,
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
        );
        assert_eq!(cancelled.family(), "taint_analysis/cancelled");
        assert_eq!(
            cancelled.impact(),
            super::PolicyDiagnosticImpact::RunIncomplete
        );
        assert_eq!(
            cancelled.message(),
            "taint analysis was cancelled before reaching a fixed point"
        );

        let cancellation = CancellationToken::default();
        let mut budget = super::SolverBudget::uniform(0);
        let exceeded = super::DataflowRequest::new(&mut budget, &cancellation)
            .reserve(SolverWork {
                summary_applications: 1,
                ..SolverWork::default()
            })
            .expect("the zero summary-application budget is exhausted");
        let budgeted = super::taint_incomplete_diagnostic(
            exceeded,
            PolicyIncompleteReason::PartialDiscovery,
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
        );
        assert_eq!(
            budgeted.family(),
            "taint_analysis/solver_budget/summary_applications"
        );
        assert_eq!(
            budgeted.impact(),
            super::PolicyDiagnosticImpact::RunIncomplete
        );
    }

    /// #3644: two fixed points with equal coverage totals used to produce one
    /// warning. The retained reasons and kinds now tell them apart, at the
    /// same locations, and `primary` and `related` name the selected rows.
    #[test]
    #[hardwon("#3644: coverage diagnostics lost distinct retained reasons at equal counts")]
    fn fixed_point_incompleteness_names_distinct_reasons_at_equal_counts() {
        fn fixed_point(proof: &ProofStatus, boundary: &SummaryBoundaryKind) -> PolicyDiagnostic {
            let gap = EvidenceCompleteness::Partial(
                "the callee exit has exact return-affecting semantic gaps".into(),
            );
            let proven = ProofStatus::Proven;
            let unproven = super::CoverageRow {
                origin: Some(coverage_rows::at("handler.js", 12)),
                ..coverage_rows::edge(
                    IcfgEdgeKind::ExceptionalReturn,
                    coverage_rows::at("handler.js", 7),
                    proof,
                    &gap,
                )
            };
            let partial = coverage_rows::edge(
                IcfgEdgeKind::NormalReturn,
                coverage_rows::at("handler.js", 9),
                &proven,
                &gap,
            );
            let open = coverage_rows::boundary(
                boundary,
                coverage_rows::at("handler.js", 7),
                Some(proof),
                None,
            );
            super::taint_incomplete_diagnostic(
                super::SolverTermination::FixedPoint,
                PolicyIncompleteReason::PartialDiscovery,
                [unproven].into_iter(),
                [partial].into_iter(),
                [open].into_iter(),
            )
        }
        let operator = fixed_point(
            &ProofStatus::Unproven(
                "implicit exceptions from runtime coercion or operator dispatch are not yet lowered"
                    .into(),
            ),
            &SummaryBoundaryKind::Limit(IcfgLimitKind::CallDepth),
        );
        let property = fixed_point(
            &ProofStatus::Unproven(
                "implicit exceptions from property access, accessors, or proxies are not yet lowered"
                    .into(),
            ),
            &SummaryBoundaryKind::Dispatch(DispatchBoundaryKind::Unresolved),
        );

        let totals = "taint analysis is incomplete after reaching a fixed point: 1 unproven edge(s), 1 partial edge(s), and 1 open boundary row(s); ";
        assert_eq!(operator.family(), "taint_analysis/partial_discovery");
        assert_eq!(operator.family(), property.family());
        assert!(
            operator.message().starts_with(totals),
            "{}",
            operator.message()
        );
        assert!(
            property.message().starts_with(totals),
            "{}",
            property.message()
        );
        assert_ne!(operator.message(), property.message());
        assert_eq!(
            operator.message(),
            format!(
                "{totals}unproven edge exceptional_return at handler.js:7:3 origin=handler.js:12:3 proof=unproven (implicit exceptions from runtime coercion or operator dispatch are not yet lowered) completeness=partial (the callee exit has exact return-affecting semantic gaps); partial edge normal_return at handler.js:9:3 proof=proven completeness=partial (the callee exit has exact return-affecting semantic gaps); open boundary row limit:call_depth_limit at handler.js:7:3 proof=unproven (implicit exceptions from runtime coercion or operator dispatch are not yet lowered)"
            )
        );
        assert!(
            property
                .message()
                .contains("; open boundary row dispatch:unresolved at handler.js:7:3 proof=unproven (implicit exceptions from property access, accessors, or proxies are not yet lowered)"),
            "{}",
            property.message()
        );
        assert!(!property.message().contains("operator dispatch"));
        assert!(!property.message().contains("limit:"));

        for diagnostic in [&operator, &property] {
            assert_eq!(
                diagnostic.primary(),
                Some(&coverage_rows::at("handler.js", 7))
            );
            // The boundary shares the unproven edge's location, and
            // try_new_in_family keeps one entry per identical location.
            let related = diagnostic
                .related()
                .iter()
                .map(|related| {
                    assert_eq!(
                        related.relationship(),
                        crate::finding::PolicyLocationRelationship::Evidence
                    );
                    related.location().clone()
                })
                .collect::<Vec<_>>();
            assert_eq!(
                related,
                vec![
                    coverage_rows::at("handler.js", 7),
                    coverage_rows::at("handler.js", 9)
                ]
            );
        }
    }

    /// #3644: far more rows than the warning names, with 2 KiB reasons and one
    /// oversized path, construct under the report prose bound with three rows
    /// per category in coverage order and each category's exact omitted count.
    #[test]
    #[hardwon("#3644: fixed-point diagnostics dropped proof reasons under report bounds")]
    fn fixed_point_incompleteness_is_bounded_per_category() {
        const ROWS: usize = 40;
        // Two-byte characters after a five-byte label, so the 108-byte reason
        // cut falls inside a character and must step back to 107.
        let reason = |label: String| format!("({label}){}", "\u{e9}".repeat(1_024));
        let proofs = (0..ROWS)
            .map(|index| ProofStatus::Unproven(reason(format!("r{index:02}")).into()))
            .collect::<Vec<_>>();
        let gaps = (0..ROWS)
            .map(|index| EvidenceCompleteness::Partial(reason(format!("g{index:02}")).into()))
            .collect::<Vec<_>>();
        let limit = SummaryBoundaryKind::Limit(IcfgLimitKind::Nodes);
        let edges = |kind: IcfgEdgeKind| {
            (0..ROWS)
                .map(|index| {
                    coverage_rows::edge(
                        kind,
                        coverage_rows::at("handler.js", index as u64 + 1),
                        &proofs[index],
                        &gaps[index],
                    )
                })
                .collect::<Vec<_>>()
        };
        let mut boundaries = (0..ROWS)
            .map(|index| {
                coverage_rows::boundary(
                    &limit,
                    coverage_rows::at("handler.js", index as u64 + 1),
                    Some(&proofs[index]),
                    Some(&gaps[index]),
                )
            })
            .collect::<Vec<_>>();
        let long_path = format!("{}handler.js", "nested/".repeat(70));
        boundaries[0].location = coverage_rows::at(&long_path, 1);

        let diagnostic = super::taint_incomplete_diagnostic(
            super::SolverTermination::FixedPoint,
            PolicyIncompleteReason::PartialDiscovery,
            edges(IcfgEdgeKind::ExceptionalReturn).into_iter(),
            edges(IcfgEdgeKind::NormalReturn).into_iter(),
            boundaries.into_iter(),
        );
        let message = diagnostic.message();
        assert!(
            message.len() <= super::MAX_REPORT_PROSE_BYTES,
            "{}",
            message.len()
        );
        let totals = "taint analysis is incomplete after reaching a fixed point: 40 unproven edge(s), 40 partial edge(s), and 40 open boundary row(s); ";
        assert!(message.starts_with(totals), "{message}");
        let parts = message[totals.len()..].split("; ").collect::<Vec<_>>();
        assert_eq!(parts.len(), 12, "{parts:#?}");
        let kept = "\u{e9}".repeat(51);
        for (offset, category) in [
            (0, "unproven edge"),
            (4, "partial edge"),
            (8, "open boundary row"),
        ] {
            for (index, row) in parts[offset..offset + 3].iter().enumerate() {
                assert!(row.starts_with(&format!("{category} ")), "{row}");
                assert!(row.len() <= super::FIXED_POINT_ROW_BYTES, "{row}");
                if category == "open boundary row" && index == 0 {
                    assert!(row.contains(&long_path[..100]), "{row}");
                    assert!(row.ends_with(" [truncated]"), "{row}");
                    continue;
                }
                // Both reasons survive, each cut on a char boundary.
                assert!(
                    row.contains(&format!(
                        "proof=unproven ((r{index:02}){kept} [truncated]) completeness=partial ((g{index:02}){kept} [truncated])"
                    )),
                    "{row}"
                );
            }
            assert_eq!(parts[offset + 3], format!("omitted 37 {category}(s)"));
        }
        assert!(!message.contains("(r03)"), "{message}");
        assert_eq!(
            diagnostic.primary(),
            Some(&coverage_rows::at("handler.js", 1))
        );
        // try_new_in_family sorts related locations and keeps one entry per
        // identical location, so nine selected rows here give four entries.
        assert_eq!(
            diagnostic
                .related()
                .iter()
                .map(|related| related.location().clone())
                .collect::<Vec<_>>(),
            vec![
                coverage_rows::at("handler.js", 1),
                coverage_rows::at("handler.js", 2),
                coverage_rows::at("handler.js", 3),
                coverage_rows::at(&long_path, 1),
            ]
        );
    }

    /// Projected coverage rows for the rendering tests (#3644). Projection
    /// needs a workspace and solver-built coverage; rendering reads only
    /// these fields.
    mod coverage_rows {
        use crate::finding::{PolicyByteSpan, PolicyDisplayRegion, PolicySourceLocation};
        use brokk_bifrost_analysis::analyzer::semantic::{
            EvidenceCompleteness, IcfgEdgeKind, ProofStatus, WorkspaceRelativePath,
        };
        use brokk_bifrost_flow::dataflow::SummaryBoundaryKind;

        use super::super::{CoverageRow, CoverageRowKind};

        /// Line `line`, columns 3 to 9, of `path`.
        pub(super) fn at(path: &str, line: u64) -> PolicySourceLocation {
            PolicySourceLocation::span(
                WorkspaceRelativePath::new(path).expect("workspace-relative path"),
                PolicyByteSpan::new(line * 100 + 2, line * 100 + 8).expect("byte span"),
                PolicyDisplayRegion::new(line, 3, line, 9).expect("display region"),
            )
        }

        pub(super) fn edge<'a>(
            kind: IcfgEdgeKind,
            location: PolicySourceLocation,
            proof: &'a ProofStatus,
            completeness: &'a EvidenceCompleteness,
        ) -> CoverageRow<'a> {
            row(
                CoverageRowKind::Edge(kind),
                location,
                Some(proof),
                Some(completeness),
            )
        }

        pub(super) fn boundary<'a>(
            kind: &'a SummaryBoundaryKind,
            location: PolicySourceLocation,
            proof: Option<&'a ProofStatus>,
            completeness: Option<&'a EvidenceCompleteness>,
        ) -> CoverageRow<'a> {
            row(
                CoverageRowKind::Boundary { kind, target: None },
                location,
                proof,
                completeness,
            )
        }

        fn row<'a>(
            kind: CoverageRowKind<'a>,
            location: PolicySourceLocation,
            proof: Option<&'a ProofStatus>,
            completeness: Option<&'a EvidenceCompleteness>,
        ) -> CoverageRow<'a> {
            CoverageRow {
                location,
                kind,
                origin: None,
                proof,
                completeness,
                provenance: &[],
            }
        }
    }

    #[test]
    fn barriers_execute_icfg_in_a_real_policy_run() {
        let baseline = engine_runs(COMPOSED_SOURCE, "optimistic");
        assert_eq!(baseline[1].0.as_deref(), Some("icfg (store-ends)"));
        assert!(!matches!(
            baseline[1].1,
            PolicyRunCompletion::Unsupported { .. }
        ));
        assert!(!baseline[1].2.is_empty());
        let policy = COMPOSED_POLICY.replacen(
            ":sources",
            r#":barriers (endpoint-set :entries [
            (barrier :id boolean :value-type (intrinsic bool))]) :sources"#,
            1,
        );
        let runs = engine_runs_of(&policy, COMPOSED_SOURCE, "optimistic");
        let icfg = &runs[1];
        assert_eq!(icfg.0.as_deref(), Some("icfg (store-ends)"));
        assert!(
            !matches!(
                icfg.1,
                PolicyRunCompletion::Unsupported { .. } | PolicyRunCompletion::Failed { .. }
            ),
            "{icfg:?}"
        );
        assert!(
            !icfg.2.is_empty(),
            "String flow survives value-type barriers: {icfg:?}"
        );
    }

    #[test]
    fn barriers_keep_an_unknown_type_finding_with_observation_notes() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"unknown_barrier\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "fn sink(_: Missing) {}\npub fn retained(secret: Missing) { sink(secret); }\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let options =
            PolicyEvaluationOptions::new(PolicyEvaluationDate::from_ymd(2026, 10, 14).unwrap());
        let policy = FORMAL_CARRIER_POLICY.replacen(
            ":sources",
            r#":barriers (endpoint-set :entries [
            (barrier :id boolean :value-type (intrinsic bool))
            (barrier :id fieldless :value-type (enum :fieldless true))]) :sources"#,
            1,
        );
        for (identity, policy) in [
            ("baseline", FORMAL_CARRIER_POLICY),
            ("barriers", policy.as_str()),
        ] {
            let outcome = evaluate_policy_source(
                project.root(),
                PolicySourceIdentity::new(format!("test:unknown-{identity}.rqlp")),
                policy,
                &workspace,
                &brokk_bifrost_flow::FlowWorkspaceState::new(),
                &options,
                None,
            )
            .expect("unknown type does not prevent taint evaluation");
            let [run] = outcome.report().runs() else {
                panic!("one policy run")
            };
            assert_eq!(run.findings().len(), 1, "{identity}: {run:?}");
            let notes = run.findings()[0].value_type_barrier_notes().entries();
            if identity == "baseline" {
                assert!(notes.is_empty());
            } else {
                assert!(
                    !notes.is_empty(),
                    "unknown-only witness needs notes: {run:?}"
                );
                assert!(
                    notes.iter().all(|note| note
                        .location()
                        .region()
                        .is_some_and(|region| region.start_line() == 2)),
                    "{notes:?}"
                );
                assert!(notes.iter().any(|note| note.barrier_id() == "boolean"));
                assert!(notes.iter().any(|note| note.barrier_id() == "fieldless"));
            }
        }
    }

    #[test]
    fn unsupported_barrier_languages_have_structured_diagnostics() {
        let payload = super::prepared_compile_failure_payload(super::TaintPolicyCompileFailure {
            error: super::TaintPolicyCompileError::UnsupportedBarrierEngine(
                "language:python".into(),
            ),
            work: PolicyWorkReport::default(),
        });
        assert!(matches!(
            payload.completion,
            PolicyRunCompletion::Unsupported { .. }
        ));
        assert!(payload.projections.is_empty());
        let diagnostic = &payload.diagnostics[0];
        assert_eq!(
            diagnostic.code(),
            &super::PolicyDiagnosticCode::UnsupportedAnalysis
        );
        assert_eq!(
            diagnostic.impact(),
            super::PolicyDiagnosticImpact::RunUnsupported
        );
        assert!(diagnostic.message().contains("ICFG"));
    }

    #[test]
    #[hardwon("#2779: overlong failure detail erased the refusal explanation")]
    fn an_oversized_compile_failure_detail_still_names_the_refusal() {
        // #2779: the xss category refused all 455 cases with an empty
        // diagnostics list because the QueryIncomplete detail (which joins
        // every underlying query diagnostic) exceeded the report prose bound
        // and the payload's only diagnostic was dropped by `.ok()`.
        let failure = super::TaintPolicyCompileFailure {
            error: super::TaintPolicyCompileError::QueryIncomplete {
                completion: super::CodeQueryCompletion::Incomplete { codes: Vec::new() },
                detail: "d".repeat(64 * 1024),
            },
            work: PolicyWorkReport::default(),
        };
        let payload = super::prepared_compile_failure_payload(failure);
        assert!(
            matches!(
                &payload.completion,
                PolicyRunCompletion::Inconclusive { reasons, .. }
                    if reasons.contains(&PolicyIncompleteReason::PartialDiscovery)
            ),
            "{:?}",
            payload.completion
        );
        assert!(
            !payload.diagnostics.is_empty(),
            "an oversized failure detail must not erase the refusal's only explanation"
        );
        assert!(
            payload.diagnostics[0].message().ends_with("[truncated]"),
            "{}",
            payload.diagnostics[0].message()
        );
    }

    #[test]
    #[hardwon("#2738: authored selector summaries could overstate clean coverage")]
    fn authored_selector_summary_caps_only_a_clean_compile() {
        let policy_id = PolicyId::new("test.issue-2714-cap").expect("valid policy id");
        let clean = compiled_payload(
            &policy_id,
            PolicyWorkReport::default(),
            Vec::new(),
            None,
            true,
            Vec::new(),
            |path| path.to_string(),
        );
        assert_eq!(clean.completion, PolicyRunCompletion::ProvenBySummary);

        let refused = compiled_payload(
            &policy_id,
            PolicyWorkReport::default(),
            vec![super::RefusalNotice {
                message: "contract-violating workspace target".to_owned(),
                impact: super::PolicyDiagnosticImpact::RunIncomplete,
            }],
            None,
            true,
            Vec::new(),
            |path| path.to_string(),
        );
        assert!(matches!(
            refused.completion,
            PolicyRunCompletion::Inconclusive { .. }
        ));
    }

    #[test]
    #[hardwon("b1b77f63a031: incomplete selector discovery dropped supported taint results")]
    fn incomplete_selector_preserves_partial_discovery_without_refusal() {
        let policy_id = PolicyId::new("test.issue-3712").expect("valid policy id");
        let payload = compiled_payload(
            &policy_id,
            PolicyWorkReport::default(),
            Vec::new(),
            None,
            false,
            vec![super::IncompleteTaintSelector {
                path: crate::PolicySelectorPath::new("/analysis/sources/entries/input/selector")
                    .expect("valid selector path"),
                message: "selector /analysis/sources/entries/input is incomplete".to_owned(),
                discovery: Vec::new(),
            }],
            |path| path.to_string(),
        );
        assert!(matches!(
            payload.completion,
            PolicyRunCompletion::Inconclusive { ref reasons, .. }
                if reasons == &[PolicyIncompleteReason::PartialDiscovery]
        ));
        assert_eq!(payload.diagnostics.len(), 1);
        assert_eq!(
            payload.diagnostics[0].impact(),
            super::PolicyDiagnosticImpact::RunIncomplete
        );
    }

    /// One taint flow: `source_one` returns attacker input and `sink_one`
    /// consumes it through a nested call, which is a witness of several steps.
    const FIRST_FLOW_SOURCE: &str = "\
def source_one():
    return \"one\"

def sink_one(value):
    pass

def run_one():
    sink_one(source_one())
";

    /// A second, independent flow. It lives in its own file so the compile
    /// discovers a second taint region, and a region is one batch.
    const SECOND_FLOW_SOURCE: &str = "\
def source_one():
    return \"two\"

def sink_one(value):
    pass

def run_two():
    sink_one(source_one())
";

    /// The same per-file region shape with two written sink sites. This is the
    /// focused form of the #2481 XSS assembly failure: before #2544 assigned a
    /// source-ordered ordinal to each sink site, both projections claimed one
    /// strong finding identity and assembly failed with `InternalInvariant`.
    const FANOUT_FLOW_SOURCE: &str = "\
def source_one():
    return \"fanout\"

def sink_one(value):
    pass

def run_fanout():
    value = source_one()
    sink_one(value)
    sink_one(value)
";

    /// A taint policy over the two fixtures above. `report` is the authored
    /// report-option block; passing an empty string keeps the defaults.
    fn two_flow_policy(report: &str) -> String {
        format!(
            r#"(policy
              :schema-version 1
              :id "test.issue-2356"
              :name "Issue 2356 taint"
              :message "tainted value reached sink_one"
              :severity warning
              {report}
              :analysis (analysis
                :type taint
                :mode may
                :call-modeling (call-modeling :unmodeled optimistic)
                :sources (endpoint-set :entries [
                  (source :id first :display-name "first source" :categories [input.user]
                    :selector (rql :schema-version 1
                      (language python (call :callee (name "source_one"))))
                    :bind return-value :labels [untrusted])])
                :sinks (endpoint-set :entries [
                  (sink :id first-store :display-name "first sink" :categories [data.sensitive]
                    :selector (rql :schema-version 1
                      (language python (call :callee (name "sink_one"))))
                    :dangerous-operand (argument :index 0) :accepts [untrusted])]))
              :classification (classification
                :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
        )
    }

    fn two_flow_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        workspace_with_sources(&[
            ("first.py", FIRST_FLOW_SOURCE),
            ("second.py", SECOND_FLOW_SOURCE),
        ])
    }

    fn three_fanout_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        workspace_with_sources(&[
            ("first.py", FANOUT_FLOW_SOURCE),
            ("second.py", FANOUT_FLOW_SOURCE),
            ("third.py", FANOUT_FLOW_SOURCE),
        ])
    }

    fn workspace_with_sources(
        files: &[(&str, &str)],
    ) -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        let project = files
            .iter()
            .fold(InlineTestProject::new(), |project, (path, source)| {
                project.file(*path, *source)
            })
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        (project, analyzer)
    }

    fn assert_findings_lane_exhausted(
        completion: &PolicyRunCompletion,
        diagnostics: &[PolicyDiagnostic],
    ) {
        assert!(
            matches!(
                completion,
                PolicyRunCompletion::Inconclusive { reasons, .. }
                    if reasons.contains(&PolicyIncompleteReason::BatchFindingLimit)
            ),
            "a spent findings lane is typed rather than an invariant: completion={completion:?} diagnostics={diagnostics:?}"
        );
        assert!(
            diagnostics.iter().any(|diagnostic| diagnostic.message()
                == "taint request-wide budget is exhausted: findings"),
            "a diagnostic must name the exhausted lane: {diagnostics:?}"
        );
    }

    fn registry_for(source: &str) -> PolicyRegistry {
        crate::test_support::registry_with_policy(
            "test:issue-2356.rqlp",
            source,
            "the fixture policy loads",
        )
    }

    /// #2356: a request-wide lane that runs out is a budget outcome, not a
    /// broken invariant.
    ///
    /// `remaining_findings` is deliberately request-wide (#2208), so on a
    /// corpus one batch eventually starts with the lane already spent. Before
    /// this fix that batch returned a bare error string, and the caller turned
    /// every policy in it into `Failed { reasons: [InternalInvariant] }` and
    /// replaced the payload, discarding every finding the earlier batches had
    /// already projected. The run must instead stay inconclusive, name the
    /// exhausted lane, and keep those findings.
    #[test]
    #[hardwon(
        "#2356: the budget fix turns request-wide lane exhaustion into typed incompleteness instead of InternalInvariant failure."
    )]
    fn an_exhausted_request_wide_lane_degrades_the_run_instead_of_failing_it() {
        let (_workspace, analyzer) = two_flow_workspace();
        let registry = registry_for(&two_flow_policy(""));
        let budget = PolicyBudget::builder()
            .with_max_findings(1)
            .expect("one finding is inside the host cap")
            .build()
            .expect("a one-finding budget is valid");

        let evaluator = ProductionTaintPolicyEvaluator::prepare(
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            registry.policies(),
            &analyzer,
            Ok(None),
            None,
            &budget,
        );
        let payloads = evaluator
            .prepared
            .lock()
            .expect("taint prepared payloads mutex poisoned");
        let [(_, payload)] = payloads.iter().collect::<Vec<_>>()[..] else {
            panic!("one taint policy produces one payload");
        };

        assert_findings_lane_exhausted(&payload.completion, &payload.diagnostics);
        assert!(
            !payload.projections.is_empty(),
            "the findings the earlier batch already projected must survive"
        );
    }

    /// #2481 end-to-end regression: the historical XSS failure after #2356
    /// was not another kind of budget exhaustion. One source reached several
    /// written sink sites in a procedure, and those sites collided on one
    /// finding identity during assembly. The #2544 site-ordinal repair makes
    /// both findings valid. Once that first region genuinely spends the
    /// request-wide cap, the next region must still take #2356's typed budget
    /// path and preserve the already assembled findings.
    #[test]
    #[hardwon(
        "#2544: the fanout regression preserves distinct sink findings when one source reaches two sinks in one procedure."
    )]
    fn xss_style_fanout_assembles_before_the_findings_lane_exhausts() {
        let (_workspace, analyzer) = three_fanout_workspace();
        let registry = registry_for(&two_flow_policy(""));
        let budget = PolicyBudget::builder()
            .with_max_findings(4)
            .expect("four analysis findings are inside the host cap")
            .build()
            .expect("a four-finding budget is valid");
        let taint = ProductionTaintPolicyEvaluator::prepare(
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            registry.policies(),
            &analyzer,
            Ok(None),
            None,
            &budget,
        );
        let policy = registry.policies().next().expect("one policy");
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::default();
        let context = PolicyEvaluationContext {
            analyzer: analyzer.analyzer(),
            workspace: Some(&analyzer),
            flow_state: &flow_state,
            root_memo: None,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
        };
        let mut evaluation_budget = budget;
        let run = DefaultPolicyEvaluator::new()
            .with_taint(&taint)
            .evaluate(policy, &context, &mut evaluation_budget)
            .expect("the prepared fanout payload assembles");

        assert_findings_lane_exhausted(run.completion(), run.diagnostics());
        assert_eq!(
            run.findings().len(),
            2,
            "both sink sites assembled before the request-wide cap was spent; findings={:?} diagnostics={:?} work={:?}",
            run.findings(),
            run.diagnostics(),
            run.work()
        );
        assert_ne!(
            run.findings()[0].id(),
            run.findings()[1].id(),
            "written sink sites need distinct stable identities"
        );
        assert!(
            run.diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.message()
                    == "taint request-wide budget is exhausted: findings"),
            "the exhausted lane must remain named: {:?}",
            run.diagnostics()
        );
    }

    /// #2356: a witness longer than the effective report limit must truncate,
    /// not take its finding down with it.
    ///
    /// The projection authority validates each witness against the policy's
    /// authored report options capped by the host budget. The taint adapter
    /// projected against the host budget alone, so an authored `max-steps`
    /// below the host cap produced an over-long witness, the authority
    /// rejected the whole envelope, and the finding was lost.
    #[test]
    #[hardwon(
        "#2356: the report fix retains an over-limit witness as a truncated finding instead of failing or dropping it."
    )]
    fn a_witness_over_the_effective_report_limit_truncates_instead_of_dropping_the_finding() {
        let (workspace, analyzer) = two_flow_workspace();
        let source = two_flow_policy(":report (report :witness (witness :max-steps 2))");
        let options = PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 8, 18).expect("fixed evaluation date"),
        );
        let outcome = evaluate_policy_source(
            workspace.root(),
            PolicySourceIdentity::new("test:issue-2356.rqlp"),
            &source,
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &options,
            None,
        )
        .expect("production taint evaluation");

        let [run] = outcome.report().runs() else {
            panic!("one policy produces one run");
        };
        assert!(
            !run.findings().is_empty(),
            "the finding must survive a witness that exceeds the report limit: {:#?}",
            run.diagnostics()
        );
        for finding in run.findings() {
            for witness in finding.witnesses() {
                assert!(
                    witness.steps().len() <= 2,
                    "a projected witness must respect the authored step limit: {witness:#?}"
                );
                assert!(
                    witness.truncated(),
                    "a shortened witness must say so: {witness:#?}"
                );
                assert!(
                    witness.omitted_steps_lower_bound() > 0,
                    "a shortened witness must carry its omitted-step lower bound: {witness:#?}"
                );
            }
        }
    }

    /// A batch that starts after an exhausting predecessor must still be able to
    /// solve.
    ///
    /// The semantic-materialization and IFDS solver ledgers are charged only
    /// inside `solve_and_project_batch`, once per batch. Before #2208 they were
    /// threaded request-wide, so a corpus whose early batches spent the ledgers
    /// left every later batch unable to materialize or propagate and its real
    /// flows abstained by queue position. This test drives the two lanes to
    /// exhaustion, then asserts that the per-batch reset makes the same charge
    /// succeed again, while `remaining_findings` -- the cap on total output, not
    /// on per-batch work -- keeps its running value.
    #[test]
    #[hardwon("#2208: earlier roots drained later per-batch solver budgets")]
    fn per_batch_reset_restores_solve_lanes_without_restoring_the_finding_cap() {
        let budget = PolicyBudget::default();
        let mut execution = TaintExecutionBudget::new(&budget);

        let semantic_limits = execution.semantic.limits();
        let solver_limits = execution.solver.limits();
        execution
            .semantic
            .admit(semantic_limits)
            .expect("a first batch may spend the whole semantic ledger");
        execution
            .solver
            .charge(solver_limits)
            .expect("a first batch may spend the whole solver ledger");
        execution
            .semantic
            .admit(SemanticWork::uniform(1))
            .expect_err("the drained semantic ledger refuses further work");
        execution
            .solver
            .charge(SolverWork::uniform(1))
            .expect_err("the drained solver ledger refuses further work");

        execution.remaining_findings = 3;
        execution.reset_per_batch_solve_budget(&budget);

        execution
            .semantic
            .admit(semantic_limits)
            .expect("the next batch starts from a fresh semantic ledger");
        execution
            .solver
            .charge(solver_limits)
            .expect("the next batch starts from a fresh solver ledger");
        assert_eq!(execution.semantic.limits(), semantic_limits);
        assert_eq!(execution.solver.limits(), solver_limits);
        assert_eq!(
            execution.remaining_findings, 3,
            "the request-wide output cap is not a per-batch lane"
        );
    }

    /// Mutually recursive Python relays. The walk that starts at `head`
    /// reaches `tail`, and `tail` calls back to `head`, so a walk whose oracle
    /// belongs to a different analyzer generation than its root meets `head`
    /// through both materializations of one artifact.
    const TWO_MATERIALIZATION_SOURCE: &str = "\
def head(value):
    return tail(value)

def tail(value):
    return head(value)
";

    /// #2289: the per-compile discovery cache must recognize one procedure
    /// across two materializations of its artifact.
    ///
    /// The complete-artifact cache is byte-bounded, so a large file can be
    /// evicted and re-materialized while one compile is still discovering.
    /// `ProcedureHandle` equality compares the owning `Arc<SemanticArtifact>`
    /// by pointer, so keyed on handles the walk held two unequal handles for
    /// one procedure: it missed the snapshot, dispatch, and binding caches for
    /// the second, re-ran all three oracle calls, re-charged the shared
    /// semantic budget, and pushed a second copy of one snapshot into the
    /// region plan.
    ///
    /// Two analyzers over one project root own separate artifact caches, so
    /// each materializes its own instance of one immutable artifact, which is
    /// the shape an eviction produces inside one compile. Discovering with the
    /// first analyzer's oracle from a root the second materialized reproduces
    /// the pair deterministically: the fixture's recursion back to the root
    /// resolves through the first analyzer's cache.
    #[test]
    #[hardwon(
        "#2289: durable procedure identity must deduplicate discovery across artifact materializations"
    )]
    fn a_procedure_reached_through_two_materializations_is_discovered_once() {
        let workspace = tempfile::tempdir().expect("temporary workspace");
        std::fs::write(
            workspace.path().join("relay.py"),
            TWO_MATERIALIZATION_SOURCE,
        )
        .expect("fixture source");

        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(workspace.path()).expect("fixture project"));
        let config = || AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        };
        let first = WorkspaceAnalyzer::build_ephemeral_footgun(Arc::clone(&project), config())
            .expect("an analyzer over the fixture");
        let second = WorkspaceAnalyzer::build_ephemeral_footgun(project, config())
            .expect("a second analyzer over the fixture");

        let file = first
            .analyzer()
            .get_analyzed_files()
            .into_iter()
            .find(|file| file.rel_path().ends_with("relay.py"))
            .expect("the fixture file is analyzed");

        let materialize = |analyzer: &WorkspaceAnalyzer| -> Arc<SemanticArtifact> {
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("the fixture materializes")
                .available_value()
                .cloned()
                .expect("the fixture artifact is available")
        };
        let head = |artifact: &Arc<SemanticArtifact>| -> ProcedureHandle {
            let procedure = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some("head")
                })
                .expect("the fixture declares head");
            artifact
                .procedure_handle(procedure.id())
                .expect("the selected procedure remains live")
        };

        let first_artifact = materialize(&first);
        let second_artifact = materialize(&second);
        assert_eq!(
            first_artifact.key(),
            second_artifact.key(),
            "both instances must describe one immutable artifact"
        );
        let first_head = head(&first_artifact);
        let second_head = head(&second_artifact);
        assert_ne!(
            first_head, second_head,
            "handle equality is materialization-scoped, which is the precondition this test pins"
        );
        assert_eq!(
            first_head.durable_key(),
            second_head.durable_key(),
            "the durable identity must not depend on which materialization produced the handle"
        );

        // The compiler's oracle belongs to the first analyzer, and the root
        // comes from the second, so the walk necessarily meets both instances.
        let cancellation = CancellationToken::default();
        let mut compiler = TaintPolicyCompiler::new(
            &first,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            CodeQueryExecutionLimits::default(),
            64,
            &cancellation,
        );
        let cache = DiscoveryMaterializationCache::default();
        let discovery = compiler
            .discover_value_flow(&second_head, &std::collections::HashSet::new(), &cache)
            .expect("the fixture closure is discovered");

        assert!(
            cache.handle_identity_reuses.get() > 0,
            "the fixture must actually present a second materialization, \
             otherwise this test proves nothing"
        );
        assert_eq!(
            cache.procedure_misses.get(),
            2,
            "each distinct procedure must reach the oracle once: \
             hits={}, misses={}, handle-identity reuses={}",
            cache.procedure_hits.get(),
            cache.procedure_misses.get(),
            cache.handle_identity_reuses.get()
        );
        assert_eq!(
            discovery.procedures.len(),
            2,
            "the closure holds two distinct procedures, not one per materialization"
        );
        assert_eq!(
            discovery.snapshots.len(),
            2,
            "a duplicated procedure would push its local rules into the plan twice"
        );

        // Every handle the walk produced belongs to one artifact instance, so
        // one region plan never mixes materializations.
        let artifacts = cache.artifacts.borrow();
        let canonical = artifacts
            .get(second_artifact.key())
            .expect("the walk canonicalized the fixture artifact");
        assert!(
            Arc::ptr_eq(canonical, &second_artifact),
            "the first instance the walk saw must stay canonical"
        );
        assert!(
            Arc::ptr_eq(discovery.root.artifact(), canonical),
            "the region root must be anchored to the canonical instance"
        );
        for snapshot in &discovery.snapshots {
            assert!(
                Arc::ptr_eq(snapshot.value().procedure().artifact(), canonical),
                "every retained snapshot must be anchored to the canonical instance"
            );
        }

        // The compile-visible counter tells the same story.
        let report = compiler.selectors.work_report("taint");
        let materializations = report
            .metrics()
            .iter()
            .find(|metric| metric.name() == "taint.semantic_snapshot_materializations")
            .map(|metric| metric.value())
            .expect("discovery reports its snapshot materializations");
        assert_eq!(materializations, 2);
    }

    /// Discovery records the same replayable inputs when its per-compile cache
    /// serves a second region. The second ledger is deliberately separate from
    /// the cold acquisition so a missing cache-hit funnel cannot be hidden by
    /// set deduplication in one request.
    #[test]
    #[hardwon(
        "#2970: the read-ledger fix attributes cached discovery reads to the same cold inputs as the initial materialization."
    )]
    fn discovery_cache_hits_retain_cold_read_attribution() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("relay.py", TWO_MATERIALIZATION_SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let file = workspace
            .analyzer()
            .get_analyzed_files()
            .into_iter()
            .find(|file| file.rel_path().ends_with("relay.py"))
            .expect("the fixture file is analyzed");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("the fixture materializes")
            .available_value()
            .cloned()
            .expect("the fixture artifact is available");
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
                    == Some("head")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("the fixture declares head");
        let mut compiler = TaintPolicyCompiler::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            CodeQueryExecutionLimits::default(),
            64,
            &cancellation,
        );
        let cache = DiscoveryMaterializationCache::default();
        let cold = Arc::new(ReadLedger::new());
        {
            let _scope =
                AnalyzerQueryScope::with_read_ledger(workspace.analyzer(), Arc::clone(&cold));
            compiler
                .discover_value_flow(&root, &std::collections::HashSet::new(), &cache)
                .expect("the cold closure is discovered");
        }
        let cold_misses = cache.procedure_misses.get();
        compiler.selectors.reset_region_semantic_budget();
        let warm = Arc::new(ReadLedger::new());
        {
            let _scope =
                AnalyzerQueryScope::with_read_ledger(workspace.analyzer(), Arc::clone(&warm));
            compiler
                .discover_value_flow(&root, &std::collections::HashSet::new(), &cache)
                .expect("the cached closure is discovered");
        }
        let semantic_keys = |ledger: &ReadLedger| {
            ledger
                .keys()
                .into_iter()
                .filter(|key| {
                    matches!(
                        key,
                        ReadKey::Artifact { .. } | ReadKey::Lookup {
                            kind:
                                brokk_bifrost_analysis::analyzer::read_ledger::LookupKind::ProcedureDispatch,
                            ..
                        }
                    )
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        let cold_keys = semantic_keys(&cold);
        let warm_keys = semantic_keys(&warm);
        assert!(
            !cold_keys.is_empty(),
            "cold discovery must name semantic inputs"
        );
        assert!(
            cold_keys
                .iter()
                .any(|key| matches!(key, ReadKey::Artifact { .. })),
            "cold discovery must name semantic artifacts"
        );
        assert!(
            cold_keys.iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::ProcedureDispatch,
                    ..
                }
            )),
            "cold discovery must name dispatch answers"
        );
        assert_eq!(cold.unattributed_reads(), 0);
        assert_eq!(warm.unattributed_reads(), 0);
        assert!(
            cache.procedure_hits.get() > 0,
            "the second closure must exercise cached procedure snapshots"
        );
        assert_eq!(
            cache.procedure_misses.get(),
            cold_misses,
            "warm discovery must not rematerialize cached procedures"
        );
        assert_eq!(warm_keys, cold_keys, "cache hits must name the cold inputs");
    }

    /// A relay chain in one file. Every procedure in it is a compile root, and
    /// every root's forward closure reaches the same one file, so one compile
    /// materializes that file from many roots and many call sites.
    const MANY_ROOT_RELAY_SOURCE: &str = "\
def source_one():
    return \"one\"

def sink_one(value):
    pass

def relay_0(value):
    sink_one(value)

def relay_1(value):
    relay_0(value)

def relay_2(value):
    relay_1(value)

def relay_3(value):
    relay_2(value)

def relay_4(value):
    relay_3(value)

def relay_5(value):
    relay_4(value)

def relay_6(value):
    relay_5(value)

def relay_7(value):
    relay_6(value)

def entry_0():
    relay_7(source_one())
";

    /// #2295: a semantic budget of the order of one materialization of a file
    /// admits a compile that reaches that file from every one of its roots.
    ///
    /// The compile calls `WorkspaceAnalyzer::materialize_program_semantics` once
    /// for each declaration group each call site resolves into, and a
    /// complete-artifact cache hit used to be charged the whole file's retained
    /// census. A budget sized for the material the compile actually holds was
    /// therefore exhausted by the second or third call site, and the compile
    /// abstained on work it had already paid for. The budget now pays one census
    /// per scope, so the same budget carries the whole walk.
    ///
    /// The budget is derived from the artifact, not guessed: `SCALE` times the
    /// largest row lane of the file's own census. The second half of the test
    /// pins that this really is a tight budget -- half of one census cannot even
    /// materialize the file once -- so the first half cannot pass on slack.
    #[test]
    #[hardwon(
        "#2295: one artifact census must fund every root that reaches the same materialized file"
    )]
    fn a_budget_sized_for_one_materialization_admits_every_root() {
        /// One census for the material, plus headroom for the compile's own
        /// value-flow walk over it, which #2289 measured as linear in the
        /// number of procedures.
        const SCALE: usize = 4;

        let workspace_dir = tempfile::tempdir().expect("temporary workspace");
        std::fs::write(
            workspace_dir.path().join("relay.py"),
            MANY_ROOT_RELAY_SOURCE,
        )
        .expect("fixture source");
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(workspace_dir.path()).expect("fixture project"));
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
        )
        .expect("an analyzer over the fixture");

        let file = workspace
            .analyzer()
            .get_analyzed_files()
            .into_iter()
            .find(|file| file.rel_path().ends_with("relay.py"))
            .expect("the fixture file is analyzed");
        let cancellation = CancellationToken::default();
        let mut warming_budget = SemanticBudget::default();
        let artifact: Arc<SemanticArtifact> = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut warming_budget, &cancellation),
            )
            .expect("the fixture materializes")
            .available_value()
            .cloned()
            .expect("the fixture artifact is available");
        let census = artifact.work();
        let largest_row_lane = [
            census.procedures,
            census.blocks,
            census.program_points,
            census.values,
            census.allocations,
            census.call_sites,
            census.memory_locations,
            census.captures,
            census.source_mappings,
            census.evidence,
            census.gaps,
            census.events,
            census.control_edges,
            census.nested_entries,
        ]
        .into_iter()
        .max()
        .expect("the census has row lanes");
        assert!(
            largest_row_lane > 1,
            "the fixture must retain enough rows for a census-sized budget to mean something"
        );

        let roots = artifact
            .procedures()
            .iter()
            .map(|procedure| {
                artifact
                    .procedure_handle(procedure.id())
                    .expect("the selected procedure remains live")
            })
            .collect::<Vec<_>>();
        assert!(
            roots.len() >= 8,
            "the fixture must present many roots over one artifact, got {}",
            roots.len()
        );

        let limits = |max_rows_per_dimension: usize| CodeQueryExecutionLimits {
            semantic: CodeQuerySemanticLimits {
                max_rows_per_dimension,
                ..CodeQuerySemanticLimits::default()
            },
            ..CodeQueryExecutionLimits::default()
        };

        // Sized for the file's own material: every root discovers.
        let mut compiler = TaintPolicyCompiler::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            limits(largest_row_lane.saturating_mul(SCALE)),
            64,
            &cancellation,
        );
        let cache = DiscoveryMaterializationCache::default();
        for root in &roots {
            compiler.discover_value_flow(root, &std::collections::HashSet::new(), &cache).unwrap_or_else(|error| {
                panic!(
                    "a budget of {SCALE} times the {largest_row_lane}-row census must carry every \
                     root's discovery, failed at {:?}: {error:?}",
                    root.semantics().locator()
                )
            });
        }

        // The budget above is a tight one, not a generous one: the whole walk
        // charged well under half of what one census per root would have cost.
        // Measured at 971 against a 846-row census over 11 roots; charged once
        // per call site the same walk charged about 8,460.
        let used = compiler.selectors.semantic_used();
        assert!(
            used.nested_entries.saturating_mul(2)
                < census.nested_entries.saturating_mul(roots.len()),
            "the walk must charge one census per scope, not one per root: \
             charged {} against a census of {} over {} roots",
            used.nested_entries,
            census.nested_entries,
            roots.len()
        );
    }

    /// One value-flow fixture: `read` establishes the tracked value, `put`
    /// observes it, and `validate` is the kill.
    const FLOW_FIXTURE_SOURCE: &str = "\
def read():
    return \"raw\"

def validate(value):
    return value

def put(value):
    pass

def direct():
    put(validate(read()))
";

    const RECEIVER_SANITIZER_SOURCE: &str = r#"
use std::string::String;

fn source(value: String) -> String {
    value
}

fn sink(_: String) {}

fn run(input: String) {
    let value: String = source(input);
    let cleaned: String = value.replace("\r", "");
    sink(cleaned);
}
"#;

    fn named_rust_type(name: &str) -> serde_json::Value {
        serde_json::json!({
            "kind": "named",
            "name": name,
            "arguments": [],
            "nullable": false
        })
    }

    fn compile_receiver_sanitizer_pack(
        pack_id: &str,
        shard_id: &str,
        payload: serde_json::Value,
    ) -> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
        let source = serde_json::to_vec(&serde_json::json!({
            "schema_version": 2,
            "pack_id": pack_id,
            "version": "1.0.0",
            "producer": { "name": "bifrost-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": {
                "bifrost": ">=0.12.0, <1.0.0",
                "toolchains": []
            },
            "provenance": { "source": "test:inline", "revision": "receiver-sanitizer" },
            "license": "Apache-2.0",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": shard_id,
                "activation": [{
                    "targets": [],
                    "configurations": []
                }],
                "payload": payload
            }]
        }))
        .expect("receiver sanitizer semantic pack serializes");
        compile_source(SourceFormat::Json, &source, &CompilerOptions::default()).unwrap_or_else(
            |diagnostics| panic!("receiver sanitizer semantic pack compiles: {diagnostics:#?}"),
        )
    }

    fn receiver_sanitizer_declaration_pack()
    -> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
        compile_receiver_sanitizer_pack(
            "test.receiver-sanitizer-declarations",
            "declarations.string",
            serde_json::json!({
                "kind": "declaration_facts",
                "types": [
                    {
                        "id": "type.rust-codeql.std",
                        "name": "std",
                        "type_kind": "module",
                        "visibility": "public",
                        "locator": {
                            "kind": "artifact",
                            "path": "library/std/src/lib.rs",
                            "symbol": "std"
                        }
                    },
                    {
                        "id": "type.rust-codeql.std-string",
                        "name": "std.string",
                        "type_kind": "module",
                        "visibility": "public",
                        "locator": {
                            "kind": "artifact",
                            "path": "library/alloc/src/lib.rs",
                            "symbol": "std.string"
                        }
                    },
                    {
                        "id": "type.rust-codeql.std-string-string",
                        "name": "std.string.String",
                        "type_kind": "struct",
                        "visibility": "public",
                        "locator": {
                            "kind": "artifact",
                            "path": "library/alloc/src/string.rs",
                            "symbol": "std.string.String"
                        }
                    }
                ],
                "members": [{
                    "id": "member.rust-codeql.std-string-string-replace",
                    "owner": "type.rust-codeql.std-string-string",
                    "name": "replace",
                    "member_kind": "method",
                    "visibility": "public",
                    "is_static": false,
                    "callable_family_complete": true,
                    "signature": {
                        "parameters": [
                            { "name": "pattern", "type": named_rust_type("untyped") },
                            { "name": "replacement", "type": named_rust_type("untyped") }
                        ],
                        "returns": named_rust_type("std.string.String")
                    },
                    "aliases": [],
                    "locator": {
                        "kind": "artifact",
                        "path": "library/alloc/src/string.rs",
                        "symbol": "std.string.String.replace"
                    }
                }],
                "relations": []
            }),
        )
    }

    fn receiver_sanitizer_summary_pack()
    -> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
        compile_receiver_sanitizer_pack(
            "test.receiver-sanitizer-summaries",
            "summaries.string",
            serde_json::json!({
                "kind": "procedure_summaries",
                "summaries": [{
                    "id": "summary.rust-codeql.std-string-string-replace",
                    "target": {
                        "path": "library/alloc/src/string.rs",
                        "symbol": "std.string.String.replace",
                        "has_receiver": true,
                        "parameter_count": 2
                    },
                    "completeness": "complete",
                    "covers_overrides": true,
                    "locations": [],
                    "transfers": [{
                        "input": { "kind": "receiver" },
                        "exit_kind": "normal",
                        "output": { "kind": "normal_return" }
                    }],
                    "effects": []
                }]
            }),
        )
    }

    const RECEIVER_SANITIZER_POLICY: &str = r#"(policy
      :schema-version 1
      :id "test.receiver-sanitizer"
      :name "Receiver sanitizer"
      :message "tainted data reached sink"
      :severity warning
      :analysis (analysis
        :type taint
        :mode may
        :call-modeling (call-modeling :unmodeled optimistic)
        :sources (endpoint-set :entries [
          (source :id raw-input :display-name "raw input" :categories [input.user]
            :selector (rql :schema-version 1
              (language rust (call :callee (name "source"))))
            :bind return-value :labels [attacker-controlled])])
        :sinks (endpoint-set :entries [
          (sink :id sink :display-name "sink" :categories [data.sensitive]
            :selector (rql :schema-version 1
              (language rust (call :callee (name "sink"))))
            :dangerous-operand (argument :index 0)
            :accepts [attacker-controlled])])
        :sanitizers (endpoint-set :entries [
          (sanitizer :id clean
            :selector (rql :schema-version 1
              (language rust
                (call-argument :formal-index 0
                  (resolved-call :resolves-to "std.string.String.replace" :proof declared
                    (call-bindings
                      (call-shape
                        (call :callee (name "replace") :args [
                          (string_literal (text/regex "^\\\"\\\\r\\\"$"))
                          (string_literal (text/regex "^\\\"\\\"$"))])))))))
            :input receiver
            :output return-value
            :removes [attacker-controlled])])))"#;

    #[test]
    fn receiver_input_sanitizer_compiles_against_a_small_fixture() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", RECEIVER_SANITIZER_SOURCE)
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("open an ephemeral semantic-pack catalog");
        for (pack, source_id) in [
            (
                receiver_sanitizer_declaration_pack(),
                "test:receiver-sanitizer-declarations",
            ),
            (
                receiver_sanitizer_summary_pack(),
                "test:receiver-sanitizer-summaries",
            ),
        ] {
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: source_id.to_owned(),
                    },
                )
                .expect("register receiver sanitizer pack");
        }
        let request = SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: env!("CARGO_PKG_VERSION")
                .parse()
                .expect("test Bifrost version parses"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "rust".to_owned(),
                ecosystem: "cargo".to_owned(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: Default::default(),
        };
        let outcome = evaluate_policy_inputs_with_analyzer_and_semantic_models(
            project.root(),
            &[PolicyEvaluationInput::embedded(
                PolicySourceIdentity::new("test:receiver-sanitizer.rqlp"),
                RECEIVER_SANITIZER_POLICY,
            )],
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            &PolicyEvaluationOptions::new(
                PolicyEvaluationDate::from_ymd(2026, 10, 2).expect("fixed evaluation date"),
            ),
            PolicySemanticModelContext {
                catalog: &catalog,
                request: &request,
                persistence: None,
            },
            None,
        )
        .expect("receiver sanitizer policy evaluates");
        assert!(
            !outcome.report().runs().is_empty(),
            "the policy produces runs: rules={}, diagnostics={:?}",
            outcome.report().rules().len(),
            outcome.report().diagnostics()
        );
        for run in outcome.report().runs() {
            assert!(
                !matches!(run.completion(), PolicyRunCompletion::Failed { .. }),
                "receiver sanitizer binding must compile: completion={:?}, diagnostics={:?}",
                run.completion(),
                run.diagnostics()
            );
        }
    }

    /// A flow policy over the fixture above. `kill_callee` names the procedure
    /// whose returned value no longer carries the tracked provenance, so two
    /// policies that differ only in it have different propagation semantics.
    fn flow_policy(id: &str, kill_callee: &str) -> String {
        format!(
            r#"(policy
              :schema-version 1
              :id "{id}"
              :name "Generic value flow"
              :message "the tracked value reached put"
              :severity warning
              :analysis (analysis
                :type flow
                :mode may
                :call-modeling (call-modeling :unmodeled optimistic)
                :origins (endpoint-set :entries [
                  (origin :id raw-input :display-name "read"
                    :selector (rql :schema-version 1
                      (language python (call :callee (name "read"))))
                    :bind return-value)])
                :observations (endpoint-set :entries [
                  (observation :id store-put :display-name "put"
                    :selector (rql :schema-version 1
                      (language python (call :callee (name "put"))))
                    :observed-operand (argument :index 0))])
                :kills (endpoint-set :entries [
                  (kill :id validated
                    :selector (rql :schema-version 1
                      (language python (call :callee (name "{kill_callee}"))))
                    :input (argument :index 0)
                    :output return-value)])))"#
        )
    }

    fn flow_workspace() -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        python_workspace(FLOW_FIXTURE_SOURCE)
    }

    fn python_workspace(source: &str) -> (BuiltInlineTestProject, WorkspaceAnalyzer) {
        workspace_with_sources(&[("flow.py", source)])
    }

    fn registry_for_sources(sources: &[(&str, &str)]) -> PolicyRegistry {
        crate::test_support::registry_with_policies(sources, "the fixture policy loads")
    }

    fn shared_memberships(work: &PolicyWorkReport) -> u64 {
        work.metrics()
            .iter()
            .find(|metric| metric.name() == "taint.propagation_shared_memberships")
            .map_or(0, PolicyWorkMetric::value)
    }

    /// The metric *name* set one policy publishes must be a function of the
    /// policy family, never of the workspace it ran over.
    ///
    /// `PolicyWorkReport::retained_size` sums metric name capacities and feeds
    /// `PolicyRun`'s, and the evaluator's retention search picks how many
    /// findings a run keeps from that size. A name that appeared only once its
    /// counter moved would therefore let the input data decide which findings
    /// a run at the retention boundary keeps, which would violate the contract
    /// that incremental and full evaluations produce byte-identical reports.
    #[test]
    #[hardwon(
        "#2659: the metric-schema fix publishes the same fields for solved and unbound runs, eliminating slice-dependent output shape."
    )]
    fn one_flow_policy_publishes_the_same_metric_names_over_every_workspace() {
        let work_for = |source: &str| {
            let (_workspace, analyzer) = python_workspace(source);
            let registry =
                registry_for_sources(&[("test:flow.rqlp", &flow_policy("test.flow", "validate"))]);
            let evaluator = ProductionTaintPolicyEvaluator::prepare(
                &brokk_bifrost_flow::FlowWorkspaceState::default(),
                registry.policies(),
                &analyzer,
                Ok(None),
                None,
                &PolicyBudget::default(),
            );
            let payloads = evaluator
                .prepared
                .lock()
                .expect("taint prepared payloads mutex poisoned");
            let [(_, payload)] = payloads.iter().collect::<Vec<_>>()[..] else {
                panic!(
                    "one flow policy produces one payload, got {}",
                    payloads.len()
                );
            };
            payload.work.clone()
        };

        // The fixture binds both endpoints and reaches the observation, so the
        // batch is solved and the semantic counters move. The second workspace
        // declares neither endpoint, so nothing is bound and nothing is solved.
        let solved = work_for(FLOW_FIXTURE_SOURCE);
        let unbound = work_for("def unrelated(value):\n    return value\n");

        let names = |work: &PolicyWorkReport| {
            let mut names = work
                .metrics()
                .iter()
                .map(|metric| metric.name().to_owned())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        assert_eq!(names(&solved), names(&unbound), "{solved:#?}\n{unbound:#?}");

        // The two runs really did different work, so the equality above is not
        // two identically empty reports agreeing with each other.
        let value = |work: &PolicyWorkReport, name: &str| {
            work.metrics()
                .iter()
                .find(|metric| metric.name() == name)
                .unwrap_or_else(|| panic!("{name} is published: {work:#?}"))
                .value()
        };
        assert_eq!(value(&solved, "taint.propagation_solves"), 1);
        assert_eq!(value(&unbound, "taint.propagation_solves"), 0);
        assert!(value(&solved, "taint.compiled_source_endpoints") > 0);
        assert_eq!(value(&unbound, "taint.compiled_source_endpoints"), 0);
        // Previously conditional (#2284, #2289): published now even at zero.
        for name in [
            "taint.semantic_snapshot_materializations",
            "taint.semantic_handle_identity_reuses",
            "taint.semantic_result_contract_artifact_leases",
            "taint.propagation_shared_memberships",
        ] {
            assert_eq!(value(&unbound, name), 0, "{unbound:#?}");
        }
    }

    /// Kills change propagation, so two policies with different active kills
    /// must not share a solve. `direct` calls `validate` so the first policy
    /// binds a kill; the second policy selects `read()`, whose missing argument
    /// is refused Advisory, leaving it with no kill. Without the kill semantics
    /// in the batch compatibility key these plans would collide.
    #[test]
    fn flow_policies_with_different_kills_do_not_share_a_solve() {
        let (_workspace, analyzer) = flow_workspace();
        let registry = registry_for_sources(&[
            ("test:flow-a.rqlp", &flow_policy("test.flow-a", "validate")),
            ("test:flow-c.rqlp", &flow_policy("test.flow-c", "read")),
        ]);
        let evaluator = ProductionTaintPolicyEvaluator::prepare(
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            registry.policies(),
            &analyzer,
            Ok(None),
            None,
            &PolicyBudget::default(),
        );
        let payloads = evaluator
            .prepared
            .lock()
            .expect("taint prepared payloads mutex poisoned");
        assert_eq!(payloads.len(), 2);
        for (policy_id, payload) in payloads.iter() {
            assert!(
                !matches!(payload.completion, PolicyRunCompletion::Failed { .. }),
                "{policy_id} must not fail because an incompatible policy exists: {:#?}",
                payload.completion
            );
            assert_eq!(
                shared_memberships(&payload.work),
                0,
                "{policy_id} must not share a solve with an incompatible policy: {:#?}",
                payload.work
            );
        }
    }

    /// #3686: only a flow candidate question runs a candidate pass. An
    /// ordinary run runs none, so normal scans pay no candidate cost. A reached
    /// candidate runs one pass; a killed negative runs the authored pass and
    /// the kill-free pass; and an execution limit of one stops after the
    /// authored pass. The route's acceptance tests over the P0 reference
    /// trees live in the root suite (`policy_flow_candidate.rs`).
    #[test]
    fn flow_candidate_passes_run_only_for_a_candidate_question() {
        use crate::explain::{
            ExplanationCandidate, ExplanationLimits, ExplanationOutcome, FlowExplanationCandidate,
            explain_flow_candidate,
        };

        let (workspace, analyzer) = python_workspace(FLOW_CANDIDATE_SOURCE);
        let source = flow_policy("test.flow-candidate", "validate");
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::default();

        let before = super::candidate::candidate_passes_for_test();
        let outcome = evaluate_policy_source(
            workspace.root(),
            PolicySourceIdentity::new("test:flow-candidate.rqlp"),
            &source,
            &analyzer,
            &flow_state,
            &PolicyEvaluationOptions::new(
                PolicyEvaluationDate::from_ymd(2026, 10, 2).expect("fixed evaluation date"),
            ),
            None,
        )
        .expect("the ordinary run evaluates");
        assert_eq!(
            super::candidate::candidate_passes_for_test(),
            before,
            "an ordinary policy run must not run a candidate pass"
        );
        let [run] = outcome.report().runs() else {
            panic!("one policy produces one run");
        };
        assert_eq!(
            run.findings().len(),
            1,
            "only `direct` reaches put: {:#?}",
            run.findings()
        );

        let registry = registry_for_sources(&[("test:flow-candidate.rqlp", &source)]);
        let policy = registry.policies().next().expect("one loaded policy");
        let context = PolicyEvaluationContext {
            analyzer: analyzer.analyzer(),
            workspace: Some(&analyzer),
            flow_state: &flow_state,
            root_memo: None,
            cancellation: None,
            cvss_overlays: &[],
            organizational_risk: &[],
            incremental: None,
        };
        // The origin is the `read()` call inside each observed `put(...)`.
        let candidate = |observation: &str, origin_offset: usize| {
            let start = FLOW_CANDIDATE_SOURCE
                .find(observation)
                .expect("the fixture holds the observation");
            let origin = start + origin_offset;
            FlowExplanationCandidate::new(
                ExplanationCandidate::in_range(
                    "flow.py",
                    origin as u64,
                    (origin + "read()".len()) as u64,
                )
                .expect("a workspace-relative origin"),
                ExplanationCandidate::in_range(
                    "flow.py",
                    start as u64,
                    (start + observation.len()) as u64,
                )
                .expect("a workspace-relative observation"),
            )
        };
        let reached = candidate("put(read())", "put(".len());
        let killed = candidate("put(validate(read()))", "put(validate(".len());
        let explain = |candidate: &FlowExplanationCandidate, limits: &ExplanationLimits| {
            let before = super::candidate::candidate_passes_for_test();
            let explanation = explain_flow_candidate(
                policy,
                &context,
                candidate,
                &PolicyBudget::default(),
                limits,
            )
            .expect("the candidate explains");
            (
                explanation,
                super::candidate::candidate_passes_for_test() - before,
            )
        };
        let attribution = |explanation: &crate::explain::PolicyExplanation| {
            explanation
                .root()
                .children()
                .iter()
                .find(|node| node.label() == "kill_attribution")
                .map(|node| node.outcome())
        };

        let limits = ExplanationLimits::default();
        let (explanation, passes) = explain(&reached, &limits);
        assert_eq!(
            explanation.outcome(),
            ExplanationOutcome::Satisfied,
            "{explanation:#?}"
        );
        assert_eq!(passes, 1, "a reached candidate needs one production pass");

        let (explanation, passes) = explain(&killed, &limits);
        assert_eq!(
            explanation.outcome(),
            ExplanationOutcome::Failed,
            "{explanation:#?}"
        );
        assert_eq!(
            attribution(&explanation),
            Some(ExplanationOutcome::Satisfied),
            "{explanation:#?}"
        );
        assert_eq!(passes, 2, "the authored pass and the kill-free pass");

        let (explanation, passes) = explain(&killed, &limits.with_max_prefix_executions(1));
        assert_eq!(
            explanation.outcome(),
            ExplanationOutcome::Failed,
            "{explanation:#?}"
        );
        assert_eq!(
            attribution(&explanation),
            Some(ExplanationOutcome::Unknown),
            "{explanation:#?}"
        );
        assert_eq!(
            passes, 1,
            "an execution limit of one runs the authored pass only"
        );
    }

    /// One origin that reaches `put` directly and one that `validate` kills on
    /// its way there, for the flow candidate pass counts (#3686).
    const FLOW_CANDIDATE_SOURCE: &str = "\
def read():
    return \"raw\"

def validate(value):
    return value

def put(value):
    pass

def direct():
    put(read())

def validated():
    put(validate(read()))
";

    #[test]
    fn a_spent_findings_lane_keeps_a_flow_run_inconclusive() {
        let (_workspace, analyzer) = flow_workspace();
        let registry = registry_for_sources(&[(
            "test:flow-budget.rqlp",
            &flow_policy("test.flow-budget", "validate"),
        )]);
        let budget = PolicyBudget::builder()
            .with_max_findings(0)
            .expect("a zero-finding cap is inside the host cap")
            .build()
            .expect("a zero-finding budget is valid");
        let evaluator = ProductionTaintPolicyEvaluator::prepare(
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            registry.policies(),
            &analyzer,
            Ok(None),
            None,
            &budget,
        );
        let payloads = evaluator
            .prepared
            .lock()
            .expect("taint prepared payloads mutex poisoned");
        let [(_, payload)] = payloads.iter().collect::<Vec<_>>()[..] else {
            panic!("one flow policy produces one payload");
        };
        assert!(
            !matches!(payload.completion, PolicyRunCompletion::Complete),
            "an exhausted findings lane must not report a conclusive clean run: {:#?}",
            payload.completion
        );
    }

    const COMPOSED_SOURCE: &str = r#"fn source() -> String {
    String::new()
}

fn pass_through(value: String) -> String {
    value
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run() {
    let raw = source();
    let moved = pass_through(raw);
    sink(moved);
}
"#;

    const COMPOSED_POLICY: &str = r#"(policy
      :schema-version 1
      :id "test.composed"
      :name "Composed"
      :message "tainted data reached sink"
      :severity warning
      :analysis (analysis
        :type taint
        :mode may
        :call-modeling (call-modeling :unmodeled optimistic)
        :sources (endpoint-set :entries [
          (source :id raw-input :display-name "raw input" :categories [input.user]
            :selector (rql :schema-version 1
              (language rust (call :callee (name "source"))))
            :bind return-value :labels [attacker-controlled])])
        :sinks (endpoint-set :entries [
          (sink :id sink :display-name "sink" :categories [data.sensitive]
            :selector (rql :schema-version 1
              (language rust (call :callee (name "sink"))))
            :dangerous-operand (argument :index 0)
            :accepts [attacker-controlled])])))"#;

    /// The composed policy's engine names of its compiled roots, compiled once
    /// under `identity` on `project`.
    fn compiled_engines(
        project: &BuiltInlineTestProject,
        workspace: &WorkspaceAnalyzer,
        identity: &str,
        source: &str,
    ) -> Vec<TaintEngine> {
        let mut registry = crate::registry::test_registry_for_workspace(project.root());
        let policy = registry
            .register_policy_bytes(PolicySourceIdentity::new(identity), source.as_bytes())
            .expect("the policy registers");
        let spec = policy
            .resolved_taint()
            .expect("the policy is a taint policy");
        let cancellation = CancellationToken::default();
        let compilation = TaintPolicyCompiler::new(
            workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            CodeQueryExecutionLimits::default(),
            64,
            &cancellation,
        )
        .compile(policy, spec)
        .unwrap_or_else(|failure| panic!("the policy compiles: {:?}", failure.error));
        let TaintPolicyCompilation::Plans { roots, .. } = compilation else {
            panic!("the policy compiles to analysis plans");
        };
        roots.into_iter().map(|root| root.engine).collect()
    }

    /// The engine rule is a pure function of the policy and the workspace: the
    /// same policy on the same fixture selects the same engine on every
    /// compile, and adding a store end selects the ICFG engine.
    #[test]
    fn the_engine_rule_is_stable_and_a_store_end_selects_icfg() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", COMPOSED_SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let first = compiled_engines(
            &project,
            &workspace,
            "test:engine-first.rqlp",
            COMPOSED_POLICY,
        );
        let second = compiled_engines(
            &project,
            &workspace,
            "test:engine-second.rqlp",
            COMPOSED_POLICY,
        );
        assert!(
            !first.is_empty()
                && first
                    .iter()
                    .all(|engine| *engine == TaintEngine::Composition),
            "the composed policy selects the composition engine: {first:?}"
        );
        assert_eq!(first, second, "the same policy selects the same engine");

        let with_store = COMPOSED_POLICY.replacen(
            ":sinks",
            ":stores (endpoint-set :entries [(store-write :id put \
               :selector (rql :schema-version 1 (language rust (call :callee (name \"pass_through\")))) \
               :store primary :input (argument :index 0))]) :sinks",
            1,
        );
        let stored = compiled_engines(&project, &workspace, "test:engine-store.rqlp", &with_store);
        assert!(
            !stored.is_empty()
                && stored.iter().all(|engine| {
                    *engine
                        == TaintEngine::Icfg {
                            reason: "store-ends".into(),
                        }
                }),
            "a store end selects the ICFG engine: {stored:?}"
        );
    }

    /// A source reaches a sink across one call. The composition engine finds
    /// the finding from the sink backwards through the callee's stored or
    /// computed partial flows, not from a whole-workspace solve. The same
    /// fixture also runs through the policy evaluator, and its run records the
    /// composition engine.
    #[test]
    fn composition_finds_a_source_that_reaches_a_sink_across_a_call() {
        use super::TaintPolicyCompilation;
        use crate::registry::test_registry_for_workspace;
        use crate::taint_compose_provider::{CompositionMemo, PolicyCompositionProvider};
        use brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudget;
        use brokk_bifrost_analysis::analyzer::semantic::{SemanticBudget, SemanticRequest};
        use brokk_bifrost_flow::taint::compose::{CompositionBudget, compose_taint_batch};

        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", COMPOSED_SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let mut registry = test_registry_for_workspace(project.root());
        let policy = registry
            .register_policy_bytes(
                PolicySourceIdentity::new("test:composed.rqlp"),
                COMPOSED_POLICY.as_bytes(),
            )
            .expect("the composed policy registers");
        let spec = policy
            .resolved_taint()
            .expect("the composed policy is a taint policy");
        let cancellation = CancellationToken::default();
        let compilation = TaintPolicyCompiler::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            CodeQueryExecutionLimits::default(),
            64,
            &cancellation,
        )
        .compile(policy, spec)
        .unwrap_or_else(|failure| panic!("the composed policy compiles: {:?}", failure.error));
        let TaintPolicyCompilation::Plans { roots, .. } = compilation else {
            panic!("the composed policy compiles to analysis plans");
        };
        let [root] = roots.as_slice() else {
            panic!("the composed policy has one root, found {}", roots.len());
        };
        assert_eq!(root.engine, TaintEngine::Composition);
        let plan = root.plan.analysis();

        let cache = DiscoveryMaterializationCache::default();
        let memo = CompositionMemo::default();
        let provider = PolicyCompositionProvider::new(
            &workspace,
            SemanticExecutionBudget::new(usize::MAX),
            &cache,
            plan,
            &root.external_models,
            64,
            super::FrontierEndpointBinder::new(
                TaintPolicyCompiler::new(
                    &workspace,
                    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                    None,
                    CodeQueryExecutionLimits::default(),
                    64,
                    &cancellation,
                ),
                policy,
                spec,
                plan.universe().clone(),
            ),
            &memo,
        );
        let mut budget = SemanticBudget::default();
        let outcome = compose_taint_batch(
            plan,
            &provider,
            CompositionBudget {
                max_procedures: 64,
                max_hops: 4096,
                max_callers_per_procedure: 64,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("the composition runs");
        assert!(
            provider.failure().is_none(),
            "the provider failed: {:?}",
            provider.failure()
        );
        let findings = outcome.report.findings();
        assert_eq!(findings.len(), 1, "one finding is expected: {findings:#?}");
        let sink = plan
            .value_flow()
            .sink(findings[0].sink())
            .expect("the finding names a sink of its plan");
        assert_eq!(
            sink.point()
                .procedure()
                .semantics()
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name()),
            Some("run"),
            "the sink is the call in run"
        );

        let options = PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 10, 9).expect("fixed evaluation date"),
        );
        let outcome = evaluate_policy_source(
            project.root(),
            PolicySourceIdentity::new("test:composed-surface.rqlp"),
            COMPOSED_POLICY,
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &options,
            None,
        )
        .expect("production taint evaluation");
        let [run] = outcome.report().runs() else {
            panic!("one policy produces one run");
        };
        assert_eq!(run.findings().len(), 1, "{:#?}", run.diagnostics());
        assert_eq!(
            run.engine().map(TaintEngine::render).as_deref(),
            Some("composition"),
        );
    }

    #[test]
    #[hardwon(
        "a6f4c6b2ca52: a matched-value sanitizer at a call other than its observation point was not applied"
    )]
    fn composition_applies_a_matched_value_sanitizer_at_a_later_call_use() {
        const SOURCE: &str = r#"fn source() -> String {
    String::new()
}

fn sink(value: String) -> usize {
    value.len()
}

fn clean(value: String) -> String {
    value
}

pub fn run() {
    let raw = source();
    let cleaned = clean(raw);
    sink(cleaned);
}
"#;
        const POLICY: &str = r#"(policy
      :schema-version 1
      :id "test.composed-sanitizer"
      :name "Composed sanitizer"
      :message "tainted data reached sink"
      :severity warning
      :analysis (analysis
        :type taint
        :mode may
        :call-modeling (call-modeling :unmodeled optimistic)
        :sources (endpoint-set :entries [
          (source :id raw-input :display-name "raw input" :categories [input.user]
            :selector (rql :schema-version 1
              (language rust (call :callee (name "source"))))
            :bind return-value :labels [attacker-controlled])])
        :sanitizers (endpoint-set :entries [
          (sanitizer :id clean-value :selector (rql :schema-version 1
              (language rust (occurrences-in :role value_reference :namespace value
                (identifier :name/regex "^cleaned$"))))
            :input matched-value :output matched-value :removes [attacker-controlled])])
        :sinks (endpoint-set :entries [
          (sink :id sink :display-name "sink" :categories [data.sensitive]
            :selector (rql :schema-version 1
              (language rust (call :callee (name "sink"))))
            :dangerous-operand (argument :index 0)
            :accepts [attacker-controlled])])))"#;

        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let outcome = evaluate_policy_source(
            project.root(),
            PolicySourceIdentity::new("test:composed-sanitizer.rqlp"),
            POLICY,
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &PolicyEvaluationOptions::new(
                PolicyEvaluationDate::from_ymd(2026, 10, 12).expect("fixed evaluation date"),
            ),
            None,
        )
        .expect("the sanitizer policy evaluates");
        let [run] = outcome.report().runs() else {
            panic!("one policy produces one run: {:?}", outcome.report());
        };
        assert_eq!(
            run.engine().map(TaintEngine::render).as_deref(),
            Some("composition")
        );
        assert!(
            run.findings().is_empty(),
            "the sanitizer removes the source label: {run:#?}"
        );
    }

    /// `run` passes its source to `std::convert::identity`, which has no body
    /// in the workspace, and logs the result. Only the policy's
    /// unmodeled-call behavior can carry the source across the call.
    const UNMODELED_CALL_SOURCE: &str = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run() {
    let raw = source();
    let moved = std::convert::identity(raw);
    sink(moved);
}
"#;

    /// `run` puts its source in a `vec!` and logs the vector.
    const VEC_MACRO_SOURCE: &str = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run() {
    let raw = source();
    let moved = vec![raw];
    sink(moved);
}
"#;

    /// One run as the engine comparison reads it: the engine, the completion,
    /// each finding's location, certainty and completeness, the distinct
    /// diagnostic families, and every diagnostic message, sorted.
    type EngineRun = (
        Option<String>,
        PolicyRunCompletion,
        Vec<(
            crate::finding::PolicySourceLocation,
            crate::finding::FindingCertainty,
            crate::finding::FindingCompleteness,
        )>,
        Vec<String>,
        Vec<String>,
        Vec<(PolicyDiagnosticSeverity, PolicyDiagnosticImpact, String)>,
    );

    /// `COMPOSED_POLICY` with `:unmodeled behavior` over `source`, evaluated
    /// once on each engine: as written, which selects the composition, and
    /// with an inert store end, which selects the ICFG engine.
    fn engine_runs(source: &str, behavior: &str) -> [EngineRun; 2] {
        engine_runs_of(COMPOSED_POLICY, source, behavior)
    }

    /// `base` with `:unmodeled behavior` over `source`, evaluated once on each
    /// engine as `engine_runs` does.
    fn engine_runs_of(base: &str, source: &str, behavior: &str) -> [EngineRun; 2] {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let composed = base.replacen(
            ":unmodeled optimistic",
            &format!(":unmodeled {behavior}"),
            1,
        );
        let icfg = composed.replacen(
            ":sinks",
            ":stores (endpoint-set :entries [(store-write :id put \
               :selector (rql :schema-version 1 (language rust (call :callee (name \"nothing_here\")))) \
               :store primary :input (argument :index 0))]) :sinks",
            1,
        );
        let options = PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 10, 9).expect("fixed evaluation date"),
        );
        [("composed", composed), ("icfg", icfg)].map(|(name, policy)| {
            let outcome = evaluate_policy_source(
                project.root(),
                PolicySourceIdentity::new(format!("test:{name}-{behavior}.rqlp")),
                &policy,
                &workspace,
                &brokk_bifrost_flow::FlowWorkspaceState::new(),
                &options,
                None,
            )
            .expect("production taint evaluation");
            let [run] = outcome.report().runs() else {
                panic!("one policy produces one run");
            };
            let mut families = run
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.family().to_owned())
                .collect::<Vec<_>>();
            families.sort();
            families.dedup();
            let mut messages = run
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.message().to_owned())
                .collect::<Vec<_>>();
            messages.sort();
            let diagnostics = run
                .diagnostics()
                .iter()
                .map(|diagnostic| {
                    (
                        diagnostic.severity(),
                        diagnostic.impact(),
                        diagnostic.message().to_owned(),
                    )
                })
                .collect();
            (
                run.engine().map(TaintEngine::render),
                run.completion().clone(),
                run.findings()
                    .iter()
                    .map(|finding| {
                        (
                            finding.primary().clone(),
                            finding.certainty().clone(),
                            finding.completeness().clone(),
                        )
                    })
                    .collect(),
                families,
                messages,
                diagnostics,
            )
        })
    }

    /// Assert that both engines select as intended and agree on the
    /// completion and the findings of `source` under every unmodeled-call
    /// behavior. Returns the number of findings under each behavior.
    fn assert_engines_agree_on_every_behavior(source: &str) -> [usize; 3] {
        ["paranoid", "optimistic", "require-model"].map(|behavior| {
            let [composed, icfg] = engine_runs(source, behavior);
            assert_eq!(composed.0.as_deref(), Some("composition"), "{behavior}");
            assert_eq!(icfg.0.as_deref(), Some("icfg (store-ends)"), "{behavior}");
            assert_eq!(
                (&composed.1, &composed.2),
                (&icfg.1, &icfg.2),
                "the engines disagree under {behavior}"
            );
            composed.2.len()
        })
    }

    #[test]
    #[hardwon("#4919: one non-call sink row aborted valid flows in the whole policy")]
    fn both_engines_refuse_a_non_call_sink_row() {
        // The literal shares a procedure with the valid sink. Excluding
        // that whole region would erase the valid sink's finding too.
        let source = COMPOSED_SOURCE
            .replace("let moved = pass_through(raw);", "let moved = raw;")
            .replace(
                "let raw = source();",
                "\"refused_sink\";\n    let raw = source();",
            );
        let policy = COMPOSED_POLICY.replace(
            ":sinks (endpoint-set :entries [",
            r#":sinks (endpoint-set :entries [
              (sink :id non-call :display-name "non-call" :categories [data.sensitive]
                :selector (rql :schema-version 1
                  (language rust (string_literal :text/regex "refused_sink")))
                :dangerous-operand (argument :index 0) :accepts [attacker-controlled])"#,
        );
        for run in engine_runs_of(&policy, &source, "optimistic") {
            assert_eq!(run.2.len(), 1, "valid sink retains its finding: {run:?}");
            assert!(
                matches!(run.1, PolicyRunCompletion::Inconclusive { .. }),
                "refusal leaves the run incomplete: {run:?}"
            );
            assert!(
                run.4
                    .iter()
                    .any(|message| message.contains("selector row at src/lib.rs:")
                        && message.contains("does not identify a semantic call site")),
                "refusal names the row and reason: {run:?}"
            );
        }
    }

    #[test]
    #[hardwon("#4919: one source without a point-sensitive observation aborted valid flows")]
    fn both_engines_refuse_a_source_without_a_value_observation() {
        let source = COMPOSED_SOURCE
            .replace("let moved = pass_through(raw);", "let moved = raw;")
            .replace(
                "let raw = source();",
                "const GAP: &str = \"unobserved_source\";\n    let raw = source();",
            );
        // A nested constant's initializer is selected structurally but is
        // excluded from the surrounding procedure's runtime observations.
        for binding in ["matched-value", "return-value"] {
            let policy = COMPOSED_POLICY.replace(
                ":sources (endpoint-set :entries [",
                &format!(
                    r#":sources (endpoint-set :entries [
                  (source :id gap :display-name "gap" :categories [input.user]
                    :selector (rql :schema-version 1
                      (language rust (string_literal :text/regex "unobserved_source")))
                    :bind {binding} :labels [attacker-controlled])"#
                ),
            );
            for run in engine_runs_of(&policy, &source, "optimistic") {
                assert_eq!(run.2.len(), 1, "valid source retains its finding: {run:?}");
                assert!(
                    matches!(run.1, PolicyRunCompletion::Inconclusive { .. }),
                    "refusal leaves the run incomplete: {run:?}"
                );
                let reason = if binding == "matched-value" {
                    "produced no point-sensitive value observation"
                } else {
                    "does not identify a semantic call site"
                };
                assert!(
                    run.4
                        .iter()
                        .any(|message| message.contains("row at src/lib.rs:")
                            && message.contains(reason)),
                    "refusal names the row and reason: {run:?}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "a2e548b43fb7: six out-of-arity operand refusals made a complete Vector taint run inconclusive"
    )]
    fn missing_operand_with_only_refinement_gaps_is_advisory() {
        const SOURCE: &str = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

fn sink_valid(text: String) -> usize {
    text.len()
}

pub fn run() {
    sink(source());
    sink_valid(source());
}
"#;
        let policy = COMPOSED_POLICY
            .replacen(
                ":dangerous-operand (argument :index 0)",
                ":dangerous-operand (argument :index 3)",
                1,
            )
            .replacen(
                ":accepts [attacker-controlled])])))",
                ":accepts [attacker-controlled])
          (sink :id valid-sink :display-name \"valid sink\" :categories [data.sensitive]
            :selector (rql :schema-version 1
              (language rust (call :callee (name \"sink_valid\"))))
            :dangerous-operand (argument :index 0)
            :accepts [attacker-controlled])])))",
                1,
            );
        let [composed, icfg] = engine_runs_of(&policy, SOURCE, "optimistic");
        for run in [&composed, &icfg] {
            assert_eq!(
                run.1,
                PolicyRunCompletion::Complete,
                "call-target refinement gaps do not imply a dropped operand: {run:#?}"
            );
            assert_eq!(
                run.5.len(),
                1,
                "one advisory diagnostic is emitted: {run:#?}"
            );
            assert_eq!(run.5[0].0, PolicyDiagnosticSeverity::Warning);
            assert_eq!(run.5[0].1, PolicyDiagnosticImpact::Advisory);
            assert!(
                run.5[0]
                    .2
                    .contains("the call's lowering records no unanswered operand gap")
            );
        }
        assert_eq!(
            (&composed.1, &composed.2, &composed.5),
            (&icfg.1, &icfg.2, &icfg.5),
            "the engines agree on advisory missing-operand handling"
        );
    }

    /// `other` contains a one-argument `println!` call selected with an
    /// out-of-range argument port. Its malformed macro arguments leave a
    /// Blocked Values gap at that call point, so the refusal remains
    /// run-incomplete. `run` contains a separate valid sink, and both engines
    /// retain its finding. Before missing operands were refused, binding
    /// aborted the whole compile with `selected call has no argument at index 1`.
    #[test]
    #[hardwon(
        "9ce1a3aecb5a: a selected call without the declared argument aborted the compile instead of being refused"
    )]
    fn both_engines_keep_a_refusal_incomplete_when_the_call_has_a_blocked_values_gap() {
        const OPERAND_SOURCE: &str = r#"fn source() -> String {
    String::new()
}

fn sink(label: usize, text: String) -> usize {
    label + text.len()
}

fn sink_valid(text: String) -> usize {
    text.len()
}

fn other() {
    println!(source());
}

pub fn run() {
    let raw = source();
    sink_valid(raw);
}
"#;
        let policy = COMPOSED_POLICY
            .replacen(
                ":dangerous-operand (argument :index 0)",
                ":dangerous-operand (argument :index 1)",
                1,
            )
            .replacen("(name \"sink\")", "(name \"println\")", 1)
            .replacen(
                ":accepts [attacker-controlled])])))",
                ":accepts [attacker-controlled])
          (sink :id valid-sink :display-name \"valid sink\" :categories [data.sensitive]
            :selector (rql :schema-version 1
              (language rust (call :callee (name \"sink_valid\"))))
            :dangerous-operand (argument :index 0)
            :accepts [attacker-controlled])])))",
                1,
            );
        let [composed, icfg] = engine_runs_of(&policy, OPERAND_SOURCE, "optimistic");
        assert_eq!(composed.0.as_deref(), Some("composition"));
        assert_eq!(icfg.0.as_deref(), Some("icfg (store-ends)"));
        assert_eq!(
            (&composed.1, &composed.2, &composed.3, &composed.4),
            (&icfg.1, &icfg.2, &icfg.3, &icfg.4),
            "the engines disagree on the refused-operand run"
        );
        assert_eq!(
            icfg.1,
            PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::CapabilityIncomplete])
                .expect("a canonical capability reason"),
            "the refusal leaves the run incomplete"
        );
        assert_eq!(
            icfg.2.len(),
            1,
            "the valid sink's flow is reported: {:?}",
            icfg.2
        );
        assert_eq!(
            icfg.5
                .iter()
                .filter(
                    |diagnostic| diagnostic.1 == PolicyDiagnosticImpact::RunIncomplete
                        && diagnostic
                            .2
                            .contains("the call's lowering leaves an unanswered gap at this site")
                )
                .count(),
            1,
            "the call with a lowering gap is refused as incomplete: {:?}",
            icfg.5
        );
    }

    /// `run` holds both sinks the name selector matches: the two-argument
    /// `sink`, which receives the source as argument 1, and the one-argument
    /// `sink1`, which has no argument 1 and is refused. The call-target gap
    /// classifies as a refinement question, so the refusal is advisory. The
    /// flow into `sink` is reported and the composed run is complete. Before, the
    /// composed compile discovered regions and dropped every region holding
    /// `run` (#2308), so the run compiled to no root and failed with "no
    /// analysis root contains both a selected source and sink". An advisory
    /// refusal no longer drops that region from either engine.
    #[test]
    #[hardwon(
        "c3dd2cb6be7f: a refused sink site dropped every sink of its procedure from a composed run"
    )]
    fn a_composed_refusal_drops_its_site_and_keeps_the_procedures_other_sinks() {
        const SAME_PROCEDURE_SOURCE: &str = r#"fn source() -> String {
    String::new()
}

fn sink(label: usize, text: String) -> usize {
    label + text.len()
}

fn sink1(text: String) -> usize {
    text.len()
}

pub fn run() -> usize {
    let raw = source();
    sink(0, raw) + sink1(String::new())
}
"#;
        let policy = COMPOSED_POLICY
            .replacen(
                ":dangerous-operand (argument :index 0)",
                ":dangerous-operand (argument :index 1)",
                1,
            )
            .replacen("(name \"sink\")", "(name/regex \"^sink1?$\")", 1);
        let [composed, icfg] = engine_runs_of(&policy, SAME_PROCEDURE_SOURCE, "optimistic");
        assert_eq!(composed.0.as_deref(), Some("composition"));
        assert_eq!(
            composed.1,
            PolicyRunCompletion::Complete,
            "an answered call-target refinement gap does not degrade the run"
        );
        assert_eq!(
            composed.2.len(),
            1,
            "the flow into the two-argument sink is reported: {:?}",
            composed.2
        );
        assert_eq!(
            composed
                .4
                .iter()
                .filter(
                    |message| message.contains("the port `(argument :index 1)` at")
                        && message.contains("which has 1 argument(s)")
                        && message
                            .contains("the call's lowering records no unanswered operand gap")
                )
                .count(),
            1,
            "the one-argument call is refused with its diagnostic: {:?}",
            composed.4
        );
        assert_eq!(
            icfg.2.len(),
            1,
            "the ICFG engine keeps the advisory region and its valid sink: {:?}",
            icfg.2
        );
    }

    /// `std::format!` leaves `run` open with blocked gaps that no call dispatch
    /// answers in the regression fixture. The composition's diagnostic must
    /// name the family the ICFG engine names for the same procedure.
    #[test]
    #[hardwon(
        "a2f46bafa030: a composed run named a blocked-gap open procedure with a family the ICFG engine does not name"
    )]
    fn composition_names_a_blocked_gap_with_the_icfg_family() {
        const BLOCKED_GAP_SOURCE: &str = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run() {
    let raw = source();
    let moved = std::format!("{}", raw);
    sink(moved);
}
"#;
        let [composed, icfg] = engine_runs(BLOCKED_GAP_SOURCE, "paranoid");
        assert_eq!(composed.0.as_deref(), Some("composition"));
        assert_eq!(icfg.0.as_deref(), Some("icfg (store-ends)"));
        assert_eq!(
            icfg.3,
            ["taint discovery is incomplete: procedure semantics is unknown"],
            "the ICFG engine names one family for this procedure"
        );
        assert!(
            composed.3.iter().all(|family| icfg.3.contains(family)),
            "composed families {:?} are not a subset of the ICFG's {:?}",
            composed.3,
            icfg.3
        );
        assert_eq!((&composed.1, &composed.2), (&icfg.1, &icfg.2));
    }

    /// The composition crosses a call no model covers and no candidate body
    /// answers exactly as the ICFG engine does: paranoid carries the argument
    /// to the result, uncertain; optimistic and require-model carry nothing.
    #[test]
    fn both_engines_cross_an_unmodeled_call_by_the_policy_behavior() {
        assert_eq!(
            assert_engines_agree_on_every_behavior(UNMODELED_CALL_SOURCE),
            [1, 0, 0]
        );
    }

    /// The Rust lowering of `vec!` writes the elements into the call's result
    /// value before the call. Both engines keep that fact across the unmodeled
    /// call, so under optimistic and require-model the composition finds the
    /// flow as the ICFG does.
    #[hardwon(
        "1b531c29a629: the fixpoint erased a result value written before its call, so vec! elements never reached the sink"
    )]
    #[test]
    fn both_engines_carry_a_vec_macro_element_under_every_behavior() {
        assert_eq!(
            assert_engines_agree_on_every_behavior(VEC_MACRO_SOURCE),
            [1, 1, 1]
        );
    }

    /// The ICFG engine reaches a call's continuation only over the call's
    /// continuation edges, which carry its dispatch's proof and completeness,
    /// and it applies them to every fact leaving the call's point, whether or
    /// not the fact enters the callee. Each fixture leaves the source's path
    /// across an unresolved call without passing through it: a `println!`
    /// between the source and the sink that prints the source in one regression
    /// fixture or another value in a second, a source bound to an unresolved
    /// trait-object call's result, and a sink at an unresolved trait-object
    /// call. Both engines report each flow as possible and partial. When a
    /// `println!` sits on one branch only, the other path crosses no call, so
    /// the flow is definite and complete on both engines; the same holds when
    /// the other branch calls a resolved function instead, whose
    /// continuation is proven and complete, which only a separate crossed-call
    /// set per path keeps apart from the `println!` branch.
    #[test]
    #[hardwon(
        "4187b3b0a032: a flow live across an unresolved call kept a proven, complete quality that the ICFG degrades"
    )]
    fn both_engines_degrade_a_flow_live_across_an_unresolved_call() {
        let prints_the_source = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run() {
    let raw = source();
    println!("{}", raw);
    let moved = raw;
    sink(moved);
}
"#;
        let prints_another_value = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run() {
    let raw = source();
    let other = String::new();
    println!("{}", other);
    let moved = raw;
    sink(moved);
}
"#;
        let prints_on_one_branch = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run(flag: bool) {
    let raw = source();
    if flag {
        println!("{}", "branch");
    }
    let moved = raw;
    sink(moved);
}
"#;
        let resolved_call_on_the_other_branch = r#"fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

fn note() {}

pub fn run(flag: bool) {
    let raw = source();
    if flag {
        note();
    } else {
        println!("{}", "branch");
    }
    let moved = raw;
    sink(moved);
}
"#;
        let unresolved_source = r#"pub trait Feed {
    fn source(&self) -> String;
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run(feed: &dyn Feed) {
    let raw = feed.source();
    sink(raw);
}
"#;
        let unresolved_sink = r#"pub trait Out {
    fn sink(&self, text: String) -> usize;
}

fn source() -> String {
    String::new()
}

pub fn run(out: &dyn Out) {
    let raw = source();
    out.sink(raw);
}
"#;
        for (source, expected) in [
            (prints_the_source, ("possible", "partial")),
            (prints_another_value, ("possible", "partial")),
            (unresolved_source, ("possible", "partial")),
            (unresolved_sink, ("possible", "partial")),
            (prints_on_one_branch, ("definite", "complete")),
            (resolved_call_on_the_other_branch, ("definite", "complete")),
        ] {
            let [composed, icfg] = engine_runs(source, "paranoid");
            assert_eq!(composed.0.as_deref(), Some("composition"));
            assert_eq!(icfg.0.as_deref(), Some("icfg (store-ends)"));
            assert_eq!(
                (&composed.1, &composed.2),
                (&icfg.1, &icfg.2),
                "the engines disagree on {source}"
            );
            let [(_, certainty, completeness)] = composed.2.as_slice() else {
                panic!("one finding on {source}: {:#?}", composed.2);
            };
            assert_eq!(
                (certainty.label(), completeness.label()),
                expected,
                "{source}"
            );
        }
    }

    /// `run` logs its source through an unresolved trait-object call, so the
    /// open `run` keeps that call as a residual call. Both engines name it
    /// with the same call-site message, which prints the procedure's
    /// snapshot input status rather than the call's dispatch status, so the
    /// run carries one diagnostic on each engine.
    #[test]
    fn both_engines_name_a_residual_call_with_the_same_message() {
        const UNRESOLVED_SINK: &str = r#"pub trait Out {
    fn sink(&self, text: String) -> usize;
}

fn source() -> String {
    String::new()
}

pub fn run(out: &dyn Out) {
    let raw = source();
    out.sink(raw);
}
"#;
        let [composed, icfg] = engine_runs(UNRESOLVED_SINK, "paranoid");
        assert_eq!(composed.0.as_deref(), Some("composition"));
        assert_eq!(icfg.0.as_deref(), Some("icfg (store-ends)"));
        assert_eq!((&composed.1, &composed.2), (&icfg.1, &icfg.2));
        assert_eq!(icfg.4.len(), 1, "{:#?}", icfg.4);
        assert_eq!(composed.4, icfg.4);
    }

    /// The fixture of the authored-summary composition test. `replace` is a
    /// std method with no body in the workspace, so its boundary is closed by
    /// the summary alone: `receiver.replace(raw, "")` returns its first
    /// argument's value.
    const SUMMARY_CALL_SOURCE: &str = r#"use std::string::String;

fn source() -> String {
    String::new()
}

fn sink(text: String) -> usize {
    text.len()
}

pub fn run(receiver: String) {
    let raw = source();
    let moved = receiver.replace(raw, "");
    sink(moved);
}
"#;

    /// A summary whose one transfer runs from parameter 0 to the normal
    /// return. The declaration pack and the target match the receiver
    /// sanitizer fixture above.
    fn parameter_summary_pack()
    -> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
        compile_receiver_sanitizer_pack(
            "test.parameter-summaries",
            "summaries.string",
            serde_json::json!({
                "kind": "procedure_summaries",
                "summaries": [{
                    "id": "summary.rust-codeql.std-string-string-replace",
                    "target": {
                        "path": "library/alloc/src/string.rs",
                        "symbol": "std.string.String.replace",
                        "has_receiver": true,
                        "parameter_count": 2
                    },
                    "completeness": "complete",
                    "covers_overrides": true,
                    "locations": [],
                    "transfers": [{
                        "input": { "kind": "parameter", "ordinal": 0 },
                        "exit_kind": "normal",
                        "output": { "kind": "normal_return" }
                    }],
                    "effects": []
                }]
            }),
        )
    }

    /// A source reaches a sink through a call whose boundary the resolver
    /// proves and completes from the authored summary. The summary's transfer
    /// is the only way the flow crosses the call, so the composition finds the
    /// finding only if it applies the summary on that complete boundary.
    #[hardwon(
        "a2f46bafa034: covering_model skipped a proven and complete boundary before it looked up the summary that closed it"
    )]
    #[test]
    fn composition_applies_an_authored_summary_on_a_complete_external_boundary() {
        use super::TaintPolicyCompilation;
        use crate::registry::test_registry_for_workspace;
        use crate::taint_compose_provider::{CompositionMemo, PolicyCompositionProvider};
        use brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudget;
        use brokk_bifrost_analysis::analyzer::semantic::{SemanticBudget, SemanticRequest};
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            SemanticModelRuntimeOutcome, acquire_active_semantic_models,
        };
        use brokk_bifrost_flow::taint::compose::{CompositionBudget, compose_taint_batch};

        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", SUMMARY_CALL_SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("open an ephemeral semantic-pack catalog");
        for (pack, source_id) in [
            (
                receiver_sanitizer_declaration_pack(),
                "test:summary-call-declarations",
            ),
            (parameter_summary_pack(), "test:summary-call-summaries"),
        ] {
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: source_id.to_owned(),
                    },
                )
                .expect("register the summary fixture");
        }
        let cancellation = CancellationToken::default();
        let SemanticModelRuntimeOutcome::Ready {
            active, snapshot, ..
        } = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                approximate_standard_libraries: Vec::new(),
                bifrost_version: env!("CARGO_PKG_VERSION")
                    .parse()
                    .expect("test Bifrost version parses"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "rust".to_owned(),
                    ecosystem: "cargo".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: Default::default(),
            },
            &cancellation,
        )
        else {
            panic!("the summary fixture activates");
        };
        let mut registry = test_registry_for_workspace(project.root());
        let policy = registry
            .register_policy_bytes(
                PolicySourceIdentity::new("test:summary-call.rqlp"),
                COMPOSED_POLICY.as_bytes(),
            )
            .expect("the composed policy registers");
        let spec = policy
            .resolved_taint()
            .expect("the composed policy is a taint policy");
        let compilation = TaintPolicyCompiler::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            Some(active),
            CodeQueryExecutionLimits::default(),
            64,
            &cancellation,
        )
        .with_active_semantic_model_snapshot(Some(Arc::clone(&snapshot)))
        .compile(policy, spec)
        .unwrap_or_else(|failure| panic!("the composed policy compiles: {:?}", failure.error));
        let TaintPolicyCompilation::Plans { roots, .. } = compilation else {
            panic!("the composed policy compiles to analysis plans");
        };
        let [root] = roots.as_slice() else {
            panic!("the composed policy has one root, found {}", roots.len());
        };
        assert_eq!(root.engine, TaintEngine::Composition);
        let plan = root.plan.analysis();

        let cache = DiscoveryMaterializationCache::default();
        let memo = CompositionMemo::default();
        let provider = PolicyCompositionProvider::new(
            &workspace,
            SemanticExecutionBudget::new(usize::MAX),
            &cache,
            plan,
            &root.external_models,
            64,
            // The composition binds a call's summaries at the call, from the
            // active models its binder's compiler holds.
            super::FrontierEndpointBinder::new(
                TaintPolicyCompiler::new(
                    &workspace,
                    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                    None,
                    CodeQueryExecutionLimits::default(),
                    64,
                    &cancellation,
                )
                .with_active_semantic_model_snapshot(Some(Arc::clone(&snapshot))),
                policy,
                spec,
                plan.universe().clone(),
            ),
            &memo,
        );
        let mut budget = SemanticBudget::default();
        let outcome = compose_taint_batch(
            plan,
            &provider,
            CompositionBudget {
                max_procedures: 64,
                max_hops: 4096,
                max_callers_per_procedure: 64,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("the composition runs");
        assert!(
            provider.failure().is_none(),
            "the provider failed: {:?}",
            provider.failure()
        );
        let findings = outcome.report.findings();
        assert_eq!(findings.len(), 1, "one finding is expected: {findings:#?}");
        // The complete, exactly bound authored summary closes its external
        // boundary, so the finding is complete and the composition retains no
        // partial-finding cause to render (#5218).
        assert!(
            findings[0].is_complete(),
            "the authored summary closes its complete external boundary: {findings:#?}"
        );
        assert!(
            outcome.finding_incompleteness.is_empty(),
            "a summary-closed run retains no partial-finding cause: {:?}",
            outcome.finding_incompleteness
        );
    }

    const COMPOSED_FIELD_SOURCE: &str = r#"pub struct Config {
    pub key: String,
}

fn source() -> String {
    String::new()
}

fn sink(text: &String) -> usize {
    text.len()
}

fn callee(c: &Config) {
    sink(&c.key);
}

pub fn caller() {
    let mut c = Config {
        key: String::new(),
    };
    c.key = source();
    callee(&c);
}
"#;

    /// Compose `COMPOSED_POLICY` over one Rust file and hand the plan and the
    /// outcome to `check` while the workspace that owns them is alive.
    fn compose_rust(
        source: &str,
        check: impl FnOnce(
            &brokk_bifrost_flow::taint::TaintAnalysisPlan,
            &brokk_bifrost_flow::taint::compose::ComposeOutcome,
        ),
    ) {
        use super::TaintPolicyCompilation;
        use crate::registry::test_registry_for_workspace;
        use crate::taint_compose_provider::{CompositionMemo, PolicyCompositionProvider};
        use brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudget;
        use brokk_bifrost_analysis::analyzer::semantic::{SemanticBudget, SemanticRequest};
        use brokk_bifrost_flow::taint::compose::{CompositionBudget, compose_taint_batch};

        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let mut registry = test_registry_for_workspace(project.root());
        let policy = registry
            .register_policy_bytes(
                PolicySourceIdentity::new("test:composed.rqlp"),
                COMPOSED_POLICY.as_bytes(),
            )
            .expect("the composed policy registers");
        let spec = policy
            .resolved_taint()
            .expect("the composed policy is a taint policy");
        let cancellation = CancellationToken::default();
        let compilation = TaintPolicyCompiler::new(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::default(),
            None,
            CodeQueryExecutionLimits::default(),
            64,
            &cancellation,
        )
        .compile(policy, spec)
        .unwrap_or_else(|failure| panic!("the composed policy compiles: {:?}", failure.error));
        let TaintPolicyCompilation::Plans { roots, .. } = compilation else {
            panic!("the composed policy compiles to analysis plans");
        };
        let [root] = roots.as_slice() else {
            panic!("the composed policy has one root, found {}", roots.len());
        };
        let plan = root.plan.analysis();

        let cache = DiscoveryMaterializationCache::default();
        let memo = CompositionMemo::default();
        let provider = PolicyCompositionProvider::new(
            &workspace,
            SemanticExecutionBudget::new(usize::MAX),
            &cache,
            plan,
            &root.external_models,
            64,
            super::FrontierEndpointBinder::new(
                TaintPolicyCompiler::new(
                    &workspace,
                    &brokk_bifrost_flow::FlowWorkspaceState::default(),
                    None,
                    CodeQueryExecutionLimits::default(),
                    64,
                    &cancellation,
                ),
                policy,
                spec,
                plan.universe().clone(),
            ),
            &memo,
        );
        let mut budget = SemanticBudget::default();
        let outcome = compose_taint_batch(
            plan,
            &provider,
            CompositionBudget {
                max_procedures: 64,
                max_hops: 4096,
                max_callers_per_procedure: 64,
            },
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("the composition runs");
        assert!(
            provider.failure().is_none(),
            "the provider failed: {:?}",
            provider.failure()
        );
        check(plan, &outcome);
    }

    /// A source the caller stores in a field reaches a sink the callee
    /// applies to that field of its parameter. The demand at the callee's
    /// heap input port climbs to the caller, where it is the location rooted
    /// at the bound argument, observed before the call's effects.
    ///
    /// The run is not complete: without a standard library the workspace
    /// leaves `String::new` undispatched and the procedures open, as it does
    /// for the ICFG engine. No interior run may be incomplete, which is how
    /// an unobserved caller-side location shows.
    #[test]
    fn composition_finds_a_source_in_a_field_the_callee_reads() {
        use brokk_bifrost_flow::taint::compose::Incompleteness;

        compose_rust(COMPOSED_FIELD_SOURCE, |plan, outcome| {
            assert!(
                !outcome
                    .incompleteness
                    .iter()
                    .any(|reason| matches!(reason, Incompleteness::Interior { .. })),
                "every interior run is complete: {:#?}",
                outcome.incompleteness
            );
            let findings = outcome.report.findings();
            assert_eq!(findings.len(), 1, "one finding is expected: {findings:#?}");
            let finding = &findings[0];
            let name = |point: &brokk_bifrost_analysis::analyzer::semantic::ProgramPointHandle| {
                point
                    .procedure()
                    .semantics()
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    .map(str::to_owned)
            };
            let sink = plan
                .value_flow()
                .sink(finding.sink())
                .expect("the finding names a sink of its plan");
            assert_eq!(
                name(sink.point()).as_deref(),
                Some("callee"),
                "the sink is the call in callee"
            );
            let [evidence] = finding.origins().evidence() else {
                panic!("one origin is expected: {:#?}", finding.origins());
            };
            let [witness] = evidence.witnesses() else {
                panic!("one witness is expected: {evidence:#?}");
            };
            let procedures = witness
                .steps()
                .iter()
                .filter_map(|step| name(step.source()))
                .fold(Vec::<String>::new(), |mut names, name| {
                    if names.last() != Some(&name) {
                        names.push(name);
                    }
                    names
                });
            assert_eq!(
                procedures,
                ["caller", "callee"],
                "the witness runs from the caller into the callee: {witness:#?}"
            );
        });
    }

    /// A parameter source read where the formal is named by its value rather
    /// than by its port.
    ///
    /// `printed` passes the formal to `println!` by an inline capture, which
    /// the Rust lowering publishes as a `LanguageDefined` relation from the
    /// formal's value into the macro's argument. `formatted` passes it to
    /// `format!` by an inline capture, which the lowering passes to the macro
    /// call as a direct argument. Each `_control` variant is the same macro
    /// over a local copy, and `control` passes the formal straight to a call.
    /// `returned` passes the formal to `pass`, which returns its own formal;
    /// the lowering reads that formal through a `Parameter` relation into a
    /// temporary, so its `NormalReturn` relation names the temporary. Without
    /// the Cargo manifest, `formatted_control` is missed too, so the fixture
    /// keeps one.
    const FORMAL_CARRIER_SOURCE: &str = r#"
fn sink(_: &str) {}

fn sink_owned(_: String) {}

fn pass(x: &str) -> &str {
    x
}

pub fn control(secret: &str) {
    sink(secret);
}

pub fn returned(secret: &str) {
    sink(pass(secret));
}

pub fn printed(secret: &str) {
    std::println!("{secret}");
}

pub fn printed_control(secret: &str) {
    let copy = secret;
    std::println!("{copy}");
}

pub fn formatted(secret: &str) {
    let s = format!("{secret}");
    sink_owned(s);
}

pub fn formatted_control(secret: &str) {
    let copy = secret;
    let s = format!("{copy}");
    sink_owned(s);
}
"#;

    const FORMAL_CARRIER_POLICY: &str = r#"(policy
      :schema-version 1
      :id "test.formal-carrier"
      :name "Formal carrier"
      :message "a secret parameter reached a sink"
      :severity warning
      :analysis (analysis
        :type taint
        :mode may
        :call-modeling (call-modeling :unmodeled optimistic)
        :sources (endpoint-set :entries [
          (source :id secret-parameter :display-name "secret parameter" :categories [data.sensitive]
            :selector (rql :schema-version 1
              (language rust (parameter :name "secret")))
            :bind matched-value :labels [sensitive])])
        :sinks (endpoint-set :entries [
          (sink :id sink :display-name "sink" :categories [logging.cleartext]
            :selector (rql :schema-version 1
              (language rust (call :callee (name/regex "^sink(_owned)?$"))))
            :dangerous-operand (argument :index 0)
            :accepts [sensitive])
          (sink :id print :display-name "print" :categories [logging.cleartext]
            :selector (rql :schema-version 1
              (language rust (call :receiver (name "std") :callee (name "println"))))
            :dangerous-operand (argument :index 0)
            :accepts [sensitive])])))"#;

    #[test]
    #[hardwon(
        "bcdf0afc67d0+f3aec911b1c7: a formal read by value (println! LanguageDefined relation, format! direct call argument) had a second carrier identity, so a parameter source never reached the sink"
    )]
    fn a_parameter_source_reaches_the_sink_through_a_relation_that_names_the_formal_by_value() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"formal_carrier\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", FORMAL_CARRIER_SOURCE)
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let outcome = evaluate_policy_source(
            project.root(),
            PolicySourceIdentity::new("test:formal-carrier.rqlp"),
            FORMAL_CARRIER_POLICY,
            &analyzer,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &PolicyEvaluationOptions::new(
                PolicyEvaluationDate::from_ymd(2026, 10, 9).expect("fixed evaluation date"),
            ),
            None,
        )
        .expect("formal carrier policy evaluates");
        let [run] = outcome.report().runs() else {
            panic!("one policy produces one run: {:?}", outcome.report());
        };
        let mut sink_lines = run
            .findings()
            .iter()
            .map(|finding| {
                finding
                    .primary()
                    .region()
                    .expect("a taint finding has a source region")
                    .start_line()
            })
            .collect::<Vec<_>>();
        sink_lines.sort_unstable();
        // control (11), returned (15), printed (19), printed_control (24),
        // formatted (29) and formatted_control (35).
        assert_eq!(
            sink_lines,
            vec![11, 15, 19, 24, 29, 35],
            "completion={:?} diagnostics={:#?}",
            run.completion(),
            run.diagnostics()
        );
    }
}
