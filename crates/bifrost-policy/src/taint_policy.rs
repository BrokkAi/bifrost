//! Production lowering and execution preparation for resolved taint policies.
//!
//! Policy loading owns authoring and composition. This module starts at the
//! closed [`ResolvedTaintPolicySpec`] boundary and lowers only structured,
//! source-backed selector results into the diagnostic-neutral taint engine.

use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::hash::Hasher;
use std::ops::Range as ByteRange;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::budget::PolicyBudget;
use crate::definition::{PolicyId, PolicyPort, PolicySelectorPath, TaintLabel};
use crate::evaluator::{PolicyEvaluationContext, TaintPolicyEvaluator};
use crate::finding::{
    AuthoredArmClosureEvidence, BoundedWitness, CertaintyReason, FindingCertainty,
    FindingCompleteness, FindingIncompleteReason, PolicyDiagnostic, PolicyDiagnosticCode,
    PolicyDiagnosticImpact, PolicyDiagnosticSeverity, PolicyFailureReason, PolicyIncompleteReason,
    PolicyLocationRelationship, PolicyRunCompletion, ProofMetadata, ProofReason, ProofState,
    RelatedPolicyLocation, WitnessStepKind,
};
use crate::finding::{PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit};
use crate::finding_identity::{
    AnalysisEventRef, AnalysisFindingId, EvidenceRef, SourceScenarioId, StableSemanticIdentity,
    WitnessId,
};
use crate::future_evidence::{
    TaintFindingAnchor, TaintPolicyProjectionFacts, TaintSourceProjectionFact,
};
use crate::projection::{
    ProjectedFindingReport, TaintOriginProjection, TaintPairProjection, TaintProjectedFinding,
    TaintProjectionAuthority, TaintProjectionPayload,
};
use crate::resolved::{
    LoadedPolicy, ResolvedEndpointIdentity, ResolvedPolicySelector, ResolvedTaintEndpoint,
    ResolvedTaintPolicySpec, ResolvedTaintSourceDefinition,
};
use crate::selector_compiler::{parameter_name_matches, parameter_names_match};
use crate::{ProductionTaintAnalysisResult, ProductionTaintPhaseMetrics};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots;
use brokk_bifrost_analysis::analyzer::semantic::{
    CallArgumentMapping, CallArgumentMember, CallBinding, CallSiteHandle, CandidateCoverage,
    EvidenceCompleteness, ExactExternalProcedureTarget, ObservationPhase, OracleCallContext,
    ProcedureHandle, ProcedurePortKind, ProgramPointHandle, ProofStatus, SemanticArtifactKey,
    SemanticBudget, SemanticOutcome, SemanticValueKind, UnmaterializedExternalTarget, ValueHandle,
    WorkspaceIcfgProvider, WorkspaceRelativePath, split_qualified_member,
};
use brokk_bifrost_analysis::analyzer::semantic::{DispatchOracle, ValueFlowOracle};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CompiledProcedureSummary, CompiledSummaryEffect, ProcedureSummaryMemberKey,
    ProcedureSummaryTargetKey, ResolvedActiveSemanticModels, SemanticModelMatchDisposition,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;
use brokk_bifrost_analysis::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use brokk_bifrost_flow::dataflow::{
    DataflowRequest, ExternalSemanticSummarySet, ExternalSummaryCompatibilityKey,
    SemanticInputStatus, SolverBudget, SummaryBehaviorKey, SummaryContextKey, SummarySchemaVersion,
    SummarySemanticsVersion, SummaryWitness, SummaryWitnessStepKind, WitnessReconstructionLimits,
    WitnessRetentionLimits,
};
use brokk_bifrost_flow::taint::{
    SourceClassId, SourceEventKey, TaintAnalysisPlan, TaintBatch, TaintBatchCompatibilityKey,
    TaintBatchPlanner, TaintClassSet, TaintFindingCollectionLimits, TaintFindingReport,
    TaintOriginFindingEvidence, TaintPolicyPlan, TaintPropagationSemanticsId,
    TaintSanitizerBinding, TaintSinkBinding, TaintSourceBinding, TaintUniverse,
    collect_taint_findings_with_limits,
};
use brokk_bifrost_flow::value_flow::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowEventKey, ValueFlowEventKind,
    ValueFlowIncompleteCause, ValueFlowInput, ValueFlowObservationPhase, ValueFlowPlan,
    ValueFlowSinkSpec, ValueFlowSourceSpec,
};
use brokk_bifrost_flow::{
    ExactProcedureSummaryBoundary, ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, bind_compiled_procedure_summaries,
};
use brokk_bifrost_rql::structural::{
    CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryExecutionLimits,
};

#[derive(Debug)]
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
    pub(crate) labels: Box<[TaintLabel]>,
}

pub(crate) struct CompiledTaintPolicyPlan {
    pub(crate) internal_policy_id: String,
    pub(crate) plan: TaintPolicyPlan,
    pub(crate) sources: Box<[CompiledTaintEndpoint]>,
    pub(crate) sinks: Box<[CompiledTaintEndpoint]>,
}

enum TaintPolicyCompilation {
    Plans {
        roots: Vec<CompiledTaintPolicyPlan>,
        work: PolicyWorkReport,
        /// One message per selector row the compile refused to bind (#2308).
        /// Non-empty means the run does not cover the whole selection, so it
        /// must not report `Complete`.
        refusals: Vec<String>,
    },
    /// A compile whose endpoint selection was empty, so there is nothing to
    /// solve. The run is complete and clean, and `empty_endpoints` names the
    /// sets that matched nothing so the report does not read as a proof.
    Clean {
        work: PolicyWorkReport,
        refusals: Vec<String>,
        empty_endpoints: EmptyEndpointSets,
    },
}

struct PreparedTaintPlan {
    policy_id: PolicyId,
    sources: Box<[CompiledTaintEndpoint]>,
    sinks: Box<[CompiledTaintEndpoint]>,
    compilation_elapsed: Duration,
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
fn compiled_payload(
    policy_id: &PolicyId,
    work: PolicyWorkReport,
    refusals: Vec<String>,
    empty_endpoints: Option<EmptyEndpointSets>,
) -> TaintProjectionPayload {
    let mut diagnostics = empty_endpoints
        .map(|empty| empty_selection_diagnostics(policy_id, empty))
        .unwrap_or_default();
    if refusals.is_empty() {
        return TaintProjectionPayload {
            projections: Vec::new(),
            completion: PolicyRunCompletion::Complete,
            diagnostics,
            diagnostics_truncated: false,
            work,
            authored_arm_closures: Vec::new(),
        };
    }
    let completion =
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::CapabilityIncomplete])
            .expect("one incomplete reason is canonical");
    diagnostics.extend(refusals.into_iter().filter_map(|message| {
        PolicyDiagnostic::try_new(
            PolicyDiagnosticCode::EvaluationFailure,
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticImpact::RunIncomplete,
            message,
            None,
            Vec::new(),
        )
        .ok()
    }));
    TaintProjectionPayload {
        projections: Vec::new(),
        completion,
        diagnostics,
        diagnostics_truncated: false,
        work,
        authored_arm_closures: Vec::new(),
    }
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
    empty
        .named()
        .into_iter()
        .filter_map(|set| {
            PolicyDiagnostic::try_new(
                PolicyDiagnosticCode::EmptySelection,
                PolicyDiagnosticSeverity::Note,
                PolicyDiagnosticImpact::Advisory,
                format!(
                    "taint policy `{}` bound no {set} endpoint: its {set} selectors matched no \
                     location in the scanned workspace, so this run reports zero findings \
                     vacuously rather than proving that no flow exists",
                    policy_id.as_str()
                ),
                None,
                Vec::new(),
            )
            .ok()
        })
        .collect()
}

/// Render one diagnostic per refused selector row, naming the file, the row's
/// byte range, and the distinct call ranges that tied. The complete tie set is
/// in the message so a corpus report says which site could not be named rather
/// than only that some site could not be.
fn refusal_messages(refused: &[RefusedCallSite]) -> Vec<String> {
    refused
        .iter()
        .map(|refusal| {
            let site = format!(
                "{}:{}..{}",
                refusal.file, refusal.span.start, refusal.span.end
            );
            match &refusal.reason {
                RefusalReason::AmbiguousCallSite(ranges) => format!(
                    "taint semantic binding refused one site: the selector row at {site} \
                     identifies {} distinct semantic call sites {ranges:?}, so it names no \
                     single call",
                    ranges.len(),
                ),
                RefusalReason::UnidentifiedFormal { name, detail } => format!(
                    "taint semantic binding refused one site: the port `(argument :name \
                     \"{name}\")` at {site} does not identify one actual there: {detail}"
                ),
            }
        })
        .collect()
}

/// Coordinator-owned production adapter.
///
/// Preparation compiles every runnable taint policy before partitioning its
/// plans. Each resulting [`TaintBatchPlanner`] batch is solved once and its
/// retained finding report is projected into every participating policy.
#[derive(Default)]
pub(crate) struct ProductionTaintPolicyEvaluator {
    prepared: RefCell<HashMap<PolicyId, TaintProjectionPayload>>,
    public_findings: RefCell<Vec<brokk_bifrost_rql::structural::CodeQueryTaintFinding>>,
    retained_analyses: RefCell<Vec<Arc<ProductionTaintAnalysisResult>>>,
}

struct TaintExecutionBudget {
    semantic: SemanticBudget,
    solver: SolverBudget,
    remaining_findings: usize,
    remaining_witnesses: usize,
    remaining_witness_steps: usize,
    remaining_witness_expansions: usize,
    remaining_witness_bytes: usize,
}

/// The request-wide output lane one batch found already spent.
///
/// `remaining_findings` is the only lane that is deliberately request-wide
/// (#2208): the witness lanes are restored per batch, so they read zero only
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
enum TaintBatchError {
    BudgetExhausted(ExhaustedTaintLane),
    Internal(String),
}

impl From<String> for TaintBatchError {
    fn from(message: String) -> Self {
        Self::Internal(message)
    }
}

impl TaintExecutionBudget {
    fn fresh_semantic(budget: &PolicyBudget) -> SemanticBudget {
        SemanticBudget::new(super::selector_compiler::semantic_work_limits(
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
        self.semantic = Self::fresh_semantic(budget);
        self.solver = Self::fresh_solver(budget);
    }
}

impl ProductionTaintPolicyEvaluator {
    pub(crate) fn prepare<'policy>(
        policies: impl IntoIterator<Item = &'policy LoadedPolicy>,
        workspace: &WorkspaceAnalyzer,
        active_semantic_models: Result<Option<Arc<ResolvedActiveSemanticModels>>, String>,
        cancellation: Option<&CancellationToken>,
        budget: &PolicyBudget,
    ) -> Self {
        let uncancelled = CancellationToken::default();
        let cancellation = cancellation.unwrap_or(&uncancelled);
        let policies = policies
            .into_iter()
            .filter(|policy| policy.resolved_taint().is_some())
            .collect::<Vec<_>>();
        let mut payloads = HashMap::with_capacity(policies.len());
        let mut metadata = HashMap::new();
        let mut plans = Vec::new();
        let mut public_findings = Vec::new();
        let mut retained_analyses = Vec::new();
        let mut execution_budget = TaintExecutionBudget::new(budget);

        for policy in &policies {
            let policy_id = policy.definition().metadata.id.clone();
            let spec = policy
                .resolved_taint()
                .expect("filtered policies retain resolved taint specifications");
            let compilation_started = Instant::now();
            let compilation = match &active_semantic_models {
                Ok(active) => TaintPolicyCompiler::new(
                    workspace,
                    active.clone(),
                    budget.query_limits(),
                    budget.max_selector_results(),
                    cancellation,
                )
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
                }) => {
                    payloads.insert(
                        policy_id.clone(),
                        compiled_payload(&policy_id, work, refusals, None),
                    );
                    for compiled in roots {
                        metadata.insert(
                            compiled.internal_policy_id.clone(),
                            PreparedTaintPlan {
                                policy_id: policy_id.clone(),
                                sources: compiled.sources,
                                sinks: compiled.sinks,
                                compilation_elapsed,
                            },
                        );
                        plans.push(compiled.plan);
                    }
                }
                Ok(TaintPolicyCompilation::Clean {
                    work,
                    refusals,
                    empty_endpoints,
                }) => {
                    let payload =
                        compiled_payload(&policy_id, work, refusals, Some(empty_endpoints));
                    payloads.insert(policy_id, payload);
                }
                Err(failure) => {
                    payloads.insert(policy_id, prepared_compile_failure_payload(*failure));
                }
            }
        }

        let batch_planning_started = Instant::now();
        let batches = TaintBatchPlanner::partition(plans);
        let batch_planning_elapsed = batch_planning_started.elapsed();
        match batches {
            Ok(batches) => {
                for batch in batches {
                    let Err(failure) = solve_and_project_batch(
                        &batch,
                        &metadata,
                        &policies,
                        &mut payloads,
                        workspace,
                        cancellation,
                        budget,
                        &mut execution_budget,
                        &mut public_findings,
                        &mut retained_analyses,
                        batch_planning_elapsed,
                    ) else {
                        continue;
                    };
                    for internal_id in batch.policy_ids() {
                        let Some(plan) = metadata.get(internal_id) else {
                            continue;
                        };
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
                            TaintBatchError::Internal(message) => {
                                payloads.insert(
                                    plan.policy_id.clone(),
                                    prepared_failure_payload(message, PolicyWorkReport::default()),
                                );
                            }
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

        Self {
            prepared: RefCell::new(payloads),
            public_findings: RefCell::new(public_findings),
            retained_analyses: RefCell::new(retained_analyses),
        }
    }

    pub(crate) fn take_public_findings(
        &self,
    ) -> Vec<brokk_bifrost_rql::structural::CodeQueryTaintFinding> {
        std::mem::take(&mut *self.public_findings.borrow_mut())
    }

    pub(crate) fn take_retained_analyses(&self) -> Vec<Arc<ProductionTaintAnalysisResult>> {
        std::mem::take(&mut *self.retained_analyses.borrow_mut())
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
            .borrow_mut()
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
    active_semantic_models: Option<Arc<ResolvedActiveSemanticModels>>,
    /// Selector rows this compile refused to bind because they named more than
    /// one distinct semantic call site, or because a `(argument :name ...)`
    /// port identified no single actual there. Kept per row rather than raised
    /// as a compile failure so one unresolvable row costs its own sites and not
    /// the whole run (#2308).
    refused_sites: Vec<RefusedCallSite>,
    /// Per-callee formal parameter names, in declaration order, for
    /// `(argument :name ...)` resolution. The names are syntax-derived, so the
    /// cache is keyed on the materialization-scoped procedure handle the
    /// dispatch candidate names.
    formal_slot_names: HashMap<ProcedureHandle, Option<FormalSlotNames>>,
    /// Parsed declaration trees reused by formal-name resolution.
    syntax_trees: HashMap<ProjectFile, tree_sitter::Tree>,
    /// Per (selector, formal name), the source spans of the actuals the
    /// analyzer's structural actual-to-formal relation bound to that formal.
    /// It is consulted only where the oracle relation retains no mapping, and
    /// computed once per pair because it costs one extra selector scan.
    named_actuals: HashMap<(PolicySelectorPath, String), NamedActualSpans>,
    /// How many source and sink endpoint locations the compile bound, reported
    /// on every taint run so a raw report says what the policy's endpoint
    /// selectors actually matched in this workspace (#2659).
    bound_endpoints: BoundEndpointCounts,
}

/// The number of endpoint locations one taint compile bound, per endpoint set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct BoundEndpointCounts {
    sources: usize,
    sinks: usize,
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
}

impl EmptyEndpointSets {
    const fn any(self) -> bool {
        self.sources || self.sinks
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

type SelectedSite = super::selector_compiler::PolicySelectedSite;

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
    /// Every procedure that holds a candidate for the refused row. A region
    /// containing none of these cannot contain the refused site.
    procedures: Vec<DurableProcedureKey>,
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
    /// A `(argument :name ...)` port did not identify exactly one actual at the
    /// selected call, because the callee is unresolved, because the retained
    /// argument binding is open, or because two dispatch candidates map the
    /// formal to different actuals (#2496).
    UnidentifiedFormal { name: String, detail: String },
}

#[derive(Clone)]
struct BoundEndpoint {
    endpoint: ResolvedEndpointIdentity,
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
}

struct ResolvedTaintValue {
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
    value: ValueHandle,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
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
struct DiscoveryMaterializationCache {
    /// One canonical artifact instance per artifact key, for the whole compile.
    artifacts: HashMap<
        SemanticArtifactKey,
        Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>,
    >,
    procedures: HashMap<
        DurableProcedureKey,
        ValueFlowInput<brokk_bifrost_analysis::analyzer::semantic::ValueFlowSnapshot>,
    >,
    dispatch: HashMap<
        DurableCallSiteKey,
        (
            Option<brokk_bifrost_analysis::analyzer::semantic::DispatchResult>,
            SemanticInputStatus,
        ),
    >,
    bindings: HashMap<
        (DurableCallSiteKey, DurableProcedureKey),
        ValueFlowInput<brokk_bifrost_analysis::analyzer::semantic::CallBindings>,
    >,
    /// Snapshot lookups served from an entry this compile already held.
    procedure_hits: u64,
    /// Snapshot lookups with no entry at all, each of which runs the oracle and
    /// charges the budget. This is the number the compile reports as
    /// `taint.semantic_snapshot_materializations`, and it must equal the number
    /// of distinct procedures the compile reached.
    procedure_misses: u64,
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
    handle_identity_reuses: u64,
    /// Per-artifact index from a procedure to the procedures it lexically
    /// encloses, built once per artifact key (#2640).
    lexical_children: HashMap<
        SemanticArtifactKey,
        HashMap<
            brokk_bifrost_analysis::analyzer::semantic::ProcedureId,
            Vec<brokk_bifrost_analysis::analyzer::semantic::ProcedureId>,
        >,
    >,
}

impl DiscoveryMaterializationCache {
    /// Return `procedure` anchored to this compile's canonical instance of its
    /// artifact, adopting it as canonical when the artifact is new here.
    ///
    /// See the type's documentation for why one instance per artifact key is
    /// required and why the substitution is sound.
    fn canonical_procedure(&mut self, procedure: &ProcedureHandle) -> ProcedureHandle {
        let canonical = self
            .artifacts
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
        self.handle_identity_reuses = self.handle_identity_reuses.saturating_add(1);
        canonical
            .procedure_handle(procedure.id())
            .expect("one artifact key denotes one procedure table in every materialization")
    }

    /// Every procedure `procedure` lexically encloses, as handles on
    /// `procedure`'s own artifact instance.
    ///
    /// The index is built once per artifact key because a discovery asks this
    /// of every procedure it visits, and rescanning the artifact's procedure
    /// table on each visit is quadratic in the file's callable count.
    fn lexical_children(&mut self, procedure: &ProcedureHandle) -> Vec<ProcedureHandle> {
        let artifact = Arc::clone(procedure.artifact());
        let index = self
            .lexical_children
            .entry(artifact.key().clone())
            .or_insert_with(|| {
                let mut index: HashMap<_, Vec<_>> = HashMap::new();
                for child in artifact.procedures() {
                    if let Some(parent) = child.lexical_parent() {
                        index.entry(parent).or_default().push(child.id());
                    }
                }
                index
            });
        let Some(children) = index.get(&procedure.id()) else {
            return Vec::new();
        };
        children
            .iter()
            .map(|id| {
                artifact
                    .procedure_handle(*id)
                    .expect("a live artifact owns each retained procedure")
            })
            .collect()
    }
}

struct SelectedSummaryFamily {
    language: String,
    payload: Vec<CompiledProcedureSummary>,
    root_ids: HashSet<String>,
}

impl<'a> TaintPolicyCompiler<'a> {
    pub(crate) fn new(
        workspace: &'a WorkspaceAnalyzer,
        active_semantic_models: Option<Arc<ResolvedActiveSemanticModels>>,
        query_limits: CodeQueryExecutionLimits,
        max_selector_results: usize,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            selectors: super::selector_compiler::PolicySelectorSession::new(
                workspace,
                "taint",
                query_limits,
                max_selector_results,
                cancellation,
            ),
            active_semantic_models,
            refused_sites: Vec::new(),
            formal_slot_names: HashMap::new(),
            syntax_trees: HashMap::new(),
            named_actuals: HashMap::new(),
            bound_endpoints: BoundEndpointCounts::default(),
        }
    }

    fn compile(
        mut self,
        policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
    ) -> Result<TaintPolicyCompilation, Box<TaintPolicyCompileFailure>> {
        let compiled = self.compile_inner(policy, spec);
        // Every taint run reports what its endpoint selectors bound, so a raw
        // report distinguishes a proven verdict from one taken over an empty
        // relation without re-running the policy (#2659).
        let mut work = self.selectors.work_report("taint");
        record_endpoint_metrics(&mut work, self.bound_endpoints);
        match compiled {
            Ok(compiled) => Ok(TaintPolicyCompilation::Plans {
                roots: compiled,
                work,
                refusals: refusal_messages(&self.refused_sites),
            }),
            Err(TaintPolicyCompileError::EmptyCompiledEndpoints(empty_endpoints)) => {
                Ok(TaintPolicyCompilation::Clean {
                    work,
                    refusals: refusal_messages(&self.refused_sites),
                    empty_endpoints,
                })
            }
            Err(error) => Err(Box::new(TaintPolicyCompileFailure { error, work })),
        }
    }

    fn compile_inner(
        &mut self,
        policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
    ) -> Result<Vec<CompiledTaintPolicyPlan>, TaintPolicyCompileError> {
        if !spec.transforms.is_empty() {
            return Err(TaintPolicyCompileError::UnsupportedAuxiliarySemantics(
                "transform",
            ));
        }
        if !spec.external_models.is_empty() {
            return Err(TaintPolicyCompileError::UnsupportedAuxiliarySemantics(
                "external-model",
            ));
        }

        let selectors = policy
            .resolved_selectors()
            .iter()
            .map(|selector| (&selector.path, selector))
            .collect::<HashMap<_, _>>();
        let mut all_sources = Vec::new();
        let mut all_sinks = Vec::new();

        for source in &spec.sources {
            let selector = required_selector(&selectors, &source.definition.selector_path)?;
            for selected in self.select(selector, &source.definition.bind)? {
                for resolved in
                    self.resolve_selected_values(selected, selector, &source.definition.bind)?
                {
                    all_sources.push(BoundEndpoint {
                        endpoint: source.identity.clone(),
                        point: resolved.point,
                        phase: resolved.phase,
                        carrier: ValueFlowCarrier::Value(resolved.value),
                        proof: resolved.proof,
                        completeness: resolved.completeness,
                        labels: source.definition.labels.clone().into_boxed_slice(),
                    });
                }
            }
        }
        for sink in &spec.sinks {
            let selector = required_selector(&selectors, &sink.definition.selector_path)?;
            for selected in self.select(selector, &sink.definition.dangerous_operand)? {
                for resolved in self.resolve_selected_values(
                    selected,
                    selector,
                    &sink.definition.dangerous_operand,
                )? {
                    all_sinks.push(BoundEndpoint {
                        endpoint: sink.identity.clone(),
                        point: resolved.point,
                        phase: resolved.phase,
                        carrier: ValueFlowCarrier::Value(resolved.value),
                        proof: resolved.proof,
                        completeness: resolved.completeness,
                        labels: sink.definition.accepts.clone().into_boxed_slice(),
                    });
                }
            }
        }
        // Sanitizers (a taint policy's `sanitizer`, a flow policy's `kill`)
        // bind the value their `:output` port establishes. The lowering keys on
        // the output alone because `TaintEdgeFunction::kill` is a function of
        // one carrier at one point and phase: it states that the value the
        // site produces no longer carries the listed labels. The `:input` port
        // is authored, validated and hashed, and it is what a later
        // conditional-kill slice will read; it does not change this lowering.
        let mut all_kills = Vec::new();
        for sanitizer in &spec.sanitizers {
            let selector = required_selector(&selectors, &sanitizer.selector_path)?;
            for selected in self.select(selector, &sanitizer.definition.output)? {
                for resolved in
                    self.resolve_selected_values(selected, selector, &sanitizer.definition.output)?
                {
                    all_kills.push(BoundEndpoint {
                        endpoint: sanitizer.identity.clone(),
                        point: resolved.point,
                        phase: resolved.phase,
                        carrier: ValueFlowCarrier::Value(resolved.value),
                        proof: resolved.proof,
                        completeness: resolved.completeness,
                        labels: sanitizer.definition.removes.clone().into_boxed_slice(),
                    });
                }
            }
        }
        self.bound_endpoints = BoundEndpointCounts {
            sources: all_sources.len(),
            sinks: all_sinks.len(),
        };
        // Both sets are tested before returning, so a policy whose source and
        // sink selectors both match nothing reports both rather than only the
        // first one the compiler happened to reach (#2659).
        let empty = EmptyEndpointSets {
            sources: all_sources.is_empty(),
            sinks: all_sinks.is_empty(),
        };
        if empty.any() {
            return Err(TaintPolicyCompileError::EmptyCompiledEndpoints(empty));
        }

        let mut stable_classes = spec
            .sources
            .iter()
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
            .map(|label| {
                SourceClassId::new(label.as_str())
                    .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        stable_classes.sort();
        stable_classes.dedup();
        let universe = TaintUniverse::new(stable_classes)
            .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))?;

        let mut roots = all_sources
            .iter()
            .chain(&all_sinks)
            .chain(&all_kills)
            .map(|endpoint| endpoint.point.procedure().clone())
            .chain(
                self.selectors
                    .materialized_artifacts()
                    .flat_map(|artifact| {
                        artifact.procedures().iter().map(|procedure| {
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
        // One cache serves every root in this compile. It charges each shared
        // procedure, dispatch, and binding one time, not one time for each root
        // that reaches it (#1936).
        let mut materialization = DiscoveryMaterializationCache::default();
        for root in roots {
            // Each region is an independent source-to-sink analysis, so budget
            // it independently rather than accumulating every region's
            // materialization into one shared cap (which makes a corpus abstain
            // by accumulation). The shared `materialization` cache keeps
            // cross-region work amortized, so a region's fresh budget only
            // accounts for the procedures it newly pulls.
            self.selectors.reset_region_semantic_budget();
            match self.discover_value_flow(&root, &mut materialization) {
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
                }
                Err(error) => return Err(error),
            }
        }
        self.selectors
            .record_semantic_handle_identity_reuses(materialization.handle_identity_reuses);
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
            .map(|endpoint| endpoint.point.procedure().durable_key())
            .collect::<Vec<_>>();
        discoveries.retain(|discovery| {
            source_procedures
                .iter()
                .any(|procedure| discovery.procedures.contains(procedure))
                && sink_procedures
                    .iter()
                    .any(|procedure| discovery.procedures.contains(procedure))
        });
        let covered = discoveries
            .iter()
            .map(|discovery| discovery.procedures.clone())
            .collect::<Vec<_>>();
        discoveries = discoveries
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
            .collect();
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
                .map(|(endpoint, _)| endpoint.clone())
                .collect::<Vec<_>>();
            sort_bound_endpoints(&mut sources);
            sort_bound_endpoints(&mut sinks);
            sort_bound_endpoints(&mut kills);
            let source_specs = source_event_specs(&sources)?;
            let sink_specs = sink_event_specs(&sinks)?;
            let value_flow = self.build_value_flow_plan(
                discovery,
                source_specs,
                sink_specs,
                spec.call_modeling.unmodeled,
            )?;
            let taint_sources = bind_taint_sources(&value_flow, &universe, &sources)?;
            let taint_sinks = bind_taint_sinks(&value_flow, &universe, &sinks)?;
            let taint_sanitizers = bind_taint_sanitizers(&value_flow, &universe, &kills)?;
            let sanitizer_hash = sanitizer_compatibility_hash(&value_flow, &taint_sanitizers);
            let analysis = TaintAnalysisPlan::new(
                value_flow,
                universe.clone(),
                taint_sources,
                taint_sinks,
                taint_sanitizers,
                Vec::new(),
            )
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
            let internal_policy_id = format!(
                "{}#root-{root_index}",
                policy.definition().metadata.id.as_str()
            );
            let compatibility = TaintBatchCompatibilityKey::with_call_behavior(
                // The value-flow propagation hash deliberately excludes
                // endpoint observations so compatible demand can share a solve,
                // but it also excludes sanitizers, which DO change propagation.
                // Folding them in is what keeps two policies with different
                // kills in different batches instead of colliding on one key
                // and failing the planner's own equality check.
                TaintPropagationSemanticsId::new(
                    &root.artifact().key().fingerprint(),
                    root.semantics().locator(),
                    value_flow_compatibility_hash(analysis.value_flow()),
                    sanitizer_hash,
                ),
                spec.call_modeling.unmodeled,
                universe.hash(),
            );
            let plan = TaintPolicyPlan::new(internal_policy_id.clone(), compatibility, analysis)
                .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
            let source_metadata = value_flow_sources(&plan, &sources)?;
            let sink_metadata = value_flow_sinks(&plan, &sinks)?;
            compiled.push(CompiledTaintPolicyPlan {
                internal_policy_id,
                plan,
                sources: source_metadata.into_boxed_slice(),
                sinks: sink_metadata.into_boxed_slice(),
            });
        }
        if compiled.is_empty() {
            return Err(TaintPolicyCompileError::SemanticUnavailable(
                "no analysis root contains both a selected source and sink".to_owned(),
            ));
        }
        Ok(compiled)
    }

    fn select(
        &mut self,
        selector: &ResolvedPolicySelector,
        _binding: &PolicyPort,
    ) -> Result<Vec<SelectedSite>, TaintPolicyCompileError> {
        self.selectors
            .select(selector)
            .map_err(taint_selector_error)
    }

    fn resolve_selected_values(
        &mut self,
        selection: SelectedSite,
        selector: &ResolvedPolicySelector,
        binding: &PolicyPort,
    ) -> Result<Vec<ResolvedTaintValue>, TaintPolicyCompileError> {
        if matches!(binding, PolicyPort::MatchedValue) {
            return self.resolve_matched_value(selection);
        }
        let artifact = self
            .selectors
            .materialize(&selection.file)
            .map_err(taint_selector_error)?;
        // Bind against every procedure in the file artifact. Narrowing by
        // procedure-anchor containment loses calls in languages whose
        // procedure anchors cover only the declaration header (Ruby anchors
        // `def name`, not the body, #1953); the call site's own source anchor
        // in select_call is the identity that decides the binding.
        let max_steps = self
            .selectors
            .remaining_semantic_traversal_steps()
            .map_err(taint_selector_error)?;
        let cancellation = self.selectors.cancellation();
        let mut handles = Vec::with_capacity(artifact.procedures().len());
        let mut examined = 0_usize;
        for procedure in artifact.procedures() {
            if cancellation.is_cancelled() {
                return Err(TaintPolicyCompileError::QueryIncomplete {
                    completion: CodeQueryCompletion::Cancelled,
                    detail: "taint semantic call binding was cancelled".to_owned(),
                });
            }
            examined = examined.saturating_add(1 + procedure.call_sites().len());
            if examined > max_steps {
                return Err(query_budget_error(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    "taint semantic call binding exhausted the shared traversal budget",
                ));
            }
            let handle = artifact
                .procedure_handle(procedure.id())
                .expect("validated artifact procedure has a scoped handle");
            handles.push(handle);
        }
        if !self.selectors.execution_budget().charge_traversal(examined) {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "taint semantic call binding exhausted the shared traversal budget",
            ));
        }
        let sites = match select_call(&handles, &selection)? {
            SelectedCallSites::One(sites) => sites,
            SelectedCallSites::Ambiguous { ranges, procedures } => {
                // The row names more than one distinct call. Refuse this row
                // only, and record which procedures could hold the site so the
                // regions that could contain it are dropped below (#2308). A
                // whole-policy failure here cost every case in the run its
                // verdict for one unresolvable row.
                self.refused_sites.push(RefusedCallSite {
                    file: selection.file.clone(),
                    span: selection.span.clone(),
                    reason: RefusalReason::AmbiguousCallSite(ranges),
                    procedures,
                });
                return Ok(Vec::new());
            }
        };
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
            let effective = match binding {
                PolicyPort::ArgumentName { name } => {
                    if let Some(row) = selection.call_binding.as_ref() {
                        if row.formal_name != *name {
                            return Err(TaintPolicyCompileError::UnsupportedBinding(format!(
                                "selected call-binding row maps formal `{}`, not requested formal `{name}`",
                                row.formal_name
                            )));
                        }
                        named = PolicyPort::ArgumentIndex {
                            index: u32::try_from(row.actual_index).map_err(|_| {
                                TaintPolicyCompileError::UnsupportedBinding(
                                    "selected actual index does not fit the policy port".to_owned(),
                                )
                            })?,
                        };
                        Some((&named, ProofStatus::Proven, EvidenceCompleteness::Complete))
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
                                    procedures: vec![procedure.durable_key()],
                                });
                                None
                            }
                        }
                    }
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
                    Some((&named, ProofStatus::Proven, EvidenceCompleteness::Complete))
                }
                _ => Some((binding, ProofStatus::Proven, EvidenceCompleteness::Complete)),
            };
            let Some((port, proof, completeness)) = effective else {
                continue;
            };
            let (value, point) = select_value(procedure, call, &selection.span, port)?;
            resolved.push(ResolvedTaintValue {
                point,
                // A call port is a carrier the selected point reads or
                // receives, never one that point's own local effects
                // define: an argument or receiver temporary is assigned at
                // the operand's own point, and a return value is bound at
                // the call's normal continuation.
                phase: ValueFlowObservationPhase::BeforeEffects,
                value,
                proof: conjoin_proof(&selection.proof, &proof),
                completeness: conjoin_completeness(&selection.completeness, &completeness),
            });
        }
        Ok(resolved)
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
        let dispatch = {
            let mut request = self.selectors.semantic_request();
            oracle
                .resolve_call(call, &mut request)
                .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?
        };
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
        // - `formal_names_unavailable`: some candidate's table was withheld.
        //   `formal_slot_names` returns `None` both when the declaration could
        //   not be parsed and when the table it would have built has a gap --
        //   a minted parameter this seam could not locate in the declaration's
        //   layout withholds the whole table rather than reporting a formal
        //   absent. Either way this seam does not know what that candidate
        //   declares, so it may neither bind through the structural relation
        //   nor raise `UnknownFormalName`.
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
            let names = self.formal_slot_names(candidate.target())?;
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
        // The semantic call row records that an actual is a keyword argument
        // but not which keyword, so the oracle relation retains no mapping for
        // `put(value=x)`. Fall back to the analyzer's structural
        // actual-to-formal relation, which reads the label from the call's own
        // syntax. It is the same relation `(call-input :parameter-name ...)`
        // publishes, and the mapping it makes is not oracle-proven, so a
        // binding taken from it is complete only up to that relation.
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
    /// property of the resolved target's own declaration. A mapping whose
    /// member is a keyword states the formal's name itself and binds without
    /// any knowledge of the callee; today's workspace oracle mints no such
    /// member, because the semantic call row drops the label, but the oracle
    /// contract allows one and reading it here is what makes the structural
    /// fallback below removable when the row carries it.
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
    /// Names are syntax-derived from the declaration the procedure is anchored
    /// at, which is the same source the `call_binding` relation reads, so a
    /// port and a relation row cannot disagree about what formal `n` is called.
    /// `None` means the declaration could not be read here; that is an evidence
    /// shortfall, never a decision that the formal is absent, and
    /// `resolve_named_argument` treats it as one: a candidate whose names are
    /// unavailable can neither be bound through the structural relation nor
    /// reported as declaring no such formal.
    fn formal_slot_names(
        &mut self,
        procedure: &ProcedureHandle,
    ) -> Result<Option<FormalSlotNames>, TaintPolicyCompileError> {
        if let Some(cached) = self.formal_slot_names.get(procedure) {
            return Ok(cached.clone());
        }
        if self.selectors.cancellation().is_cancelled() {
            return Err(TaintPolicyCompileError::QueryIncomplete {
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
        let names = self.read_formal_slot_names(procedure);
        self.formal_slot_names
            .insert(procedure.clone(), names.clone());
        Ok(names)
    }

    fn read_formal_slot_names(&mut self, procedure: &ProcedureHandle) -> Option<FormalSlotNames> {
        let semantics = procedure.semantics();
        let locator = semantics
            .source_mapping(semantics.source())
            .map(|mapping| mapping.locator.clone())?;
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
        let language = language_for_file(&file);
        if !self.syntax_trees.contains_key(&file) {
            let tree = parse_tree_for_language(&file, language, &source)?;
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
        let layout =
            formal_parameter_slots(language, tree.root_node(), &source, &declaration_range)?;
        // Declaration order is not ordinal order. A language may bind a
        // declared formal as the receiver -- Python's `self` and `cls` are
        // ordinary entries in the parameter list, and Go and Java carry a
        // receiver slot the layout marks -- and the lowering that mints the
        // ordinals skips whichever one it consumed. Naming ordinal `n` after
        // the `n`th slot is therefore one slot early on every Python instance
        // method, which silently binds a port to its neighbour's operand.
        //
        // Each ordinal is taken from the procedure's own parameter value
        // instead. That value's source mapping points into the slot that
        // declared it, so the table is the lowering's own answer about which
        // syntax declared formal `n` and cannot drift from it.
        let mut names: Vec<Box<[String]>> = Vec::new();
        for value in semantics.values() {
            let SemanticValueKind::Parameter { ordinal, .. } = &value.kind else {
                continue;
            };
            let mapping = semantics.source_mapping(value.source)?;
            let span = mapping.locator.anchor().span();
            let (start, end) = (span.start_byte() as usize, span.end_byte() as usize);
            let slot = layout.slots.iter().find(|slot| {
                slot.declaration_range.start_byte <= start && slot.declaration_range.end_byte >= end
            })?;
            let ordinal = *ordinal as usize;
            if names.len() <= ordinal {
                names.resize(ordinal + 1, Box::default());
            }
            names[ordinal] = slot.names.clone().into_boxed_slice();
        }
        // A dense table is what makes "the target declares no such formal" a
        // statement about the declaration rather than about this lookup. A gap
        // means a parameter the lowering minted was not located in the layout,
        // so the whole answer is withheld as the shortfall it is.
        if names.iter().any(|slot| slot.is_empty()) {
            return None;
        }
        Some(names.into())
    }

    fn resolve_matched_value(
        &mut self,
        selection: SelectedSite,
    ) -> Result<Vec<ResolvedTaintValue>, TaintPolicyCompileError> {
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        let outcome = {
            let mut request = self.selectors.semantic_request();
            oracle
                .pointees_at_source(
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
        let result = outcome.available_value().ok_or_else(|| {
            TaintPolicyCompileError::SemanticUnavailable(
                "matched source row produced no point-sensitive value observation".to_owned(),
            )
        })?;
        if let Some(observation) = result.observations().first() {
            self.selectors.remember_artifact(
                selection.file.clone(),
                Arc::clone(observation.query().point().procedure().artifact()),
            );
        }
        let proof = if matches!(outcome, SemanticOutcome::Complete { .. }) {
            selection.proof
        } else {
            conjoin_proof(
                &selection.proof,
                &ProofStatus::Unproven("matched source observation is not proven".into()),
            )
        };
        let completeness = if result.coverage() == CandidateCoverage::Exhaustive {
            selection.completeness
        } else {
            conjoin_completeness(
                &selection.completeness,
                &EvidenceCompleteness::Partial(
                    "matched source observation coverage is not exhaustive".into(),
                ),
            )
        };
        Ok(result
            .observations()
            .iter()
            .map(|observation| ResolvedTaintValue {
                point: observation.query().point().clone(),
                // Keep the phase the oracle attached to the observation. A
                // matched value is usually the one the point defines, so the
                // observation holds after that point's effects; binding it
                // before them lets the defining assignment's strong update
                // kill the endpoint at its own site.
                phase: value_flow_phase(observation.query().phase()),
                value: observation.query().value().clone(),
                proof: proof.clone(),
                completeness: completeness.clone(),
            })
            .collect())
    }

    fn discover_value_flow(
        &mut self,
        root: &ProcedureHandle,
        cache: &mut DiscoveryMaterializationCache,
    ) -> Result<DiscoveredValueFlow, TaintPolicyCompileError> {
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        let context = OracleCallContext::empty();
        // Anchor the root, and below every procedure the walk reaches, to this
        // compile's canonical instance of its artifact, so one discovery never
        // mixes two materializations of one file (#2289).
        let root = cache.canonical_procedure(root);
        let mut pending = vec![root.clone()];
        let mut seen: HashSet<DurableProcedureKey> = HashSet::new();
        let mut seen_bindings = HashSet::new();
        let mut seen_external_targets = HashSet::new();
        let mut seen_unmaterialized_targets = HashSet::new();
        let mut snapshots = Vec::new();
        let mut bindings = Vec::new();
        let mut external_targets = Vec::new();
        let mut unmaterialized_external_targets = Vec::new();
        while let Some(procedure) = pending.pop() {
            let procedure = cache.canonical_procedure(&procedure);
            let procedure_key = procedure.durable_key();
            if !seen.insert(procedure_key.clone()) {
                continue;
            }
            // Reuse the cached snapshot when a prior root already materialized
            // this procedure. The cache holds only present snapshots: the miss
            // path returns a `SemanticUnavailable` error before it inserts, so a
            // hit always carries a valid snapshot.
            //
            // The cache is deliberately not gated on the snapshot being
            // complete (#2284). Most procedures at corpus scale are not
            // complete -- an unlowered construct or an unresolved dispatch is
            // ordinary -- and a cache that retained only complete answers would
            // re-materialize and re-charge nearly everything for every root
            // that reaches it. A non-complete snapshot is still a finished
            // answer, and it is replayed with its typed status intact, so a
            // cached `unsupported` stays `unsupported`.
            let snapshot_input = if let Some(cached) = cache.procedures.get(&procedure_key) {
                cache.procedure_hits = cache.procedure_hits.saturating_add(1);
                cached.clone()
            } else {
                cache.procedure_misses = cache.procedure_misses.saturating_add(1);
                self.selectors.record_semantic_snapshot_materialization();
                let outcome = {
                    let mut request = self.selectors.semantic_request();
                    oracle
                        .procedure_relations(&procedure, &context, &mut request)
                        .map_err(|error| {
                            TaintPolicyCompileError::SemanticProvider(error.to_string())
                        })?
                };
                require_uninterrupted_outcome(&outcome, "taint value-flow discovery")?;
                self.selectors
                    .require_execution_budget("taint value-flow discovery")
                    .map_err(taint_selector_error)?;
                let status = SemanticInputStatus::from_outcome(&outcome);
                let snapshot = outcome.available_value().cloned().ok_or_else(|| {
                    TaintPolicyCompileError::SemanticUnavailable(
                        "taint value-flow discovery returned no procedure snapshot".to_owned(),
                    )
                })?;
                let input = ValueFlowInput::new(snapshot, status);
                cache
                    .procedures
                    .insert(procedure_key.clone(), input.clone());
                input
            };
            snapshots.push(snapshot_input);

            // A nested callable's body belongs to its enclosing procedure's
            // analysis region even when no call in the region resolves to it
            // (#2640). The forward closure over calls alone cannot reach a
            // lambda, closure, Ruby block, or anonymous class body: the
            // invocation that runs it dispatches on an interface method, a
            // higher-order library callee, or a runtime block, never on the
            // nested procedure's own declaration, so the nested body entered no
            // region and a sink inside it was co-located with no source. The
            // whole compile then declined with "no analysis root contains both
            // a selected source and sink".
            //
            // Lexical containment answers this structurally: it needs no
            // dispatch resolution, it is available in every language that
            // lowers nested callables, and the parent links are validated
            // acyclic, so the closure still terminates. Widening the region is
            // also the right half to change -- the containment test below is
            // durable-key membership and stays exact.
            for child in cache.lexical_children(&procedure) {
                pending.push(child);
            }

            for call_row in procedure.semantics().call_sites() {
                let call = procedure
                    .call_site_handle(call_row.id)
                    .expect("a live procedure owns each retained call site");
                // Reuse the cached dispatch when a prior root already resolved
                // this call site. The per-discovery boundary and candidate walk
                // below still runs, because it feeds this root's own region.
                let call_key = call.durable_key();
                let (dispatch_value, dispatch_status) =
                    if let Some(cached) = cache.dispatch.get(&call_key) {
                        cached.clone()
                    } else {
                        let dispatch = {
                            let mut request = self.selectors.semantic_request();
                            oracle.resolve_call(&call, &mut request).map_err(|error| {
                                TaintPolicyCompileError::SemanticProvider(error.to_string())
                            })?
                        };
                        require_uninterrupted_outcome(&dispatch, "taint call dispatch")?;
                        self.selectors
                            .require_execution_budget("taint call dispatch")
                            .map_err(taint_selector_error)?;
                        let dispatch_status = SemanticInputStatus::from_outcome(&dispatch);
                        let entry = (dispatch.available_value().cloned(), dispatch_status);
                        cache.dispatch.insert(call_key.clone(), entry.clone());
                        entry
                    };
                let Some(dispatch) = dispatch_value else {
                    continue;
                };
                for boundary in dispatch.boundaries() {
                    if let Some(target) = boundary.exact_external_target()
                        && seen_external_targets.insert(target.clone())
                    {
                        external_targets.push(target.clone());
                    }
                    // #1978: a fully-qualified external callee that never
                    // materializes carries its canonical identity here instead of
                    // a materialized `exact_external_target`.
                    if let Some(target) = boundary.unmaterialized_external_target()
                        && seen_unmaterialized_targets.insert(target.clone())
                    {
                        unmaterialized_external_targets.push(target.clone());
                    }
                }
                for candidate in dispatch.candidates() {
                    let binding_key = (call_key.clone(), candidate.target().durable_key());
                    if !seen_bindings.insert(binding_key.clone()) {
                        continue;
                    }
                    // Reuse the cached binding when a prior root already bound
                    // this (call, target) pair. The cache holds only present
                    // bindings, so a hit reproduces both the pushed binding and
                    // the pushed callee.
                    let binding_input = if let Some(cached) = cache.bindings.get(&binding_key) {
                        Some(cached.clone())
                    } else {
                        let outcome = {
                            let mut request = self.selectors.semantic_request();
                            oracle
                                .call_bindings(&call, candidate, &context, &mut request)
                                .map_err(|error| {
                                    TaintPolicyCompileError::SemanticProvider(error.to_string())
                                })?
                        };
                        require_uninterrupted_outcome(&outcome, "taint call binding")?;
                        self.selectors
                            .require_execution_budget("taint call binding")
                            .map_err(taint_selector_error)?;
                        let status =
                            dispatch_status.merge(SemanticInputStatus::from_outcome(&outcome));
                        outcome.available_value().cloned().map(|binding| {
                            let input = ValueFlowInput::new(binding, status);
                            cache.bindings.insert(binding_key.clone(), input.clone());
                            input
                        })
                    };
                    if let Some(binding_input) = binding_input {
                        bindings.push(binding_input);
                        pending.push(candidate.target().clone());
                    }
                }
            }
        }
        Ok(DiscoveredValueFlow {
            root,
            snapshots,
            bindings,
            procedures: seen,
            external_targets,
            unmaterialized_external_targets,
        })
    }

    fn build_value_flow_plan(
        &mut self,
        discovery: DiscoveredValueFlow,
        source_specs: Vec<ValueFlowSourceSpec>,
        sink_specs: Vec<ValueFlowSinkSpec>,
        call_behavior: brokk_bifrost_flow::dataflow::UnmodeledCallBehavior,
    ) -> Result<ValueFlowPlan, TaintPolicyCompileError> {
        let external_summaries = self.bind_external_summaries(
            &discovery.external_targets,
            &discovery.unmaterialized_external_targets,
            discovery.root.artifact().key(),
            call_behavior,
        )?;
        let plan = ValueFlowPlan::with_call_behavior(
            discovery.root,
            discovery.snapshots,
            discovery.bindings,
            source_specs,
            sink_specs,
            call_behavior,
        )
        .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
        match external_summaries {
            Some(summaries) => plan
                .with_external_summaries(summaries)
                .map_err(|error| TaintPolicyCompileError::Plan(error.to_string())),
            None => Ok(plan),
        }
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
                target.artifact().language().stable_label(),
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
            let family_key = selected.payload.as_ptr() as usize;
            let family = families
                .entry(family_key)
                .or_insert_with(|| SelectedSummaryFamily {
                    language: selected.shard.manifest.language.clone(),
                    payload: selected.payload.to_vec(),
                    root_ids: HashSet::new(),
                });
            family.root_ids.insert(selected.record.id.clone());
        }
        if families.is_empty() && unmaterialized.is_empty() {
            return Ok(None);
        }

        let mut families = families.into_values().collect::<Vec<_>>();
        families.sort_unstable_by(|left, right| {
            left.language.cmp(&right.language).then_with(|| {
                left.payload
                    .iter()
                    .map(|summary| (&summary.model_id, &summary.id))
                    .cmp(
                        right
                            .payload
                            .iter()
                            .map(|summary| (&summary.model_id, &summary.id)),
                    )
            })
        });
        let mut lowered = Vec::new();
        for family in families {
            let by_id = family
                .payload
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
            let summaries = family
                .payload
                .iter()
                .filter(|summary| selected_ids.contains(&summary.id))
                .cloned()
                .collect::<Vec<_>>();
            let mut bindings = Vec::with_capacity(summaries.len());
            for summary in &summaries {
                let mut exact = targets
                    .iter()
                    .filter(|target| {
                        target.artifact().language().stable_label() == family.language
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
            lowered.extend(set.entries().map(|(_, summary)| summary.clone()));
        }

        // #1978: bind activated summaries to fully-qualified external callees that
        // never materialize. They select a summary by canonical identity
        // (language, owner FQN, member, arity, has_receiver) rather than by
        // artifact path or parameter-typed symbol, and anchor the lowered summary
        // to the boundary's synthetic locator so it applies at solve time. The
        // materialized-external binding above is untouched.
        let mut unmaterialized_families = HashMap::<usize, SelectedSummaryFamily>::new();
        for target in unmaterialized {
            let matched = active.procedure_summaries_for_member(ProcedureSummaryMemberKey::new(
                target.language().stable_label(),
                target.owner_fqn(),
                target.member(),
                target.has_receiver(),
                target.arity(),
            ));
            let selected = match matched.disposition {
                SemanticModelMatchDisposition::Empty => continue,
                SemanticModelMatchDisposition::Unique => {
                    let [selected] = matched.records.as_slice() else {
                        return Err(TaintPolicyCompileError::Model(
                            "unique unmaterialized procedure-summary lookup returned a non-unique record set"
                                .to_owned(),
                        ));
                    };
                    selected
                }
                SemanticModelMatchDisposition::Conflict => {
                    // Several activated summaries collapse to the same
                    // unmaterialized identity (owner, member, arity,
                    // has_receiver) because parameter types are unrecoverable for
                    // an unmaterialized callee, so overloads like
                    // `StringBuilder.append(String)` / `append(Object)` /
                    // `append(char[])` map to one key. When they model the same
                    // flow -- identical transfers and effects -- picking any one
                    // is exact. When they genuinely differ, the overload cannot
                    // be disambiguated, so skip this member: the call stays
                    // unmodeled and require-model abstains, rather than aborting
                    // the whole compile (instance-method binding at #1936 made
                    // these members reachable and surfaced the collapse).
                    let Some(first) = matched.records.first() else {
                        continue;
                    };
                    let identical = matched.records.iter().all(|other| {
                        other.record.transfers == first.record.transfers
                            && other.record.effects == first.record.effects
                    });
                    if identical {
                        first
                    } else {
                        continue;
                    }
                }
            };
            let family_key = selected.payload.as_ptr() as usize;
            let family = unmaterialized_families
                .entry(family_key)
                .or_insert_with(|| SelectedSummaryFamily {
                    language: selected.shard.manifest.language.clone(),
                    payload: selected.payload.to_vec(),
                    root_ids: HashSet::new(),
                });
            family.root_ids.insert(selected.record.id.clone());
        }
        let mut unmaterialized_families = unmaterialized_families.into_values().collect::<Vec<_>>();
        unmaterialized_families.sort_unstable_by(|left, right| {
            left.language.cmp(&right.language).then_with(|| {
                left.payload
                    .iter()
                    .map(|summary| (&summary.model_id, &summary.id))
                    .cmp(
                        right
                            .payload
                            .iter()
                            .map(|summary| (&summary.model_id, &summary.id)),
                    )
            })
        });
        for family in unmaterialized_families {
            let by_id = family
                .payload
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
            let summaries = family
                .payload
                .iter()
                .filter(|summary| selected_ids.contains(&summary.id))
                .cloned()
                .collect::<Vec<_>>();
            let mut bindings = Vec::with_capacity(summaries.len());
            for summary in &summaries {
                // Re-match this closure summary to its unmaterialized external
                // target by canonical identity. Parameter types are discarded, so
                // a same-arity overload set collapses to one identity here.
                let binding_error = || {
                    TaintPolicyCompileError::Model(format!(
                        "unmaterialized procedure summary `{}` dependency closure lacks one external target identity",
                        summary.id
                    ))
                };
                let mut exact = unmaterialized.iter().filter(|target| {
                    target.language().stable_label() == family.language
                        && target.has_receiver() == summary.target.has_receiver
                        && target.arity() == summary.target.parameter_count
                        && split_qualified_member(&summary.target.symbol).is_some_and(
                            |(owner, member)| {
                                owner == target.owner_fqn() && member == target.member()
                            },
                        )
                });
                let Some(target) = exact.next() else {
                    return Err(binding_error());
                };
                if exact.any(|candidate| candidate != target) {
                    return Err(binding_error());
                }
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
                    target.provenance_artifact_key(root_artifact),
                    target.locator().clone(),
                    ExactProcedureSummaryBoundary::new(receiver, parameters),
                ));
            }
            let set = bind_compiled_procedure_summaries(&summaries, bindings, compatibility)
                .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))?;
            lowered.extend(set.entries().map(|(_, summary)| summary.clone()));
        }

        if lowered.is_empty() {
            return Ok(None);
        }
        ExternalSemanticSummarySet::try_new(lowered, compatibility)
            .map(Some)
            .map_err(|error| TaintPolicyCompileError::Model(error.to_string()))
    }
}

#[allow(clippy::too_many_arguments)]
fn solve_and_project_batch(
    batch: &TaintBatch,
    metadata: &HashMap<String, PreparedTaintPlan>,
    policies: &[&LoadedPolicy],
    payloads: &mut HashMap<PolicyId, TaintProjectionPayload>,
    workspace: &WorkspaceAnalyzer,
    cancellation: &CancellationToken,
    budget: &PolicyBudget,
    execution_budget: &mut TaintExecutionBudget,
    public_findings: &mut Vec<brokk_bifrost_rql::structural::CodeQueryTaintFinding>,
    retained_analyses: &mut Vec<Arc<ProductionTaintAnalysisResult>>,
    batch_planning_elapsed: Duration,
) -> Result<(), TaintBatchError> {
    // Each batch solves its own regions and reconstructs evidence only for its
    // own findings, so give it a fresh solve and witness budget instead of the
    // request-wide remainder a corpus would have already drained (#1935 for the
    // witness lanes, #2208 for the semantic and solver lanes).
    // `remaining_findings` is deliberately not reset: it stays the request-wide
    // cap on total output.
    execution_budget.reset_per_batch_witness_budget(budget);
    execution_budget.reset_per_batch_solve_budget(budget);
    let limits = budget.query_limits();
    let value_flow_limits = limits.value_flow;
    let witness_retention = WitnessRetentionLimits::best_effort(
        1,
        value_flow_limits.max_retained_relations,
        value_flow_limits.max_retained_bytes,
    )
    .map_err(|error| error.to_string())?;
    let mut request = DataflowRequest::new(&mut execution_budget.solver, cancellation);
    let provider = WorkspaceIcfgProvider::new(workspace);
    let propagation_started = Instant::now();
    let result = brokk_bifrost_flow::taint::solve_taint_batch_with_witnesses(
        batch.analysis().value_flow().root(),
        &provider,
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
    if let Some(lane) = [
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
    {
        return Err(TaintBatchError::BudgetExhausted(lane));
    }
    let reconstruction_started = Instant::now();
    let report = collect_taint_findings_with_limits(
        batch.analysis(),
        result,
        budget.max_origins_per_finding(),
        witness_limits,
        TaintFindingCollectionLimits::new(
            execution_budget.remaining_findings,
            execution_budget.remaining_witnesses,
            execution_budget.remaining_witness_steps,
            execution_budget.remaining_witness_expansions,
            execution_budget.remaining_witness_bytes,
        )
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let reconstruction_elapsed = reconstruction_started.elapsed();
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
        let plan = metadata
            .get(projection.policy_id())
            .ok_or_else(|| "taint batch projection has no compiled policy metadata".to_owned())?;
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
            budget,
            &mut dropped_for_missing_origins,
        )?;
        let payload = payloads
            .get_mut(&plan.policy_id)
            .ok_or_else(|| "compiled taint policy has no prepared payload".to_owned())?;
        payload.projections.extend(projected);
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
        if dropped_for_missing_origins > 0
            && matches!(payload.completion, PolicyRunCompletion::Complete)
        {
            // The run solved cleanly, but a candidate finding retained no
            // source origin evidence and could not be projected. Reporting
            // Complete would silently drop a real candidate, so the run
            // stays typed inconclusive until origin retention is fixed.
            payload.completion =
                PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery])
                    .map_err(|error| error.to_string())?;
            if let Ok(diagnostic) = PolicyDiagnostic::try_new(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Warning,
                PolicyDiagnosticImpact::RunIncomplete,
                format!(
                    "{dropped_for_missing_origins} candidate finding(s) retained no source origin evidence and could not be projected"
                ),
                None,
                Vec::new(),
            ) {
                payload.diagnostics.push(diagnostic);
            }
        }
        if !retained.report().is_complete() {
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
                let cause = batch.analysis().value_flow().first_incomplete_cause();
                let reason = match cause.and_then(ValueFlowIncompleteCause::status) {
                    Some(SemanticInputStatus::Unsupported { .. }) => {
                        PolicyIncompleteReason::CapabilityIncomplete
                    }
                    _ => PolicyIncompleteReason::PartialDiscovery,
                };
                payload.completion = PolicyRunCompletion::inconclusive(vec![reason])
                    .map_err(|error| error.to_string())?;
                payload.authored_arm_closures.clear();
                if let Some(cause) = cause {
                    let locator = cause.procedure().semantics().locator();
                    let name = locator
                        .declaration()
                        .segments()
                        .iter()
                        .filter_map(|segment| segment.name())
                        .collect::<Vec<_>>()
                        .join(".");
                    // Name the missing capability when the input is unsupported,
                    // so a corpus abstention report says which value-flow
                    // capability the procedure lacked rather than a bare
                    // "unsupported".
                    let status = match cause.status() {
                        Some(status @ SemanticInputStatus::Unsupported { capability }) => {
                            format!("{} ({})", status.label(), capability.label())
                        }
                        Some(status) => status.label().to_owned(),
                        None => "incomplete coverage".to_owned(),
                    };
                    // The family names only the repeating cause. A corpus
                    // produces one of these per procedure, so without a family
                    // the per-policy diagnostic cap kept the first 256 by sort
                    // order and hid every later cause (#2356).
                    if let Ok(diagnostic) = PolicyDiagnostic::try_new_in_family(
                        PolicyDiagnosticCode::EvaluationFailure,
                        PolicyDiagnosticSeverity::Warning,
                        PolicyDiagnosticImpact::RunIncomplete,
                        format!(
                            "taint discovery is incomplete: {} is {status}",
                            cause.label(),
                        ),
                        format!(
                            "taint discovery is incomplete: {} for {}:{name} is {status}",
                            cause.label(),
                            locator.path().as_str(),
                        ),
                        None,
                        Vec::new(),
                    ) {
                        payload.diagnostics.push(diagnostic);
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
    public_findings.extend(projected_findings);
    retained_analyses.push(retained);
    Ok(())
}

/// Publish the compile's bound endpoint counts on the run's work report.
///
/// Reported unconditionally, including the zeros: a permanent zero is exactly
/// the signal a reader of a raw benchmark artifact needs, because it says the
/// policy's selectors bound nothing here rather than that the analysis found
/// nothing (#2659).
fn record_endpoint_metrics(work: &mut PolicyWorkReport, counts: BoundEndpointCounts) {
    for (name, value) in [
        ("taint.compiled_source_endpoints", counts.sources),
        ("taint.compiled_sink_endpoints", counts.sinks),
    ] {
        increment_work_metric(
            work,
            name,
            PolicyWorkUnit::Count,
            u64::try_from(value).unwrap_or(u64::MAX),
        )
        .expect("two endpoint-count metrics fit the taint work report");
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
    labels: Vec<TaintLabel>,
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

#[allow(clippy::too_many_arguments)]
fn project_policy_findings(
    workspace: &WorkspaceAnalyzer,
    policy: &LoadedPolicy,
    spec: &ResolvedTaintPolicySpec,
    plan: &PreparedTaintPlan,
    universe: &TaintUniverse,
    report: &TaintFindingReport,
    budget: &PolicyBudget,
    dropped_for_missing_origins: &mut usize,
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
        let sink_findings = report
            .findings()
            .iter()
            .filter(|finding| {
                reported_sink_site(plan, finding.key().sink())
                    .and_then(Result::ok)
                    .is_some_and(|site| &site == reported_sink)
            })
            .collect::<Vec<_>>();
        let finding = sink_findings
            .iter()
            .copied()
            .max_by_key(|finding| {
                (
                    finding.is_proven(),
                    finding.is_complete(),
                    finding.origins().is_complete(),
                )
            })
            .expect("every reported sink site came from a finding of its own group");
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
                let Some(compiled_source) = plan
                    .sources
                    .iter()
                    .find(|source| &source.event == origin.origin().value_flow_key())
                else {
                    continue;
                };
                let source = spec
                    .sources
                    .iter()
                    .find(|source| source.identity == compiled_source.endpoint)
                    .ok_or_else(|| {
                        "compiled taint source is absent from the loaded policy".to_owned()
                    })?;
                let labels = stable_taint_labels(universe, origin)?
                    .into_iter()
                    .filter(|label| {
                        compiled_source.labels.contains(label)
                            && source.definition.labels.contains(label)
                            && sink.definition.accepts.contains(label)
                    })
                    .collect::<Vec<_>>();
                if labels.is_empty() {
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
                    }
                    None => groups.push(ProjectedSourceGroup {
                        source,
                        origins: vec![origin],
                        findings: vec![finding],
                        labels,
                    }),
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
                    TaintSourceProjectionFact::try_new(
                        group.source.identity.clone(),
                        group.source.semantic_hash,
                        group.source.analysis_projection_hash,
                        group.source.definition.display_name.clone(),
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
            let (origins, origins_omitted) = project_taint_origins(
                workspace,
                universe,
                group,
                report_options
                    .origins_per_finding
                    .min(budget.max_origins_per_finding()),
            )?;
            let origins_truncated = group
                .findings
                .iter()
                .any(|finding| finding.origins().origin_truncated())
                || origins_omitted > 0;
            let pair_proven = group.findings.iter().all(|finding| finding.is_proven());
            let pair_finding_incomplete =
                group.findings.iter().any(|finding| !finding.is_complete());
            let pair_witness_incomplete = group.findings.iter().any(|finding| {
                finding.origins().witness_truncated() || finding.origins().witness_unavailable()
            });
            let (projected_report, witness_refs) = project_taint_report(
                workspace,
                group,
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
                report.authored_arm_closures(),
            )?;
            let witness_refs_truncated = projected_report.witnesses_truncated;
            pairs.push(TaintPairProjection {
                source_endpoint: group.source.identity.clone(),
                analysis_finding_id: AnalysisFindingId::try_new("bifrost", &pair_key)
                    .map_err(|error| error.to_string())?,
                anchor,
                sink: sink_ref.clone(),
                origins,
                origins_truncated,
                witness_refs,
                witness_refs_truncated,
                report: projected_report,
            });
        }
        let reached_labels = source_facts
            .iter()
            .map(|fact| fact.source_label.clone())
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
    origin: &TaintOriginFindingEvidence,
) -> Result<Vec<TaintLabel>, String> {
    universe
        .stable_classes(origin.classes())
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
    limit: usize,
) -> Result<(Vec<TaintOriginProjection>, usize), String> {
    let scenarios = source_scenarios(workspace, group)?;
    let mut origins = Vec::new();
    for origin in &group.origins {
        let scenario = source_scenario(workspace, origin)?;
        let labels = stable_taint_labels(universe, origin)?;
        for label in labels
            .into_iter()
            .filter(|label| group.labels.contains(label))
        {
            origins.push(TaintOriginProjection {
                source_endpoint: group.source.identity.clone(),
                source_label: label.clone(),
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
            });
        }
    }
    origins.sort_by(|left, right| {
        left.source_label
            .cmp(&right.source_label)
            .then_with(|| left.scenario_id.cmp(&right.scenario_id))
    });
    origins.dedup_by(|left, right| {
        left.source_label == right.source_label && left.scenario_id == right.scenario_id
    });
    let omitted = origins.len().saturating_sub(limit);
    origins.truncate(limit);
    Ok((origins, omitted))
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
        if &location == primary
            || related
                .iter()
                .any(|item: &RelatedPolicyLocation| item.location() == &location)
        {
            continue;
        }
        if related.len() >= related_limit {
            omitted_related = omitted_related.saturating_add(1);
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
            |kind| match kind {
                SummaryWitnessStepKind::Seed => (WitnessStepKind::Source, "taint source"),
                SummaryWitnessStepKind::Edge(_) => {
                    (WitnessStepKind::Propagation, "taint propagation")
                }
                SummaryWitnessStepKind::EndSummaryGap(_) => {
                    (WitnessStepKind::Return, "taint summary boundary")
                }
            },
        )?;
        let Some(projected) = projected else {
            omitted = omitted.saturating_add(1);
            continue;
        };
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

/// Degrade one payload for a request-wide lane that ran out mid-run.
///
/// Before #2356 the caller replaced the payload with a failed one, so a corpus
/// large enough to spend the request-wide finding cap reported
/// `Failed { reasons: [InternalInvariant] }` and threw away every finding the
/// earlier batches had already projected. Exhausting a declared budget is a
/// normal, honest outcome: the findings stay, the run becomes inconclusive, and
/// the diagnostic names the lane.
fn record_exhausted_lane(payload: &mut TaintProjectionPayload, lane: ExhaustedTaintLane) {
    match &mut payload.completion {
        PolicyRunCompletion::Complete
        | PolicyRunCompletion::ProvenSubset { .. }
        | PolicyRunCompletion::ProvenBySummary => {
            payload.completion = PolicyRunCompletion::inconclusive(vec![lane.incomplete_reason()])
                .expect("one incomplete reason is canonical");
            payload.authored_arm_closures.clear();
        }
        PolicyRunCompletion::Inconclusive { reasons } => {
            reasons.push(lane.incomplete_reason());
            reasons.sort();
            reasons.dedup();
        }
        // A run that already failed or is unsupported cannot be made more
        // reliable by a budget note, and its completion forbids an incomplete
        // diagnostic impact.
        PolicyRunCompletion::Unsupported { .. } | PolicyRunCompletion::Failed { .. } => return,
    }
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

fn prepared_failure_payload(message: &str, work: PolicyWorkReport) -> TaintProjectionPayload {
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
    TaintProjectionPayload {
        projections: Vec::new(),
        completion,
        diagnostics: diagnostic.into_iter().collect(),
        diagnostics_truncated: false,
        work,
        authored_arm_closures: Vec::new(),
    }
}

fn prepared_compile_failure_payload(failure: TaintPolicyCompileFailure) -> TaintProjectionPayload {
    let TaintPolicyCompileFailure { error, work } = failure;
    let message = error.to_string();
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
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        message,
        None,
        Vec::new(),
    )
    .ok();
    TaintProjectionPayload {
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
    selectors
        .get(path)
        .copied()
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

/// What one selector row names in the semantic model.
enum SelectedCallSites {
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
/// No candidate stays a typed capability failure.
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
fn select_call(
    procedures: &[ProcedureHandle],
    selection: &SelectedSite,
) -> Result<SelectedCallSites, TaintPolicyCompileError> {
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
        return Err(TaintPolicyCompileError::SemanticUnavailable(
            "selected row does not identify a semantic call site".to_owned(),
        ));
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
        return Ok(SelectedCallSites::Ambiguous { ranges, procedures });
    }
    Ok(SelectedCallSites::One(
        tied.into_iter()
            .map(|candidate| (candidate.procedure.clone(), candidate.handle.clone()))
            .collect(),
    ))
}

fn select_value(
    procedure: &ProcedureHandle,
    call_handle: &brokk_bifrost_analysis::analyzer::semantic::CallSiteHandle,
    selected_span: &ByteRange<usize>,
    binding: &PolicyPort,
) -> Result<(ValueHandle, ProgramPointHandle), TaintPolicyCompileError> {
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
        PolicyPort::Receiver => call.receiver.ok_or_else(|| {
            TaintPolicyCompileError::SemanticUnavailable(
                "receiver binding selected a call without a receiver".to_owned(),
            )
        })?,
        PolicyPort::ReturnValue => call.result.ok_or_else(|| {
            TaintPolicyCompileError::SemanticUnavailable(
                "return-value binding selected a call without a normal result".to_owned(),
            )
        })?,
        PolicyPort::ArgumentIndex { index } => {
            call.arguments
                .get(usize::try_from(*index).map_err(|_| {
                    TaintPolicyCompileError::UnsupportedBinding(
                        "argument index does not fit this platform".to_owned(),
                    )
                })?)
                .ok_or_else(|| {
                    TaintPolicyCompileError::SemanticUnavailable(format!(
                        "selected call has no argument at index {index}"
                    ))
                })?
                .value
        }
        PolicyPort::ArgumentName { .. } => {
            unreachable!("formal-name ports resolve to an ordinal before carrier selection")
        }
    };
    let point_id = if matches!(binding, PolicyPort::ReturnValue) {
        call.normal_continuation.target()
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
    Ok((value, point))
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

fn sort_bound_endpoints(endpoints: &mut [BoundEndpoint]) {
    endpoints.sort_by(|left, right| {
        left.point
            .procedure()
            .semantics()
            .locator()
            .cmp(right.point.procedure().semantics().locator())
            .then_with(|| left.point.id().cmp(&right.point.id()))
            .then_with(|| left.endpoint.cmp(&right.endpoint))
    });
}

fn source_event_specs(
    endpoints: &[BoundEndpoint],
) -> Result<Vec<ValueFlowSourceSpec>, TaintPolicyCompileError> {
    endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| {
            let ordinal = u32::try_from(index).map_err(|_| {
                TaintPolicyCompileError::Plan("taint source ordinal overflow".to_owned())
            })?;
            let key =
                ValueFlowEventKey::at_point(&endpoint.point, ordinal, ValueFlowEventKind::Source)
                    .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
            Ok(ValueFlowSourceSpec::new(
                key,
                endpoint.point.clone(),
                endpoint.phase,
                endpoint.carrier.clone(),
                endpoint.proof.clone(),
                endpoint.completeness.clone(),
            ))
        })
        .collect()
}

fn sink_event_specs(
    endpoints: &[BoundEndpoint],
) -> Result<Vec<ValueFlowSinkSpec>, TaintPolicyCompileError> {
    endpoints
        .iter()
        .enumerate()
        .map(|(index, endpoint)| {
            let ordinal = u32::try_from(index).map_err(|_| {
                TaintPolicyCompileError::Plan("taint sink ordinal overflow".to_owned())
            })?;
            let key =
                ValueFlowEventKey::at_point(&endpoint.point, ordinal, ValueFlowEventKind::Sink)
                    .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
            Ok(ValueFlowSinkSpec::new(
                key,
                endpoint.point.clone(),
                endpoint.phase,
                endpoint.carrier.clone(),
                endpoint.proof.clone(),
                endpoint.completeness.clone(),
            ))
        })
        .collect()
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
) -> Result<Vec<TaintSourceBinding>, TaintPolicyCompileError> {
    if value_flow.sources().len() != endpoints.len() {
        return Err(TaintPolicyCompileError::Plan(
            "compiled taint source metadata does not match the value-flow plan".to_owned(),
        ));
    }
    value_flow
        .sources()
        .zip(endpoints)
        .map(|((id, spec), endpoint)| {
            Ok(TaintSourceBinding::new(
                id,
                class_set(universe, &endpoint.labels)?,
                SourceEventKey::new(spec.key().clone()),
            ))
        })
        .collect()
}

fn bind_taint_sinks(
    value_flow: &ValueFlowPlan,
    universe: &TaintUniverse,
    endpoints: &[BoundEndpoint],
) -> Result<Vec<TaintSinkBinding>, TaintPolicyCompileError> {
    if value_flow.sinks().len() != endpoints.len() {
        return Err(TaintPolicyCompileError::Plan(
            "compiled taint sink metadata does not match the value-flow plan".to_owned(),
        ));
    }
    value_flow
        .sinks()
        .zip(endpoints)
        .map(|((id, _), endpoint)| {
            Ok(TaintSinkBinding::new(
                id,
                class_set(universe, &endpoint.labels)?,
            ))
        })
        .collect()
}

/// Lower the region's bound kills into per-carrier taint kill functions.
///
/// One `(point, phase, carrier)` slot carries at most one binding: the plan
/// rejects two transfers that share an ordering slot
/// (`TaintPlanError::AmbiguousTransferOrder`), and two kills at one slot mean
/// one kill of the union of their labels, so the union is what this mints. The
/// event index is therefore always zero and is deterministic by construction;
/// the solver reads the slot, never the index.
///
/// A kill whose carrier is absent from the value-flow plan is skipped. That is
/// the one direction of error this compile is allowed to make silently: a
/// missing kill can only leave labels in place, so it can add a finding and can
/// never turn a real flow into a clean verdict. A kill whose *selector* could
/// not be executed is a different thing and has already failed the compile with
/// a query-incompleteness error before this point.
fn bind_taint_sanitizers(
    value_flow: &ValueFlowPlan,
    universe: &TaintUniverse,
    kills: &[BoundEndpoint],
) -> Result<Vec<TaintSanitizerBinding>, TaintPolicyCompileError> {
    let mut slots: Vec<(
        ProgramPointHandle,
        ValueFlowObservationPhase,
        ValueFlowCarrierId,
        TaintClassSet,
    )> = Vec::new();
    for kill in kills {
        let Some(carrier) = value_flow.carrier_id(&kill.carrier) else {
            continue;
        };
        let removed = class_set(universe, &kill.labels)?;
        match slots
            .iter_mut()
            .find(|slot| slot.0 == kill.point && slot.1 == kill.phase && slot.2 == carrier)
        {
            Some(slot) => slot.3 = slot.3.union(&removed),
            None => slots.push((kill.point.clone(), kill.phase, carrier, removed)),
        }
    }
    Ok(slots
        .into_iter()
        .map(|(point, phase, carrier, removed)| {
            TaintSanitizerBinding::resolved(point, phase, 0, carrier, removed)
        })
        .collect())
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
        std::hash::Hash::hash(binding.removed(), &mut hasher);
        hasher.write_u8(u8::from(binding.is_resolved()));
    }
    hasher.finish()
}

fn value_flow_sources(
    plan: &TaintPolicyPlan,
    endpoints: &[BoundEndpoint],
) -> Result<Vec<CompiledTaintEndpoint>, TaintPolicyCompileError> {
    plan.analysis()
        .value_flow()
        .sources()
        .zip(endpoints)
        .map(|((_id, spec), endpoint)| {
            Ok(CompiledTaintEndpoint {
                endpoint: endpoint.endpoint.clone(),
                event: spec.key().clone(),
                labels: endpoint.labels.clone(),
            })
        })
        .collect()
}

fn value_flow_sinks(
    plan: &TaintPolicyPlan,
    endpoints: &[BoundEndpoint],
) -> Result<Vec<CompiledTaintEndpoint>, TaintPolicyCompileError> {
    plan.analysis()
        .value_flow()
        .sinks()
        .zip(endpoints)
        .map(|((_id, spec), endpoint)| {
            Ok(CompiledTaintEndpoint {
                endpoint: endpoint.endpoint.clone(),
                event: spec.key().clone(),
                labels: endpoint.labels.clone(),
            })
        })
        .collect()
}

fn require_uninterrupted_outcome<T>(
    outcome: &brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome<T>,
    operation: &str,
) -> Result<(), TaintPolicyCompileError> {
    match outcome {
        SemanticOutcome::Cancelled { .. } => Err(TaintPolicyCompileError::QueryIncomplete {
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

fn query_budget_error(
    code: CodeQueryDiagnosticCode,
    detail: impl Into<String>,
) -> TaintPolicyCompileError {
    TaintPolicyCompileError::QueryIncomplete {
        completion: CodeQueryCompletion::Incomplete { codes: vec![code] },
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
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        DiscoveryMaterializationCache, ProductionTaintPolicyEvaluator, TaintExecutionBudget,
        TaintPolicyCompiler,
    };
    use crate::budget::PolicyBudget;
    use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
    use crate::coordinator::{PolicyEvaluationOptions, evaluate_policy_source};
    use crate::finding::{
        PolicyIncompleteReason, PolicyRunCompletion, PolicyWorkMetric, PolicyWorkReport,
    };
    use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
    use crate::source::PolicySourceIdentity;
    use crate::suppression::PolicyEvaluationDate;
    use brokk_bifrost_analysis::CancellationToken;
    use brokk_bifrost_analysis::analyzer::semantic::{
        ProcedureHandle, SemanticArtifact, SemanticBudget, SemanticRequest, SemanticWork,
    };
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
    };
    use brokk_bifrost_flow::dataflow::SolverWork;
    use brokk_bifrost_rql::structural::{CodeQueryExecutionLimits, CodeQuerySemanticLimits};

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

    fn two_flow_workspace() -> (tempfile::TempDir, WorkspaceAnalyzer) {
        let workspace = tempfile::tempdir().expect("temporary workspace");
        std::fs::write(workspace.path().join("first.py"), FIRST_FLOW_SOURCE)
            .expect("first fixture source");
        std::fs::write(workspace.path().join("second.py"), SECOND_FLOW_SOURCE)
            .expect("second fixture source");
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(workspace.path()).expect("fixture project"));
        let analyzer = WorkspaceAnalyzer::build_ephemeral(
            project,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
        )
        .expect("an analyzer over the fixture");
        (workspace, analyzer)
    }

    fn registry_for(source: &str) -> PolicyRegistry {
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        registry
            .register_policy_bytes(
                PolicySourceIdentity::new("test:issue-2356.rqlp"),
                source.as_bytes(),
            )
            .expect("the fixture policy loads");
        registry
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
    fn an_exhausted_request_wide_lane_degrades_the_run_instead_of_failing_it() {
        let (_workspace, analyzer) = two_flow_workspace();
        let registry = registry_for(&two_flow_policy(""));
        let budget = PolicyBudget::builder()
            .with_max_findings(1)
            .expect("one finding is inside the host cap")
            .build()
            .expect("a one-finding budget is valid");

        let evaluator = ProductionTaintPolicyEvaluator::prepare(
            registry.policies(),
            &analyzer,
            Ok(None),
            None,
            &budget,
        );
        let payloads = evaluator.prepared.borrow();
        let [(_, payload)] = payloads.iter().collect::<Vec<_>>()[..] else {
            panic!("one taint policy produces one payload");
        };

        assert!(
            !matches!(payload.completion, PolicyRunCompletion::Failed { .. }),
            "a spent budget must not surface as a run failure: {:#?}",
            payload.completion
        );
        let PolicyRunCompletion::Inconclusive { reasons } = &payload.completion else {
            panic!(
                "expected an inconclusive run, got {:#?}",
                payload.completion
            );
        };
        assert!(
            reasons.contains(&PolicyIncompleteReason::BatchFindingLimit),
            "the exhausted findings lane must be named: {reasons:#?}"
        );
        assert!(
            payload
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message()
                    == "taint request-wide budget is exhausted: findings"),
            "a diagnostic must name the exhausted lane: {:#?}",
            payload.diagnostics
        );
        assert!(
            !payload.projections.is_empty(),
            "the findings the earlier batch already projected must survive"
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
    fn a_witness_over_the_effective_report_limit_truncates_instead_of_dropping_the_finding() {
        let (workspace, analyzer) = two_flow_workspace();
        let source = two_flow_policy(":report (report :witness (witness :max-steps 2))");
        let options = PolicyEvaluationOptions::new(
            PolicyEvaluationDate::from_ymd(2026, 8, 18).expect("fixed evaluation date"),
        );
        let outcome = evaluate_policy_source(
            workspace.path(),
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
    fn per_batch_reset_restores_solve_lanes_without_restoring_the_finding_cap() {
        let budget = PolicyBudget::default();
        let mut execution = TaintExecutionBudget::new(&budget);

        let semantic_limits = execution.semantic.limits();
        let solver_limits = execution.solver.limits();
        execution
            .semantic
            .charge(semantic_limits)
            .expect("a first batch may spend the whole semantic ledger");
        execution
            .solver
            .charge(solver_limits)
            .expect("a first batch may spend the whole solver ledger");
        execution
            .semantic
            .charge(SemanticWork::uniform(1))
            .expect_err("the drained semantic ledger refuses further work");
        execution
            .solver
            .charge(SolverWork::uniform(1))
            .expect_err("the drained solver ledger refuses further work");

        execution.remaining_findings = 3;
        execution.reset_per_batch_solve_budget(&budget);

        execution
            .semantic
            .charge(semantic_limits)
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
        let first = WorkspaceAnalyzer::build_ephemeral(Arc::clone(&project), config())
            .expect("an analyzer over the fixture");
        let second = WorkspaceAnalyzer::build_ephemeral(project, config())
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
            None,
            CodeQueryExecutionLimits::default(),
            64,
            &cancellation,
        );
        let mut cache = DiscoveryMaterializationCache::default();
        let discovery = compiler
            .discover_value_flow(&second_head, &mut cache)
            .expect("the fixture closure is discovered");

        assert!(
            cache.handle_identity_reuses > 0,
            "the fixture must actually present a second materialization, \
             otherwise this test proves nothing"
        );
        assert_eq!(
            cache.procedure_misses, 2,
            "each distinct procedure must reach the oracle once: \
             hits={}, misses={}, handle-identity reuses={}",
            cache.procedure_hits, cache.procedure_misses, cache.handle_identity_reuses
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
        let canonical = cache
            .artifacts
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
        let workspace = WorkspaceAnalyzer::build_ephemeral(
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
            None,
            limits(largest_row_lane.saturating_mul(SCALE)),
            64,
            &cancellation,
        );
        let mut cache = DiscoveryMaterializationCache::default();
        for root in &roots {
            compiler.discover_value_flow(root, &mut cache).unwrap_or_else(|error| {
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
    put(read())
";

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

    fn flow_workspace() -> (tempfile::TempDir, WorkspaceAnalyzer) {
        let workspace = tempfile::tempdir().expect("temporary workspace");
        std::fs::write(workspace.path().join("flow.py"), FLOW_FIXTURE_SOURCE)
            .expect("fixture source");
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(workspace.path()).expect("fixture project"));
        let analyzer = WorkspaceAnalyzer::build_ephemeral(
            project,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
        )
        .expect("an analyzer over the fixture");
        (workspace, analyzer)
    }

    fn registry_for_sources(sources: &[(&str, &str)]) -> PolicyRegistry {
        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        for (identity, source) in sources {
            registry
                .register_policy_bytes(PolicySourceIdentity::new(*identity), source.as_bytes())
                .expect("the fixture policy loads");
        }
        registry
    }

    fn shared_memberships(work: &PolicyWorkReport) -> u64 {
        work.metrics()
            .iter()
            .find(|metric| metric.name() == "taint.propagation_shared_memberships")
            .map_or(0, PolicyWorkMetric::value)
    }

    /// #2436: two flow policies whose propagation semantics agree must share
    /// one solve. The shared-membership metric counts the other members of the
    /// batch each policy landed in, so a shared batch reports at least one.
    #[test]
    fn two_compatible_flow_policies_share_one_propagation_solve() {
        let (_workspace, analyzer) = flow_workspace();
        let registry = registry_for_sources(&[
            ("test:flow-a.rqlp", &flow_policy("test.flow-a", "validate")),
            ("test:flow-b.rqlp", &flow_policy("test.flow-b", "validate")),
        ]);
        let evaluator = ProductionTaintPolicyEvaluator::prepare(
            registry.policies(),
            &analyzer,
            Ok(None),
            None,
            &PolicyBudget::default(),
        );
        let payloads = evaluator.prepared.borrow();
        assert_eq!(payloads.len(), 2, "two flow policies produce two payloads");
        for (policy_id, payload) in payloads.iter() {
            assert!(
                shared_memberships(&payload.work) >= 1,
                "{policy_id} must share its solve with the compatible policy: {:#?}",
                payload.work
            );
        }
    }

    /// The other half of the same claim: kills change propagation, so two
    /// policies that disagree about them must not share a solve. Without the
    /// kill semantics in the batch compatibility key these two would collide
    /// on one key and the planner's own equality check would fail the run.
    #[test]
    fn flow_policies_with_different_kills_do_not_share_a_solve() {
        let (_workspace, analyzer) = flow_workspace();
        let registry = registry_for_sources(&[
            ("test:flow-a.rqlp", &flow_policy("test.flow-a", "validate")),
            ("test:flow-c.rqlp", &flow_policy("test.flow-c", "read")),
        ]);
        let evaluator = ProductionTaintPolicyEvaluator::prepare(
            registry.policies(),
            &analyzer,
            Ok(None),
            None,
            &PolicyBudget::default(),
        );
        let payloads = evaluator.prepared.borrow();
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

    /// #2436 no-false-green: a spent request-wide findings lane must leave the
    /// flow run inconclusive. A truncated run that reported `Complete` with
    /// fewer findings would be a clean verdict the analysis never proved.
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
            registry.policies(),
            &analyzer,
            Ok(None),
            None,
            &budget,
        );
        let payloads = evaluator.prepared.borrow();
        let [(_, payload)] = payloads.iter().collect::<Vec<_>>()[..] else {
            panic!("one flow policy produces one payload");
        };
        assert!(
            !matches!(payload.completion, PolicyRunCompletion::Complete),
            "an exhausted findings lane must not report a conclusive clean run: {:#?}",
            payload.completion
        );
    }
}
