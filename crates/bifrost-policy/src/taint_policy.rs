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
    BoundedWitness, CertaintyReason, FindingCertainty, FindingCompleteness,
    FindingIncompleteReason, PolicyDiagnostic, PolicyDiagnosticCode, PolicyDiagnosticImpact,
    PolicyDiagnosticSeverity, PolicyFailureReason, PolicyIncompleteReason,
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
use crate::{ProductionTaintAnalysisResult, ProductionTaintPhaseMetrics};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::dataflow::{
    DataflowRequest, ExternalSemanticSummarySet, ExternalSummaryCompatibilityKey,
    SemanticInputStatus, SolverBudget, SummaryBehaviorKey, SummaryContextKey, SummarySchemaVersion,
    SummarySemanticsVersion, SummaryWitness, SummaryWitnessStepKind, WitnessReconstructionLimits,
    WitnessRetentionLimits,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    CandidateCoverage, EvidenceCompleteness, ExactExternalProcedureTarget, ObservationPhase,
    OracleCallContext, ProcedureHandle, ProgramPointHandle, ProofStatus, SemanticArtifactKey,
    SemanticBudget, SemanticOutcome, UnmaterializedExternalTarget, ValueHandle,
    WorkspaceIcfgProvider, WorkspaceRelativePath, split_qualified_member,
};
use brokk_bifrost_analysis::analyzer::semantic::{DispatchOracle, ValueFlowOracle};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CompiledProcedureSummary, CompiledSummaryEffect, ExactProcedureSummaryBoundary,
    ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, ProcedureSummaryMemberKey, ProcedureSummaryTargetKey,
    ResolvedActiveSemanticModels, SemanticModelMatchDisposition, bind_compiled_procedure_summaries,
};
use brokk_bifrost_analysis::analyzer::structural::{
    CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryExecutionLimits,
};
use brokk_bifrost_analysis::analyzer::taint::{
    SourceClassId, SourceEventKey, TaintAnalysisPlan, TaintBatch, TaintBatchCompatibilityKey,
    TaintBatchPlanner, TaintClassSet, TaintFindingCollectionLimits, TaintFindingReport,
    TaintOriginFindingEvidence, TaintPolicyPlan, TaintSinkBinding, TaintSourceBinding,
    TaintUniverse, collect_taint_findings_with_limits,
};
use brokk_bifrost_analysis::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowIncompleteCause,
    ValueFlowInput, ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec,
    ValueFlowSourceSpec,
};
use brokk_bifrost_analysis::analyzer::{ProjectFile, WorkspaceAnalyzer};

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
    UnsupportedBinding(String),
    UnsupportedAuxiliarySemantics(&'static str),
    EmptyCompiledSources,
    EmptyCompiledSinks,
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
            Self::UnsupportedBinding(message) => {
                write!(formatter, "taint binding is unsupported: {message}")
            }
            Self::UnsupportedAuxiliarySemantics(kind) => {
                write!(
                    formatter,
                    "production taint {kind} lowering is not available"
                )
            }
            Self::EmptyCompiledSources => {
                formatter.write_str("taint policy compiled to an empty source set")
            }
            Self::EmptyCompiledSinks => {
                formatter.write_str("taint policy compiled to an empty sink set")
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
    Clean {
        work: PolicyWorkReport,
        refusals: Vec<String>,
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
fn compiled_payload(work: PolicyWorkReport, refusals: Vec<String>) -> TaintProjectionPayload {
    if refusals.is_empty() {
        return TaintProjectionPayload {
            projections: Vec::new(),
            completion: PolicyRunCompletion::Complete,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work,
        };
    }
    let completion =
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::CapabilityIncomplete])
            .expect("one incomplete reason is canonical");
    let diagnostics = refusals
        .into_iter()
        .filter_map(|message| {
            PolicyDiagnostic::try_new(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Warning,
                PolicyDiagnosticImpact::RunIncomplete,
                message,
                None,
                Vec::new(),
            )
            .ok()
        })
        .collect();
    TaintProjectionPayload {
        projections: Vec::new(),
        completion,
        diagnostics,
        diagnostics_truncated: false,
        work,
    }
}

/// Render one diagnostic per refused selector row, naming the file, the row's
/// byte range, and the distinct call ranges that tied. The complete tie set is
/// in the message so a corpus report says which site could not be named rather
/// than only that some site could not be.
fn refusal_messages(refused: &[RefusedCallSite]) -> Vec<String> {
    refused
        .iter()
        .map(|refusal| {
            format!(
                "taint semantic binding refused one site: the selector row at {}:{}..{} \
                 identifies {} distinct semantic call sites {:?}, so it names no single call",
                refusal.file,
                refusal.span.start,
                refusal.span.end,
                refusal.ranges.len(),
                refusal.ranges,
            )
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
    public_findings:
        RefCell<Vec<brokk_bifrost_analysis::analyzer::structural::CodeQueryTaintFinding>>,
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
                    payloads.insert(policy_id.clone(), compiled_payload(work, refusals));
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
                Ok(TaintPolicyCompilation::Clean { work, refusals }) => {
                    payloads.insert(policy_id, compiled_payload(work, refusals));
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
                    if let Err(message) = solve_and_project_batch(
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
                    ) {
                        for internal_id in batch.policy_ids() {
                            if let Some(plan) = metadata.get(internal_id) {
                                payloads.insert(
                                    plan.policy_id.clone(),
                                    prepared_failure_payload(&message, PolicyWorkReport::default()),
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
    ) -> Vec<brokk_bifrost_analysis::analyzer::structural::CodeQueryTaintFinding> {
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
    /// one distinct semantic call site. Kept per row rather than raised as a
    /// compile failure so one unresolvable row costs its own sites and not the
    /// whole run (#2308).
    refused_sites: Vec<RefusedCallSite>,
}

type SelectedSite = super::selector_compiler::PolicySelectedSite;

/// One selector row that binding refused because its best-matching candidates
/// name more than one distinct source call site.
struct RefusedCallSite {
    file: ProjectFile,
    /// The selector row's own byte range.
    span: ByteRange<usize>,
    /// The tied candidates' source ranges, for the diagnostic.
    ranges: Vec<ByteRange<usize>>,
    /// Every procedure that holds a tied candidate. A region containing none of
    /// these cannot contain the refused site.
    procedures: Vec<DurableProcedureKey>,
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
        }
    }

    fn compile(
        mut self,
        policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
    ) -> Result<TaintPolicyCompilation, Box<TaintPolicyCompileFailure>> {
        match self.compile_inner(policy, spec) {
            Ok(compiled) => Ok(TaintPolicyCompilation::Plans {
                roots: compiled,
                work: self.selectors.work_report("taint"),
                refusals: refusal_messages(&self.refused_sites),
            }),
            Err(
                TaintPolicyCompileError::EmptyCompiledSources
                | TaintPolicyCompileError::EmptyCompiledSinks,
            ) => Ok(TaintPolicyCompilation::Clean {
                work: self.selectors.work_report("taint"),
                refusals: refusal_messages(&self.refused_sites),
            }),
            Err(error) => Err(Box::new(TaintPolicyCompileFailure {
                error,
                work: self.selectors.work_report("taint"),
            })),
        }
    }

    fn compile_inner(
        &mut self,
        policy: &LoadedPolicy,
        spec: &ResolvedTaintPolicySpec,
    ) -> Result<Vec<CompiledTaintPolicyPlan>, TaintPolicyCompileError> {
        if !spec.sanitizers.is_empty() {
            return Err(TaintPolicyCompileError::UnsupportedAuxiliarySemantics(
                "sanitizer",
            ));
        }
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
                for resolved in self.resolve_selected_values(selected, &source.definition.bind)? {
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
                for resolved in
                    self.resolve_selected_values(selected, &sink.definition.dangerous_operand)?
                {
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
        if all_sources.is_empty() {
            return Err(TaintPolicyCompileError::EmptyCompiledSources);
        }
        if all_sinks.is_empty() {
            return Err(TaintPolicyCompileError::EmptyCompiledSinks);
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
            sort_bound_endpoints(&mut sources);
            sort_bound_endpoints(&mut sinks);
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
            let analysis = TaintAnalysisPlan::new(
                value_flow,
                universe.clone(),
                taint_sources,
                taint_sinks,
                Vec::new(),
                Vec::new(),
            )
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
            let internal_policy_id = format!(
                "{}#root-{root_index}",
                policy.definition().metadata.id.as_str()
            );
            let compatibility = TaintBatchCompatibilityKey::with_call_behavior(
                root.artifact().key().fingerprint().to_string(),
                format!(
                    "bifrost.production-taint.v1:{:?}:{:016x}",
                    root.semantics().locator(),
                    value_flow_compatibility_hash(analysis.value_flow()),
                ),
                spec.call_modeling.unmodeled,
                universe.hash(),
            )
            .map_err(|error| TaintPolicyCompileError::Plan(error.to_string()))?;
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
                    ranges,
                    procedures,
                });
                return Ok(Vec::new());
            }
        };
        // One source call site, lowered once per control-flow specialization.
        // Every lowering is a program site the value can reach, so bind all of
        // them; binding one would silently drop the others' paths (#2308).
        sites
            .iter()
            .map(|(procedure, call)| {
                let (value, point) = select_value(procedure, call, &selection.span, binding)?;
                Ok(ResolvedTaintValue {
                    point,
                    // A call port is a carrier the selected point reads or
                    // receives, never one that point's own local effects
                    // define: an argument or receiver temporary is assigned at
                    // the operand's own point, and a return value is bound at
                    // the call's normal continuation.
                    phase: ValueFlowObservationPhase::BeforeEffects,
                    value,
                    proof: selection.proof.clone(),
                    completeness: selection.completeness.clone(),
                })
            })
            .collect()
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
        call_behavior: brokk_bifrost_analysis::analyzer::dataflow::UnmodeledCallBehavior,
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
        call_behavior: brokk_bifrost_analysis::analyzer::dataflow::UnmodeledCallBehavior,
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
            match matched.disposition {
                SemanticModelMatchDisposition::Empty => continue,
                SemanticModelMatchDisposition::Conflict => {
                    return Err(TaintPolicyCompileError::Model(format!(
                        "conflicting activated procedure summaries target unmaterialized external {}.{}",
                        target.owner_fqn(),
                        target.member()
                    )));
                }
                SemanticModelMatchDisposition::Unique => {}
            }
            let [selected] = matched.records.as_slice() else {
                return Err(TaintPolicyCompileError::Model(
                    "unique unmaterialized procedure-summary lookup returned a non-unique record set"
                        .to_owned(),
                ));
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
    public_findings: &mut Vec<brokk_bifrost_analysis::analyzer::structural::CodeQueryTaintFinding>,
    retained_analyses: &mut Vec<Arc<ProductionTaintAnalysisResult>>,
    batch_planning_elapsed: Duration,
) -> Result<(), String> {
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
    let result = brokk_bifrost_analysis::analyzer::taint::solve_taint_batch_with_witnesses(
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
    if [
        execution_budget.remaining_findings,
        execution_budget.remaining_witnesses,
        execution_budget.remaining_witness_steps,
        execution_budget.remaining_witness_expansions,
        execution_budget.remaining_witness_bytes,
    ]
    .contains(&0)
    {
        return Err("taint request-wide finding or witness budget is exhausted".to_owned());
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
    let projection_limits =
        brokk_bifrost_analysis::analyzer::structural::CodeQueryTaintProjectionLimits::new(
            budget.max_origins_per_finding(),
            budget.max_witnesses_per_finding(),
            budget.max_witness_steps(),
            budget.max_witness_bytes(),
        );
    let mut retained = ProductionTaintAnalysisResult::new(
        Arc::new(batch.analysis().clone()),
        Arc::new(report),
        batch.compatibility().clone(),
        projection_limits,
    );
    debug_assert!(retained.plan_report_match());
    let standalone_projection_started = Instant::now();
    let projected_findings = retained
        .project_findings(workspace, projection_limits)
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
                    if let Ok(diagnostic) = PolicyDiagnostic::try_new(
                        PolicyDiagnosticCode::EvaluationFailure,
                        PolicyDiagnosticSeverity::Warning,
                        PolicyDiagnosticImpact::RunIncomplete,
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
    findings: Vec<&'a brokk_bifrost_analysis::analyzer::taint::TaintFinding>,
    labels: Vec<TaintLabel>,
}

/// The place one projected taint finding reports: one declared sink endpoint at
/// one place in the source.
///
/// "One place in the source" is the file, the enclosing declaration, and the
/// anchor's byte span. It deliberately excludes the anchor's *occurrence*
/// counter, which is what distinguishes several lowerings of one written call
/// from one another (#2308).
type ReportedSinkSite = (
    ResolvedEndpointIdentity,
    WorkspaceRelativePath,
    String,
    ByteRange<u32>,
);

/// Where one value-flow sink event is reported, or `None` when the event
/// belongs to another policy in the shared batch.
fn reported_sink_site(
    plan: &PreparedTaintPlan,
    event: &ValueFlowEventKey,
) -> Option<Result<ReportedSinkSite, String>> {
    let compiled = plan.sinks.iter().find(|sink| &sink.event == event)?;
    let locator = event.site();
    let span = locator.anchor().span();
    Some(canonical_locator_identity(locator).map(|declaration| {
        (
            compiled.endpoint.clone(),
            locator.path().clone(),
            declaration,
            span.start_byte()..span.end_byte(),
        )
    }))
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
    let mut projected_sinks = Vec::<ReportedSinkSite>::new();
    for candidate in report.findings() {
        let Some(reported_sink) = reported_sink_site(plan, candidate.key().sink()) else {
            continue;
        };
        let reported_sink = reported_sink?;
        if projected_sinks.contains(&reported_sink) {
            continue;
        }
        let sink_findings = report
            .findings()
            .iter()
            .filter(|finding| {
                reported_sink_site(plan, finding.key().sink())
                    .and_then(Result::ok)
                    .is_some_and(|site| site == reported_sink)
            })
            .collect::<Vec<_>>();
        projected_sinks.push(reported_sink);
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
            .expect("the candidate row belongs to its own sink group");
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
                budget,
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
    budget: &PolicyBudget,
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
        budget,
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
    let proof = ProofMetadata::try_new(
        if proven {
            ProofState::Proven
        } else {
            ProofState::Unproven
        },
        vec![ProofReason::DataflowWitness],
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

fn project_taint_witnesses(
    workspace: &WorkspaceAnalyzer,
    group: &ProjectedSourceGroup<'_>,
    finding_key: &str,
    finding_incomplete: bool,
    witness_limit: usize,
    budget: &PolicyBudget,
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
            budget.max_witness_steps(),
            budget.max_witness_bytes(),
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
        | TaintPolicyCompileError::UnsupportedBinding(_)
        | TaintPolicyCompileError::UnsupportedAuxiliarySemantics(_) => {
            Some(PolicyIncompleteReason::CapabilityIncomplete)
        }
        TaintPolicyCompileError::MissingSelector(_)
        | TaintPolicyCompileError::SemanticProvider(_)
        | TaintPolicyCompileError::Model(_)
        | TaintPolicyCompileError::Plan(_) => None,
        TaintPolicyCompileError::EmptyCompiledSources
        | TaintPolicyCompileError::EmptyCompiledSinks => {
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
        PolicyPort::ArgumentName { name } => {
            return Err(TaintPolicyCompileError::UnsupportedBinding(format!(
                "named argument `{name}` requires complete dispatch-aware formal binding"
            )));
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

    use super::{DiscoveryMaterializationCache, TaintExecutionBudget, TaintPolicyCompiler};
    use crate::budget::PolicyBudget;
    use brokk_bifrost_analysis::CancellationToken;
    use brokk_bifrost_analysis::analyzer::dataflow::SolverWork;
    use brokk_bifrost_analysis::analyzer::semantic::{
        ProcedureHandle, SemanticArtifact, SemanticBudget, SemanticRequest, SemanticWork,
    };
    use brokk_bifrost_analysis::analyzer::structural::{
        CodeQueryExecutionLimits, CodeQuerySemanticLimits,
    };
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
    };

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
}
