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
use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::dataflow::{
    DataflowRequest, ExternalSemanticSummarySet, ExternalSummaryCompatibilityKey,
    SemanticInputStatus, SolverBudget, SummaryBehaviorKey, SummaryContextKey, SummarySchemaVersion,
    SummarySemanticsVersion, SummaryWitness, SummaryWitnessStepKind, WitnessReconstructionLimits,
    WitnessRetentionLimits,
};
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    ProcedureRangeLookupStatus, procedures_for_source_ranges,
};
use brokk_bifrost_analysis::analyzer::semantic::{
    CandidateCoverage, EvidenceCompleteness, ExactExternalProcedureTarget, OracleCallContext,
    ProcedureHandle, ProgramPointHandle, ProofStatus, SemanticBudget, SemanticOutcome, ValueHandle,
    WorkspaceIcfgProvider,
};
use brokk_bifrost_analysis::analyzer::semantic::{DispatchOracle, ValueFlowOracle};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CompiledProcedureSummary, CompiledSummaryEffect, ExactProcedureSummaryBoundary,
    ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, ProcedureSummaryTargetKey, ResolvedActiveSemanticModels,
    SemanticModelMatchDisposition, bind_compiled_procedure_summaries,
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
    ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec, ValueFlowSourceSpec,
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
    },
    Clean(PolicyWorkReport),
}

struct PreparedTaintPlan {
    policy_id: PolicyId,
    sources: Box<[CompiledTaintEndpoint]>,
    sinks: Box<[CompiledTaintEndpoint]>,
    compilation_elapsed: Duration,
}

fn complete_payload(work: PolicyWorkReport) -> TaintProjectionPayload {
    TaintProjectionPayload {
        projections: Vec::new(),
        completion: PolicyRunCompletion::Complete,
        diagnostics: Vec::new(),
        diagnostics_truncated: false,
        work,
    }
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
    fn new(budget: &PolicyBudget) -> Self {
        let limits = budget.query_limits();
        Self {
            semantic: SemanticBudget::new(super::selector_compiler::semantic_work_limits(
                limits.semantic,
            ))
            .expect("validated policy semantic limits are positive"),
            solver: SolverBudget::new(limits.value_flow.solver_work),
            remaining_findings: budget.max_findings(),
            remaining_witnesses: budget
                .max_findings()
                .saturating_mul(budget.max_witnesses_per_finding()),
            remaining_witness_steps: budget.max_witness_steps(),
            remaining_witness_expansions: limits.value_flow.max_witness_expansions,
            remaining_witness_bytes: budget.max_witness_bytes(),
        }
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
                Ok(TaintPolicyCompilation::Plans { roots, work }) => {
                    payloads.insert(policy_id.clone(), complete_payload(work));
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
                Ok(TaintPolicyCompilation::Clean(work)) => {
                    payloads.insert(policy_id, complete_payload(work));
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
}

type SelectedSite = super::selector_compiler::PolicySelectedSite;

#[derive(Clone)]
struct BoundEndpoint {
    endpoint: ResolvedEndpointIdentity,
    point: ProgramPointHandle,
    carrier: ValueFlowCarrier,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    labels: Box<[TaintLabel]>,
}

struct ResolvedTaintValue {
    point: ProgramPointHandle,
    value: ValueHandle,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

struct DiscoveredValueFlow {
    root: ProcedureHandle,
    snapshots: Vec<ValueFlowInput<brokk_bifrost_analysis::analyzer::semantic::ValueFlowSnapshot>>,
    bindings: Vec<ValueFlowInput<brokk_bifrost_analysis::analyzer::semantic::CallBindings>>,
    procedures: HashSet<ProcedureHandle>,
    external_targets: Vec<ExactExternalProcedureTarget>,
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
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            selectors: super::selector_compiler::PolicySelectorSession::new(
                workspace,
                "taint",
                query_limits,
                cancellation,
            ),
            active_semantic_models,
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
            }),
            Err(
                TaintPolicyCompileError::EmptyCompiledSources
                | TaintPolicyCompileError::EmptyCompiledSinks,
            ) => Ok(TaintPolicyCompilation::Clean(
                self.selectors.work_report("taint"),
            )),
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
        roots.dedup();
        let mut discoveries = Vec::with_capacity(roots.len());
        for root in roots {
            discoveries.push(self.discover_value_flow(&root)?);
        }
        discoveries.retain(|discovery| {
            all_sources
                .iter()
                .any(|endpoint| discovery.procedures.contains(endpoint.point.procedure()))
                && all_sinks
                    .iter()
                    .any(|endpoint| discovery.procedures.contains(endpoint.point.procedure()))
        });
        let covered_sources = all_sources.iter().all(|endpoint| {
            discoveries
                .iter()
                .any(|discovery| discovery.procedures.contains(endpoint.point.procedure()))
        });
        let covered_sinks = all_sinks.iter().all(|endpoint| {
            discoveries
                .iter()
                .any(|discovery| discovery.procedures.contains(endpoint.point.procedure()))
        });
        if !covered_sources || !covered_sinks {
            return Err(TaintPolicyCompileError::SemanticUnavailable(
                "selected taint endpoints do not share a completely discovered call region"
                    .to_owned(),
            ));
        }
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
                .filter(|endpoint| discovery.procedures.contains(endpoint.point.procedure()))
                .cloned()
                .collect::<Vec<_>>();
            let mut sinks = all_sinks
                .iter()
                .filter(|endpoint| discovery.procedures.contains(endpoint.point.procedure()))
                .cloned()
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
        let lookup = procedures_for_source_ranges(
            &artifact,
            &[super::selector_compiler::source_range(&selection.span)],
            self.selectors
                .remaining_semantic_traversal_steps()
                .map_err(taint_selector_error)?,
            self.selectors.cancellation(),
        );
        if !self
            .selectors
            .execution_budget()
            .charge_traversal(lookup.examined)
        {
            return Err(query_budget_error(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                "taint enclosing-procedure lookup exhausted the shared traversal budget",
            ));
        }
        match lookup.status {
            ProcedureRangeLookupStatus::Complete => {}
            ProcedureRangeLookupStatus::Cancelled => {
                return Err(TaintPolicyCompileError::QueryIncomplete {
                    completion: CodeQueryCompletion::Cancelled,
                    detail: "taint enclosing-procedure lookup was cancelled".to_owned(),
                });
            }
            ProcedureRangeLookupStatus::BudgetExhausted => {
                return Err(query_budget_error(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    "taint enclosing-procedure lookup exhausted the shared traversal budget",
                ));
            }
            ProcedureRangeLookupStatus::SourceChanged => {
                return Err(TaintPolicyCompileError::SemanticUnavailable(
                    "taint enclosing-procedure lookup observed a changed source snapshot"
                        .to_owned(),
                ));
            }
        }
        let (procedure, call) = select_call(&lookup.handles, &selection)?;
        let (value, point) = select_value(&procedure, &call, &selection.span, binding)?;
        Ok(vec![ResolvedTaintValue {
            point,
            value,
            proof: selection.proof,
            completeness: selection.completeness,
        }])
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
                value: observation.query().value().clone(),
                proof: proof.clone(),
                completeness: completeness.clone(),
            })
            .collect())
    }

    fn discover_value_flow(
        &mut self,
        root: &ProcedureHandle,
    ) -> Result<DiscoveredValueFlow, TaintPolicyCompileError> {
        let oracle = self.selectors.workspace().semantic_oracle_provider();
        let context = OracleCallContext::empty();
        let mut pending = vec![root.clone()];
        let mut seen = HashSet::new();
        let mut seen_bindings = HashSet::new();
        let mut seen_external_targets = HashSet::new();
        let mut snapshots = Vec::new();
        let mut bindings = Vec::new();
        let mut external_targets = Vec::new();
        while let Some(procedure) = pending.pop() {
            if !seen.insert(procedure.clone()) {
                continue;
            }
            let outcome = {
                let mut request = self.selectors.semantic_request();
                oracle
                    .procedure_relations(&procedure, &context, &mut request)
                    .map_err(|error| TaintPolicyCompileError::SemanticProvider(error.to_string()))?
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
            snapshots.push(ValueFlowInput::new(snapshot, status));

            for call_row in procedure.semantics().call_sites() {
                let call = procedure
                    .call_site_handle(call_row.id)
                    .expect("a live procedure owns each retained call site");
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
                let Some(dispatch) = dispatch.available_value() else {
                    continue;
                };
                for boundary in dispatch.boundaries() {
                    if let Some(target) = boundary.exact_external_target()
                        && seen_external_targets.insert(target.clone())
                    {
                        external_targets.push(target.clone());
                    }
                }
                for candidate in dispatch.candidates() {
                    let binding_key = (call.clone(), candidate.target().clone());
                    if !seen_bindings.insert(binding_key) {
                        continue;
                    }
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
                    let status = dispatch_status.merge(SemanticInputStatus::from_outcome(&outcome));
                    if let Some(binding) = outcome.available_value().cloned() {
                        bindings.push(ValueFlowInput::new(binding, status));
                        pending.push(candidate.target().clone());
                    }
                }
            }
        }
        Ok(DiscoveredValueFlow {
            root: root.clone(),
            snapshots,
            bindings,
            procedures: seen,
            external_targets,
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
            discovery.root.artifact().key().dependencies(),
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
        dependencies: brokk_bifrost_analysis::analyzer::semantic::DependencyFingerprint,
        call_behavior: brokk_bifrost_analysis::analyzer::dataflow::UnmodeledCallBehavior,
    ) -> Result<Option<ExternalSemanticSummarySet>, TaintPolicyCompileError> {
        let Some(active) = &self.active_semantic_models else {
            return Ok(None);
        };
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
        if families.is_empty() {
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
                        | CompiledSummaryEffect::UnknownCallBoundary { .. } => {}
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
        let projected = project_policy_findings(
            workspace,
            policy,
            spec,
            plan,
            retained.plan().universe(),
            retained.report(),
            budget,
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
        if !retained.report().is_complete() {
            payload.completion =
                PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery])
                    .map_err(|error| error.to_string())?;
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

fn project_policy_findings(
    workspace: &WorkspaceAnalyzer,
    _policy: &LoadedPolicy,
    spec: &ResolvedTaintPolicySpec,
    plan: &PreparedTaintPlan,
    universe: &TaintUniverse,
    report: &TaintFindingReport,
    budget: &PolicyBudget,
) -> Result<Vec<TaintProjectedFinding>, String> {
    let mut projected = Vec::new();
    let mut projected_sinks = Vec::<ValueFlowEventKey>::new();
    for candidate in report.findings() {
        if projected_sinks
            .iter()
            .any(|sink| sink == candidate.key().sink())
        {
            continue;
        }
        projected_sinks.push(candidate.key().sink().clone());
        let sink_findings = report
            .findings()
            .iter()
            .filter(|finding| finding.key().sink() == candidate.key().sink())
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
            .expect("a discovered sink retains at least one finding row");
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
                budget.max_origins_per_finding(),
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
    let (witnesses, witness_refs, omitted_witnesses) =
        project_taint_witnesses(workspace, group, finding_key, budget)?;
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
        },
        witness_refs,
    ))
}

fn project_taint_witnesses(
    workspace: &WorkspaceAnalyzer,
    group: &ProjectedSourceGroup<'_>,
    finding_key: &str,
    budget: &PolicyBudget,
) -> Result<(Vec<BoundedWitness>, Vec<WitnessId>, usize), String> {
    let mut retained = Vec::<&SummaryWitness>::new();
    for witness in group.origins.iter().flat_map(|origin| origin.witnesses()) {
        let witness = witness.as_ref();
        if !retained.contains(&witness) {
            retained.push(witness);
        }
    }
    let retained_limit = retained.len().min(budget.max_witnesses_per_finding());
    let mut omitted = retained.len().saturating_sub(retained_limit);
    let mut witnesses = Vec::new();
    let mut witness_refs = Vec::new();
    for (index, witness) in retained.into_iter().take(retained_limit).enumerate() {
        let id_key =
            super::semantic_identity::stable_hex(format!("{finding_key}:{index}").as_bytes());
        let id = WitnessId::try_new("bifrost", id_key).map_err(|error| error.to_string())?;
        let projected = super::witness_projection::project_summary_witness(
            workspace,
            witness,
            id.clone(),
            budget.max_witness_steps(),
            budget.max_witness_bytes(),
            true,
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
        witnesses.push(projected);
        witness_refs.push(id);
    }
    Ok((witnesses, witness_refs, omitted))
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

fn select_call(
    procedures: &[ProcedureHandle],
    selection: &SelectedSite,
) -> Result<
    (
        ProcedureHandle,
        brokk_bifrost_analysis::analyzer::semantic::CallSiteHandle,
    ),
    TaintPolicyCompileError,
> {
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
        return Err(TaintPolicyCompileError::SemanticUnavailable(
            "selected source row does not identify a semantic call site".to_owned(),
        ));
    };
    if candidates
        .get(1)
        .is_some_and(|next| (next.0, next.1) == (best.0, best.1))
    {
        return Err(TaintPolicyCompileError::AmbiguousSemanticSite(
            "selected source row identifies multiple equal semantic call sites".to_owned(),
        ));
    }
    Ok((best.2.clone(), best.3.clone()))
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
                ValueFlowObservationPhase::BeforeEffects,
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
                ValueFlowObservationPhase::BeforeEffects,
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
