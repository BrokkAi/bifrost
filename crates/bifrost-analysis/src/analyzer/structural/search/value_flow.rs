use std::sync::Arc;

use super::witness_projection::{
    hash_public_locator, locator_file, locator_range, public_evidence, retain_prefix_by_bytes,
    saturating_u64,
};
use super::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryFlowCarrierSymbol, CodeQueryFlowCertainty, CodeQueryFlowCompletion,
    CodeQueryFlowDeclarationSegment, CodeQueryFlowEndpoint, CodeQueryFlowEvent,
    CodeQueryFlowFactSymbol, CodeQueryFlowMustStatus, CodeQueryFlowPortSymbol,
    CodeQueryFlowReachability, CodeQueryFlowSelectorSymbol, CodeQueryFlowSolverTermination,
    CodeQueryFlowSymbolSite, CodeQueryFlowWitness, CodeQueryFlowWitnessStep,
    CodeQueryFlowWitnessStepKind, CodeQuerySemanticCompleteness, CodeQuerySemanticEvidence,
    CodeQuerySemanticProof, CodeQuerySourceSite, CodeQueryValueFlowLimits, CodeQueryValueFlowWork,
    SemanticProcedureValue,
};
use crate::analyzer::dataflow::{
    DataflowRequest, FactId, PathQuality, SemanticInputStatus, SolverBudget, SolverTermination,
    SummaryWitnessStepKind, WitnessReconstructionLimits, WitnessRetentionLimits,
};
use crate::analyzer::semantic::{
    DispatchBoundaryKind, LengthDelimitedDigest, ProcedureHandle, ProgramPointHandle,
    ReturnTransferKind, SemanticBudget, SemanticLocator,
};
use crate::analyzer::structural::analysis_context::{
    QueryAnalysisContext, QueryAnalysisContextError, ValueFlowPlanRef,
};
use crate::analyzer::structural::query::WitnessTraversal;
use crate::analyzer::value_flow::{
    ValueFlowCarrierKey, ValueFlowMayStatus, ValueFlowMeeting, ValueFlowObservationPhase,
    ValueFlowPlan, ValueFlowPortKey, ValueFlowScopedRootKind, ValueFlowSelectorKey,
    ValueFlowSourceSpec, ValueFlowSummaryResult, solve_value_flow_with_witnesses,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ValueFlowCacheKey {
    root: ProcedureHandle,
    plan_allocation: usize,
}

#[derive(Debug)]
struct ValueFlowAnalysisResult {
    plan: Arc<ValueFlowPlan>,
    result: Arc<ValueFlowSummaryResult>,
}

#[derive(Debug, Clone)]
enum CachedValueFlowAnalysis {
    Complete(Arc<ValueFlowAnalysisResult>),
    Failed,
}

#[derive(Default)]
pub(super) struct ValueFlowQueryState {
    cache: HashMap<ValueFlowCacheKey, CachedValueFlowAnalysis>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    work: CodeQueryValueFlowWork,
    semantic_budget_exhausted: bool,
    query_budget_exhausted: bool,
    witness_reconstruction_steps: usize,
}

#[derive(Debug, Clone)]
pub(super) struct SemanticFlowEndpointValue {
    pub(super) public: CodeQueryFlowEndpoint,
    plan_ref: ValueFlowPlanRef,
    analysis: Arc<ValueFlowAnalysisResult>,
    meeting: Option<ValueFlowMeeting>,
    file: ProjectFile,
    byte_span: std::ops::Range<usize>,
}

#[derive(Debug, Clone)]
pub(super) struct SemanticFlowWitnessValue {
    pub(super) public: CodeQueryFlowWitness,
    file: ProjectFile,
    byte_span: std::ops::Range<usize>,
}

impl ValueFlowQueryState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn endpoints(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        workspace_generation: u64,
        analysis_context: Option<&QueryAnalysisContext>,
        procedure: &SemanticProcedureValue,
        plan_ref: &ValueFlowPlanRef,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryValueFlowLimits,
        max_endpoints: usize,
        cancellation: &CancellationToken,
    ) -> Vec<SemanticFlowEndpointValue> {
        let Some(analysis_context) = analysis_context else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::UnresolvedValueFlowPlanReference,
                format!("value-flow plan reference `{plan_ref}` was not supplied by the host"),
            );
            return Vec::new();
        };
        let Some(handle) = analysis_context.value_flow_handle(plan_ref) else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::UnresolvedValueFlowPlanReference,
                format!("value-flow plan reference `{plan_ref}` is not registered"),
            );
            return Vec::new();
        };
        let registration = match analysis_context.resolve_value_flow(
            workspace_generation,
            &procedure.handle,
            handle,
        ) {
            Ok(registration) => registration,
            Err(error) => {
                self.push_context_error(error);
                return Vec::new();
            }
        };
        let plan = Arc::clone(registration.plan());
        let root = plan.root().clone();
        let cache_key = ValueFlowCacheKey {
            root: root.clone(),
            plan_allocation: Arc::as_ptr(&plan) as usize,
        };
        let analysis = match self.cache.get(&cache_key).cloned() {
            Some(CachedValueFlowAnalysis::Complete(analysis)) => {
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                analysis
            }
            Some(CachedValueFlowAnalysis::Failed) => {
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                return Vec::new();
            }
            None => {
                self.work.solves = self.work.solves.saturating_add(1);
                let retention = WitnessRetentionLimits::best_effort(
                    1,
                    limits.max_retained_relations,
                    limits.max_retained_bytes,
                )
                .expect("validated CodeQuery value-flow retention limits are positive");
                let mut solver_budget = SolverBudget::new(limits.solver_work);
                let mut request = DataflowRequest::new(&mut solver_budget, cancellation);
                let provider = workspace.icfg_provider();
                let solved = match solve_value_flow_with_witnesses(
                    &root,
                    &provider,
                    &plan,
                    retention,
                    semantic_budget,
                    &mut request,
                ) {
                    Ok(solved) => solved,
                    Err(error) => {
                        self.work.failed_solves = self.work.failed_solves.saturating_add(1);
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::ValueFlowProviderFailed,
                            format!("value-flow analysis failed: {error}"),
                        );
                        self.cache
                            .insert(cache_key, CachedValueFlowAnalysis::Failed);
                        return Vec::new();
                    }
                };
                self.work.reached_rows = self
                    .work
                    .reached_rows
                    .saturating_add(saturating_u64(solved.result().reached().len()));
                self.work.meetings = self
                    .work
                    .meetings
                    .saturating_add(saturating_u64(solved.meetings().len()));
                match solved.result().termination() {
                    SolverTermination::FixedPoint => {
                        self.work.fixed_point_solves =
                            self.work.fixed_point_solves.saturating_add(1)
                    }
                    SolverTermination::Cancelled => {
                        self.work.cancelled_solves = self.work.cancelled_solves.saturating_add(1);
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::Cancelled,
                            "value-flow solver was cancelled".to_string(),
                        );
                    }
                    SolverTermination::ExceededBudget(exceeded) => {
                        self.work.budget_exhausted_solves =
                            self.work.budget_exhausted_solves.saturating_add(1);
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::ValueFlowSolverBudgetExhausted,
                            exceeded.to_string(),
                        );
                    }
                }
                self.record_semantic_status(
                    plan.discovery_status()
                        .merge(solved.result().coverage().semantic_status()),
                );
                if !solved.is_complete() {
                    self.push_diagnostic(
                        CodeQueryDiagnosticCode::ValueFlowAnalysisPartial,
                        "value-flow analysis retained incomplete semantic evidence".to_string(),
                    );
                }
                let analysis = Arc::new(ValueFlowAnalysisResult {
                    plan,
                    result: Arc::new(solved),
                });
                self.cache.insert(
                    cache_key,
                    CachedValueFlowAnalysis::Complete(Arc::clone(&analysis)),
                );
                analysis
            }
        };
        self.project_endpoints(
            workspace,
            plan_ref,
            analysis,
            max_endpoints.min(limits.max_endpoints),
        )
    }

    fn project_endpoints(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        plan_ref: &ValueFlowPlanRef,
        analysis: Arc<ValueFlowAnalysisResult>,
        max_endpoints: usize,
    ) -> Vec<SemanticFlowEndpointValue> {
        let semantic_status = analysis_semantic_status(&analysis);
        let completion = public_completion(semantic_status, &analysis.result);
        let solver_termination = public_termination(analysis.result.result().termination());
        let ambiguous = matches!(
            analysis.plan.discovery_status(),
            SemanticInputStatus::Ambiguous
        ) || matches!(
            analysis.result.result().coverage().semantic_status(),
            SemanticInputStatus::Ambiguous
        );
        let mut meetings_by_sink = HashMap::default();
        for meeting in analysis.result.meetings() {
            meetings_by_sink
                .entry(meeting.sink())
                .or_insert_with(Vec::new)
                .push(meeting);
        }
        let mut projected = Vec::new();
        'sinks: for (sink_id, sink) in analysis.plan.sinks() {
            if projected.len() >= max_endpoints {
                self.record_endpoint_budget(1);
                break;
            }
            let sink_public = public_event(workspace, plan_ref, "sink", sink);
            match meetings_by_sink.remove(&sink_id) {
                Some(meetings) => {
                    for meeting in meetings {
                        if projected.len() >= max_endpoints {
                            self.record_endpoint_budget(1);
                            break 'sinks;
                        }
                        let source = analysis
                            .plan
                            .source(meeting.source())
                            .expect("validated meeting source resolves");
                        let source_public = public_event(workspace, plan_ref, "source", source);
                        let endpoint_id = endpoint_id(
                            plan_ref,
                            Some(&source_public.id),
                            &sink_public.id,
                            &analysis.plan,
                            &analysis.result,
                            meeting,
                        );
                        let locator = sink.key().site();
                        let path_qualities = meeting
                            .path_qualities()
                            .iter()
                            .map(public_path_quality)
                            .collect::<Vec<_>>();
                        let retained_witnesses = path_qualities.len();
                        projected.push(SemanticFlowEndpointValue {
                            public: CodeQueryFlowEndpoint {
                                id: endpoint_id,
                                plan_ref: plan_ref.to_string(),
                                source: Some(source_public),
                                sink: sink_public.clone(),
                                reachability: CodeQueryFlowReachability::Reached,
                                certainty: Some(match meeting.may_status() {
                                    ValueFlowMayStatus::Proven => CodeQueryFlowCertainty::Exact,
                                    ValueFlowMayStatus::Unproven => CodeQueryFlowCertainty::May,
                                }),
                                must: CodeQueryFlowMustStatus::NotEstablished,
                                ambiguous,
                                completion,
                                semantic_status: semantic_status.label(),
                                solver_termination,
                                path: locator.path().as_str().to_string(),
                                language: locator.language().config_label(),
                                range: locator_range(workspace, locator),
                                path_qualities,
                                retained_witnesses,
                                omitted_witnesses: 0,
                            },
                            plan_ref: plan_ref.clone(),
                            analysis: Arc::clone(&analysis),
                            meeting: Some(meeting.clone()),
                            file: locator_file(workspace, locator),
                            byte_span: locator_span(locator),
                        });
                    }
                }
                None => {
                    let reachability = if analysis.result.is_complete() {
                        CodeQueryFlowReachability::NotReached
                    } else {
                        CodeQueryFlowReachability::Inconclusive
                    };
                    let locator = sink.key().site();
                    projected.push(SemanticFlowEndpointValue {
                        public: CodeQueryFlowEndpoint {
                            id: negative_endpoint_id(plan_ref, &sink_public.id, reachability),
                            plan_ref: plan_ref.to_string(),
                            source: None,
                            sink: sink_public,
                            reachability,
                            certainty: None,
                            must: CodeQueryFlowMustStatus::NotEstablished,
                            ambiguous,
                            completion,
                            semantic_status: semantic_status.label(),
                            solver_termination,
                            path: locator.path().as_str().to_string(),
                            language: locator.language().config_label(),
                            range: locator_range(workspace, locator),
                            path_qualities: Vec::new(),
                            retained_witnesses: 0,
                            omitted_witnesses: 0,
                        },
                        plan_ref: plan_ref.clone(),
                        analysis: Arc::clone(&analysis),
                        meeting: None,
                        file: locator_file(workspace, locator),
                        byte_span: locator_span(locator),
                    });
                }
            }
            self.work.sink_outcomes = self.work.sink_outcomes.saturating_add(1);
        }
        projected
    }

    pub(super) fn witnesses(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        endpoint: &SemanticFlowEndpointValue,
        traversal: &WitnessTraversal,
        limits: CodeQueryValueFlowLimits,
    ) -> Vec<SemanticFlowWitnessValue> {
        let Some(meeting) = endpoint.meeting.as_ref() else {
            return Vec::new();
        };
        let query_max_steps = traversal
            .max_steps
            .unwrap_or(limits.max_witness_steps)
            .min(limits.max_witness_steps);
        let query_max_bytes = traversal
            .max_bytes
            .unwrap_or(limits.max_witness_bytes)
            .min(limits.max_witness_bytes);
        let mut values = Vec::new();
        for (witness_index, quality) in meeting.path_qualities().iter().enumerate() {
            let remaining_witnesses = limits
                .max_witnesses
                .saturating_sub(usize::try_from(self.work.witnesses).unwrap_or(usize::MAX));
            let remaining_steps = limits
                .max_total_witness_steps
                .saturating_sub(self.witness_reconstruction_steps);
            let remaining_expansions = limits.max_total_witness_expansions.saturating_sub(
                usize::try_from(self.work.witness_expansions).unwrap_or(usize::MAX),
            );
            let remaining_bytes = limits
                .max_total_witness_bytes
                .saturating_sub(usize::try_from(self.work.witness_bytes).unwrap_or(usize::MAX));
            if remaining_witnesses == 0
                || remaining_steps == 0
                || remaining_expansions == 0
                || remaining_bytes == 0
            {
                self.record_witness_budget(1);
                break;
            }
            let reconstruction = WitnessReconstructionLimits::new(
                limits.max_witness_steps.min(remaining_steps),
                limits.max_witness_expansions.min(remaining_expansions),
            )
            .expect("positive remaining CodeQuery value-flow witness budget");
            let Ok(witness) =
                endpoint
                    .analysis
                    .result
                    .witness_for_meeting(meeting, quality, reconstruction)
            else {
                continue;
            };
            self.work.witness_expansions = self
                .work
                .witness_expansions
                .saturating_add(saturating_u64(witness.work().evidence_expansions()));
            self.witness_reconstruction_steps = self
                .witness_reconstruction_steps
                .saturating_add(witness.work().emitted_steps());
            let (steps, retained_bytes, removed_steps) = retain_prefix_by_bytes(
                witness.steps().iter().map(|step| {
                    public_value_flow_witness_step(
                        workspace,
                        &endpoint.plan_ref,
                        &endpoint.analysis.plan,
                        &endpoint.analysis.result,
                        step,
                    )
                }),
                query_max_steps.min(remaining_steps),
                query_max_bytes.min(remaining_bytes),
                |step| serde_json::to_vec(step).map_or(usize::MAX, |bytes| bytes.len()),
            );
            let truncated = witness.truncated() || removed_steps > 0;
            if truncated {
                self.work.witness_truncated = true;
            }
            if removed_steps > 0 {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::ValueFlowWitnessTruncated,
                    format!(
                        "value-flow witness projection omitted at least {removed_steps} step(s)"
                    ),
                );
            } else if witness.truncated() {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::ValueFlowWitnessTruncated,
                    format!(
                        "value-flow witness reconstruction or retention omitted at least {} step(s)",
                        witness.omitted_steps_lower_bound()
                    ),
                );
            }
            self.work.witnesses = self.work.witnesses.saturating_add(1);
            self.work.witness_steps = self
                .work
                .witness_steps
                .saturating_add(saturating_u64(steps.len()));
            self.work.witness_bytes = self
                .work
                .witness_bytes
                .saturating_add(saturating_u64(retained_bytes));
            let id = witness_id(&endpoint.public.id, witness_index, quality);
            let mut public_quality = public_path_quality(quality);
            if truncated {
                public_quality.completeness = CodeQuerySemanticCompleteness::Partial;
                public_quality.completeness_reason = Some(if removed_steps > 0 {
                    format!("query witness limits omitted at least {removed_steps} step(s)")
                } else if witness.retention_truncated() {
                    "retained witness evidence was exhausted during the solver run".to_string()
                } else {
                    format!(
                        "witness reconstruction omitted at least {} step(s)",
                        witness.omitted_steps_lower_bound()
                    )
                });
            }
            values.push(SemanticFlowWitnessValue {
                public: CodeQueryFlowWitness {
                    id,
                    endpoint_id: endpoint.public.id.clone(),
                    plan_ref: endpoint.public.plan_ref.clone(),
                    witness_index,
                    path: endpoint.public.path.clone(),
                    language: endpoint.public.language,
                    range: endpoint.public.range,
                    quality: public_quality,
                    steps,
                    retained_bytes,
                    truncated,
                    omitted_steps_lower_bound: witness
                        .omitted_steps_lower_bound()
                        .saturating_add(removed_steps),
                    alternatives_truncated: witness.alternatives_truncated(),
                    retention_truncated: witness.retention_truncated(),
                },
                file: endpoint.file.clone(),
                byte_span: endpoint.byte_span.clone(),
            });
        }
        values
    }

    fn record_endpoint_budget(&mut self, omitted_lower_bound: usize) {
        self.query_budget_exhausted = true;
        self.work.endpoint_truncated = true;
        self.work.omitted_endpoints = self
            .work
            .omitted_endpoints
            .saturating_add(saturating_u64(omitted_lower_bound));
        self.push_diagnostic(
            CodeQueryDiagnosticCode::PipelineBudgetExhausted,
            format!(
                "value-flow endpoint projection omitted at least {omitted_lower_bound} endpoint(s)"
            ),
        );
    }

    fn record_witness_budget(&mut self, omitted_lower_bound: usize) {
        self.query_budget_exhausted = true;
        self.work.witness_truncated = true;
        self.work.omitted_witnesses = self
            .work
            .omitted_witnesses
            .saturating_add(saturating_u64(omitted_lower_bound));
        self.push_diagnostic(
            CodeQueryDiagnosticCode::ValueFlowWitnessTruncated,
            format!(
                "value-flow request witness budget omitted at least {omitted_lower_bound} witness(es)"
            ),
        );
    }

    fn record_semantic_status(&mut self, status: SemanticInputStatus) {
        match status {
            SemanticInputStatus::Unsupported { capability } => self.push_diagnostic(
                CodeQueryDiagnosticCode::ValueFlowCapabilityUnsupported,
                format!(
                    "value-flow analysis requires unsupported semantic capability `{}`",
                    capability.label()
                ),
            ),
            SemanticInputStatus::ExceededBudget { exceeded } => {
                self.semantic_budget_exhausted = true;
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    format!("value-flow semantic input exceeded its budget: {exceeded}"),
                );
            }
            SemanticInputStatus::Cancelled => self.push_diagnostic(
                CodeQueryDiagnosticCode::Cancelled,
                "value-flow semantic input materialization was cancelled".to_string(),
            ),
            SemanticInputStatus::Ambiguous
            | SemanticInputStatus::Unknown
            | SemanticInputStatus::Unproven => self.push_diagnostic(
                CodeQueryDiagnosticCode::ValueFlowAnalysisPartial,
                format!("value-flow semantic input is {}", status.label()),
            ),
            SemanticInputStatus::Complete => {}
        }
    }

    fn push_context_error(&mut self, error: QueryAnalysisContextError) {
        if matches!(
            error,
            QueryAnalysisContextError::ValidationBudgetExceeded { .. }
        ) {
            self.semantic_budget_exhausted = true;
        }
        let code = match error {
            QueryAnalysisContextError::UnresolvedValueFlowPlanReference { .. } => {
                CodeQueryDiagnosticCode::UnresolvedValueFlowPlanReference
            }
            QueryAnalysisContextError::ValueFlowRootMismatch => {
                CodeQueryDiagnosticCode::ValueFlowRootMismatch
            }
            QueryAnalysisContextError::StaleValueFlowPlanHandle => {
                CodeQueryDiagnosticCode::ValueFlowHandleStale
            }
            QueryAnalysisContextError::Cancelled => CodeQueryDiagnosticCode::Cancelled,
            QueryAnalysisContextError::ValidationBudgetExceeded { .. } => {
                CodeQueryDiagnosticCode::SemanticBudgetExhausted
            }
            _ => CodeQueryDiagnosticCode::ValueFlowRegistrationStale,
        };
        self.push_diagnostic(code, error.to_string());
    }

    fn push_diagnostic(&mut self, code: CodeQueryDiagnosticCode, message: String) {
        if self
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == code && diagnostic.message == message)
        {
            return;
        }
        self.diagnostics.push(CodeQueryDiagnostic {
            code,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message,
        });
    }

    pub(super) fn take_diagnostics(&mut self) -> Vec<CodeQueryDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    pub(super) const fn work(&self) -> CodeQueryValueFlowWork {
        self.work
    }

    pub(super) const fn semantic_budget_exhausted(&self) -> bool {
        self.semantic_budget_exhausted
    }

    pub(super) const fn query_budget_exhausted(&self) -> bool {
        self.query_budget_exhausted
    }
}

impl SemanticFlowEndpointValue {
    pub(super) fn key(&self) -> &str {
        &self.public.id
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn byte_span(&self) -> std::ops::Range<usize> {
        self.byte_span.clone()
    }

    pub(super) fn public_ref(&self) -> super::CodeQueryResultRef {
        super::CodeQueryResultRef::FlowEndpoint {
            id: self.public.id.clone(),
            plan_ref: self.public.plan_ref.clone(),
            path: self.public.path.clone(),
            range: self.public.range,
        }
    }
}

impl SemanticFlowWitnessValue {
    pub(super) fn key(&self) -> &str {
        &self.public.id
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn byte_span(&self) -> std::ops::Range<usize> {
        self.byte_span.clone()
    }

    pub(super) fn public_ref(&self) -> super::CodeQueryResultRef {
        super::CodeQueryResultRef::FlowWitness {
            id: self.public.id.clone(),
            endpoint_id: self.public.endpoint_id.clone(),
            path: self.public.path.clone(),
            range: self.public.range,
        }
    }
}

fn analysis_semantic_status(analysis: &ValueFlowAnalysisResult) -> SemanticInputStatus {
    analysis
        .plan
        .discovery_status()
        .merge(analysis.result.result().coverage().semantic_status())
}

fn public_completion(
    semantic_status: SemanticInputStatus,
    result: &ValueFlowSummaryResult,
) -> CodeQueryFlowCompletion {
    if result.is_complete() && matches!(semantic_status, SemanticInputStatus::Complete) {
        return CodeQueryFlowCompletion::Complete;
    }
    match result.result().termination() {
        SolverTermination::Cancelled => CodeQueryFlowCompletion::Cancelled,
        SolverTermination::ExceededBudget(_) => CodeQueryFlowCompletion::BudgetExhausted,
        SolverTermination::FixedPoint => match semantic_status {
            SemanticInputStatus::Cancelled => CodeQueryFlowCompletion::Cancelled,
            SemanticInputStatus::ExceededBudget { .. } => CodeQueryFlowCompletion::BudgetExhausted,
            SemanticInputStatus::Unsupported { .. } => CodeQueryFlowCompletion::Unsupported,
            SemanticInputStatus::Complete
            | SemanticInputStatus::Ambiguous
            | SemanticInputStatus::Unknown
            | SemanticInputStatus::Unproven => CodeQueryFlowCompletion::Incomplete,
        },
    }
}

fn public_termination(termination: SolverTermination) -> CodeQueryFlowSolverTermination {
    match termination {
        SolverTermination::FixedPoint => CodeQueryFlowSolverTermination::FixedPoint,
        SolverTermination::Cancelled => CodeQueryFlowSolverTermination::Cancelled,
        SolverTermination::ExceededBudget(_) => CodeQueryFlowSolverTermination::BudgetExhausted,
    }
}

fn public_event(
    workspace: &WorkspaceAnalyzer,
    plan_ref: &ValueFlowPlanRef,
    role: &'static str,
    spec: &impl FlowEventSpec,
) -> CodeQueryFlowEvent {
    let locator = spec.locator();
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.flow_event.v1");
    digest.push(plan_ref.to_string().as_bytes());
    digest.push(role.as_bytes());
    hash_public_locator(&mut digest, locator);
    digest.push(&spec.ordinal().to_le_bytes());
    CodeQueryFlowEvent {
        id: digest.finish().to_string(),
        site: public_symbol_site(workspace, locator),
        path: locator.path().as_str().to_string(),
        range: locator_range(workspace, locator),
        phase: spec.phase_label(),
        ordinal: spec.ordinal(),
        carrier: public_carrier_symbol(
            workspace,
            &spec
                .carrier()
                .stable_key()
                .expect("validated value-flow event carrier has stable identity"),
        ),
    }
}

trait FlowEventSpec {
    fn locator(&self) -> &SemanticLocator;
    fn ordinal(&self) -> u32;
    fn phase_label(&self) -> &'static str;
    fn carrier(&self) -> &crate::analyzer::value_flow::ValueFlowCarrier;
}

impl FlowEventSpec for ValueFlowSourceSpec {
    fn locator(&self) -> &SemanticLocator {
        self.key().site()
    }

    fn ordinal(&self) -> u32 {
        self.key().ordinal()
    }

    fn phase_label(&self) -> &'static str {
        phase_label(self.phase())
    }

    fn carrier(&self) -> &crate::analyzer::value_flow::ValueFlowCarrier {
        ValueFlowSourceSpec::carrier(self)
    }
}

impl FlowEventSpec for crate::analyzer::value_flow::ValueFlowSinkSpec {
    fn locator(&self) -> &SemanticLocator {
        self.key().site()
    }

    fn ordinal(&self) -> u32 {
        self.key().ordinal()
    }

    fn phase_label(&self) -> &'static str {
        phase_label(self.phase())
    }

    fn carrier(&self) -> &crate::analyzer::value_flow::ValueFlowCarrier {
        crate::analyzer::value_flow::ValueFlowSinkSpec::carrier(self)
    }
}

fn phase_label(phase: ValueFlowObservationPhase) -> &'static str {
    match phase {
        ValueFlowObservationPhase::BeforeEffects => "before_effects",
        ValueFlowObservationPhase::AfterEffects => "after_effects",
    }
}

fn endpoint_id(
    plan_ref: &ValueFlowPlanRef,
    source_id: Option<&str>,
    sink_id: &str,
    plan: &ValueFlowPlan,
    result: &ValueFlowSummaryResult,
    meeting: &ValueFlowMeeting,
) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.flow_endpoint.v1");
    digest.push(plan_ref.to_string().as_bytes());
    digest.push(source_id.unwrap_or("").as_bytes());
    digest.push(sink_id.as_bytes());
    hash_public_point(&mut digest, meeting.entry().entry_point());
    hash_public_point(&mut digest, meeting.point());
    digest.push(match meeting.may_status() {
        ValueFlowMayStatus::Proven => b"exact",
        ValueFlowMayStatus::Unproven => b"may",
    });
    for quality in meeting.path_qualities().iter() {
        digest.push(if quality.is_proven() {
            b"proven"
        } else {
            b"unproven"
        });
        digest.push(if quality.is_complete() {
            b"complete"
        } else {
            b"partial"
        });
    }
    if let Some(entry_fact) = result.result().fact(meeting.entry().entry_fact()) {
        digest.push(if entry_fact.uncertainty().is_empty() {
            b"certain"
        } else {
            b"uncertain"
        });
        if let Some(carrier) = entry_fact.carrier().and_then(|id| plan.carrier_key(id)) {
            hash_public_carrier_key(&mut digest, carrier);
        } else if entry_fact.sink().is_some() {
            digest.push(b"meeting");
        } else if entry_fact.source().is_some() {
            digest.push(b"source");
        } else {
            digest.push(b"zero");
        }
    }
    digest.finish().to_string()
}

fn hash_public_carrier_key(digest: &mut LengthDelimitedDigest, root: &ValueFlowCarrierKey) {
    enum Part<'key> {
        Carrier(&'key ValueFlowCarrierKey),
        Selector(&'key ValueFlowSelectorKey),
    }

    let mut pending = vec![Part::Carrier(root)];
    while let Some(part) = pending.pop() {
        match part {
            Part::Carrier(ValueFlowCarrierKey::Value {
                locator,
                role,
                ordinal,
            }) => {
                digest.push(b"value");
                hash_public_locator(digest, locator);
                digest.push(role.as_bytes());
                digest.push(&ordinal.unwrap_or(u32::MAX).to_le_bytes());
            }
            Part::Carrier(ValueFlowCarrierKey::Port { procedure, kind }) => {
                digest.push(b"port");
                hash_public_locator(digest, procedure);
                match kind {
                    ValueFlowPortKey::Receiver => digest.push(b"receiver"),
                    ValueFlowPortKey::Parameter { ordinal } => {
                        digest.push(b"parameter");
                        digest.push(&ordinal.to_le_bytes());
                    }
                    ValueFlowPortKey::NormalReturn => digest.push(b"normal_return"),
                    ValueFlowPortKey::ExceptionalReturn => digest.push(b"exceptional_return"),
                    ValueFlowPortKey::Capture { slot } => {
                        digest.push(b"capture");
                        digest.push(&slot.to_le_bytes());
                    }
                }
            }
            Part::Carrier(ValueFlowCarrierKey::Allocation { locator }) => {
                digest.push(b"allocation");
                hash_public_locator(digest, locator);
            }
            Part::Carrier(ValueFlowCarrierKey::CallResult {
                call,
                result,
                callee,
            }) => {
                digest.push(b"call_result");
                hash_public_locator(digest, call);
                hash_public_locator(digest, callee);
                pending.push(Part::Carrier(result));
            }
            Part::Carrier(ValueFlowCarrierKey::ScopedRoot { kind, locator }) => {
                digest.push(b"scoped_root");
                digest.push(match kind {
                    ValueFlowScopedRootKind::Static => b"static",
                    ValueFlowScopedRootKind::LexicalCell => b"lexical_cell",
                    ValueFlowScopedRootKind::TypeSummary => b"type_summary",
                    ValueFlowScopedRootKind::ModuleObject => b"module_object",
                    ValueFlowScopedRootKind::External => b"external",
                });
                hash_public_locator(digest, locator);
            }
            Part::Carrier(ValueFlowCarrierKey::Location {
                root,
                selectors,
                exact,
            }) => {
                digest.push(b"location");
                digest.push(if *exact { b"exact" } else { b"prefix" });
                digest.push(&saturating_u64(selectors.len()).to_le_bytes());
                for selector in selectors.iter().rev() {
                    pending.push(Part::Selector(selector));
                }
                pending.push(Part::Carrier(root));
            }
            Part::Selector(ValueFlowSelectorKey::Field(locator)) => {
                digest.push(b"field");
                hash_public_locator(digest, locator);
            }
            Part::Selector(ValueFlowSelectorKey::ExactIndex(index)) => {
                digest.push(b"exact_index");
                pending.push(Part::Carrier(index));
            }
            Part::Selector(ValueFlowSelectorKey::AnyIndex) => digest.push(b"any_index"),
        }
    }
}

fn negative_endpoint_id(
    plan_ref: &ValueFlowPlanRef,
    sink_id: &str,
    reachability: CodeQueryFlowReachability,
) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.flow_endpoint.v1");
    digest.push(plan_ref.to_string().as_bytes());
    digest.push(b"");
    digest.push(sink_id.as_bytes());
    digest.push(match reachability {
        CodeQueryFlowReachability::Reached => b"reached",
        CodeQueryFlowReachability::NotReached => b"not_reached",
        CodeQueryFlowReachability::Inconclusive => b"inconclusive",
    });
    digest.finish().to_string()
}

fn witness_id(endpoint_id: &str, witness_index: usize, quality: PathQuality) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.flow_witness.v1");
    digest.push(endpoint_id.as_bytes());
    digest.push(&(witness_index as u64).to_le_bytes());
    digest.push(if quality.is_proven() {
        b"proven"
    } else {
        b"unproven"
    });
    digest.push(if quality.is_complete() {
        b"complete"
    } else {
        b"partial"
    });
    digest.finish().to_string()
}

fn public_path_quality(quality: PathQuality) -> CodeQuerySemanticEvidence {
    CodeQuerySemanticEvidence {
        proof: if quality.is_proven() {
            CodeQuerySemanticProof::Proven
        } else {
            CodeQuerySemanticProof::Unproven
        },
        proof_reason: None,
        completeness: if quality.is_complete() {
            CodeQuerySemanticCompleteness::Complete
        } else {
            CodeQuerySemanticCompleteness::Partial
        },
        completeness_reason: None,
    }
}

pub(crate) fn public_witness_step(
    workspace: &WorkspaceAnalyzer,
    step: &crate::analyzer::dataflow::SummaryWitnessStep,
) -> CodeQueryFlowWitnessStep {
    let kind = match step.kind() {
        SummaryWitnessStepKind::Seed => CodeQueryFlowWitnessStepKind::Seed,
        SummaryWitnessStepKind::Edge(kind) => CodeQueryFlowWitnessStepKind::Edge {
            edge_kind: kind.label(),
        },
        SummaryWitnessStepKind::EndSummaryGap(kind) => {
            CodeQueryFlowWitnessStepKind::EndSummaryGap {
                return_kind: match kind {
                    ReturnTransferKind::Normal => "normal",
                    ReturnTransferKind::Exceptional => "exceptional",
                },
            }
        }
    };
    CodeQueryFlowWitnessStep {
        kind,
        source: point_site(workspace, step.source()),
        source_symbol: None,
        target: step.target().map(|point| point_site(workspace, point)),
        target_symbol: None,
        origin: step.origin().map(|call| call_site(workspace, call)),
        origin_symbol: None,
        boundary: step.boundary().map(boundary_label),
        input: None,
        output: None,
        evidence: public_evidence(step.proof(), step.completeness()),
    }
}

fn public_value_flow_witness_step(
    workspace: &WorkspaceAnalyzer,
    plan_ref: &ValueFlowPlanRef,
    plan: &ValueFlowPlan,
    result: &ValueFlowSummaryResult,
    step: &crate::analyzer::dataflow::SummaryWitnessStep,
) -> CodeQueryFlowWitnessStep {
    let mut public = public_witness_step(workspace, step);
    public.source_symbol = Some(point_symbol_site(workspace, step.source()));
    public.target_symbol = step
        .target()
        .map(|point| point_symbol_site(workspace, point));
    public.origin_symbol = step.origin().map(|call| call_symbol_site(workspace, call));
    public.input = Some(public_fact_symbol(
        workspace,
        plan_ref,
        plan,
        result,
        step.input_fact(),
    ));
    public.output = Some(public_fact_symbol(
        workspace,
        plan_ref,
        plan,
        result,
        step.output_fact(),
    ));
    public
}

fn public_fact_symbol(
    workspace: &WorkspaceAnalyzer,
    plan_ref: &ValueFlowPlanRef,
    plan: &ValueFlowPlan,
    result: &ValueFlowSummaryResult,
    fact_id: FactId,
) -> CodeQueryFlowFactSymbol {
    let fact = *result
        .result()
        .fact(fact_id)
        .expect("validated value-flow witness fact resolves");
    let uncertain = !fact.uncertainty().is_empty();
    match (fact.source(), fact.carrier(), fact.sink()) {
        (None, None, None) => CodeQueryFlowFactSymbol::Zero,
        (Some(source_id), Some(carrier_id), None) => CodeQueryFlowFactSymbol::Carrier {
            source: Box::new(public_event(
                workspace,
                plan_ref,
                "source",
                plan.source(source_id)
                    .expect("validated value-flow witness source resolves"),
            )),
            carrier: Box::new(public_carrier_symbol(
                workspace,
                plan.carrier_key(carrier_id)
                    .expect("validated value-flow witness carrier resolves"),
            )),
            uncertain,
        },
        (Some(source_id), None, Some(sink_id)) => CodeQueryFlowFactSymbol::Meeting {
            source: Box::new(public_event(
                workspace,
                plan_ref,
                "source",
                plan.source(source_id)
                    .expect("validated value-flow witness source resolves"),
            )),
            sink: Box::new(public_event(
                workspace,
                plan_ref,
                "sink",
                plan.sink(sink_id)
                    .expect("validated value-flow witness sink resolves"),
            )),
            uncertain,
        },
        shape => panic!("invalid value-flow witness fact shape: {shape:?}"),
    }
}

fn public_carrier_symbol(
    workspace: &WorkspaceAnalyzer,
    key: &ValueFlowCarrierKey,
) -> CodeQueryFlowCarrierSymbol {
    let id = public_carrier_symbol_id(key);
    match key {
        ValueFlowCarrierKey::Value {
            locator,
            role,
            ordinal,
        } => CodeQueryFlowCarrierSymbol::Value {
            id,
            site: public_symbol_site(workspace, locator),
            role: role.to_string(),
            ordinal: *ordinal,
        },
        ValueFlowCarrierKey::Port { procedure, kind } => CodeQueryFlowCarrierSymbol::Port {
            id,
            procedure: public_symbol_site(workspace, procedure),
            port: match kind {
                ValueFlowPortKey::Receiver => CodeQueryFlowPortSymbol::Receiver,
                ValueFlowPortKey::Parameter { ordinal } => {
                    CodeQueryFlowPortSymbol::Parameter { ordinal: *ordinal }
                }
                ValueFlowPortKey::NormalReturn => CodeQueryFlowPortSymbol::NormalReturn,
                ValueFlowPortKey::ExceptionalReturn => CodeQueryFlowPortSymbol::ExceptionalReturn,
                ValueFlowPortKey::Capture { slot } => {
                    CodeQueryFlowPortSymbol::Capture { slot: *slot }
                }
            },
        },
        ValueFlowCarrierKey::Allocation { locator } => CodeQueryFlowCarrierSymbol::Allocation {
            id,
            site: public_symbol_site(workspace, locator),
        },
        ValueFlowCarrierKey::CallResult {
            call,
            result,
            callee,
        } => CodeQueryFlowCarrierSymbol::CallResult {
            id,
            call: public_symbol_site(workspace, call),
            result: Box::new(public_carrier_symbol(workspace, result)),
            callee: public_symbol_site(workspace, callee),
        },
        ValueFlowCarrierKey::ScopedRoot { kind, locator } => {
            CodeQueryFlowCarrierSymbol::ScopedRoot {
                id,
                root_kind: match kind {
                    ValueFlowScopedRootKind::Static => "static",
                    ValueFlowScopedRootKind::LexicalCell => "lexical_cell",
                    ValueFlowScopedRootKind::TypeSummary => "type_summary",
                    ValueFlowScopedRootKind::ModuleObject => "module_object",
                    ValueFlowScopedRootKind::External => "external",
                },
                site: public_symbol_site(workspace, locator),
            }
        }
        ValueFlowCarrierKey::Location {
            root,
            selectors,
            exact,
        } => CodeQueryFlowCarrierSymbol::Location {
            id,
            root: Box::new(public_carrier_symbol(workspace, root)),
            selectors: selectors
                .iter()
                .map(|selector| match selector {
                    ValueFlowSelectorKey::Field(locator) => CodeQueryFlowSelectorSymbol::Field {
                        field: public_symbol_site(workspace, locator),
                    },
                    ValueFlowSelectorKey::ExactIndex(index) => {
                        CodeQueryFlowSelectorSymbol::ExactIndex {
                            index: Box::new(public_carrier_symbol(workspace, index)),
                        }
                    }
                    ValueFlowSelectorKey::AnyIndex => CodeQueryFlowSelectorSymbol::AnyIndex,
                })
                .collect(),
            exact: *exact,
        },
    }
}

fn public_carrier_symbol_id(key: &ValueFlowCarrierKey) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.flow_carrier.v1");
    hash_public_carrier_key(&mut digest, key);
    digest.finish().to_string()
}

fn public_symbol_site(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> CodeQueryFlowSymbolSite {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.flow_symbol_site.v1");
    hash_public_locator(&mut digest, locator);
    let anchor = locator.anchor();
    let span = anchor.span();
    CodeQueryFlowSymbolSite {
        id: digest.finish().to_string(),
        path: locator.path().as_str().to_string(),
        language: locator.language().stable_label(),
        declaration: locator
            .declaration()
            .segments()
            .iter()
            .map(|segment| {
                let span = segment.anchor().span();
                CodeQueryFlowDeclarationSegment {
                    kind: segment.kind().stable_label(),
                    name: segment.name().map(str::to_string),
                    start_byte: span.start_byte(),
                    end_byte: span.end_byte(),
                    occurrence: segment.anchor().occurrence(),
                    sibling_ordinal: segment.sibling_ordinal(),
                }
            })
            .collect(),
        role: locator.role().stable_label(),
        start_byte: span.start_byte(),
        end_byte: span.end_byte(),
        occurrence: anchor.occurrence(),
        range: locator_range(workspace, locator),
    }
}

fn boundary_label(boundary: &DispatchBoundaryKind) -> String {
    match boundary {
        DispatchBoundaryKind::External(_) => "external",
        DispatchBoundaryKind::Unmaterialized(_) => "unmaterialized",
        DispatchBoundaryKind::Deferred { .. } => "deferred",
        DispatchBoundaryKind::Unresolved => "unresolved",
        DispatchBoundaryKind::Truncated => "truncated",
    }
    .to_string()
}

fn point_site(workspace: &WorkspaceAnalyzer, handle: &ProgramPointHandle) -> CodeQuerySourceSite {
    let point = handle
        .procedure()
        .semantics()
        .point(handle.id())
        .expect("validated witness point resolves");
    let locator = &handle
        .procedure()
        .semantics()
        .source_mapping(point.source)
        .expect("validated witness point has source mapping")
        .locator;
    public_site(workspace, locator)
}

fn point_symbol_site(
    workspace: &WorkspaceAnalyzer,
    handle: &ProgramPointHandle,
) -> CodeQueryFlowSymbolSite {
    let point = handle
        .procedure()
        .semantics()
        .point(handle.id())
        .expect("validated witness point resolves");
    let locator = &handle
        .procedure()
        .semantics()
        .source_mapping(point.source)
        .expect("validated witness point has source mapping")
        .locator;
    public_symbol_site(workspace, locator)
}

fn call_site(
    workspace: &WorkspaceAnalyzer,
    handle: &crate::analyzer::semantic::CallSiteHandle,
) -> CodeQuerySourceSite {
    let call = handle
        .procedure()
        .semantics()
        .call_site(handle.id())
        .expect("validated witness call resolves");
    let locator = &handle
        .procedure()
        .semantics()
        .source_mapping(call.source)
        .expect("validated witness call has source mapping")
        .locator;
    public_site(workspace, locator)
}

fn call_symbol_site(
    workspace: &WorkspaceAnalyzer,
    handle: &crate::analyzer::semantic::CallSiteHandle,
) -> CodeQueryFlowSymbolSite {
    let call = handle
        .procedure()
        .semantics()
        .call_site(handle.id())
        .expect("validated witness call resolves");
    let locator = &handle
        .procedure()
        .semantics()
        .source_mapping(call.source)
        .expect("validated witness call has source mapping")
        .locator;
    public_symbol_site(workspace, locator)
}

fn public_site(workspace: &WorkspaceAnalyzer, locator: &SemanticLocator) -> CodeQuerySourceSite {
    CodeQuerySourceSite {
        path: locator.path().as_str().to_string(),
        range: locator_range(workspace, locator),
    }
}

fn hash_public_point(digest: &mut LengthDelimitedDigest, point: &ProgramPointHandle) {
    let row = point
        .procedure()
        .semantics()
        .point(point.id())
        .expect("validated value-flow point resolves");
    let locator = &point
        .procedure()
        .semantics()
        .source_mapping(row.source)
        .expect("validated value-flow point has source mapping")
        .locator;
    hash_public_locator(digest, locator);
}

fn locator_span(locator: &SemanticLocator) -> std::ops::Range<usize> {
    let span = locator.anchor().span();
    span.start_byte() as usize..span.end_byte() as usize
}
