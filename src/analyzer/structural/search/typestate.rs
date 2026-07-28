use std::sync::Arc;

use super::{
    CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact, CodeQueryRange,
    CodeQuerySemanticCompleteness, CodeQuerySemanticEvidence, CodeQuerySemanticProof,
    CodeQuerySourceSite, CodeQueryTypestateCertainty, CodeQueryTypestateFinding,
    CodeQueryTypestateFindingKind, CodeQueryTypestateLimits, CodeQueryTypestateSubject,
    CodeQueryTypestateUncertainty, CodeQueryTypestateWitness, CodeQueryTypestateWitnessStep,
    CodeQueryTypestateWitnessStepKind, CodeQueryTypestateWork, SemanticProcedureValue,
};
use crate::analyzer::dataflow::{
    DataflowRequest, SemanticInputStatus, SolverBudget, SolverTermination, SummaryWitnessStepKind,
    WitnessReconstructionLimits,
};
use crate::analyzer::semantic::{
    CallSiteHandle, EvidenceCompleteness, LengthDelimitedDigest, ProcedureHandle,
    ProgramPointHandle, ProofStatus, SemanticBudget, SemanticLocator,
};
use crate::analyzer::structural::analysis_context::{
    ProtocolRef, QueryAnalysisContext, QueryAnalysisContextError,
};
use crate::analyzer::structural::query::WitnessTraversal;
use crate::analyzer::typestate::{
    CompiledProtocol, ProductionSummaryLifecycleCounters, ProductionTypestateExecutionContext,
    ProtocolStateId, TypestateBindingPlan, TypestateFinding, TypestateFindingCertainty,
    TypestateFindingKind, TypestateFindingLimits, TypestateFindingReport,
    TypestateFlowProblemError, TypestateUncertainty, TypestateUncertaintySet,
    collect_summary_findings_with_limits, solve_typestate_with_production_summaries,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::text_utils::{compute_line_starts, line_column_for_offset};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TypestateCacheKey {
    root: ProcedureHandle,
    protocol_hash: crate::analyzer::typestate::TypestateProtocolHash,
    binding_plan_hash: crate::analyzer::typestate::TypestateBindingPlanHash,
}

#[derive(Debug)]
struct TypestateAnalysisResult {
    protocol: Arc<CompiledProtocol>,
    bindings: Arc<TypestateBindingPlan>,
    report: TypestateFindingReport,
}

#[derive(Debug, Clone)]
enum CachedTypestateAnalysis {
    Complete(Arc<TypestateAnalysisResult>),
    Failed,
}

#[derive(Default)]
pub(super) struct TypestateQueryState {
    cache: HashMap<TypestateCacheKey, CachedTypestateAnalysis>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    work: CodeQueryTypestateWork,
    semantic_budget_exhausted: bool,
}

#[derive(Debug, Clone)]
pub(super) struct SemanticTypestateFindingValue {
    pub(super) public: CodeQueryTypestateFinding,
    protocol: Arc<CompiledProtocol>,
    finding: Arc<TypestateFinding>,
    file: ProjectFile,
    byte_span: std::ops::Range<usize>,
}

#[derive(Debug, Clone)]
pub(super) struct SemanticTypestateWitnessValue {
    pub(super) public: CodeQueryTypestateWitness,
    file: ProjectFile,
    byte_span: std::ops::Range<usize>,
}

impl TypestateQueryState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn findings(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        workspace_generation: u64,
        analysis_context: Option<&QueryAnalysisContext>,
        procedure: &SemanticProcedureValue,
        protocol_ref: &ProtocolRef,
        semantic_budget: &mut SemanticBudget,
        limits: CodeQueryTypestateLimits,
        cancellation: &CancellationToken,
    ) -> Vec<SemanticTypestateFindingValue> {
        let Some(analysis_context) = analysis_context else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::UnresolvedProtocolReference,
                format!(
                    "typestate protocol reference `{protocol_ref}` was not supplied by the host"
                ),
            );
            return Vec::new();
        };
        let Some(handle) = analysis_context.handle(protocol_ref) else {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::UnresolvedProtocolReference,
                format!("typestate protocol reference `{protocol_ref}` is not registered"),
            );
            return Vec::new();
        };
        let registration = match analysis_context.resolve(
            workspace,
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
        // Registrations retain the immutable semantic allocation used to
        // construct their binding handles. The selected procedure may be an
        // equivalent rematerialization after cache eviction, so execute
        // against the registered root after the durable identity check above.
        let analysis_root = registration.expected_root().clone();
        let cache_key = TypestateCacheKey {
            root: analysis_root.clone(),
            protocol_hash: registration.protocol().hash(),
            binding_plan_hash: registration.bindings().hash(),
        };
        let analysis = match self.cache.get(&cache_key).cloned() {
            Some(CachedTypestateAnalysis::Complete(analysis)) => {
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                analysis
            }
            Some(CachedTypestateAnalysis::Failed) => {
                self.work.cache_hits = self.work.cache_hits.saturating_add(1);
                return Vec::new();
            }
            None => {
                let protocol = Arc::clone(registration.protocol());
                let bindings = Arc::clone(registration.bindings());
                self.work.solves = self.work.solves.saturating_add(1);
                let mut solver_budget = SolverBudget::new(limits.solver_work);
                let mut request = DataflowRequest::new(&mut solver_budget, cancellation);
                let summary_lease = analysis_context.summary_lease();
                let provider = workspace.icfg_provider();
                let solved = solve_typestate_with_production_summaries(
                    summary_lease,
                    &analysis_root,
                    &[],
                    &provider,
                    &provider,
                    ProductionTypestateExecutionContext::Workspace,
                    &protocol,
                    &bindings,
                    semantic_budget,
                    &mut request,
                );
                let solved = match solved {
                    Ok(solved) => solved,
                    Err(error) => {
                        self.work.failed_solves = self.work.failed_solves.saturating_add(1);
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::TypestateProviderFailed,
                            format!("typestate analysis failed: {error}"),
                        );
                        self.cache
                            .insert(cache_key, CachedTypestateAnalysis::Failed);
                        return Vec::new();
                    }
                };
                self.record_summary_work(solved.lifecycle());
                self.work.reached_rows = self
                    .work
                    .reached_rows
                    .saturating_add(saturating_u64(solved.result().result().reached().len()));
                match solved.result().result().termination() {
                    SolverTermination::FixedPoint => {
                        self.work.fixed_point_solves =
                            self.work.fixed_point_solves.saturating_add(1);
                    }
                    SolverTermination::Cancelled => {
                        self.work.cancelled_solves = self.work.cancelled_solves.saturating_add(1);
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::Cancelled,
                            "typestate solver was cancelled".to_string(),
                        );
                    }
                    SolverTermination::ExceededBudget(exceeded) => {
                        self.work.budget_exhausted_solves =
                            self.work.budget_exhausted_solves.saturating_add(1);
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::TypestateSolverBudgetExhausted,
                            exceeded.to_string(),
                        );
                    }
                }
                self.record_semantic_status(solved.result().result().coverage().semantic_status());
                let finding_limits = TypestateFindingLimits::with_witness_limits(
                    limits.max_reached_rows,
                    limits.max_candidates,
                    WitnessReconstructionLimits::new(
                        limits.max_witness_steps,
                        limits.max_witness_expansions,
                    )
                    .expect("validated CodeQuery typestate witness limits are positive"),
                    limits.max_total_witness_expansions,
                    limits.max_witness_bytes,
                )
                .expect("validated CodeQuery typestate finding limits are bounded");
                let report = match collect_summary_findings_with_limits(
                    &protocol,
                    &bindings,
                    solved.result(),
                    finding_limits,
                    cancellation,
                ) {
                    Ok(report) => report,
                    Err(TypestateFlowProblemError::FindingBudgetExceeded) => {
                        self.work.finding_budget_exhausted = true;
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::TypestateFindingBudgetExhausted,
                            "typestate finding or witness reconstruction budget was exhausted"
                                .to_string(),
                        );
                        self.cache
                            .insert(cache_key, CachedTypestateAnalysis::Failed);
                        return Vec::new();
                    }
                    Err(TypestateFlowProblemError::FindingCancelled) => {
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::Cancelled,
                            "typestate finding collection was cancelled".to_string(),
                        );
                        self.cache
                            .insert(cache_key, CachedTypestateAnalysis::Failed);
                        return Vec::new();
                    }
                    Err(error) => {
                        self.work.failed_solves = self.work.failed_solves.saturating_add(1);
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::TypestateProviderFailed,
                            format!("typestate finding collection failed: {error}"),
                        );
                        self.cache
                            .insert(cache_key, CachedTypestateAnalysis::Failed);
                        return Vec::new();
                    }
                };
                self.work.findings = self
                    .work
                    .findings
                    .saturating_add(saturating_u64(report.findings().len()));
                self.work.omitted_findings = self
                    .work
                    .omitted_findings
                    .saturating_add(saturating_u64(report.omitted()));
                for finding in report.findings() {
                    self.work.witnesses = self
                        .work
                        .witnesses
                        .saturating_add(saturating_u64(finding.witnesses().len()));
                    self.work.omitted_witnesses = self
                        .work
                        .omitted_witnesses
                        .saturating_add(saturating_u64(finding.omitted_witnesses()));
                    for witness in finding.witnesses() {
                        self.work.witness_steps = self
                            .work
                            .witness_steps
                            .saturating_add(saturating_u64(witness.witness().step_count()));
                        self.work.witness_bytes = self
                            .work
                            .witness_bytes
                            .saturating_add(saturating_u64(witness.witness().retained_bytes()));
                    }
                }
                if report.omitted() > 0 {
                    self.push_diagnostic(
                        CodeQueryDiagnosticCode::TypestateFindingBudgetExhausted,
                        format!(
                            "typestate finding retention omitted at least {} finding(s)",
                            report.omitted()
                        ),
                    );
                }
                if !report.analysis_complete() {
                    self.push_diagnostic(
                        CodeQueryDiagnosticCode::TypestateAnalysisPartial,
                        "typestate analysis retained incomplete semantic evidence".to_string(),
                    );
                }
                let analysis = Arc::new(TypestateAnalysisResult {
                    protocol,
                    bindings,
                    report,
                });
                self.cache.insert(
                    cache_key,
                    CachedTypestateAnalysis::Complete(Arc::clone(&analysis)),
                );
                analysis
            }
        };
        self.project_findings(workspace, protocol_ref, analysis)
    }

    fn project_findings(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        protocol_ref: &ProtocolRef,
        analysis: Arc<TypestateAnalysisResult>,
    ) -> Vec<SemanticTypestateFindingValue> {
        analysis
            .report
            .findings()
            .iter()
            .map(|finding| {
                let subject = analysis
                    .bindings
                    .subject(finding.subject())
                    .expect("validated typestate finding subject resolves in its binding plan");
                let public_subject = CodeQueryTypestateSubject {
                    class: subject.key().class().as_str().to_string(),
                    identity: subject.key().public_canonical_rendering(),
                };
                let finding_kind = public_finding_kind(&analysis.protocol, finding.kind());
                let id = finding_id(
                    &analysis.protocol,
                    &analysis.bindings,
                    &public_subject,
                    finding.site(),
                    &finding_kind,
                    finding.certainty(),
                );
                let file = locator_file(workspace, finding.site());
                let range = locator_range(workspace, finding.site());
                let span = finding.site().anchor().span();
                let evidence = finding.evidence();
                let retained_witnesses = finding.witnesses().len();
                let omitted_witnesses = finding.omitted_witnesses();
                SemanticTypestateFindingValue {
                    public: CodeQueryTypestateFinding {
                        id,
                        protocol_ref: protocol_ref.to_string(),
                        protocol_hash: analysis.protocol.hash().to_string(),
                        binding_plan_hash: analysis.bindings.hash().to_string(),
                        subject: public_subject,
                        finding_kind,
                        certainty: public_certainty(finding.certainty()),
                        path: finding.site().path().as_str().to_string(),
                        language: finding.site().language().config_label(),
                        range,
                        path_proven: evidence.path_proven(),
                        path_complete: evidence.path_complete(),
                        analysis_complete: evidence.analysis_complete(),
                        uncertainty: public_uncertainty(evidence.uncertainty()),
                        abstained: evidence.abstained(),
                        retained_witnesses,
                        omitted_witnesses,
                    },
                    protocol: Arc::clone(&analysis.protocol),
                    finding: Arc::new(finding.clone()),
                    file,
                    byte_span: span.start_byte() as usize..span.end_byte() as usize,
                }
            })
            .collect()
    }

    fn push_context_error(&mut self, error: QueryAnalysisContextError) {
        if matches!(
            &error,
            QueryAnalysisContextError::ValidationBudgetExceeded { .. }
        ) {
            self.semantic_budget_exhausted = true;
        }
        let code = match error {
            QueryAnalysisContextError::UnresolvedReference { .. } => {
                CodeQueryDiagnosticCode::UnresolvedProtocolReference
            }
            QueryAnalysisContextError::AnalysisRootMismatch => {
                CodeQueryDiagnosticCode::TypestateRootMismatch
            }
            QueryAnalysisContextError::StaleHandle => CodeQueryDiagnosticCode::TypestateHandleStale,
            QueryAnalysisContextError::Cancelled => CodeQueryDiagnosticCode::Cancelled,
            QueryAnalysisContextError::ValidationBudgetExceeded { .. } => {
                CodeQueryDiagnosticCode::SemanticBudgetExhausted
            }
            QueryAnalysisContextError::GenerationExhausted
            | QueryAnalysisContextError::TooManyResolvedProtocols
            | QueryAnalysisContextError::WorkspaceGenerationMismatch { .. }
            | QueryAnalysisContextError::StaleArtifact { .. }
            | QueryAnalysisContextError::ArtifactIdentityUnavailable { .. }
            | QueryAnalysisContextError::ArtifactValidationFailed { .. } => {
                CodeQueryDiagnosticCode::TypestateRegistrationStale
            }
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

    fn record_semantic_status(&mut self, status: SemanticInputStatus) {
        match status {
            SemanticInputStatus::Unsupported { capability } => self.push_diagnostic(
                CodeQueryDiagnosticCode::TypestateCapabilityUnsupported,
                format!(
                    "typestate analysis requires unsupported semantic capability `{}`",
                    capability.label()
                ),
            ),
            SemanticInputStatus::ExceededBudget { exceeded } => {
                self.semantic_budget_exhausted = true;
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                    format!("typestate semantic input exceeded its budget: {exceeded}"),
                );
            }
            SemanticInputStatus::Cancelled => self.push_diagnostic(
                CodeQueryDiagnosticCode::Cancelled,
                "typestate semantic input materialization was cancelled".to_string(),
            ),
            SemanticInputStatus::Complete
            | SemanticInputStatus::Ambiguous
            | SemanticInputStatus::Unknown
            | SemanticInputStatus::Unproven => {}
        }
    }

    pub(super) fn take_diagnostics(&mut self) -> Vec<CodeQueryDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    pub(super) const fn work(&self) -> CodeQueryTypestateWork {
        self.work
    }

    fn record_summary_work(&mut self, work: ProductionSummaryLifecycleCounters) {
        self.work.summary_hits = self
            .work
            .summary_hits
            .saturating_add(saturating_u64(work.hits));
        self.work.summary_misses = self
            .work
            .summary_misses
            .saturating_add(saturating_u64(work.misses));
        self.work.summary_rejections = self
            .work
            .summary_rejections
            .saturating_add(saturating_u64(work.rejections));
        self.work.summary_evictions = self
            .work
            .summary_evictions
            .saturating_add(saturating_u64(work.evictions));
        self.work.summary_recomputations = self
            .work
            .summary_recomputations
            .saturating_add(saturating_u64(work.recomputations));
    }

    pub(super) const fn semantic_budget_exhausted(&self) -> bool {
        self.semantic_budget_exhausted
    }

    pub(super) fn witness_truncated(&mut self, count: usize) {
        if count > 0 {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::TypestateWitnessTruncated,
                format!("typestate witness projection truncated {count} witness(es)"),
            );
        }
    }
}

impl SemanticTypestateFindingValue {
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
        super::CodeQueryResultRef::TypestateFinding {
            id: self.public.id.clone(),
            path: self.public.path.clone(),
            range: self.public.range,
            protocol_ref: self.public.protocol_ref.clone(),
        }
    }

    pub(super) fn witnesses(
        &self,
        workspace: &WorkspaceAnalyzer,
        traversal: &WitnessTraversal,
        limits: CodeQueryTypestateLimits,
    ) -> (Vec<SemanticTypestateWitnessValue>, usize) {
        let max_steps = traversal.max_steps.unwrap_or(limits.max_witness_steps);
        let max_bytes = traversal.max_bytes.unwrap_or(limits.max_witness_bytes);
        let mut truncated_count = 0;
        let values = self
            .finding
            .witnesses()
            .iter()
            .enumerate()
            .map(|(witness_index, finding_witness)| {
                let witness = finding_witness.witness();
                let (steps, retained_bytes, removed_steps) = retain_prefix_by_bytes(
                    witness
                        .steps()
                        .map(|step| public_witness_step(workspace, step)),
                    max_steps,
                    max_bytes,
                    |step| {
                        serde_json::to_vec(step)
                            .expect("public typestate witness steps are serializable")
                            .len()
                    },
                );
                let truncated = witness.truncated() || removed_steps > 0;
                if truncated {
                    truncated_count += 1;
                }
                let observed_state = finding_witness
                    .observed_state()
                    .and_then(|state| self.protocol.state_key(state))
                    .map(ToString::to_string);
                let id = witness_id(&self.public.id, witness_index, observed_state.as_deref());
                SemanticTypestateWitnessValue {
                    public: CodeQueryTypestateWitness {
                        id,
                        finding_id: self.public.id.clone(),
                        protocol_ref: self.public.protocol_ref.clone(),
                        protocol_hash: self.public.protocol_hash.clone(),
                        binding_plan_hash: self.public.binding_plan_hash.clone(),
                        subject: self.public.subject.clone(),
                        witness_index,
                        observed_state,
                        path: self.public.path.clone(),
                        language: self.public.language,
                        range: self.public.range,
                        quality: CodeQuerySemanticEvidence {
                            proof: if witness.quality().is_proven() {
                                CodeQuerySemanticProof::Proven
                            } else {
                                CodeQuerySemanticProof::Unproven
                            },
                            proof_reason: None,
                            completeness: if witness.quality().is_complete() && removed_steps == 0 {
                                CodeQuerySemanticCompleteness::Complete
                            } else {
                                CodeQuerySemanticCompleteness::Partial
                            },
                            completeness_reason: (removed_steps > 0).then(|| {
                                format!(
                                    "query witness limits omitted at least {removed_steps} step(s)"
                                )
                            }),
                        },
                        uncertainty: public_uncertainty(witness.uncertainty()),
                        abstained: witness.abstained(),
                        steps,
                        retained_bytes,
                        truncated,
                        omitted_steps_lower_bound: witness
                            .omitted_steps_lower_bound()
                            .saturating_add(removed_steps),
                        alternatives_truncated: witness.alternatives_truncated(),
                        retention_truncated: witness.retention_truncated(),
                    },
                    file: self.file.clone(),
                    byte_span: self.byte_span.clone(),
                }
            })
            .collect();
        (values, truncated_count)
    }
}

fn retain_prefix_by_bytes<T>(
    items: impl IntoIterator<Item = T>,
    max_items: usize,
    max_bytes: usize,
    measure: impl Fn(&T) -> usize,
) -> (Vec<T>, usize, usize) {
    let mut items = items.into_iter();
    let mut retained = Vec::new();
    let mut retained_bytes = 0usize;
    while let Some(item) = items.next() {
        let item_bytes = measure(&item);
        if retained.len() >= max_items || item_bytes > max_bytes.saturating_sub(retained_bytes) {
            let omitted = 1usize.saturating_add(items.count());
            return (retained, retained_bytes, omitted);
        }
        retained_bytes = retained_bytes.saturating_add(item_bytes);
        retained.push(item);
    }
    (retained, retained_bytes, 0)
}

impl SemanticTypestateWitnessValue {
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
        super::CodeQueryResultRef::TypestateWitness {
            id: self.public.id.clone(),
            finding_id: self.public.finding_id.clone(),
            path: self.public.path.clone(),
            range: self.public.range,
        }
    }
}

fn public_finding_kind(
    protocol: &CompiledProtocol,
    kind: &TypestateFindingKind,
) -> CodeQueryTypestateFindingKind {
    match kind {
        TypestateFindingKind::ErrorTransition {
            event, from, to, ..
        } => CodeQueryTypestateFindingKind::ErrorTransition {
            event: protocol
                .event(*event)
                .expect("validated finding event resolves")
                .key()
                .to_string(),
            from_state: state_key(protocol, *from),
            to_state: state_key(protocol, *to),
        },
        TypestateFindingKind::TerminalExpectation {
            expectation,
            actual_states,
            ..
        } => CodeQueryTypestateFindingKind::TerminalExpectation {
            expectation: protocol
                .terminal_expectation(*expectation)
                .expect("validated finding expectation resolves")
                .key()
                .to_string(),
            actual_states: actual_states
                .iter()
                .map(|state| state_key(protocol, *state))
                .collect(),
        },
    }
}

fn state_key(protocol: &CompiledProtocol, state: ProtocolStateId) -> String {
    protocol
        .state_key(state)
        .expect("validated finding state resolves")
        .to_string()
}

fn public_certainty(certainty: TypestateFindingCertainty) -> CodeQueryTypestateCertainty {
    match certainty {
        TypestateFindingCertainty::May => CodeQueryTypestateCertainty::May,
        TypestateFindingCertainty::Must => CodeQueryTypestateCertainty::Must,
        TypestateFindingCertainty::Inconclusive => CodeQueryTypestateCertainty::Inconclusive,
    }
}

fn public_uncertainty(set: TypestateUncertaintySet) -> Vec<CodeQueryTypestateUncertainty> {
    [
        (
            TypestateUncertainty::AmbiguousDispatch,
            CodeQueryTypestateUncertainty::AmbiguousDispatch,
        ),
        (
            TypestateUncertainty::UnknownCall,
            CodeQueryTypestateUncertainty::UnknownCall,
        ),
        (
            TypestateUncertainty::ExternalCall,
            CodeQueryTypestateUncertainty::ExternalCall,
        ),
        (
            TypestateUncertainty::Escape,
            CodeQueryTypestateUncertainty::Escape,
        ),
        (
            TypestateUncertainty::IncompleteAnalysis,
            CodeQueryTypestateUncertainty::IncompleteAnalysis,
        ),
        (
            TypestateUncertainty::UnmatchedEvent,
            CodeQueryTypestateUncertainty::UnmatchedEvent,
        ),
    ]
    .into_iter()
    .filter_map(|(internal, public)| set.contains(internal).then_some(public))
    .collect()
}

fn public_witness_step(
    workspace: &WorkspaceAnalyzer,
    step: crate::analyzer::typestate::TypestateWitnessStep<'_>,
) -> CodeQueryTypestateWitnessStep {
    CodeQueryTypestateWitnessStep {
        kind: match step.kind() {
            SummaryWitnessStepKind::Seed => CodeQueryTypestateWitnessStepKind::Seed,
            SummaryWitnessStepKind::Edge(kind) => CodeQueryTypestateWitnessStepKind::Edge {
                edge_kind: kind.label(),
            },
            SummaryWitnessStepKind::EndSummaryGap(kind) => {
                CodeQueryTypestateWitnessStepKind::EndSummaryGap {
                    return_kind: match kind {
                        crate::analyzer::semantic::ReturnTransferKind::Normal => "normal",
                        crate::analyzer::semantic::ReturnTransferKind::Exceptional => "exceptional",
                    },
                }
            }
        },
        source: program_point_site(workspace, step.source()),
        target: step
            .target()
            .map(|target| program_point_site(workspace, target)),
        origin: step.origin().map(|origin| call_site(workspace, origin)),
        evidence: public_evidence(step.proof(), step.completeness()),
    }
}

fn program_point_site(
    workspace: &WorkspaceAnalyzer,
    handle: &ProgramPointHandle,
) -> CodeQuerySourceSite {
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

fn call_site(workspace: &WorkspaceAnalyzer, handle: &CallSiteHandle) -> CodeQuerySourceSite {
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

fn public_site(workspace: &WorkspaceAnalyzer, locator: &SemanticLocator) -> CodeQuerySourceSite {
    CodeQuerySourceSite {
        path: locator.path().as_str().to_string(),
        range: locator_range(workspace, locator),
    }
}

fn locator_file(workspace: &WorkspaceAnalyzer, locator: &SemanticLocator) -> ProjectFile {
    ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    )
}

fn locator_range(workspace: &WorkspaceAnalyzer, locator: &SemanticLocator) -> CodeQueryRange {
    let span = locator.anchor().span();
    let file = locator_file(workspace, locator);
    let Some(source) = workspace.analyzer().indexed_source(&file) else {
        return anchor_range(span);
    };
    let line_starts = compute_line_starts(&source);
    let (start_line, start_column) =
        line_column_for_offset(&source, &line_starts, span.start_byte() as usize);
    let (end_line, end_column) =
        line_column_for_offset(&source, &line_starts, span.end_byte() as usize);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

fn anchor_range(span: crate::analyzer::semantic::SourceSpan) -> CodeQueryRange {
    CodeQueryRange {
        start_line: span.start().line() as usize + 1,
        start_column: span.start().byte_column() as usize + 1,
        end_line: span.end().line() as usize + 1,
        end_column: span.end().byte_column() as usize + 1,
    }
}

fn public_evidence(
    proof: &ProofStatus,
    completeness: &EvidenceCompleteness,
) -> CodeQuerySemanticEvidence {
    CodeQuerySemanticEvidence {
        proof: match proof {
            ProofStatus::Proven => CodeQuerySemanticProof::Proven,
            ProofStatus::Unproven(_) => CodeQuerySemanticProof::Unproven,
        },
        proof_reason: match proof {
            ProofStatus::Proven => None,
            ProofStatus::Unproven(reason) => Some(bounded_reason(reason)),
        },
        completeness: match completeness {
            EvidenceCompleteness::Complete => CodeQuerySemanticCompleteness::Complete,
            EvidenceCompleteness::Partial(_) => CodeQuerySemanticCompleteness::Partial,
        },
        completeness_reason: match completeness {
            EvidenceCompleteness::Complete => None,
            EvidenceCompleteness::Partial(reason) => Some(bounded_reason(reason)),
        },
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

fn finding_id(
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    subject: &CodeQueryTypestateSubject,
    site: &SemanticLocator,
    kind: &CodeQueryTypestateFindingKind,
    certainty: TypestateFindingCertainty,
) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.typestate_finding.v2");
    digest.push(protocol.hash().to_string().as_bytes());
    digest.push(subject.class.as_bytes());
    digest.push(subject.identity.as_bytes());
    hash_public_binding_inputs(&mut digest, bindings);
    hash_public_locator(&mut digest, site);
    digest.push(&serde_json::to_vec(kind).expect("public typestate finding kind is serializable"));
    digest.push(match certainty {
        TypestateFindingCertainty::May => b"may",
        TypestateFindingCertainty::Must => b"must",
        TypestateFindingCertainty::Inconclusive => b"inconclusive",
    });
    digest.finish().to_string()
}

fn hash_public_binding_inputs(digest: &mut LengthDelimitedDigest, bindings: &TypestateBindingPlan) {
    let mut fingerprints = Vec::new();
    bindings.for_each_retained_artifact_key(|key| {
        fingerprints.push(key.public_fingerprint());
    });
    fingerprints.sort_unstable();
    fingerprints.dedup();
    for fingerprint in fingerprints {
        digest.push(fingerprint.as_bytes());
    }
}

fn witness_id(finding_id: &str, witness_index: usize, observed_state: Option<&str>) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.typestate_witness.v2");
    digest.push(finding_id.as_bytes());
    digest.push(
        &u64::try_from(witness_index)
            .expect("bounded witness index fits in u64")
            .to_le_bytes(),
    );
    digest.push(observed_state.unwrap_or("").as_bytes());
    digest.finish().to_string()
}

fn hash_public_locator(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    digest.push(locator.path().as_str().as_bytes());
    digest.push(locator.language().config_label().as_bytes());
    for segment in locator.declaration().segments() {
        digest.push(segment.kind().stable_label().as_bytes());
        digest.push(segment.name().unwrap_or("").as_bytes());
        digest.push_anchor(segment.anchor());
        digest.push(&segment.sibling_ordinal().to_le_bytes());
    }
    digest.push(locator.role().stable_label().as_bytes());
    digest.push_anchor(locator.anchor());
}

fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::retain_prefix_by_bytes;

    #[test]
    fn byte_trimming_keeps_a_contiguous_prefix() {
        let (retained, retained_bytes, omitted) =
            retain_prefix_by_bytes(["aaaa", "bbbbbb", "c"], 3, 5, |value| value.len());

        assert_eq!(retained, ["aaaa"]);
        assert_eq!(retained_bytes, 4);
        assert_eq!(omitted, 2);
    }

    #[test]
    fn zero_step_projection_omits_the_whole_witness() {
        let (retained, retained_bytes, omitted) =
            retain_prefix_by_bytes(["first", "second"], 0, usize::MAX, |value| value.len());

        assert!(retained.is_empty());
        assert_eq!(retained_bytes, 0);
        assert_eq!(omitted, 2);
    }
}
