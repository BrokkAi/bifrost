use std::mem::size_of;
use std::sync::Arc;

use super::{
    CodeQueryControlEdge, CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryProcedure, CodeQueryProgramPoint, CodeQueryProgramPointBoundary,
    CodeQueryProgramPointRef, CodeQueryRange, CodeQuerySemanticCompleteness,
    CodeQuerySemanticEvidence, CodeQuerySemanticLimits, CodeQuerySemanticProof,
    CodeQuerySemanticWork, DeclarationValue, SeedMatch,
};
use crate::analyzer::semantic::service::semantic_artifact_retained_bytes;
use crate::analyzer::semantic::workspace_oracle::{
    ProcedureRangeLookupStatus, procedures_for_definition, procedures_for_source_ranges,
};
use crate::analyzer::semantic::{
    AllocationSite, BasicBlock, CapabilitySupport, CaptureBinding, ContentIdentity, ControlEdge,
    ControlEdgeHandle, Evidence, EvidenceCompleteness, LengthDelimitedDigest, MemoryLocation,
    ProcedureHandle, ProcedureSemantics, ProgramPoint, ProgramPointHandle, ProofStatus,
    SemanticArtifact, SemanticBudget, SemanticCallSite, SemanticCapability, SemanticEvent,
    SemanticGap, SemanticLocator, SemanticOutcome, SemanticRequest, SemanticValue, SemanticWork,
    SourceMapping,
};
use crate::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, line_column_for_offset};

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
        self.source
            .len()
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
enum CachedSemanticMaterialization {
    Outcome {
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        source: Option<SemanticSourceSnapshot>,
    },
    ProviderFailed(Arc<str>),
    FileBudgetExhausted,
    RetainedBudgetExhausted,
}

pub(super) struct SemanticQueryContext<'a> {
    workspace: &'a WorkspaceAnalyzer,
    cancellation: Option<&'a CancellationToken>,
    uncancelled: CancellationToken,
    limits: CodeQuerySemanticLimits,
    budget: SemanticBudget,
    cache: HashMap<ProjectFile, CachedSemanticMaterialization>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    reported: HashSet<(CodeQueryDiagnosticCode, ProjectFile, String)>,
    attempts: usize,
    materialized_files: usize,
    cache_hits: usize,
    retained_bytes: usize,
    traversal_steps: usize,
    budget_exhausted: bool,
}

impl<'a> SemanticQueryContext<'a> {
    pub(super) fn new(
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
        limits: CodeQuerySemanticLimits,
    ) -> Self {
        debug_assert!(limits.all_positive());
        Self {
            workspace,
            cancellation,
            uncancelled: CancellationToken::default(),
            limits,
            budget: SemanticBudget::new(semantic_budget_limits(limits))
                .expect("CodeQuery semantic limits are positive"),
            cache: HashMap::default(),
            diagnostics: Vec::new(),
            reported: HashSet::default(),
            attempts: 0,
            materialized_files: 0,
            cache_hits: 0,
            retained_bytes: 0,
            traversal_steps: 0,
            budget_exhausted: false,
        }
    }

    pub(super) fn cfg(&mut self) -> CfgQueryAdapter<'_, 'a> {
        CfgQueryAdapter { context: self }
    }

    fn procedure_of_match(&mut self, seed: &SeedMatch) -> Vec<SemanticProcedureValue> {
        let fact = seed.facts.node(seed.fact_match.node);
        let span = fact.span();
        let ranges = [Range {
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_line: fact.range.start_line,
            end_line: fact.range.end_line,
        }];
        let Some((artifact, source, quality)) = self.materialize(&seed.file) else {
            return Vec::new();
        };
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
        }
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
        if !self.charge_traversal(
            file,
            artifact.procedures().len().saturating_mul(2),
            "declaration-to-procedure lookup",
        ) {
            return Vec::new();
        }
        let candidates =
            procedures_for_definition(self.workspace.analyzer(), &declaration.unit, &artifact);
        self.finish_procedure_lookup(file, source, candidates, quality)
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
        std::mem::take(&mut self.diagnostics)
    }

    pub(super) fn work(&self) -> CodeQuerySemanticWork {
        let used = self.budget.used();
        CodeQuerySemanticWork {
            materialization_attempts: saturating_u64(self.attempts),
            unique_materialized_files: saturating_u64(self.materialized_files),
            request_cache_hits: saturating_u64(self.cache_hits),
            source_bytes: saturating_u64(used.source_bytes),
            procedures: saturating_u64(used.procedures),
            program_points: saturating_u64(used.program_points),
            control_edges: saturating_u64(used.control_edges),
            retained_bytes: saturating_u64(self.retained_bytes),
            traversal_steps: saturating_u64(self.traversal_steps),
            budget_exhausted: self.budget_exhausted,
        }
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

    fn materialize(
        &mut self,
        file: &ProjectFile,
    ) -> Option<(
        Arc<SemanticArtifact>,
        SemanticSourceSnapshot,
        SemanticQueryQuality,
    )> {
        if let Some(cached) = self.cache.get(file).cloned() {
            self.cache_hits = self.cache_hits.saturating_add(1);
            return self.cached_value(file, cached);
        }
        if self.attempts >= self.limits.max_materialized_files {
            self.budget_exhausted = true;
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
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        let outcome = self.workspace.materialize_program_semantics(
            file,
            &mut SemanticRequest::new(&mut self.budget, cancellation),
        );
        match outcome {
            Ok(outcome) => {
                let source = outcome
                    .available_value()
                    .and_then(|artifact| self.exact_source(file, artifact));
                if let (Some(artifact), Some(source)) = (outcome.available_value(), source.as_ref())
                {
                    let retained_bytes = usize::try_from(
                        semantic_artifact_retained_bytes(artifact)
                            .saturating_add(source.retained_bytes() as u64),
                    )
                    .unwrap_or(usize::MAX);
                    if retained_bytes
                        > self
                            .limits
                            .max_retained_bytes
                            .saturating_sub(self.retained_bytes)
                    {
                        self.budget_exhausted = true;
                        self.cache.insert(
                            file.clone(),
                            CachedSemanticMaterialization::RetainedBudgetExhausted,
                        );
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            "semantic retained-artifact byte budget exhausted",
                        );
                        return None;
                    }
                    self.retained_bytes = self.retained_bytes.saturating_add(retained_bytes);
                    self.materialized_files = self.materialized_files.saturating_add(1);
                }
                let cached = CachedSemanticMaterialization::Outcome { outcome, source };
                self.cache.insert(file.clone(), cached.clone());
                self.cached_value(file, cached)
            }
            Err(error) => {
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
        if ContentIdentity::hash_bytes(source.as_bytes()) != artifact.key().revision().content() {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticResultsOmitted,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                "source generation changed before semantic result projection; retry the query for a coherent snapshot",
            );
            return None;
        }
        Some(SemanticSourceSnapshot::new(source))
    }

    fn charge_traversal(&mut self, file: &ProjectFile, steps: usize, operation: &str) -> bool {
        if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            self.push_diagnostic(
                CodeQueryDiagnosticCode::Cancelled,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &format!("{operation} was cancelled"),
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

    fn exhaust_traversal_budget(&mut self, file: &ProjectFile, operation: &str) {
        self.traversal_steps = self.limits.max_traversal_steps;
        self.budget_exhausted = true;
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

fn semantic_budget_limits(limits: CodeQuerySemanticLimits) -> SemanticWork {
    fn rows_for<T>(limits: CodeQuerySemanticLimits) -> usize {
        const RETAINED_ROW_DIMENSIONS: usize = 15;
        const ALLOCATION_OVERHEAD_FACTOR: usize = 2;
        let retained_row_bytes = limits.max_retained_bytes / 2;
        let per_dimension_bytes = retained_row_bytes / RETAINED_ROW_DIMENSIONS;
        let conservative_row_bytes = size_of::<T>()
            .max(1)
            .saturating_mul(ALLOCATION_OVERHEAD_FACTOR);
        limits
            .max_rows_per_dimension
            .min((per_dimension_bytes / conservative_row_bytes).max(1))
    }
    let retained_text_bytes = (limits.max_retained_bytes / 2).max(1);
    SemanticWork {
        source_bytes: limits.max_source_bytes.min(retained_text_bytes),
        procedures: rows_for::<ProcedureSemantics>(limits),
        blocks: rows_for::<BasicBlock>(limits),
        program_points: rows_for::<ProgramPoint>(limits),
        values: rows_for::<SemanticValue>(limits),
        allocations: rows_for::<AllocationSite>(limits),
        call_sites: rows_for::<SemanticCallSite>(limits),
        memory_locations: rows_for::<MemoryLocation>(limits),
        captures: rows_for::<CaptureBinding>(limits),
        source_mappings: rows_for::<SourceMapping>(limits),
        evidence: rows_for::<Evidence>(limits),
        gaps: rows_for::<SemanticGap>(limits),
        events: rows_for::<SemanticEvent>(limits),
        control_edges: rows_for::<ControlEdge>(limits),
        nested_entries: rows_for::<SemanticLocator>(limits),
        owned_text_bytes: limits.max_source_bytes.min(retained_text_bytes),
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

fn procedure_wire_id(handle: &ProcedureHandle) -> String {
    let mut digest = semantic_wire_digest(handle.artifact().as_ref(), b"procedure");
    push_locator(&mut digest, handle.semantics().locator());
    digest.finish().to_string()
}

fn program_point_wire_id(handle: &ProgramPointHandle) -> String {
    let procedure = handle.procedure();
    let point = procedure
        .semantics()
        .point(handle.id())
        .expect("validated program-point handle resolves in its procedure");
    let mapping = procedure
        .semantics()
        .source_mapping(point.source)
        .expect("validated program point has a source mapping");
    let mut digest = semantic_wire_digest(procedure.artifact().as_ref(), b"program_point");
    push_locator(&mut digest, procedure.semantics().locator());
    push_locator(&mut digest, &mapping.locator);
    digest.push(
        point_boundary(handle)
            .map_or("ordinary", CodeQueryProgramPointBoundary::label)
            .as_bytes(),
    );
    digest.finish().to_string()
}

fn control_edge_wire_id(handle: &ControlEdgeHandle) -> String {
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
    push_locator(&mut digest, &mapping.locator);
    digest.push(edge.kind.label().as_bytes());
    digest.push(program_point_wire_id(&source).as_bytes());
    digest.push(program_point_wire_id(&target).as_bytes());
    push_evidence(&mut digest, procedure.semantics(), evidence);
    digest.finish().to_string()
}

fn semantic_wire_digest(artifact: &SemanticArtifact, domain: &[u8]) -> LengthDelimitedDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-code-query-semantic-wire-id-v2");
    digest.push(artifact.key().public_fingerprint().as_bytes());
    digest.push(domain);
    digest
}

fn push_locator(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    digest.push(locator.path().as_str().as_bytes());
    digest.push(locator.language().stable_label().as_bytes());
    digest.push(locator.role().stable_label().as_bytes());
    digest.push_anchor(locator.anchor());
    for segment in locator.declaration().segments() {
        digest.push(segment.kind().stable_label().as_bytes());
        match segment.name() {
            Some(name) => {
                digest.push(b"named");
                digest.push(name.as_bytes());
            }
            None => digest.push(b"anonymous"),
        }
        digest.push_anchor(segment.anchor());
        digest.push(&segment.sibling_ordinal().to_le_bytes());
    }
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
