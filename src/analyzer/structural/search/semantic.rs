use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::{
    CodeQueryControlEdge, CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryProcedure, CodeQueryProgramPoint, CodeQueryProgramPointBoundary,
    CodeQueryProgramPointRef, CodeQueryRange, CodeQuerySemanticCompleteness,
    CodeQuerySemanticEvidence, CodeQuerySemanticLimits, CodeQuerySemanticProof,
    CodeQuerySemanticWork, DeclarationValue, SeedMatch,
};
use crate::analyzer::semantic::workspace_oracle::{
    procedures_for_definition, procedures_for_source_ranges,
};
use crate::analyzer::semantic::{
    CapabilitySupport, ControlEdgeHandle, DeclarationSegmentKind, Evidence, EvidenceCompleteness,
    ProcedureHandle, ProgramPointHandle, ProofStatus, SemanticArtifact, SemanticBudget,
    SemanticCapability, SemanticLocator, SemanticOutcome, SemanticRequest, SemanticWork,
    SourceMapping, StableDigest,
};
use crate::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};

#[derive(Debug, Clone, Default)]
struct CfgSemanticQuality {
    proof_reason: Option<Arc<str>>,
    completeness_reason: Option<Arc<str>>,
}

impl CfgSemanticQuality {
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
pub(super) struct CfgProcedureValue {
    pub(super) handle: ProcedureHandle,
    file: ProjectFile,
    quality: CfgSemanticQuality,
}

#[derive(Debug, Clone)]
pub(super) struct CfgProgramPointValue {
    pub(super) handle: ProgramPointHandle,
    file: ProjectFile,
    quality: CfgSemanticQuality,
}

#[derive(Debug, Clone)]
pub(super) struct CfgControlEdgeValue {
    pub(super) handle: ControlEdgeHandle,
    file: ProjectFile,
    quality: CfgSemanticQuality,
}

#[derive(Debug, Clone)]
enum CachedSemanticMaterialization {
    Outcome(SemanticOutcome<Arc<SemanticArtifact>>),
    ProviderFailed(Arc<str>),
    FileBudgetExhausted,
}

pub(super) struct CfgQueryService<'a> {
    workspace: &'a WorkspaceAnalyzer,
    cancellation: Option<&'a CancellationToken>,
    uncancelled: CancellationToken,
    limits: CodeQuerySemanticLimits,
    budget: SemanticBudget,
    cache: HashMap<ProjectFile, CachedSemanticMaterialization>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    reported: HashSet<(CodeQueryDiagnosticCode, ProjectFile, String)>,
    attempts: usize,
    cache_hits: usize,
    budget_exhausted: bool,
}

impl<'a> CfgQueryService<'a> {
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
            cache_hits: 0,
            budget_exhausted: false,
        }
    }

    pub(super) fn procedure_of_match(&mut self, seed: &SeedMatch) -> Vec<CfgProcedureValue> {
        let fact = seed.facts.node(seed.fact_match.node);
        let span = fact.span();
        let ranges = [Range {
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_line: fact.range.start_line,
            end_line: fact.range.end_line,
        }];
        let Some((artifact, quality)) = self.materialize(&seed.file) else {
            return Vec::new();
        };
        let quality = quality.combine(&self.capability_quality(
            &seed.file,
            artifact.as_ref(),
            &[SemanticCapability::Procedures],
        ));
        let candidates = procedures_for_source_ranges(&artifact, &ranges);
        self.finish_procedure_lookup(&seed.file, candidates, quality)
    }

    pub(super) fn procedure_of_declaration(
        &mut self,
        declaration: &DeclarationValue,
    ) -> Vec<CfgProcedureValue> {
        let file = declaration.unit.source();
        let Some((artifact, quality)) = self.materialize(file) else {
            return Vec::new();
        };
        let quality = quality.combine(&self.capability_quality(
            file,
            artifact.as_ref(),
            &[SemanticCapability::Procedures],
        ));
        let candidates =
            procedures_for_definition(self.workspace.analyzer(), &declaration.unit, &artifact);
        self.finish_procedure_lookup(file, candidates, quality)
    }

    pub(super) fn cfg_entry(
        &mut self,
        procedure: &CfgProcedureValue,
    ) -> Option<CfgProgramPointValue> {
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
            .map(|handle| CfgProgramPointValue {
                handle,
                file: procedure.file.clone(),
                quality,
            })
    }

    pub(super) fn cfg_exits(&mut self, procedure: &CfgProcedureValue) -> Vec<CfgProgramPointValue> {
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
            .map(|handle| CfgProgramPointValue {
                handle,
                file: procedure.file.clone(),
                quality: quality.clone(),
            })
            .collect()
    }

    pub(super) fn cfg_successor_edges(
        &mut self,
        point: &CfgProgramPointValue,
    ) -> Vec<CfgControlEdgeValue> {
        self.cfg_edges(point, true)
    }

    pub(super) fn cfg_predecessor_edges(
        &mut self,
        point: &CfgProgramPointValue,
    ) -> Vec<CfgControlEdgeValue> {
        self.cfg_edges(point, false)
    }

    pub(super) fn cfg_edge_source(
        &mut self,
        edge: &CfgControlEdgeValue,
    ) -> Option<CfgProgramPointValue> {
        self.cfg_edge_endpoint(edge, true)
    }

    pub(super) fn cfg_edge_target(
        &mut self,
        edge: &CfgControlEdgeValue,
    ) -> Option<CfgProgramPointValue> {
        self.cfg_edge_endpoint(edge, false)
    }

    pub(super) fn take_diagnostics(&mut self) -> Vec<CodeQueryDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    pub(super) fn work(&self) -> CodeQuerySemanticWork {
        let used = self.budget.used();
        CodeQuerySemanticWork {
            materialization_attempts: saturating_u64(self.attempts),
            unique_materialized_files: saturating_u64(self.attempts),
            request_cache_hits: saturating_u64(self.cache_hits),
            source_bytes: saturating_u64(used.source_bytes),
            procedures: saturating_u64(used.procedures),
            program_points: saturating_u64(used.program_points),
            control_edges: saturating_u64(used.control_edges),
            budget_exhausted: self.budget_exhausted,
        }
    }

    fn finish_procedure_lookup(
        &mut self,
        file: &ProjectFile,
        mut candidates: Vec<ProcedureHandle>,
        mut quality: CfgSemanticQuality,
    ) -> Vec<CfgProcedureValue> {
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
            quality = quality.combine(&CfgSemanticQuality::unproven_partial(Arc::clone(&reason)));
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
            .map(|handle| CfgProcedureValue {
                handle,
                file: file.clone(),
                quality: quality.clone(),
            })
            .collect()
    }

    fn cfg_edges(
        &mut self,
        point: &CfgProgramPointValue,
        successors: bool,
    ) -> Vec<CfgControlEdgeValue> {
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
        let mut ids = if successors {
            semantics
                .successor_edges(point.handle.id())
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
        } else {
            semantics
                .predecessor_edges(point.handle.id())
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
        };
        ids.sort();
        ids.into_iter()
            .filter_map(|id| procedure.control_edge_handle(id))
            .map(|handle| CfgControlEdgeValue {
                handle,
                file: point.file.clone(),
                quality: quality.clone(),
            })
            .collect()
    }

    fn cfg_edge_endpoint(
        &mut self,
        edge: &CfgControlEdgeValue,
        source: bool,
    ) -> Option<CfgProgramPointValue> {
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
            .map(|handle| CfgProgramPointValue {
                handle,
                file: edge.file.clone(),
                quality,
            })
    }

    fn materialize(
        &mut self,
        file: &ProjectFile,
    ) -> Option<(Arc<SemanticArtifact>, CfgSemanticQuality)> {
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
                self.cache.insert(
                    file.clone(),
                    CachedSemanticMaterialization::Outcome(outcome.clone()),
                );
                self.cached_value(file, CachedSemanticMaterialization::Outcome(outcome))
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
    ) -> Option<(Arc<SemanticArtifact>, CfgSemanticQuality)> {
        match cached {
            CachedSemanticMaterialization::Outcome(outcome) => {
                let value = outcome.available_value().cloned();
                let quality = match &outcome {
                    SemanticOutcome::Complete { .. } => CfgSemanticQuality::default(),
                    SemanticOutcome::Ambiguous { .. } => {
                        let reason = "semantic provider returned an ambiguous artifact";
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            reason,
                        );
                        CfgSemanticQuality::unproven_partial(reason)
                    }
                    SemanticOutcome::Unknown { .. } => {
                        let reason = "semantic provider returned an unknown partial artifact";
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            reason,
                        );
                        CfgSemanticQuality::unproven_partial(reason)
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
                        CfgSemanticQuality::unproven_partial(reason)
                    }
                    SemanticOutcome::Unproven { .. } => {
                        let reason = "semantic provider returned an unproven partial artifact";
                        self.push_diagnostic(
                            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                            CodeQueryDiagnosticImpact::Incomplete,
                            file,
                            reason,
                        );
                        CfgSemanticQuality::unproven_partial(reason)
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
                        CfgSemanticQuality::unproven_partial(reason)
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
                value.map(|value| (value, quality))
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
        }
    }

    fn capability_quality(
        &mut self,
        file: &ProjectFile,
        artifact: &SemanticArtifact,
        required: &[SemanticCapability],
    ) -> CfgSemanticQuality {
        let mut quality = CfgSemanticQuality::default();
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
                    quality = quality.combine(&CfgSemanticQuality::partial(reason));
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
                    quality = quality.combine(&CfgSemanticQuality::partial(reason));
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

impl CfgProcedureValue {
    pub(super) fn public(&self) -> CodeQueryProcedure {
        let procedure = self.handle.semantics();
        let mapping = procedure_source_mapping(&self.handle);
        CodeQueryProcedure {
            id: procedure_wire_id(&self.handle),
            artifact_id: self.handle.artifact().key().fingerprint().to_string(),
            path: mapping.locator.path().as_str().to_string(),
            language: mapping.locator.language().config_label(),
            procedure_kind: procedure.kind().label(),
            range: public_range(mapping),
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

impl CfgProgramPointValue {
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
            range: public_range(mapping),
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

impl CfgControlEdgeValue {
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
        let source = CfgProgramPointValue {
            handle: procedure
                .point_handle(edge.source_point)
                .expect("validated control edge source resolves"),
            file: self.file.clone(),
            quality: self.quality.clone(),
        };
        let target = CfgProgramPointValue {
            handle: procedure
                .point_handle(edge.target_point)
                .expect("validated control edge target resolves"),
            file: self.file.clone(),
            quality: self.quality.clone(),
        };
        CodeQueryControlEdge {
            id: control_edge_wire_id(&self.handle),
            procedure_id: procedure_wire_id(procedure),
            path: mapping.locator.path().as_str().to_string(),
            language: mapping.locator.language().config_label(),
            range: public_range(mapping),
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
    SemanticWork {
        source_bytes: limits.max_source_bytes,
        procedures: limits.max_rows_per_dimension,
        blocks: limits.max_rows_per_dimension,
        program_points: limits.max_rows_per_dimension,
        values: limits.max_rows_per_dimension,
        allocations: limits.max_rows_per_dimension,
        call_sites: limits.max_rows_per_dimension,
        memory_locations: limits.max_rows_per_dimension,
        captures: limits.max_rows_per_dimension,
        source_mappings: limits.max_rows_per_dimension,
        evidence: limits.max_rows_per_dimension,
        gaps: limits.max_rows_per_dimension,
        events: limits.max_rows_per_dimension,
        control_edges: limits.max_rows_per_dimension,
        nested_entries: limits.max_rows_per_dimension,
        owned_text_bytes: limits.max_source_bytes,
    }
}

fn public_evidence(evidence: &Evidence, quality: &CfgSemanticQuality) -> CodeQuerySemanticEvidence {
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

fn public_range(mapping: &SourceMapping) -> CodeQueryRange {
    let span = mapping.locator.anchor().span();
    CodeQueryRange {
        start_line: span.start().line() as usize + 1,
        start_column: span.start().byte_column() as usize + 1,
        end_line: span.end().line() as usize + 1,
        end_column: span.end().byte_column() as usize + 1,
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
    wire_id(
        handle.artifact().key().fingerprint().as_bytes(),
        b"procedure",
        handle.semantics().locator(),
        None,
    )
}

fn program_point_wire_id(handle: &ProgramPointHandle) -> String {
    wire_id(
        handle.procedure().artifact().key().fingerprint().as_bytes(),
        b"program_point",
        handle.procedure().semantics().locator(),
        Some(handle.id().get()),
    )
}

fn control_edge_wire_id(handle: &ControlEdgeHandle) -> String {
    wire_id(
        handle.procedure().artifact().key().fingerprint().as_bytes(),
        b"control_edge",
        handle.procedure().semantics().locator(),
        Some(handle.id().get()),
    )
}

fn wire_id(
    artifact: &[u8; 32],
    domain: &[u8],
    locator: &SemanticLocator,
    local_id: Option<u32>,
) -> String {
    let mut digest = CanonicalDigest::new(b"bifrost-code-query-semantic-wire-id-v1");
    digest.push(artifact);
    digest.push(domain);
    digest.push(locator.path().as_str().as_bytes());
    digest.push(locator.language().stable_label().as_bytes());
    digest.push(locator.role().stable_label().as_bytes());
    digest.push_anchor(locator.anchor());
    for segment in locator.declaration().segments() {
        digest.push(declaration_segment_kind_label(segment.kind()).as_bytes());
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
    if let Some(local_id) = local_id {
        digest.push(&local_id.to_le_bytes());
    }
    digest.finish()
}

struct CanonicalDigest(Sha256);

impl CanonicalDigest {
    fn new(domain: &[u8]) -> Self {
        let mut digest = Self(Sha256::new());
        digest.push(domain);
        digest
    }

    fn push(&mut self, value: &[u8]) {
        let length = u64::try_from(value.len()).expect("semantic wire identity input fits in u64");
        self.0.update(length.to_le_bytes());
        self.0.update(value);
    }

    fn push_anchor(&mut self, anchor: crate::analyzer::semantic::SourceAnchor) {
        let span = anchor.span();
        for value in [
            span.start().byte_offset(),
            span.start().line(),
            span.start().byte_column(),
            span.end().byte_offset(),
            span.end().line(),
            span.end().byte_column(),
            anchor.occurrence(),
        ] {
            self.push(&value.to_le_bytes());
        }
    }

    fn finish(self) -> String {
        let bytes: [u8; 32] = self.0.finalize().into();
        StableDigest::from_array(bytes).to_string()
    }
}

fn declaration_segment_kind_label(kind: DeclarationSegmentKind) -> &'static str {
    match kind {
        DeclarationSegmentKind::File => "file",
        DeclarationSegmentKind::Namespace => "namespace",
        DeclarationSegmentKind::Type => "type",
        DeclarationSegmentKind::Function => "function",
        DeclarationSegmentKind::Method => "method",
        DeclarationSegmentKind::Constructor => "constructor",
        DeclarationSegmentKind::Initializer => "initializer",
        DeclarationSegmentKind::LocalFunction => "local_function",
        DeclarationSegmentKind::Lambda => "lambda",
        DeclarationSegmentKind::Closure => "closure",
        DeclarationSegmentKind::AnonymousCallable => "anonymous_callable",
    }
}

fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
