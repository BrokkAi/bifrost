use std::mem::size_of;
use std::sync::Arc;

use super::taint::{SemanticTaintFindingValue, TaintQueryState};
use super::typestate::{SemanticTypestateFindingValue, TypestateQueryState};
use super::value_flow::{SemanticFlowEndpointValue, SemanticFlowWitnessValue, ValueFlowQueryState};
use super::{
    CodeQueryControlEdge, CodeQueryDiagnostic, CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact,
    CodeQueryProcedure, CodeQueryProgramPoint, CodeQueryProgramPointBoundary,
    CodeQueryProgramPointRef, CodeQueryRange, CodeQuerySemanticCompleteness,
    CodeQuerySemanticEvidence, CodeQuerySemanticLimits, CodeQuerySemanticProof,
    CodeQuerySemanticWork, DeclarationValue, SeedMatch, seed_range,
};
use crate::analyzer::semantic::service::semantic_artifact_retained_bytes;
use crate::analyzer::semantic::workspace_oracle::{
    ProcedureRangeLookupStatus, procedures_for_definition_with_limits, procedures_for_source_ranges,
};
use crate::analyzer::semantic::{
    AllocationSite, BasicBlock, CapabilitySupport, CaptureBinding, ContentIdentity, ControlEdge,
    ControlEdgeHandle, Evidence, EvidenceCompleteness, LengthDelimitedDigest, MemoryLocation,
    ProcedureHandle, ProcedureSemantics, ProgramPoint, ProgramPointHandle, ProofStatus,
    SemanticArtifact, SemanticBudget, SemanticCallSite, SemanticCapability, SemanticEvent,
    SemanticGap, SemanticLocator, SemanticOutcome, SemanticRequest, SemanticValue, SemanticWork,
    SourceMapping,
};
use crate::analyzer::structural::analysis_context::{
    ProtocolRef, QueryAnalysisContext, TaintResultRef, ValueFlowPlanRef,
};
use crate::analyzer::structural::query::WitnessTraversal;
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
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
    typestate_limits: super::CodeQueryTypestateLimits,
    value_flow_limits: super::CodeQueryValueFlowLimits,
    taint_limits: super::CodeQueryTaintLimits,
    workspace_generation: u64,
    analysis_context: Option<&'a QueryAnalysisContext>,
    budget: SemanticBudget,
    cache: HashMap<ProjectFile, CachedSemanticMaterialization>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    reported: HashSet<(CodeQueryDiagnosticCode, ProjectFile, String)>,
    attempts: usize,
    materialized_files: usize,
    cache_hits: usize,
    retained_bytes: usize,
    traversal_steps: usize,
    indexed_source_identities: HashMap<ProjectFile, Option<ContentIdentity>>,
    budget_exhausted: bool,
    typestate: TypestateQueryState,
    value_flow: ValueFlowQueryState,
    taint: TaintQueryState,
}

impl<'a> SemanticQueryContext<'a> {
    #[cfg(test)]
    pub(super) fn new(
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
        limits: CodeQuerySemanticLimits,
    ) -> Self {
        Self::new_with_analysis(
            workspace,
            cancellation,
            limits,
            super::CodeQueryTypestateLimits::default(),
            super::CodeQueryValueFlowLimits::default(),
            super::CodeQueryTaintLimits::default(),
            0,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_with_analysis(
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
        limits: CodeQuerySemanticLimits,
        typestate_limits: super::CodeQueryTypestateLimits,
        value_flow_limits: super::CodeQueryValueFlowLimits,
        taint_limits: super::CodeQueryTaintLimits,
        workspace_generation: u64,
        analysis_context: Option<&'a QueryAnalysisContext>,
    ) -> Self {
        debug_assert!(limits.all_positive());
        Self {
            workspace,
            cancellation,
            uncancelled: CancellationToken::default(),
            limits,
            typestate_limits,
            value_flow_limits,
            taint_limits,
            workspace_generation,
            analysis_context,
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
            indexed_source_identities: HashMap::default(),
            budget_exhausted: false,
            typestate: TypestateQueryState::default(),
            value_flow: ValueFlowQueryState::default(),
            taint: TaintQueryState::default(),
        }
    }

    pub(super) fn cfg(&mut self) -> CfgQueryAdapter<'_, 'a> {
        CfgQueryAdapter { context: self }
    }

    /// Bounded dispatch for one exact source position.
    ///
    /// The answer is the workspace oracle's own, projected into the row
    /// vocabulary without re-deriving anything. Materialization runs through
    /// this context first so the query's file and retained-byte budgets stay
    /// authoritative and one file reports one diagnostic; the oracle then
    /// shares this context's semantic budget and cancellation token.
    ///
    /// The result is total: a gate, a provider failure, or an interrupted
    /// dispatch still returns a typed answer, because the mandatory outcome
    /// row must exist for every input site.
    pub(super) fn dispatch_at_source(
        &mut self,
        file: &ProjectFile,
        range: crate::analyzer::Range,
    ) -> super::dispatch::DispatchSiteAnswer {
        use super::dispatch::{DispatchArm, DispatchSiteAnswer};

        if self
            .cancellation
            .is_some_and(crate::cancellation::CancellationToken::is_cancelled)
        {
            return DispatchSiteAnswer::interrupted("cancelled", None, None);
        }
        if self.materialize(file).is_none() {
            let (outcome, unsupported) = self.materialization_gate(file);
            return DispatchSiteAnswer::interrupted(outcome, unsupported, None);
        }

        let workspace = self.workspace;
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        let oracle = workspace.semantic_oracle_provider();
        let outcome = match oracle.dispatch_at_source(
            file,
            range,
            &mut SemanticRequest::new(&mut self.budget, cancellation),
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                let reason = error.to_string();
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::SemanticProviderFailed,
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    &reason,
                );
                return DispatchSiteAnswer::interrupted("unknown", None, None);
            }
        };

        let label = match &outcome {
            SemanticOutcome::Complete { .. } => "resolved",
            SemanticOutcome::Ambiguous { .. } => "ambiguous",
            SemanticOutcome::Unknown { .. } => "unknown",
            SemanticOutcome::Unsupported { .. } => "unsupported",
            SemanticOutcome::Unproven { .. } => "unproven",
            SemanticOutcome::ExceededBudget { .. } => "exceeded_budget",
            SemanticOutcome::Cancelled { .. } => "cancelled",
        };
        let semantic_unsupported = match &outcome {
            SemanticOutcome::Unsupported { capability, .. } => Some(capability.label()),
            _ => None,
        };
        let exceeded_limit = outcome
            .budget_exceeded()
            .map(|exceeded| exceeded.dimension().label());
        if matches!(outcome, SemanticOutcome::ExceededBudget { .. }) {
            self.budget_exhausted = true;
        }
        let Some(result) = outcome.available_value() else {
            return DispatchSiteAnswer::interrupted(label, semantic_unsupported, exceeded_limit);
        };

        let coverage = result.coverage();
        let mut arms = Vec::new();
        for observation in result.observations() {
            for candidate in observation.dispatch().candidates() {
                let target = candidate.target();
                let locator = target.semantics().locator();
                arms.push(DispatchArm {
                    target_id: super::dispatch::target_identity(
                        Some(target.artifact().key().public_fingerprint().to_string()).as_deref(),
                        locator,
                    ),
                    target_path: locator.path().as_str().to_string(),
                    target_unit: self.definition_for_locator(locator),
                    proof: candidate.proof().label(),
                    completeness: candidate.completeness().label(),
                    boundary_kind: None,
                });
            }
            for boundary in observation.dispatch().boundaries() {
                // An unresolved or truncated residual arm names no target. It
                // is already reflected in the site's coverage; inventing a row
                // for it would claim a target that does not exist.
                let Some(locator) = boundary.kind.target_locator() else {
                    continue;
                };
                let fingerprint = boundary
                    .exact_external_target()
                    .map(|target| target.artifact().public_fingerprint().to_string());
                arms.push(DispatchArm {
                    target_id: super::dispatch::target_identity(fingerprint.as_deref(), locator),
                    target_path: locator.path().as_str().to_string(),
                    target_unit: self.definition_for_locator(locator),
                    proof: boundary.proof.label(),
                    completeness: boundary.completeness.label(),
                    boundary_kind: Some(boundary.kind.label()),
                });
            }
        }
        DispatchSiteAnswer {
            outcome: label,
            coverage,
            call_site_count: result.observations().len(),
            semantic_unsupported,
            exceeded_limit,
            arms,
        }
    }

    /// The typed reason [`Self::materialize`] refused, so a mandatory row can
    /// state it instead of reporting a bare unknown.
    fn materialization_gate(&self, file: &ProjectFile) -> (&'static str, Option<&'static str>) {
        match self.cache.get(file) {
            Some(CachedSemanticMaterialization::FileBudgetExhausted)
            | Some(CachedSemanticMaterialization::RetainedBudgetExhausted) => {
                ("exceeded_budget", None)
            }
            Some(CachedSemanticMaterialization::Outcome { outcome, .. }) => match outcome {
                SemanticOutcome::Cancelled { .. } => ("cancelled", None),
                SemanticOutcome::Unsupported { capability, .. } => {
                    ("unsupported", Some(capability.label()))
                }
                SemanticOutcome::ExceededBudget { .. } => ("exceeded_budget", None),
                _ => ("unknown", None),
            },
            Some(CachedSemanticMaterialization::ProviderFailed(_)) | None => ("unknown", None),
        }
    }

    /// The workspace declaration for one semantic procedure locator, or `None`
    /// when the workspace no longer indexes a callable declaration that the
    /// locator's own span aligns with.
    ///
    /// The lookup is span-structural, never name-based: an exactly aligned
    /// declaration wins, and otherwise the smallest declaration whose own
    /// range contains the procedure's anchor span does.
    fn definition_for_locator(
        &self,
        locator: &SemanticLocator,
    ) -> Option<crate::analyzer::CodeUnit> {
        let file = super::witness_projection::locator_file(self.workspace, locator);
        super::dispatch::declaration_at_locator(self.workspace.analyzer(), locator, &file)
    }

    pub(super) fn procedure_of_match(&mut self, seed: &SeedMatch) -> Vec<SemanticProcedureValue> {
        let ranges = [seed_range(seed)];
        let Some((artifact, source, quality)) = self.materialize(&seed.file) else {
            return Vec::new();
        };
        if seed.facts.source_identity() != artifact.key().revision().content() {
            self.push_source_generation_changed(&seed.file);
            return Vec::new();
        }
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
            ProcedureRangeLookupStatus::SourceChanged => {
                self.push_source_generation_changed(&seed.file);
                Vec::new()
            }
        }
    }

    pub(super) fn seed_generation_is_current(&mut self, seed: &SeedMatch) -> bool {
        let current = *self
            .indexed_source_identities
            .entry(seed.file.clone())
            .or_insert_with(|| {
                self.workspace
                    .analyzer()
                    .indexed_source(&seed.file)
                    .map(|source| ContentIdentity::hash_bytes(source.as_bytes()))
            });
        if current == Some(seed.facts.source_identity()) {
            return true;
        }
        self.push_source_generation_changed(&seed.file);
        false
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
        let lookup = procedures_for_definition_with_limits(
            self.workspace.analyzer(),
            &declaration.unit,
            &artifact,
            self.limits
                .max_traversal_steps
                .saturating_sub(self.traversal_steps),
            self.cancellation.unwrap_or(&self.uncancelled),
        );
        self.traversal_steps = self.traversal_steps.saturating_add(lookup.examined);
        match lookup.status {
            ProcedureRangeLookupStatus::Complete => {
                self.finish_procedure_lookup(file, source, lookup.handles, quality)
            }
            ProcedureRangeLookupStatus::BudgetExhausted => {
                self.exhaust_traversal_budget(file, "declaration-to-procedure lookup");
                Vec::new()
            }
            ProcedureRangeLookupStatus::Cancelled => {
                self.push_diagnostic(
                    CodeQueryDiagnosticCode::Cancelled,
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    "declaration-to-procedure lookup was cancelled",
                );
                Vec::new()
            }
            ProcedureRangeLookupStatus::SourceChanged => {
                self.push_source_generation_changed(file);
                Vec::new()
            }
        }
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
        let mut diagnostics = std::mem::take(&mut self.diagnostics);
        diagnostics.extend(self.typestate.take_diagnostics());
        diagnostics.extend(self.value_flow.take_diagnostics());
        diagnostics.extend(self.taint.take_diagnostics());
        diagnostics
    }

    pub(super) fn work(&self) -> CodeQuerySemanticWork {
        let used = self.budget.used();
        CodeQuerySemanticWork {
            materialization_attempts: saturating_u64(self.attempts),
            unique_materialized_files: saturating_u64(self.materialized_files),
            request_cache_hits: saturating_u64(self.cache_hits),
            source_bytes: saturating_u64(used.source_bytes),
            procedures: saturating_u64(used.procedures),
            blocks: saturating_u64(used.blocks),
            program_points: saturating_u64(used.program_points),
            values: saturating_u64(used.values),
            allocations: saturating_u64(used.allocations),
            call_sites: saturating_u64(used.call_sites),
            memory_locations: saturating_u64(used.memory_locations),
            captures: saturating_u64(used.captures),
            source_mappings: saturating_u64(used.source_mappings),
            evidence: saturating_u64(used.evidence),
            gaps: saturating_u64(used.gaps),
            events: saturating_u64(used.events),
            control_edges: saturating_u64(used.control_edges),
            nested_entries: saturating_u64(used.nested_entries),
            retained_bytes: saturating_u64(self.retained_bytes),
            traversal_steps: saturating_u64(self.traversal_steps),
            budget_exhausted: self.budget_exhausted
                || self.typestate.semantic_budget_exhausted()
                || self.value_flow.semantic_budget_exhausted()
                || self.value_flow.query_budget_exhausted(),
            typestate: self.typestate.work(),
            value_flow: self.value_flow.work(),
        }
    }

    pub(super) fn typestate_findings(
        &mut self,
        procedure: &SemanticProcedureValue,
        protocol_ref: &ProtocolRef,
    ) -> Vec<SemanticTypestateFindingValue> {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        self.typestate.findings(
            self.workspace,
            self.workspace_generation,
            self.analysis_context,
            procedure,
            protocol_ref,
            &mut self.budget,
            self.typestate_limits,
            cancellation,
        )
    }

    pub(super) fn typestate_witness_truncated(&mut self, count: usize) {
        self.typestate.witness_truncated(count);
    }

    pub(super) fn value_flow_endpoints(
        &mut self,
        procedure: &SemanticProcedureValue,
        plan_ref: &ValueFlowPlanRef,
        max_endpoints: usize,
    ) -> Vec<SemanticFlowEndpointValue> {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        self.value_flow.endpoints(
            self.workspace,
            self.workspace_generation,
            self.analysis_context,
            procedure,
            plan_ref,
            &mut self.budget,
            self.value_flow_limits,
            max_endpoints,
            cancellation,
        )
    }

    pub(super) fn value_flow_witnesses(
        &mut self,
        endpoint: &SemanticFlowEndpointValue,
        traversal: &WitnessTraversal,
    ) -> Vec<SemanticFlowWitnessValue> {
        self.value_flow
            .witnesses(self.workspace, endpoint, traversal, self.value_flow_limits)
    }

    pub(super) fn taint_findings(
        &mut self,
        procedure: &SemanticProcedureValue,
        taint_ref: &TaintResultRef,
        max_findings: usize,
    ) -> Vec<SemanticTaintFindingValue> {
        let cancellation = self.cancellation.unwrap_or(&self.uncancelled);
        self.taint.findings(
            self.workspace,
            self.workspace_generation,
            self.analysis_context,
            procedure,
            taint_ref,
            self.taint_limits,
            max_findings,
            cancellation,
        )
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

    fn push_source_generation_changed(&mut self, file: &ProjectFile) {
        self.push_diagnostic(
            CodeQueryDiagnosticCode::SemanticResultsOmitted,
            CodeQueryDiagnosticImpact::Incomplete,
            file,
            "source generation changed between structural matching and semantic projection; retry the query for a coherent snapshot",
        );
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
    // Two ordinary points may legitimately share all public source and
    // evidence metadata. Keep the dense ID private, but use it as the
    // artifact-scoped discriminator that makes the public digest injective.
    digest.push(&handle.id().get().to_le_bytes());
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
    // Source and evidence rows are allowed to carry distinct provenance even
    // when their public content is otherwise identical. Keep their local IDs
    // private, but include them in the artifact-scoped digest: validation
    // rejects an otherwise-identical edge with the same pair, making this
    // injective without tying the wire identity to control-edge storage order.
    digest.push(&edge.source.get().to_le_bytes());
    digest.push(&edge.evidence.get().to_le_bytes());
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

/// The shared locator digest recipe, exposed for row families outside this
/// module that identify a semantic target by its locator.
pub(super) fn push_locator_bytes(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    push_locator(digest, locator);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        AdapterSemanticsVersion, BasicBlock, BlockId, ConfigurationFingerprint, ContentIdentity,
        ControlEdgeId, ControlEdgeKind, DeclarationLocator, DeclarationSegment,
        DeclarationSegmentKind, DependencyFingerprint, EvidenceId, ProcedureId, ProcedureKind,
        ProcedureSemanticsParts, ProgramPointId, SemanticArtifactKey, SemanticCapabilities,
        SemanticEvent, SemanticIrVersion, SemanticLanguage, SemanticRole, SourceAnchor,
        SourceMappingId, SourceMappingKind, SourcePosition, SourceRevision, SourceSpan,
        WorkspaceMountId, WorkspaceRelativePath,
    };

    fn test_anchor(offset: u32) -> SourceAnchor {
        SourceAnchor::new(
            SourceSpan::new(
                SourcePosition::new(offset, 0, offset),
                SourcePosition::new(offset + 1, 0, offset + 1),
            )
            .expect("ordered test span"),
            0,
        )
    }

    fn parallel_edge_artifact(reverse_edges: bool) -> Arc<SemanticArtifact> {
        let key = SemanticArtifactKey::new(
            WorkspaceMountId::hash_bytes(b"test mount"),
            WorkspaceRelativePath::new("src/Test.java").expect("valid test path"),
            SemanticLanguage::Standard(Language::Java),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(b"class Test {}"),
            },
            AdapterSemanticsVersion::hash_bytes("test-java", b"adapter")
                .expect("non-empty adapter version"),
            SemanticIrVersion::hash_bytes(b"semantic-ir-test"),
            ConfigurationFingerprint::hash_bytes(b"configuration"),
            DependencyFingerprint::hash_bytes(b"dependencies"),
        );
        let procedure_anchor = test_anchor(1);
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(DeclarationSegmentKind::File, "Test.java", test_anchor(0), 0)
                .expect("valid file segment"),
            DeclarationSegment::named(
                DeclarationSegmentKind::Function,
                "target",
                procedure_anchor,
                0,
            )
            .expect("valid procedure segment"),
        ])
        .expect("non-empty declaration");
        let locator = SemanticLocator::new(
            key.mount(),
            key.path().clone(),
            key.language(),
            declaration,
            SemanticRole::Procedure,
            procedure_anchor,
        );
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let mut procedure = ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            locator.clone(),
            ProcedureKind::Function,
            source,
            evidence,
        );
        procedure.source_mappings.extend([
            SourceMapping {
                id: source,
                locator: locator.clone(),
                kind: SourceMappingKind::Exact,
            },
            SourceMapping {
                id: SourceMappingId::new(1),
                locator,
                kind: SourceMappingKind::Exact,
            },
        ]);
        procedure.evidence_rows.extend([
            Evidence {
                id: evidence,
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                sources: Box::new([source]),
            },
            Evidence {
                id: EvidenceId::new(1),
                proof: ProofStatus::Proven,
                completeness: EvidenceCompleteness::Complete,
                sources: Box::new([SourceMappingId::new(1)]),
            },
        ]);

        let entry = ProgramPointId::new(0);
        let normal_exit = ProgramPointId::new(1);
        let exceptional_exit = ProgramPointId::new(2);
        let ordinary_first = ProgramPointId::new(3);
        let ordinary_second = ProgramPointId::new(4);
        procedure.blocks.push(BasicBlock {
            id: BlockId::new(0),
            points: Box::new([
                entry,
                ordinary_first,
                ordinary_second,
                normal_exit,
                exceptional_exit,
            ]),
            source,
            evidence,
        });
        procedure.points.extend([
            ProgramPoint {
                id: entry,
                block: BlockId::new(0),
                events: Box::new([SemanticEvent::new(
                    crate::analyzer::semantic::SemanticEffect::Entry,
                    source,
                    evidence,
                )]),
                source,
                evidence,
            },
            ProgramPoint {
                id: normal_exit,
                block: BlockId::new(0),
                events: Box::new([SemanticEvent::new(
                    crate::analyzer::semantic::SemanticEffect::NormalExit,
                    source,
                    evidence,
                )]),
                source,
                evidence,
            },
            ProgramPoint {
                id: exceptional_exit,
                block: BlockId::new(0),
                events: Box::new([SemanticEvent::new(
                    crate::analyzer::semantic::SemanticEffect::ExceptionalExit,
                    source,
                    evidence,
                )]),
                source,
                evidence,
            },
            ProgramPoint {
                id: ordinary_first,
                block: BlockId::new(0),
                events: Box::new([]),
                source,
                evidence,
            },
            ProgramPoint {
                id: ordinary_second,
                block: BlockId::new(0),
                events: Box::new([]),
                source,
                evidence,
            },
        ]);
        procedure.control_edges.extend([
            ControlEdge {
                source_point: entry,
                target_point: ordinary_first,
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            },
            ControlEdge {
                source_point: entry,
                target_point: ordinary_first,
                kind: ControlEdgeKind::Normal,
                source: SourceMappingId::new(1),
                evidence: EvidenceId::new(1),
            },
            ControlEdge {
                source_point: entry,
                target_point: exceptional_exit,
                kind: ControlEdgeKind::Exceptional,
                source,
                evidence,
            },
            ControlEdge {
                source_point: ordinary_first,
                target_point: ordinary_second,
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            },
            ControlEdge {
                source_point: ordinary_second,
                target_point: normal_exit,
                kind: ControlEdgeKind::Normal,
                source,
                evidence,
            },
        ]);
        if reverse_edges {
            procedure.control_edges.reverse();
        }

        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Procedures)
            .complete(SemanticCapability::EntryBoundary)
            .complete(SemanticCapability::NormalExitBoundary)
            .complete(SemanticCapability::ExceptionalExitBoundary)
            .complete(SemanticCapability::BasicBlocks)
            .complete(SemanticCapability::ProgramPoints)
            .complete(SemanticCapability::NormalControlFlow)
            .complete(SemanticCapability::ExceptionalControlFlow)
            .build();
        Arc::new(
            SemanticArtifact::try_new(key, capabilities, vec![procedure])
                .expect("parallel edges with distinct provenance are valid"),
        )
    }

    #[test]
    fn parallel_control_edges_have_distinct_public_wire_ids() {
        let artifact = parallel_edge_artifact(false);
        let procedure = artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("test procedure exists");
        let first = procedure
            .control_edge_handle(ControlEdgeId::new(0))
            .expect("first parallel edge exists");
        let second = procedure
            .control_edge_handle(ControlEdgeId::new(1))
            .expect("second parallel edge exists");

        assert_ne!(
            control_edge_wire_id(&first),
            control_edge_wire_id(&second),
            "valid parallel edges must not collide on the public wire"
        );

        let reversed = parallel_edge_artifact(true);
        let reversed_procedure = reversed
            .procedure_handle(ProcedureId::new(0))
            .expect("reordered test procedure exists");
        let mut original_ids = (0..5)
            .map(|id| {
                control_edge_wire_id(
                    &procedure
                        .control_edge_handle(ControlEdgeId::new(id))
                        .expect("original edge exists"),
                )
            })
            .collect::<Vec<_>>();
        let mut reordered_ids = (0..5)
            .map(|id| {
                control_edge_wire_id(
                    &reversed_procedure
                        .control_edge_handle(ControlEdgeId::new(id))
                        .expect("reordered edge exists"),
                )
            })
            .collect::<Vec<_>>();
        original_ids.sort_unstable();
        reordered_ids.sort_unstable();
        assert_eq!(
            original_ids, reordered_ids,
            "edge storage order must not affect public identities"
        );
    }

    #[test]
    fn ordinary_points_with_identical_public_metadata_have_distinct_wire_ids() {
        let artifact = parallel_edge_artifact(false);
        let procedure = artifact
            .procedure_handle(ProcedureId::new(0))
            .expect("test procedure exists");
        let first = procedure
            .point_handle(ProgramPointId::new(3))
            .expect("first ordinary point exists");
        let second = procedure
            .point_handle(ProgramPointId::new(4))
            .expect("second ordinary point exists");

        assert_ne!(
            program_point_wire_id(&first),
            program_point_wire_id(&second),
            "valid ordinary points that share source and evidence rows must not collide"
        );
    }
}
