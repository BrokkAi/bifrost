use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryDiagnosticCode {
    InvalidPlan,
    Cancelled,
    UnsupportedStructuralFeature,
    MissingStructuralAdapter,
    UnsupportedImportAnalysis,
    SemanticResultsOmitted,
    SemanticWorkspaceRequired,
    NoEnclosingProcedure,
    SemanticCapabilityUnsupported,
    SemanticAnalysisPartial,
    SemanticBudgetExhausted,
    SemanticProviderFailed,
    UnresolvedProtocolReference,
    TypestateRegistrationStale,
    TypestateHandleStale,
    TypestateRootMismatch,
    TypestateCapabilityUnsupported,
    TypestateAnalysisPartial,
    TypestateProviderFailed,
    TypestateSolverBudgetExhausted,
    TypestateFindingBudgetExhausted,
    TypestateWitnessTruncated,
    UnresolvedValueFlowPlanReference,
    ValueFlowRegistrationStale,
    ValueFlowHandleStale,
    ValueFlowRootMismatch,
    ValueFlowCapabilityUnsupported,
    ValueFlowAnalysisPartial,
    ValueFlowProviderFailed,
    ValueFlowSolverBudgetExhausted,
    ValueFlowWitnessTruncated,
    UnresolvedTaintResultReference,
    TaintRegistrationStale,
    TaintHandleStale,
    TaintRootMismatch,
    TaintPlanReportMismatch,
    TaintProjectionFailed,
    TaintFindingTruncated,
    ReceiverAnalysisPartial,
    ReceiverAnalysisFailed,
    CallRelationBudgetExhausted,
    CallRelationParseFailed,
    CallRelationCandidatesOmitted,
    CallRelationTargetsAmbiguous,
    CallRelationCandidateLimit,
    CallRelationAnalysisFailed,
    ReferenceSourceBytesTruncated,
    ReferenceCandidateFilesTruncated,
    ReferenceCandidatesOmitted,
    ReferenceTargetsAmbiguous,
    ReferenceCallsiteLimit,
    ReferenceAnalysisFailed,
    UsesParserUnsupported,
    UsesCandidateLimit,
    UsesTargetsAmbiguous,
    UsesCandidatesOmitted,
    ExecutionBudgetExhausted,
    PipelineBudgetExhausted,
    ImportGraphBudgetExhausted,
    OccurrenceRoleUnsupported,
    OccurrenceResolutionIncomplete,
    OccurrenceRowBudgetExhausted,
    EnvironmentAxisUnsupported,
    MaterializationAxisUnsupported,
    MaterializationDerivationIncomplete,
    MaterializationRowBudgetExhausted,
    EnvironmentDerivationIncomplete,
    EnvironmentRowBudgetExhausted,
    ResolutionTraceIncomplete,
    EdgeAxisUnsupported,
    EdgeDerivationIncomplete,
    IdentityAxisUnsupported,
    PathDerivationIncomplete,
    ResultLimitReached,
    BroadQuery,
}

impl CodeQueryDiagnosticCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPlan => "invalid_plan",
            Self::Cancelled => "cancelled",
            Self::UnsupportedStructuralFeature => "unsupported_structural_feature",
            Self::MissingStructuralAdapter => "missing_structural_adapter",
            Self::UnsupportedImportAnalysis => "unsupported_import_analysis",
            Self::SemanticResultsOmitted => "semantic_results_omitted",
            Self::SemanticWorkspaceRequired => "semantic_workspace_required",
            Self::NoEnclosingProcedure => "no_enclosing_procedure",
            Self::SemanticCapabilityUnsupported => "semantic_capability_unsupported",
            Self::SemanticAnalysisPartial => "semantic_analysis_partial",
            Self::SemanticBudgetExhausted => "semantic_budget_exhausted",
            Self::SemanticProviderFailed => "semantic_provider_failed",
            Self::UnresolvedProtocolReference => "unresolved_protocol_reference",
            Self::TypestateRegistrationStale => "typestate_registration_stale",
            Self::TypestateHandleStale => "typestate_handle_stale",
            Self::TypestateRootMismatch => "typestate_root_mismatch",
            Self::TypestateCapabilityUnsupported => "typestate_capability_unsupported",
            Self::TypestateAnalysisPartial => "typestate_analysis_partial",
            Self::TypestateProviderFailed => "typestate_provider_failed",
            Self::TypestateSolverBudgetExhausted => "typestate_solver_budget_exhausted",
            Self::TypestateFindingBudgetExhausted => "typestate_finding_budget_exhausted",
            Self::TypestateWitnessTruncated => "typestate_witness_truncated",
            Self::UnresolvedValueFlowPlanReference => "unresolved_value_flow_plan_reference",
            Self::ValueFlowRegistrationStale => "value_flow_registration_stale",
            Self::ValueFlowHandleStale => "value_flow_handle_stale",
            Self::ValueFlowRootMismatch => "value_flow_root_mismatch",
            Self::ValueFlowCapabilityUnsupported => "value_flow_capability_unsupported",
            Self::ValueFlowAnalysisPartial => "value_flow_analysis_partial",
            Self::ValueFlowProviderFailed => "value_flow_provider_failed",
            Self::ValueFlowSolverBudgetExhausted => "value_flow_solver_budget_exhausted",
            Self::ValueFlowWitnessTruncated => "value_flow_witness_truncated",
            Self::UnresolvedTaintResultReference => "unresolved_taint_result_reference",
            Self::TaintRegistrationStale => "taint_registration_stale",
            Self::TaintHandleStale => "taint_handle_stale",
            Self::TaintRootMismatch => "taint_root_mismatch",
            Self::TaintPlanReportMismatch => "taint_plan_report_mismatch",
            Self::TaintProjectionFailed => "taint_projection_failed",
            Self::TaintFindingTruncated => "taint_finding_truncated",
            Self::ReceiverAnalysisPartial => "receiver_analysis_partial",
            Self::ReceiverAnalysisFailed => "receiver_analysis_failed",
            Self::CallRelationBudgetExhausted => "call_relation_budget_exhausted",
            Self::CallRelationParseFailed => "call_relation_parse_failed",
            Self::CallRelationCandidatesOmitted => "call_relation_candidates_omitted",
            Self::CallRelationTargetsAmbiguous => "call_relation_targets_ambiguous",
            Self::CallRelationCandidateLimit => "call_relation_candidate_limit",
            Self::CallRelationAnalysisFailed => "call_relation_analysis_failed",
            Self::ReferenceSourceBytesTruncated => "reference_source_bytes_truncated",
            Self::ReferenceCandidateFilesTruncated => "reference_candidate_files_truncated",
            Self::ReferenceCandidatesOmitted => "reference_candidates_omitted",
            Self::ReferenceTargetsAmbiguous => "reference_targets_ambiguous",
            Self::ReferenceCallsiteLimit => "reference_callsite_limit",
            Self::ReferenceAnalysisFailed => "reference_analysis_failed",
            Self::UsesParserUnsupported => "uses_parser_unsupported",
            Self::UsesCandidateLimit => "uses_candidate_limit",
            Self::UsesTargetsAmbiguous => "uses_targets_ambiguous",
            Self::UsesCandidatesOmitted => "uses_candidates_omitted",
            Self::ExecutionBudgetExhausted => "execution_budget_exhausted",
            Self::PipelineBudgetExhausted => "pipeline_budget_exhausted",
            Self::ImportGraphBudgetExhausted => "import_graph_budget_exhausted",
            Self::OccurrenceRoleUnsupported => "occurrence_role_unsupported",
            Self::OccurrenceResolutionIncomplete => "occurrence_resolution_incomplete",
            Self::OccurrenceRowBudgetExhausted => "occurrence_row_budget_exhausted",
            Self::EnvironmentAxisUnsupported => "environment_axis_unsupported",
            Self::MaterializationAxisUnsupported => "materialization_axis_unsupported",
            Self::MaterializationDerivationIncomplete => "materialization_derivation_incomplete",
            Self::MaterializationRowBudgetExhausted => "materialization_row_budget_exhausted",
            Self::EnvironmentDerivationIncomplete => "environment_derivation_incomplete",
            Self::EnvironmentRowBudgetExhausted => "environment_row_budget_exhausted",
            Self::ResolutionTraceIncomplete => "resolution_trace_incomplete",
            Self::EdgeAxisUnsupported => "edge_axis_unsupported",
            Self::EdgeDerivationIncomplete => "edge_derivation_incomplete",
            Self::IdentityAxisUnsupported => "identity_axis_unsupported",
            Self::PathDerivationIncomplete => "path_derivation_incomplete",
            Self::ResultLimitReached => "result_limit_reached",
            Self::BroadQuery => "broad_query",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryDiagnosticImpact {
    Advisory,
    DeclaredNonExhaustive,
    Incomplete,
    Invalid,
}

impl CodeQueryDiagnosticImpact {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::DeclaredNonExhaustive => "declared_non_exhaustive",
            Self::Incomplete => "incomplete",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryDiagnostic {
    pub code: CodeQueryDiagnosticCode,
    pub impact: CodeQueryDiagnosticImpact,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub branch: Vec<usize>,
    pub language: &'static str,
    pub message: String,
}

impl CodeQueryDiagnostic {
    /// Build the shared, unstyled diagnostic label used by text transports.
    #[doc(hidden)]
    pub fn presentation_label(&self) -> String {
        let kind = format!("{} [{}]", self.impact.as_str(), self.code.as_str());
        if self.branch.is_empty() {
            kind
        } else {
            format!("{kind} [branch {}]", format_branch_path(&self.branch))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CodeQueryExecutionLimits {
    pub max_scanned_files: usize,
    pub max_scanned_source_bytes: usize,
    pub max_fact_nodes: usize,
    pub max_pipeline_rows: usize,
    pub semantic: CodeQuerySemanticLimits,
    pub typestate: CodeQueryTypestateLimits,
    pub value_flow: CodeQueryValueFlowLimits,
    pub taint: CodeQueryTaintLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeQueryTaintLimits {
    pub max_findings: usize,
    pub max_projected_bytes: usize,
    pub max_origins_per_finding: usize,
    pub max_witnesses_per_finding: usize,
    pub max_steps_per_witness: usize,
    pub max_witness_bytes: usize,
}

impl CodeQueryTaintLimits {
    pub fn is_valid(self) -> bool {
        self.max_findings > 0
            && self.max_findings <= 50_000
            && self.max_projected_bytes > 0
            && self.max_projected_bytes <= 64 * 1024 * 1024
            && self.max_origins_per_finding > 0
            && self.max_origins_per_finding <= 50_000
            && self.max_witnesses_per_finding > 0
            && self.max_witnesses_per_finding <= 50_000
            && self.max_steps_per_witness > 0
            && self.max_steps_per_witness <= 16_384
            && self.max_witness_bytes > 0
            && self.max_witness_bytes <= 16 * 1024 * 1024
    }

    pub const fn projection_limits(self) -> CodeQueryTaintProjectionLimits {
        CodeQueryTaintProjectionLimits::new(
            self.max_origins_per_finding,
            self.max_witnesses_per_finding,
            self.max_steps_per_witness,
            self.max_witness_bytes,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeQueryValueFlowLimits {
    pub solver_work: crate::analyzer::dataflow::SolverWork,
    pub max_retained_relations: usize,
    pub max_retained_bytes: usize,
    pub max_endpoints: usize,
    pub max_witnesses: usize,
    pub max_witness_steps: usize,
    pub max_witness_expansions: usize,
    pub max_witness_bytes: usize,
    pub max_total_witness_steps: usize,
    pub max_total_witness_expansions: usize,
    pub max_total_witness_bytes: usize,
}

impl CodeQueryValueFlowLimits {
    pub fn is_valid(self) -> bool {
        let hard_solver = crate::analyzer::dataflow::SolverWork::default_limits();
        let solver_valid = crate::analyzer::dataflow::SolverBudgetDimension::ALL
            .into_iter()
            .all(|dimension| {
                let value = self.solver_work.get(dimension);
                value > 0 && value <= hard_solver.get(dimension)
            });
        solver_valid
            && self.max_retained_relations > 0
            && self.max_retained_relations <= u32::MAX as usize
            && self.max_retained_bytes > 0
            && self.max_retained_bytes <= 64 * 1024 * 1024
            && self.max_endpoints > 0
            && self.max_endpoints <= 50_000
            && self.max_witnesses > 0
            && self.max_witnesses <= 50_000
            && self.max_witness_steps > 0
            && self.max_witness_steps <= 16_384
            && self.max_witness_expansions > 0
            && self.max_witness_expansions <= 65_536
            && self.max_witness_bytes > 0
            && self.max_witness_bytes <= 16 * 1024 * 1024
            && self.max_total_witness_steps > 0
            && self.max_total_witness_steps <= 1_000_000
            && self.max_total_witness_expansions > 0
            && self.max_total_witness_expansions <= 4_000_000
            && self.max_total_witness_bytes > 0
            && self.max_total_witness_bytes <= 64 * 1024 * 1024
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeQueryTypestateLimits {
    pub solver_work: crate::analyzer::dataflow::SolverWork,
    pub max_reached_rows: usize,
    pub max_candidates: usize,
    pub max_witness_steps: usize,
    pub max_witness_expansions: usize,
    pub max_total_witness_expansions: usize,
    pub max_witness_bytes: usize,
}

impl CodeQueryTypestateLimits {
    pub fn is_valid(self) -> bool {
        let hard_solver = crate::analyzer::dataflow::SolverWork::default_limits();
        let solver_valid = crate::analyzer::dataflow::SolverBudgetDimension::ALL
            .into_iter()
            .all(|dimension| {
                let value = self.solver_work.get(dimension);
                value > 0 && value <= hard_solver.get(dimension)
            });
        solver_valid
            && self.max_reached_rows > 0
            && self.max_reached_rows
                <= crate::analyzer::typestate::MAX_TYPESTATE_FINDING_REACHED_ROWS
            && self.max_candidates > 0
            && self.max_candidates <= crate::analyzer::typestate::MAX_TYPESTATE_FINDING_CANDIDATES
            && self.max_witness_steps > 0
            && self.max_witness_steps <= crate::analyzer::typestate::MAX_TYPESTATE_WITNESS_STEPS
            && self.max_witness_expansions > 0
            && self.max_witness_expansions
                <= crate::analyzer::typestate::MAX_TYPESTATE_WITNESS_EXPANSIONS
            && self.max_total_witness_expansions > 0
            && self.max_total_witness_expansions
                <= crate::analyzer::typestate::MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS
            && self.max_witness_bytes > 0
            && self.max_witness_bytes
                <= crate::analyzer::typestate::MAX_TYPESTATE_FINDING_WITNESS_BYTES
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeQuerySemanticLimits {
    pub max_materialized_files: usize,
    pub max_source_bytes: usize,
    pub max_rows_per_dimension: usize,
    pub max_retained_bytes: usize,
    pub max_traversal_steps: usize,
}

impl CodeQuerySemanticLimits {
    pub const fn all_positive(self) -> bool {
        self.max_materialized_files > 0
            && self.max_source_bytes > 0
            && self.max_rows_per_dimension > 0
            && self.max_retained_bytes > 0
            && self.max_traversal_steps > 0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CodeQueryExecutionWork {
    pub scanned_files: u64,
    pub scanned_source_bytes: u64,
    pub fact_nodes: u64,
    pub pipeline_rows: u64,
    pub examined_references: u64,
    pub semantic: CodeQuerySemanticWork,
}

impl CodeQueryExecutionWork {
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            scanned_files: self.scanned_files.saturating_add(other.scanned_files),
            scanned_source_bytes: self
                .scanned_source_bytes
                .saturating_add(other.scanned_source_bytes),
            fact_nodes: self.fact_nodes.saturating_add(other.fact_nodes),
            pipeline_rows: self.pipeline_rows.saturating_add(other.pipeline_rows),
            examined_references: self
                .examined_references
                .saturating_add(other.examined_references),
            semantic: self.semantic.saturating_add(other.semantic),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CodeQuerySemanticWork {
    pub materialization_attempts: u64,
    pub unique_materialized_files: u64,
    pub request_cache_hits: u64,
    pub source_bytes: u64,
    pub procedures: u64,
    pub blocks: u64,
    pub program_points: u64,
    pub values: u64,
    pub allocations: u64,
    pub call_sites: u64,
    pub memory_locations: u64,
    pub captures: u64,
    pub source_mappings: u64,
    pub evidence: u64,
    pub gaps: u64,
    pub events: u64,
    pub control_edges: u64,
    pub nested_entries: u64,
    pub retained_bytes: u64,
    pub traversal_steps: u64,
    pub budget_exhausted: bool,
    #[serde(skip_serializing_if = "CodeQueryTypestateWork::is_empty")]
    pub typestate: CodeQueryTypestateWork,
    #[serde(skip_serializing_if = "CodeQueryValueFlowWork::is_empty")]
    pub value_flow: CodeQueryValueFlowWork,
}

impl CodeQuerySemanticWork {
    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        Self {
            materialization_attempts: self
                .materialization_attempts
                .saturating_add(other.materialization_attempts),
            unique_materialized_files: self
                .unique_materialized_files
                .saturating_add(other.unique_materialized_files),
            request_cache_hits: self
                .request_cache_hits
                .saturating_add(other.request_cache_hits),
            source_bytes: self.source_bytes.saturating_add(other.source_bytes),
            procedures: self.procedures.saturating_add(other.procedures),
            blocks: self.blocks.saturating_add(other.blocks),
            program_points: self.program_points.saturating_add(other.program_points),
            values: self.values.saturating_add(other.values),
            allocations: self.allocations.saturating_add(other.allocations),
            call_sites: self.call_sites.saturating_add(other.call_sites),
            memory_locations: self.memory_locations.saturating_add(other.memory_locations),
            captures: self.captures.saturating_add(other.captures),
            source_mappings: self.source_mappings.saturating_add(other.source_mappings),
            evidence: self.evidence.saturating_add(other.evidence),
            gaps: self.gaps.saturating_add(other.gaps),
            events: self.events.saturating_add(other.events),
            control_edges: self.control_edges.saturating_add(other.control_edges),
            nested_entries: self.nested_entries.saturating_add(other.nested_entries),
            retained_bytes: self.retained_bytes.saturating_add(other.retained_bytes),
            traversal_steps: self.traversal_steps.saturating_add(other.traversal_steps),
            budget_exhausted: self.budget_exhausted || other.budget_exhausted,
            typestate: self.typestate.saturating_add(other.typestate),
            value_flow: self.value_flow.saturating_add(other.value_flow),
        }
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            materialization_attempts: self
                .materialization_attempts
                .saturating_sub(earlier.materialization_attempts),
            unique_materialized_files: self
                .unique_materialized_files
                .saturating_sub(earlier.unique_materialized_files),
            request_cache_hits: self
                .request_cache_hits
                .saturating_sub(earlier.request_cache_hits),
            source_bytes: self.source_bytes.saturating_sub(earlier.source_bytes),
            procedures: self.procedures.saturating_sub(earlier.procedures),
            blocks: self.blocks.saturating_sub(earlier.blocks),
            program_points: self.program_points.saturating_sub(earlier.program_points),
            values: self.values.saturating_sub(earlier.values),
            allocations: self.allocations.saturating_sub(earlier.allocations),
            call_sites: self.call_sites.saturating_sub(earlier.call_sites),
            memory_locations: self
                .memory_locations
                .saturating_sub(earlier.memory_locations),
            captures: self.captures.saturating_sub(earlier.captures),
            source_mappings: self.source_mappings.saturating_sub(earlier.source_mappings),
            evidence: self.evidence.saturating_sub(earlier.evidence),
            gaps: self.gaps.saturating_sub(earlier.gaps),
            events: self.events.saturating_sub(earlier.events),
            control_edges: self.control_edges.saturating_sub(earlier.control_edges),
            nested_entries: self.nested_entries.saturating_sub(earlier.nested_entries),
            retained_bytes: self.retained_bytes.saturating_sub(earlier.retained_bytes),
            traversal_steps: self.traversal_steps.saturating_sub(earlier.traversal_steps),
            budget_exhausted: self.budget_exhausted && !earlier.budget_exhausted,
            typestate: self.typestate.saturating_sub(earlier.typestate),
            value_flow: self.value_flow.saturating_sub(earlier.value_flow),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CodeQueryTypestateWork {
    pub solves: u64,
    pub cache_hits: u64,
    pub summary_hits: u64,
    pub summary_misses: u64,
    pub summary_rejections: u64,
    pub summary_evictions: u64,
    pub summary_recomputations: u64,
    pub reached_rows: u64,
    pub findings: u64,
    pub omitted_findings: u64,
    pub witnesses: u64,
    pub omitted_witnesses: u64,
    pub witness_steps: u64,
    pub witness_bytes: u64,
    pub fixed_point_solves: u64,
    pub cancelled_solves: u64,
    pub budget_exhausted_solves: u64,
    pub failed_solves: u64,
    pub finding_budget_exhausted: bool,
}

impl CodeQueryTypestateWork {
    pub const fn is_empty(&self) -> bool {
        self.solves == 0
            && self.cache_hits == 0
            && self.summary_hits == 0
            && self.summary_misses == 0
            && self.summary_rejections == 0
            && self.summary_evictions == 0
            && self.summary_recomputations == 0
            && self.reached_rows == 0
            && self.findings == 0
            && self.omitted_findings == 0
            && self.witnesses == 0
            && self.omitted_witnesses == 0
            && self.witness_steps == 0
            && self.witness_bytes == 0
            && self.fixed_point_solves == 0
            && self.cancelled_solves == 0
            && self.budget_exhausted_solves == 0
            && self.failed_solves == 0
            && !self.finding_budget_exhausted
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            solves: self.solves.saturating_sub(earlier.solves),
            cache_hits: self.cache_hits.saturating_sub(earlier.cache_hits),
            summary_hits: self.summary_hits.saturating_sub(earlier.summary_hits),
            summary_misses: self.summary_misses.saturating_sub(earlier.summary_misses),
            summary_rejections: self
                .summary_rejections
                .saturating_sub(earlier.summary_rejections),
            summary_evictions: self
                .summary_evictions
                .saturating_sub(earlier.summary_evictions),
            summary_recomputations: self
                .summary_recomputations
                .saturating_sub(earlier.summary_recomputations),
            reached_rows: self.reached_rows.saturating_sub(earlier.reached_rows),
            findings: self.findings.saturating_sub(earlier.findings),
            omitted_findings: self
                .omitted_findings
                .saturating_sub(earlier.omitted_findings),
            witnesses: self.witnesses.saturating_sub(earlier.witnesses),
            omitted_witnesses: self
                .omitted_witnesses
                .saturating_sub(earlier.omitted_witnesses),
            witness_steps: self.witness_steps.saturating_sub(earlier.witness_steps),
            witness_bytes: self.witness_bytes.saturating_sub(earlier.witness_bytes),
            fixed_point_solves: self
                .fixed_point_solves
                .saturating_sub(earlier.fixed_point_solves),
            cancelled_solves: self
                .cancelled_solves
                .saturating_sub(earlier.cancelled_solves),
            budget_exhausted_solves: self
                .budget_exhausted_solves
                .saturating_sub(earlier.budget_exhausted_solves),
            failed_solves: self.failed_solves.saturating_sub(earlier.failed_solves),
            finding_budget_exhausted: self.finding_budget_exhausted
                && !earlier.finding_budget_exhausted,
        }
    }

    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        Self {
            solves: self.solves.saturating_add(other.solves),
            cache_hits: self.cache_hits.saturating_add(other.cache_hits),
            summary_hits: self.summary_hits.saturating_add(other.summary_hits),
            summary_misses: self.summary_misses.saturating_add(other.summary_misses),
            summary_rejections: self
                .summary_rejections
                .saturating_add(other.summary_rejections),
            summary_evictions: self
                .summary_evictions
                .saturating_add(other.summary_evictions),
            summary_recomputations: self
                .summary_recomputations
                .saturating_add(other.summary_recomputations),
            reached_rows: self.reached_rows.saturating_add(other.reached_rows),
            findings: self.findings.saturating_add(other.findings),
            omitted_findings: self.omitted_findings.saturating_add(other.omitted_findings),
            witnesses: self.witnesses.saturating_add(other.witnesses),
            omitted_witnesses: self
                .omitted_witnesses
                .saturating_add(other.omitted_witnesses),
            witness_steps: self.witness_steps.saturating_add(other.witness_steps),
            witness_bytes: self.witness_bytes.saturating_add(other.witness_bytes),
            fixed_point_solves: self
                .fixed_point_solves
                .saturating_add(other.fixed_point_solves),
            cancelled_solves: self.cancelled_solves.saturating_add(other.cancelled_solves),
            budget_exhausted_solves: self
                .budget_exhausted_solves
                .saturating_add(other.budget_exhausted_solves),
            failed_solves: self.failed_solves.saturating_add(other.failed_solves),
            finding_budget_exhausted: self.finding_budget_exhausted
                || other.finding_budget_exhausted,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CodeQueryValueFlowWork {
    pub solves: u64,
    pub cache_hits: u64,
    pub reached_rows: u64,
    pub meetings: u64,
    pub sink_outcomes: u64,
    pub omitted_endpoints: u64,
    pub witnesses: u64,
    pub omitted_witnesses: u64,
    pub witness_expansions: u64,
    pub witness_steps: u64,
    pub witness_bytes: u64,
    pub fixed_point_solves: u64,
    pub cancelled_solves: u64,
    pub budget_exhausted_solves: u64,
    pub failed_solves: u64,
    pub endpoint_truncated: bool,
    pub witness_truncated: bool,
}

impl CodeQueryValueFlowWork {
    pub const fn is_empty(&self) -> bool {
        self.solves == 0
            && self.cache_hits == 0
            && self.reached_rows == 0
            && self.meetings == 0
            && self.sink_outcomes == 0
            && self.omitted_endpoints == 0
            && self.witnesses == 0
            && self.omitted_witnesses == 0
            && self.witness_expansions == 0
            && self.witness_steps == 0
            && self.witness_bytes == 0
            && self.fixed_point_solves == 0
            && self.cancelled_solves == 0
            && self.budget_exhausted_solves == 0
            && self.failed_solves == 0
            && !self.endpoint_truncated
            && !self.witness_truncated
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            solves: self.solves.saturating_sub(earlier.solves),
            cache_hits: self.cache_hits.saturating_sub(earlier.cache_hits),
            reached_rows: self.reached_rows.saturating_sub(earlier.reached_rows),
            meetings: self.meetings.saturating_sub(earlier.meetings),
            sink_outcomes: self.sink_outcomes.saturating_sub(earlier.sink_outcomes),
            omitted_endpoints: self
                .omitted_endpoints
                .saturating_sub(earlier.omitted_endpoints),
            witnesses: self.witnesses.saturating_sub(earlier.witnesses),
            omitted_witnesses: self
                .omitted_witnesses
                .saturating_sub(earlier.omitted_witnesses),
            witness_expansions: self
                .witness_expansions
                .saturating_sub(earlier.witness_expansions),
            witness_steps: self.witness_steps.saturating_sub(earlier.witness_steps),
            witness_bytes: self.witness_bytes.saturating_sub(earlier.witness_bytes),
            fixed_point_solves: self
                .fixed_point_solves
                .saturating_sub(earlier.fixed_point_solves),
            cancelled_solves: self
                .cancelled_solves
                .saturating_sub(earlier.cancelled_solves),
            budget_exhausted_solves: self
                .budget_exhausted_solves
                .saturating_sub(earlier.budget_exhausted_solves),
            failed_solves: self.failed_solves.saturating_sub(earlier.failed_solves),
            endpoint_truncated: self.endpoint_truncated && !earlier.endpoint_truncated,
            witness_truncated: self.witness_truncated && !earlier.witness_truncated,
        }
    }

    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        Self {
            solves: self.solves.saturating_add(other.solves),
            cache_hits: self.cache_hits.saturating_add(other.cache_hits),
            reached_rows: self.reached_rows.saturating_add(other.reached_rows),
            meetings: self.meetings.saturating_add(other.meetings),
            sink_outcomes: self.sink_outcomes.saturating_add(other.sink_outcomes),
            omitted_endpoints: self
                .omitted_endpoints
                .saturating_add(other.omitted_endpoints),
            witnesses: self.witnesses.saturating_add(other.witnesses),
            omitted_witnesses: self
                .omitted_witnesses
                .saturating_add(other.omitted_witnesses),
            witness_expansions: self
                .witness_expansions
                .saturating_add(other.witness_expansions),
            witness_steps: self.witness_steps.saturating_add(other.witness_steps),
            witness_bytes: self.witness_bytes.saturating_add(other.witness_bytes),
            fixed_point_solves: self
                .fixed_point_solves
                .saturating_add(other.fixed_point_solves),
            cancelled_solves: self.cancelled_solves.saturating_add(other.cancelled_solves),
            budget_exhausted_solves: self
                .budget_exhausted_solves
                .saturating_add(other.budget_exhausted_solves),
            failed_solves: self.failed_solves.saturating_add(other.failed_solves),
            endpoint_truncated: self.endpoint_truncated || other.endpoint_truncated,
            witness_truncated: self.witness_truncated || other.witness_truncated,
        }
    }
}

impl Default for CodeQueryExecutionLimits {
    fn default() -> Self {
        Self {
            max_scanned_files: MAX_SCANNED_FILES,
            max_scanned_source_bytes: MAX_SCANNED_SOURCE_BYTES,
            max_fact_nodes: MAX_FACT_NODES,
            max_pipeline_rows: MAX_PIPELINE_ROWS,
            semantic: CodeQuerySemanticLimits::default(),
            typestate: CodeQueryTypestateLimits::default(),
            value_flow: CodeQueryValueFlowLimits::default(),
            taint: CodeQueryTaintLimits::default(),
        }
    }
}

impl Default for CodeQuerySemanticLimits {
    fn default() -> Self {
        Self {
            max_materialized_files: MAX_SEMANTIC_MATERIALIZED_FILES,
            max_source_bytes: MAX_SEMANTIC_SOURCE_BYTES,
            max_rows_per_dimension: MAX_SEMANTIC_ROWS_PER_DIMENSION,
            max_retained_bytes: MAX_SEMANTIC_RETAINED_BYTES,
            max_traversal_steps: MAX_SEMANTIC_TRAVERSAL_STEPS,
        }
    }
}

impl Default for CodeQueryTypestateLimits {
    fn default() -> Self {
        Self {
            solver_work: crate::analyzer::dataflow::SolverWork::default_limits(),
            max_reached_rows: crate::analyzer::typestate::MAX_TYPESTATE_FINDING_REACHED_ROWS,
            max_candidates: crate::analyzer::typestate::MAX_TYPESTATE_FINDING_CANDIDATES,
            max_witness_steps: crate::analyzer::typestate::MAX_TYPESTATE_WITNESS_STEPS,
            max_witness_expansions: crate::analyzer::typestate::MAX_TYPESTATE_WITNESS_EXPANSIONS,
            max_total_witness_expansions:
                crate::analyzer::typestate::MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS,
            max_witness_bytes: crate::analyzer::typestate::MAX_TYPESTATE_FINDING_WITNESS_BYTES,
        }
    }
}

impl Default for CodeQueryValueFlowLimits {
    fn default() -> Self {
        Self {
            solver_work: crate::analyzer::dataflow::SolverWork::default_limits(),
            max_retained_relations: 262_144,
            max_retained_bytes: 16 * 1024 * 1024,
            max_endpoints: 50_000,
            max_witnesses: 4_096,
            max_witness_steps: 4_096,
            max_witness_expansions: 16_384,
            max_witness_bytes: 4 * 1024 * 1024,
            max_total_witness_steps: 262_144,
            max_total_witness_expansions: 1_048_576,
            max_total_witness_bytes: 16 * 1024 * 1024,
        }
    }
}

impl Default for CodeQueryTaintLimits {
    fn default() -> Self {
        Self {
            max_findings: 50_000,
            max_projected_bytes: 64 * 1024 * 1024,
            max_origins_per_finding: 4_096,
            max_witnesses_per_finding: 4_096,
            max_steps_per_witness: 4_096,
            max_witness_bytes: 4 * 1024 * 1024,
        }
    }
}
