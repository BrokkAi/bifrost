use super::*;
use crate::analyzer::semantic::{SemanticBudgetDimension, SemanticWork};

/// Declare one labeled CodeQuery diagnostic vocabulary once.
///
/// The variant list, each variant's wire label, the complete label inventory,
/// and the `as_str` projection all come from the single table below. A new
/// variant therefore cannot reach the wire without also reaching `LABELS`,
/// which is the inventory the Python client's parity test mirrors (#2898).
macro_rules! code_query_labeled_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $($variant:ident => $label:literal,)+
        }
    ) => {
        $(#[$meta])*
        pub enum $name {
            $($variant,)+
        }

        impl $name {
            /// Every label this vocabulary publishes, in declaration order.
            pub const LABELS: &'static [&'static str] = &[$($label,)+];

            /// The `snake_case` label this variant serializes as.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }
        }
    };
}

code_query_labeled_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    CodeQueryDiagnosticCode {
        InvalidPlan => "invalid_plan",
        Cancelled => "cancelled",
        UnsupportedStructuralFeature => "unsupported_structural_feature",
        MissingStructuralAdapter => "missing_structural_adapter",
        UnsupportedImportAnalysis => "unsupported_import_analysis",
        SemanticResultsOmitted => "semantic_results_omitted",
        SemanticWorkspaceRequired => "semantic_workspace_required",
        NoEnclosingProcedure => "no_enclosing_procedure",
        SemanticCapabilityUnsupported => "semantic_capability_unsupported",
        SemanticAnalysisPartial => "semantic_analysis_partial",
        CallBindingDispatchPartial => "call_binding_dispatch_partial",
        SemanticBudgetExhausted => "semantic_budget_exhausted",
        SemanticProviderFailed => "semantic_provider_failed",
        UnresolvedProtocolReference => "unresolved_protocol_reference",
        TypestateRegistrationStale => "typestate_registration_stale",
        TypestateHandleStale => "typestate_handle_stale",
        TypestateRootMismatch => "typestate_root_mismatch",
        TypestateCapabilityUnsupported => "typestate_capability_unsupported",
        TypestateAnalysisPartial => "typestate_analysis_partial",
        TypestateProviderFailed => "typestate_provider_failed",
        TypestateSolverBudgetExhausted => "typestate_solver_budget_exhausted",
        TypestateFindingBudgetExhausted => "typestate_finding_budget_exhausted",
        TypestateWitnessTruncated => "typestate_witness_truncated",
        UnresolvedValueFlowPlanReference => "unresolved_value_flow_plan_reference",
        ValueFlowRegistrationStale => "value_flow_registration_stale",
        ValueFlowHandleStale => "value_flow_handle_stale",
        ValueFlowRootMismatch => "value_flow_root_mismatch",
        ValueFlowCapabilityUnsupported => "value_flow_capability_unsupported",
        ValueFlowAnalysisPartial => "value_flow_analysis_partial",
        ValueFlowProviderFailed => "value_flow_provider_failed",
        ValueFlowSolverBudgetExhausted => "value_flow_solver_budget_exhausted",
        ValueFlowWitnessTruncated => "value_flow_witness_truncated",
        UnresolvedTaintResultReference => "unresolved_taint_result_reference",
        TaintRegistrationStale => "taint_registration_stale",
        TaintHandleStale => "taint_handle_stale",
        TaintRootMismatch => "taint_root_mismatch",
        TaintPlanReportMismatch => "taint_plan_report_mismatch",
        TaintProjectionFailed => "taint_projection_failed",
        TaintFindingTruncated => "taint_finding_truncated",
        ReceiverAnalysisPartial => "receiver_analysis_partial",
        ReceiverAnalysisFailed => "receiver_analysis_failed",
        CallRelationBudgetExhausted => "call_relation_budget_exhausted",
        CallRelationParseFailed => "call_relation_parse_failed",
        CallRelationCandidatesOmitted => "call_relation_candidates_omitted",
        CallRelationTargetsAmbiguous => "call_relation_targets_ambiguous",
        CallRelationCandidateLimit => "call_relation_candidate_limit",
        CallRelationAnalysisFailed => "call_relation_analysis_failed",
        ReferenceSourceBytesTruncated => "reference_source_bytes_truncated",
        ReferenceCandidateFilesTruncated => "reference_candidate_files_truncated",
        ReferenceCandidatesOmitted => "reference_candidates_omitted",
        ReferenceTargetsAmbiguous => "reference_targets_ambiguous",
        ReferenceCallsiteLimit => "reference_callsite_limit",
        ReferenceAnalysisFailed => "reference_analysis_failed",
        UsesParserUnsupported => "uses_parser_unsupported",
        UsesCandidateLimit => "uses_candidate_limit",
        UsesTargetsAmbiguous => "uses_targets_ambiguous",
        UsesCandidatesOmitted => "uses_candidates_omitted",
        ExecutionBudgetExhausted => "execution_budget_exhausted",
        PipelineBudgetExhausted => "pipeline_budget_exhausted",
        ImportGraphBudgetExhausted => "import_graph_budget_exhausted",
        OccurrenceRoleUnsupported => "occurrence_role_unsupported",
        OccurrenceResolutionIncomplete => "occurrence_resolution_incomplete",
        OccurrenceRowBudgetExhausted => "occurrence_row_budget_exhausted",
        EnvironmentAxisUnsupported => "environment_axis_unsupported",
        MaterializationAxisUnsupported => "materialization_axis_unsupported",
        MaterializationDerivationIncomplete => "materialization_derivation_incomplete",
        MaterializationRowBudgetExhausted => "materialization_row_budget_exhausted",
        EnvironmentDerivationIncomplete => "environment_derivation_incomplete",
        EnvironmentRowBudgetExhausted => "environment_row_budget_exhausted",
        ResolutionTraceIncomplete => "resolution_trace_incomplete",
        EdgeAxisUnsupported => "edge_axis_unsupported",
        EdgeDerivationIncomplete => "edge_derivation_incomplete",
        FlowStateAxisUnsupported => "flow_state_axis_unsupported",
        FlowStateDerivationIncomplete => "flow_state_derivation_incomplete",
        RewriteDomainUnsupported => "rewrite_domain_unsupported",
        RewritePathDerivationIncomplete => "rewrite_path_derivation_incomplete",
        ControlRelationDerivationIncomplete => "control_relation_derivation_incomplete",
        ControlRelationExitPartitionPartial => "control_relation_exit_partition_partial",
        TopologyDerivationIncomplete => "topology_derivation_incomplete",
        TopologyOwnershipAmbiguous => "topology_ownership_ambiguous",
        IdentityAxisUnsupported => "identity_axis_unsupported",
        PathDerivationIncomplete => "path_derivation_incomplete",
        EffectDerivationIncomplete => "effect_derivation_incomplete",
        ResultContractDerivationIncomplete => "result_contract_derivation_incomplete",
        EffectBudgetExhausted => "effect_budget_exhausted",
        JsxProjectionIncomplete => "jsx_projection_incomplete",
        ResultLimitReached => "result_limit_reached",
        BroadQuery => "broad_query",
    }
}

code_query_labeled_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    CodeQueryDiagnosticImpact {
        Advisory => "advisory",
        DeclaredNonExhaustive => "declared_non_exhaustive",
        Incomplete => "incomplete",
        Invalid => "invalid",
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

/// Read one diagnostic back, resolving its language label to the one static
/// spelling this crate emits.
///
/// Written by hand because the label is a `&'static str`: a derived reader
/// would demand that every input outlive the program. A diagnostic names the
/// language whose analysis produced it, or one of the two whole-execution
/// labels, so a label that is neither is a row this build did not write -- an
/// error, never a label invented at load time. (`Box::leak` would answer any
/// string at the cost of leaking one allocation per corrupt row.)
impl<'de> Deserialize<'de> for CodeQueryDiagnostic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            code: CodeQueryDiagnosticCode,
            impact: CodeQueryDiagnosticImpact,
            #[serde(default)]
            branch: Vec<usize>,
            language: String,
            message: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        let language = static_language_label(&wire.language).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown code query diagnostic language `{}`",
                wire.language
            ))
        })?;
        Ok(Self {
            code: wire.code,
            impact: wire.impact,
            branch: wire.branch,
            language,
            message: wire.message,
        })
    }
}

/// The whole-execution language labels, which name no single language.
const EXECUTION_SCOPE_LABELS: [&str; 2] = ["workspace", "all"];

fn static_language_label(label: &str) -> Option<&'static str> {
    if let Some(language) = Language::from_config_label(label)
        && language.config_label() == label
    {
        return Some(language.config_label());
    }
    EXECUTION_SCOPE_LABELS
        .into_iter()
        .find(|known| *known == label)
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
    pub solver_work: brokk_bifrost_flow::dataflow::SolverWork,
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
        let hard_solver = brokk_bifrost_flow::dataflow::SolverWork::default_limits();
        let solver_valid = brokk_bifrost_flow::dataflow::SolverBudgetDimension::ALL
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
    pub solver_work: brokk_bifrost_flow::dataflow::SolverWork,
    pub max_reached_rows: usize,
    pub max_candidates: usize,
    pub max_witness_steps: usize,
    pub max_witness_expansions: usize,
    pub max_total_witness_expansions: usize,
    pub max_witness_bytes: usize,
}

impl CodeQueryTypestateLimits {
    pub fn is_valid(self) -> bool {
        let hard_solver = brokk_bifrost_flow::dataflow::SolverWork::default_limits();
        let solver_valid = brokk_bifrost_flow::dataflow::SolverBudgetDimension::ALL
            .into_iter()
            .all(|dimension| {
                let value = self.solver_work.get(dimension);
                value > 0 && value <= hard_solver.get(dimension)
            });
        solver_valid
            && self.max_reached_rows > 0
            && self.max_reached_rows
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_REACHED_ROWS
            && self.max_candidates > 0
            && self.max_candidates
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_CANDIDATES
            && self.max_witness_steps > 0
            && self.max_witness_steps <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_WITNESS_STEPS
            && self.max_witness_expansions > 0
            && self.max_witness_expansions
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_WITNESS_EXPANSIONS
            && self.max_total_witness_expansions > 0
            && self.max_total_witness_expansions
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS
            && self.max_witness_bytes > 0
            && self.max_witness_bytes
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_WITNESS_BYTES
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeQuerySemanticLimits {
    pub max_materialized_files: usize,
    pub max_source_bytes: usize,
    pub max_rows_per_dimension: usize,
    pub max_retained_bytes: usize,
    pub max_traversal_steps: usize,
    /// Per-dimension row capacities, for a caller that has them.
    ///
    /// `None` is the ordinary case: one uniform `max_rows_per_dimension`
    /// bounds every row lane, and the executor derives a memory-shaped
    /// estimate for each homogeneous retained-row lane from
    /// `max_retained_bytes` on top of it, because a caller that supplies one
    /// number for fourteen lanes of very different density has not priced any
    /// of them. `nested_entries` keeps the uniform bound: that lane mixes small
    /// nested collection entries with non-retained bounded traversal work, so
    /// pricing every entry as one retained row would not estimate its memory.
    ///
    /// `Some` says the caller has: it carries its own multi-dimensional
    /// ledger and knows exactly how much of each lane is left. Those
    /// remainders differ by orders of magnitude -- one whole-workspace bind
    /// that drains `nested_entries` leaves `procedures` almost untouched --
    /// and collapsing them to one scalar caps every dimension at the most
    /// depleted lane (#2523). When the table is present it is authoritative:
    /// it replaces the scalar and every applicable byte-shaped estimate. The
    /// real memory bound is unaffected either way, because it is measured
    /// rather than estimated: `SemanticQueryState::materialize` charges each
    /// artifact's own retained bytes against `max_retained_bytes`.
    ///
    /// The table's `SourceBytes` and `OwnedTextBytes` entries are never read.
    /// Those two lanes are not row dimensions; `max_source_bytes` and
    /// `max_retained_bytes` are their limits.
    pub rows_per_dimension: Option<CodeQuerySemanticRowLimits>,
}

impl CodeQuerySemanticLimits {
    pub fn all_positive(self) -> bool {
        self.max_materialized_files > 0
            && self.max_source_bytes > 0
            && self.max_retained_bytes > 0
            && self.max_traversal_steps > 0
            && CodeQuerySemanticRowLimits::ROW_DIMENSIONS
                .into_iter()
                .all(|dimension| self.rows(dimension) > 0)
    }

    /// This query's row capacity for one dimension: the caller's own entry
    /// when it published a per-dimension table, and the uniform scalar
    /// otherwise.
    pub fn rows(self, dimension: SemanticBudgetDimension) -> usize {
        match self.rows_per_dimension {
            Some(rows) => rows.get(dimension),
            None => self.max_rows_per_dimension,
        }
    }
}

/// One row capacity per semantic row dimension.
///
/// Built only through [`CodeQuerySemanticRowLimits::from_rows`], which fills
/// every row dimension from the caller's own ledger and leaves the two byte
/// lanes at `usize::MAX` so that a stray read of them cannot silently narrow
/// `max_source_bytes` or `max_retained_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeQuerySemanticRowLimits(SemanticWork);

impl CodeQuerySemanticRowLimits {
    /// Every semantic dimension that counts rows, which is every dimension
    /// except the two that count bytes.
    pub const ROW_DIMENSIONS: [SemanticBudgetDimension; 14] = {
        let mut dimensions = [SemanticBudgetDimension::Procedures; 14];
        let mut source = 0;
        let mut target = 0;
        while source < SemanticBudgetDimension::ALL.len() {
            let dimension = SemanticBudgetDimension::ALL[source];
            if !matches!(
                dimension,
                SemanticBudgetDimension::SourceBytes | SemanticBudgetDimension::OwnedTextBytes
            ) {
                dimensions[target] = dimension;
                target += 1;
            }
            source += 1;
        }
        assert!(target == dimensions.len());
        dimensions
    };

    pub fn from_rows(rows: impl Fn(SemanticBudgetDimension) -> usize) -> Self {
        use SemanticBudgetDimension as Dimension;
        Self(SemanticWork {
            source_bytes: usize::MAX,
            procedures: rows(Dimension::Procedures),
            blocks: rows(Dimension::Blocks),
            program_points: rows(Dimension::ProgramPoints),
            values: rows(Dimension::Values),
            allocations: rows(Dimension::Allocations),
            call_sites: rows(Dimension::CallSites),
            memory_locations: rows(Dimension::MemoryLocations),
            captures: rows(Dimension::Captures),
            source_mappings: rows(Dimension::SourceMappings),
            evidence: rows(Dimension::Evidence),
            gaps: rows(Dimension::Gaps),
            events: rows(Dimension::Events),
            control_edges: rows(Dimension::ControlEdges),
            nested_entries: rows(Dimension::NestedEntries),
            owned_text_bytes: usize::MAX,
        })
    }

    pub const fn get(self, dimension: SemanticBudgetDimension) -> usize {
        self.0.get(dimension)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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

/// Every budgeted lane an execution charged that `CodeQueryExecutionWork`
/// does not publish, plus the per-step output counts.
///
/// A merge of per-seed executions can only claim to equal one whole execution
/// while no cumulative cap was reached, and a cap the merge cannot see is a
/// truncation the sliced run cannot detect. `CodeQueryExecutionWork` is the
/// caller-facing measurement and its shape is pinned by consumers, so the
/// three budgeted lanes it drops and the per-step counts it never had live
/// here, beside it, rather than changing it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeQueryBudgetedWork {
    /// Provenance trace steps charged against `max_pipeline_rows`.
    pub provenance_steps: u64,
    /// Files resolved by import traversal, charged against
    /// `max_scanned_files`.
    pub import_files_resolved: u64,
    /// Import edges resolved, charged against `max_pipeline_rows`.
    pub import_edges_resolved: u64,
    /// Rows each plan operator emitted, indexed by its physical plan node.
    ///
    /// `max_step_outputs` is enforced per step and has no counter of its own,
    /// so a merge that sums lanes must sum these separately to see a per-step
    /// truncation. Two executions of the same query lower to the same plan and
    /// therefore index identically; a node that is not a pipeline step
    /// contributes zero.
    pub step_outputs: Vec<u64>,
}

impl CodeQueryBudgetedWork {
    /// Sum every lane of two executions of the same query.
    ///
    /// Sums over-count whatever two units both reached, so a rule that widens
    /// when a sum reaches its cap widens more often than strictly necessary,
    /// never less.
    pub fn saturating_add(&self, other: &Self) -> Self {
        assert_eq!(
            self.step_outputs.len(),
            other.step_outputs.len(),
            "per-step output counts of one query's executions have one entry per plan node"
        );
        Self {
            provenance_steps: self.provenance_steps.saturating_add(other.provenance_steps),
            import_files_resolved: self
                .import_files_resolved
                .saturating_add(other.import_files_resolved),
            import_edges_resolved: self
                .import_edges_resolved
                .saturating_add(other.import_edges_resolved),
            step_outputs: self
                .step_outputs
                .iter()
                .zip(&other.step_outputs)
                .map(|(left, right)| left.saturating_add(*right))
                .collect(),
        }
    }

    /// The largest number of rows any one step emitted.
    pub fn max_step_outputs(&self) -> u64 {
        self.step_outputs.iter().copied().max().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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
    #[serde(skip_serializing_if = "CodeQueryTypeFlowWork::is_empty")]
    pub type_flow: CodeQueryTypeFlowWork,
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
            type_flow: self.type_flow.saturating_add(other.type_flow),
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
            type_flow: self.type_flow.saturating_sub(earlier.type_flow),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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

/// Work the class-set type-flow executor charged to one query: one solver run
/// per distinct input procedure at most, with the rows each step projected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeQueryTypeFlowWork {
    pub field_slot_builds: u64,
    pub solves: u64,
    pub cache_hits: u64,
    pub class_set_rows: u64,
    pub finding_rows: u64,
    pub incomplete_roots: u64,
    pub failed_solves: u64,
}

impl CodeQueryTypeFlowWork {
    pub const fn is_empty(&self) -> bool {
        self.field_slot_builds == 0
            && self.solves == 0
            && self.cache_hits == 0
            && self.class_set_rows == 0
            && self.finding_rows == 0
            && self.incomplete_roots == 0
            && self.failed_solves == 0
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            field_slot_builds: self
                .field_slot_builds
                .saturating_sub(earlier.field_slot_builds),
            solves: self.solves.saturating_sub(earlier.solves),
            cache_hits: self.cache_hits.saturating_sub(earlier.cache_hits),
            class_set_rows: self.class_set_rows.saturating_sub(earlier.class_set_rows),
            finding_rows: self.finding_rows.saturating_sub(earlier.finding_rows),
            incomplete_roots: self
                .incomplete_roots
                .saturating_sub(earlier.incomplete_roots),
            failed_solves: self.failed_solves.saturating_sub(earlier.failed_solves),
        }
    }

    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        Self {
            field_slot_builds: self
                .field_slot_builds
                .saturating_add(other.field_slot_builds),
            solves: self.solves.saturating_add(other.solves),
            cache_hits: self.cache_hits.saturating_add(other.cache_hits),
            class_set_rows: self.class_set_rows.saturating_add(other.class_set_rows),
            finding_rows: self.finding_rows.saturating_add(other.finding_rows),
            incomplete_roots: self.incomplete_roots.saturating_add(other.incomplete_roots),
            failed_solves: self.failed_solves.saturating_add(other.failed_solves),
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
            rows_per_dimension: None,
        }
    }
}

impl Default for CodeQueryTypestateLimits {
    fn default() -> Self {
        Self {
            solver_work: brokk_bifrost_flow::dataflow::SolverWork::default_limits(),
            max_reached_rows: brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_REACHED_ROWS,
            max_candidates: brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_CANDIDATES,
            max_witness_steps: brokk_bifrost_flow::typestate::MAX_TYPESTATE_WITNESS_STEPS,
            max_witness_expansions: brokk_bifrost_flow::typestate::MAX_TYPESTATE_WITNESS_EXPANSIONS,
            max_total_witness_expansions:
                brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS,
            max_witness_bytes: brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_WITNESS_BYTES,
        }
    }
}

impl Default for CodeQueryValueFlowLimits {
    fn default() -> Self {
        Self {
            solver_work: brokk_bifrost_flow::dataflow::SolverWork::default_limits(),
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
