use super::*;
use crate::analyzer::semantic::{SemanticBudgetDimension, SemanticWork};
use schemars::JsonSchema;

macro_rules! saturating_add_work {
    ($left:ident, $right:ident; [$($field:ident),* $(,)?]; [$($flag:ident),* $(,)?] $(; [$($peak:ident),* $(,)?])?) => {
        Self {
            $($field: $left.$field.saturating_add($right.$field),)*
            $($flag: $left.$flag || $right.$flag,)*
            $($($peak: $left.$peak.component_max($right.$peak),)*)?
        }
    };
}

macro_rules! saturating_sub_work {
    ($left:ident, $right:ident; [$($field:ident),* $(,)?]; [$($flag:ident),* $(,)?] $(; [$($peak:ident),* $(,)?])?) => {
        Self {
            $($field: $left.$field.saturating_sub($right.$field),)*
            $($flag: $left.$flag && !$right.$flag,)*
            $($($peak: $left.$peak,)*)?
        }
    };
}

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
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
    )]
    #[serde(rename_all = "snake_case")]
    CodeQueryDiagnosticCode {
        InvalidPlan => "invalid_plan",
        Cancelled => "cancelled",
        UnsupportedStructuralFeature => "unsupported_structural_feature",
        MissingStructuralAdapter => "missing_structural_adapter",
        RecoveredSyntaxIncomplete => "recovered_syntax_incomplete",
        UnsupportedImportAnalysis => "unsupported_import_analysis",
        DynamicImportTarget => "dynamic_import_target",
        SemanticResultsOmitted => "semantic_results_omitted",
        SemanticWorkspaceRequired => "semantic_workspace_required",
        NoEnclosingProcedure => "no_enclosing_procedure",
        SemanticCapabilityUnsupported => "semantic_capability_unsupported",
        SemanticAnalysisPartial => "semantic_analysis_partial",
        CallBindingDispatchPartial => "call_binding_dispatch_partial",
        CallBindingSelectorRejected => "call_binding_selector_rejected",
        SemanticBudgetExhausted => "semantic_budget_exhausted",
        SemanticProviderFailed => "semantic_provider_failed",
        SemanticPackAcquisitionPending => "semantic_pack_acquisition_pending",
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
        TypeFlowWitnessTruncated => "type_flow_witness_truncated",
        TypeFlowWitnessUnavailable => "type_flow_witness_unavailable",
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
        PythonHierarchyDerivationIncomplete => "python_hierarchy_derivation_incomplete",
        EdgeAxisUnsupported => "edge_axis_unsupported",
        EdgeDerivationIncomplete => "edge_derivation_incomplete",
        FlowStateAxisUnsupported => "flow_state_axis_unsupported",
        FlowStateDerivationIncomplete => "flow_state_derivation_incomplete",
        RewriteDomainUnsupported => "rewrite_domain_unsupported",
        RewritePathDerivationIncomplete => "rewrite_path_derivation_incomplete",
        ControlRelationDerivationIncomplete => "control_relation_derivation_incomplete",
        BranchRelationDerivationIncomplete => "branch_relation_derivation_incomplete",
        LoopRelationDerivationIncomplete => "loop_relation_derivation_incomplete",
        FailureHandlerDerivationIncomplete => "failure_handler_derivation_incomplete",
        StatementReachabilityDerivationIncomplete => "statement_reachability_derivation_incomplete",
        PendingCleanupFlowDerivationIncomplete => "pending_cleanup_flow_derivation_incomplete",
        ControlRelationExitPartitionPartial => "control_relation_exit_partition_partial",
        TopologyDerivationIncomplete => "topology_derivation_incomplete",
        TopologyOwnershipAmbiguous => "topology_ownership_ambiguous",
        IdentityAxisUnsupported => "identity_axis_unsupported",
        PathDerivationIncomplete => "path_derivation_incomplete",
        EffectDerivationIncomplete => "effect_derivation_incomplete",
        ResultContractDerivationIncomplete => "result_contract_derivation_incomplete",
        ResultObligationDerivationIncomplete => "result_obligation_derivation_incomplete",
        EffectBudgetExhausted => "effect_budget_exhausted",
        CallShapeCoverageIncomplete => "call_shape_coverage_incomplete",
        JsxProjectionIncomplete => "jsx_projection_incomplete",
        CrossDomainBindingUnproven => "cross_domain_binding_unproven",
        CrossDomainKeyUnsupported => "cross_domain_key_unsupported",
        CrossDomainDocumentIncomplete => "cross_domain_document_incomplete",
        CrossDomainCorrelationAmbiguous => "cross_domain_correlation_ambiguous",
        ResultLimitReached => "result_limit_reached",
        BroadQuery => "broad_query",
    }
}

code_query_labeled_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
    #[serde(rename_all = "snake_case")]
    CodeQueryDiagnosticImpact {
        Advisory => "advisory",
        DeclaredNonExhaustive => "declared_non_exhaustive",
        Incomplete => "incomplete",
        Invalid => "invalid",
    }
}

#[derive(Clone, Serialize, JsonSchema)]
pub struct CodeQueryDiagnostic {
    pub code: CodeQueryDiagnosticCode,
    pub impact: CodeQueryDiagnosticImpact,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub branch: Vec<usize>,
    pub language: &'static str,
    pub message: String,
    /// Exact source site responsible for this diagnostic, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CodeQuerySourceSpan>,
    /// Complete attribution of the evidence that left this result open.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<CodeQueryRelatedSource>,
    /// Every root or file whose exhausted work produced this diagnostic.
    ///
    /// A budget diagnostic that says only that some budget ran out cannot be
    /// acted on: attributing one required an instrumented build (#3194). The
    /// list carries the complete attribution, and the message renders it one
    /// line per entry up to the prose bound a policy report allows. Empty for
    /// every diagnostic that is not about exhausted work.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exhausted_roots: Vec<CodeQueryExhaustedRoot>,
    /// The one workspace-relative file every row this diagnostic withheld
    /// lies in, when the producer knows it (#5451).
    ///
    /// An incomplete diagnostic means its step left rows out or open. When
    /// this is set, every such row is a row of this file, spelled as the
    /// row's own `path`, so a reader may confine the gap to it. The executor
    /// clears it once a later operator is not row-local, because that
    /// operator's rows are no longer the ones withheld. Absent means the
    /// withheld rows may lie anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld_rows_path: Option<String>,
}

impl std::fmt::Debug for CodeQueryDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut diagnostic = formatter.debug_struct("CodeQueryDiagnostic");
        diagnostic
            .field("code", &self.code)
            .field("impact", &self.impact)
            .field("branch", &self.branch)
            .field("language", &self.language)
            .field("message", &self.message);
        // Selector prose embeds Debug output. Keep absent optional source
        // out of that prose while retaining complete attributed source spans.
        if self.source.is_some() {
            diagnostic.field("source", &self.source);
        }
        if !self.related.is_empty() {
            diagnostic.field("related", &self.related);
        }
        diagnostic.field("exhausted_roots", &self.exhausted_roots);
        if self.withheld_rows_path.is_some() {
            diagnostic.field("withheld_rows_path", &self.withheld_rows_path);
        }
        diagnostic.finish()
    }
}

/// An exact workspace-relative source span shared by query diagnostics and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CodeQuerySourceSpan {
    pub path: String,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// One source that explains a diagnostic's incompleteness.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CodeQueryRelatedSource {
    pub source: CodeQuerySourceSpan,
    pub label: String,
}

/// One root or file whose work stopped against a named limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CodeQueryExhaustedRoot {
    /// The workspace-relative path of the file the work belonged to.
    pub path: String,
    /// The qualified name of the procedure that was the analysis root.
    /// Absent when the exhausted work is file-scoped rather than per root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure: Option<String>,
    /// The exhausted lane, `<budget>/<dimension>`, for example
    /// `solver/reached_states`, `semantic/nested_entries`, or
    /// `semantic/retained_bytes`.
    pub lane: String,
    /// The stage of the analysis that charged the lane, for example
    /// `plan_refinement` or `value_flow_solve`. Absent when the emitting
    /// analysis has one stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// The charge that did not fit, and the limit it was checked against.
    /// Absent when the producing code records the stop without a charge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charge: Option<CodeQueryExhaustedCharge>,
    /// The feedback iteration whose plan produced the stop, counting from
    /// zero. Absent for an analysis without feedback iterations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback_iteration: Option<usize>,
}

/// The exact charge one lane refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CodeQueryExhaustedCharge {
    pub attempted: usize,
    pub limit: usize,
}

impl CodeQueryExhaustedRoot {
    /// The one-line rendering the diagnostic message carries.
    pub fn render(&self) -> String {
        let mut line = self.path.clone();
        if let Some(procedure) = &self.procedure {
            line.push_str(&format!(" {procedure}"));
        }
        line.push_str(&format!(" lane {}", self.lane));
        if let Some(stage) = &self.stage {
            line.push_str(&format!(" stage {stage}"));
        }
        match self.charge {
            Some(charge) => line.push_str(&format!(
                " charged {} limit {}",
                charge.attempted, charge.limit
            )),
            None => line.push_str(" charge unrecorded"),
        }
        if let Some(iteration) = self.feedback_iteration {
            line.push_str(&format!(" iteration {iteration}"));
        }
        line
    }
}

/// Prose bound for one diagnostic message that lists entries. A policy report
/// validates its diagnostic prose against `MAX_REPORT_PROSE_BYTES` (4 KiB) and
/// drops a longer one, so a rendered list stops short of that. An exhausted-work
/// message keeps the complete attribution in `exhausted_roots`.
pub const MAX_DIAGNOSTIC_LIST_MESSAGE_BYTES: usize = 3_584;

/// Render one exhausted-work diagnostic message: the reason, then one line
/// per attributed entry, bounded by `max_bytes` so a policy report keeps the
/// prose it validates (`MAX_REPORT_PROSE_BYTES`). Entries the bound cuts stay
/// in `exhausted_roots`.
pub fn render_exhausted_roots(
    reason: &str,
    roots: &[CodeQueryExhaustedRoot],
    max_bytes: usize,
) -> String {
    let noun = if roots.len() == 1 { "root" } else { "roots" };
    let mut message = format!("{reason} in {} {noun}", roots.len());
    for (index, root) in roots.iter().enumerate() {
        let line = format!("\n- {}", root.render());
        let remaining = roots.len() - index;
        let elision = format!("\n- [{remaining} more in exhausted_roots]");
        if message.len() + line.len() + elision.len() > max_bytes {
            message.push_str(&elision);
            break;
        }
        message.push_str(&line);
    }
    message
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
            #[serde(default)]
            source: Option<CodeQuerySourceSpan>,
            #[serde(default)]
            related: Vec<CodeQueryRelatedSource>,
            #[serde(default)]
            exhausted_roots: Vec<CodeQueryExhaustedRoot>,
            #[serde(default)]
            withheld_rows_path: Option<String>,
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
            source: wire.source,
            related: wire.related,
            exhausted_roots: wire.exhausted_roots,
            withheld_rows_path: wire.withheld_rows_path,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Per-dimension row capacities, for a caller that has them.
    ///
    /// `None` is the ordinary case: one uniform `max_rows_per_dimension`
    /// bounds every row lane, and the executor derives a memory-shaped
    /// estimate for each homogeneous retained-row lane from
    /// `max_retained_bytes` on top of it, because a caller that supplies one
    /// number for fourteen lanes of very different density has not priced any
    /// of them. `nested_entries` keeps the uniform bound for heterogeneous
    /// retained collections. Traversal visits are work telemetry and do not
    /// consume this resident row grant.
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
    /// Admitted plus worked per lane; held-and-scanned bytes can count twice.
    /// This cumulative telemetry is not a bound.
    pub cumulative: crate::analyzer::semantic::SemanticWork,
    /// Largest live resident census per lane.
    pub resident_peaks: crate::analyzer::semantic::SemanticWork,
    /// Largest work balance of any one root or prepass per lane.
    pub root_work_peaks: crate::analyzer::semantic::SemanticWork,
    /// The `nested_entries` lane of `resident_peaks`.
    pub resident_nested_entries_peak: u64,
    /// The retained-artifact byte peak, also reported as `retained_bytes`.
    pub resident_retained_bytes_peak: u64,
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
        let left = self;
        let mut result = saturating_add_work!(left, other; [materialization_attempts, unique_materialized_files, request_cache_hits, source_bytes, procedures, blocks, program_points, values, allocations, call_sites, memory_locations, captures, source_mappings, evidence, gaps, events, control_edges, nested_entries, retained_bytes, cumulative, resident_nested_entries_peak, resident_retained_bytes_peak, traversal_steps, typestate, value_flow, type_flow]; [budget_exhausted]; [resident_peaks, root_work_peaks]);
        result.resident_nested_entries_peak =
            if left.resident_nested_entries_peak > other.resident_nested_entries_peak {
                left.resident_nested_entries_peak
            } else {
                other.resident_nested_entries_peak
            };
        result.resident_retained_bytes_peak =
            if left.resident_retained_bytes_peak > other.resident_retained_bytes_peak {
                left.resident_retained_bytes_peak
            } else {
                other.resident_retained_bytes_peak
            };
        result
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        let left = self;
        let mut result = saturating_sub_work!(left, earlier; [materialization_attempts, unique_materialized_files, request_cache_hits, source_bytes, procedures, blocks, program_points, values, allocations, call_sites, memory_locations, captures, source_mappings, evidence, gaps, events, control_edges, nested_entries, retained_bytes, cumulative, resident_nested_entries_peak, resident_retained_bytes_peak, traversal_steps, typestate, value_flow, type_flow]; [budget_exhausted]; [resident_peaks, root_work_peaks]);
        result.resident_nested_entries_peak = left.resident_nested_entries_peak;
        result.resident_retained_bytes_peak = left.resident_retained_bytes_peak;
        result
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
        let left = self;
        saturating_add_work!(left, other; [solves, cache_hits, summary_hits, summary_misses, summary_rejections, summary_evictions, summary_recomputations, reached_rows, findings, omitted_findings, witnesses, omitted_witnesses, witness_steps, witness_bytes, fixed_point_solves, cancelled_solves, budget_exhausted_solves, failed_solves]; [finding_budget_exhausted])
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
        let left = self;
        saturating_sub_work!(left, earlier; [solves, cache_hits, reached_rows, meetings, sink_outcomes, omitted_endpoints, witnesses, omitted_witnesses, witness_expansions, witness_steps, witness_bytes, fixed_point_solves, cancelled_solves, budget_exhausted_solves, failed_solves]; [endpoint_truncated, witness_truncated])
    }

    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        let left = self;
        saturating_add_work!(left, other; [solves, cache_hits, reached_rows, meetings, sink_outcomes, omitted_endpoints, witnesses, omitted_witnesses, witness_expansions, witness_steps, witness_bytes, fixed_point_solves, cancelled_solves, budget_exhausted_solves, failed_solves]; [endpoint_truncated, witness_truncated])
    }
}

/// Work the class-set type-flow executor charged to one query: one solver run
/// per distinct input procedure at most, with the rows each step projected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeQueryTypeFlowWork {
    /// Fresh whole-workspace field-slot indexes built by this query.
    pub field_slot_builds: u64,
    /// Ready indexes reused through the workspace's in-memory acquisition path.
    /// Query-local reuse does not reacquire the index and is not counted here.
    pub field_slot_memory_hits: u64,
    /// Complete durable indexes loaded and accepted for this query.
    pub field_slot_persistence_hits: u64,
    /// Durable lookups for which no matching index was present.
    pub field_slot_persistence_misses: u64,
    /// Durable rows found but rejected by exact validation or replay admission.
    pub field_slot_persistence_rejections: u64,
    /// Fresh indexes inserted into the durable store by this query.
    pub field_slot_publications: u64,
    /// Complete finding-free root projections loaded and accepted from the
    /// durable store by this query.
    pub root_result_persistence_hits: u64,
    /// Durable root-projection lookups for which no exact key was present.
    pub root_result_persistence_misses: u64,
    /// Durable root-projection rows found but rejected by validation or
    /// hydration limits.
    pub root_result_persistence_rejections: u64,
    /// Operational failures while reading or writing durable root projections.
    pub root_result_store_failures: u64,
    /// Fresh finding-free root projections inserted into the durable store by
    /// this query.
    pub root_result_publications: u64,
    pub solves: u64,
    pub cache_hits: u64,
    pub snapshot_cache_hits: u64,
    pub snapshot_cache_misses: u64,
    pub dispatch_cache_hits: u64,
    pub dispatch_cache_misses: u64,
    pub binding_cache_hits: u64,
    pub binding_cache_misses: u64,
    pub summary_cache_hits: u64,
    pub summary_cache_misses: u64,
    /// Exact Zero-entry root relations restored from reusable summaries.
    pub root_summary_cache_hits: u64,
    /// Restored root relations rejected because they did not carry a Meeting
    /// for every sink in the current plan.
    pub root_summary_observation_rejections: u64,
    pub published_summaries: u64,
    /// Independently bounded solver runs performed across all input roots.
    /// A source-refined root may contribute both an exploratory and a refined
    /// solve while `solves` remains the number of distinct root transactions.
    pub solver_attempts: u64,
    #[serde(
        skip_serializing_if = "brokk_bifrost_flow::type_flow::TypeFlowSummaryProfile::is_empty"
    )]
    pub summary_profile: brokk_bifrost_flow::type_flow::TypeFlowSummaryProfile,
    pub class_set_rows: u64,
    pub finding_rows: u64,
    pub witnesses: u64,
    pub omitted_witnesses: u64,
    pub witness_expansions: u64,
    pub witness_steps: u64,
    pub witness_bytes: u64,
    pub witness_truncated: bool,
    pub incomplete_roots: u64,
    pub failed_solves: u64,
}

impl CodeQueryTypeFlowWork {
    pub const fn is_empty(&self) -> bool {
        self.field_slot_builds == 0
            && self.field_slot_memory_hits == 0
            && self.field_slot_persistence_hits == 0
            && self.field_slot_persistence_misses == 0
            && self.field_slot_persistence_rejections == 0
            && self.field_slot_publications == 0
            && self.root_result_persistence_hits == 0
            && self.root_result_persistence_misses == 0
            && self.root_result_persistence_rejections == 0
            && self.root_result_store_failures == 0
            && self.root_result_publications == 0
            && self.solves == 0
            && self.cache_hits == 0
            && self.snapshot_cache_hits == 0
            && self.snapshot_cache_misses == 0
            && self.dispatch_cache_hits == 0
            && self.dispatch_cache_misses == 0
            && self.binding_cache_hits == 0
            && self.binding_cache_misses == 0
            && self.summary_cache_hits == 0
            && self.summary_cache_misses == 0
            && self.root_summary_cache_hits == 0
            && self.root_summary_observation_rejections == 0
            && self.published_summaries == 0
            && self.solver_attempts == 0
            && self.summary_profile.is_empty()
            && self.class_set_rows == 0
            && self.finding_rows == 0
            && self.witnesses == 0
            && self.omitted_witnesses == 0
            && self.witness_expansions == 0
            && self.witness_steps == 0
            && self.witness_bytes == 0
            && !self.witness_truncated
            && self.incomplete_roots == 0
            && self.failed_solves == 0
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        let left = self;
        saturating_sub_work!(left, earlier; [field_slot_builds, field_slot_memory_hits, field_slot_persistence_hits, field_slot_persistence_misses, field_slot_persistence_rejections, field_slot_publications, root_result_persistence_hits, root_result_persistence_misses, root_result_persistence_rejections, root_result_store_failures, root_result_publications, solves, cache_hits, snapshot_cache_hits, snapshot_cache_misses, dispatch_cache_hits, dispatch_cache_misses, binding_cache_hits, binding_cache_misses, summary_cache_hits, summary_cache_misses, root_summary_cache_hits, root_summary_observation_rejections, published_summaries, solver_attempts, summary_profile, class_set_rows, finding_rows, witnesses, omitted_witnesses, witness_expansions, witness_steps, witness_bytes, incomplete_roots, failed_solves]; [witness_truncated])
    }

    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        let left = self;
        saturating_add_work!(left, other; [field_slot_builds, field_slot_memory_hits, field_slot_persistence_hits, field_slot_persistence_misses, field_slot_persistence_rejections, field_slot_publications, root_result_persistence_hits, root_result_persistence_misses, root_result_persistence_rejections, root_result_store_failures, root_result_publications, solves, cache_hits, snapshot_cache_hits, snapshot_cache_misses, dispatch_cache_hits, dispatch_cache_misses, binding_cache_hits, binding_cache_misses, summary_cache_hits, summary_cache_misses, root_summary_cache_hits, root_summary_observation_rejections, published_summaries, solver_attempts, summary_profile, class_set_rows, finding_rows, witnesses, omitted_witnesses, witness_expansions, witness_steps, witness_bytes, incomplete_roots, failed_solves]; [witness_truncated])
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

#[cfg(test)]
mod type_flow_summary_profile_tests {
    use super::CodeQueryTypeFlowWork;

    #[test]
    fn profile_work_serializes_typed_summary_rejections() {
        let empty = serde_json::to_value(CodeQueryTypeFlowWork::default())
            .expect("empty type-flow work serializes");
        assert!(empty.get("summary_profile").is_none());

        let legacy: CodeQueryTypeFlowWork = serde_json::from_value(serde_json::json!({
            "solves": 1
        }))
        .expect("a legacy profile without summary attribution deserializes");
        assert!(legacy.summary_profile.is_empty());
        assert_eq!(legacy.field_slot_memory_hits, 0);
        assert_eq!(legacy.field_slot_persistence_hits, 0);
        assert_eq!(legacy.field_slot_persistence_misses, 0);
        assert_eq!(legacy.field_slot_persistence_rejections, 0);
        assert_eq!(legacy.field_slot_publications, 0);
        assert_eq!(legacy.root_result_persistence_hits, 0);
        assert_eq!(legacy.root_result_persistence_misses, 0);
        assert_eq!(legacy.root_result_persistence_rejections, 0);
        assert_eq!(legacy.root_result_store_failures, 0);
        assert_eq!(legacy.root_result_publications, 0);
        assert_eq!(legacy.root_summary_cache_hits, 0);
        assert_eq!(legacy.root_summary_observation_rejections, 0);
        assert_eq!(legacy.solver_attempts, 0);

        let mut work = CodeQueryTypeFlowWork::default();
        work.summary_profile.lookup_relation = 3;
        let json = serde_json::to_value(work).expect("type-flow work serializes");
        assert_eq!(json["summary_profile"]["lookup_relation"], 3);
    }

    #[test]
    fn field_slot_persistence_work_round_trips_and_composes() {
        let cold = CodeQueryTypeFlowWork {
            field_slot_builds: 1,
            field_slot_persistence_misses: 1,
            field_slot_publications: 1,
            ..CodeQueryTypeFlowWork::default()
        };
        let warm = CodeQueryTypeFlowWork {
            field_slot_memory_hits: 2,
            field_slot_persistence_hits: 1,
            field_slot_persistence_rejections: 1,
            ..CodeQueryTypeFlowWork::default()
        };

        let combined = cold.saturating_add(warm);
        assert!(!combined.is_empty());
        assert_eq!(combined.saturating_sub(cold), warm);

        let json = serde_json::to_value(combined).expect("field-slot work serializes");
        assert_eq!(json["field_slot_memory_hits"], 2);
        assert_eq!(json["field_slot_persistence_hits"], 1);
        assert_eq!(json["field_slot_persistence_misses"], 1);
        assert_eq!(json["field_slot_persistence_rejections"], 1);
        assert_eq!(json["field_slot_publications"], 1);
        assert_eq!(
            serde_json::from_value::<CodeQueryTypeFlowWork>(json)
                .expect("field-slot work deserializes"),
            combined
        );
    }

    #[test]
    fn root_summary_work_round_trips_and_composes() {
        let accepted = CodeQueryTypeFlowWork {
            summary_cache_hits: 1,
            root_summary_cache_hits: 1,
            ..CodeQueryTypeFlowWork::default()
        };
        let rejected = CodeQueryTypeFlowWork {
            summary_cache_hits: 1,
            root_summary_cache_hits: 1,
            root_summary_observation_rejections: 1,
            ..CodeQueryTypeFlowWork::default()
        };
        let combined = accepted.saturating_add(rejected);
        assert_eq!(combined.saturating_sub(accepted), rejected);
        let json = serde_json::to_value(combined).expect("root summary work serializes");
        assert_eq!(json["root_summary_cache_hits"], 2);
        assert_eq!(json["root_summary_observation_rejections"], 1);
        assert_eq!(
            serde_json::from_value::<CodeQueryTypeFlowWork>(json)
                .expect("root summary work deserializes"),
            combined
        );
    }

    #[test]
    fn root_result_persistence_work_round_trips_and_composes() {
        let lookup = CodeQueryTypeFlowWork {
            root_result_persistence_hits: 2,
            root_result_persistence_misses: 3,
            root_result_persistence_rejections: 5,
            root_result_store_failures: 7,
            root_result_publications: 11,
            ..CodeQueryTypeFlowWork::default()
        };
        let more = CodeQueryTypeFlowWork {
            root_result_persistence_hits: 13,
            root_result_persistence_misses: 17,
            root_result_persistence_rejections: 19,
            root_result_store_failures: 23,
            root_result_publications: 29,
            ..CodeQueryTypeFlowWork::default()
        };

        let combined = lookup.saturating_add(more);
        assert!(!combined.is_empty());
        assert_eq!(combined.saturating_sub(lookup), more);

        let json = serde_json::to_value(combined).expect("root-result work serializes");
        assert_eq!(json["root_result_persistence_hits"], 15);
        assert_eq!(json["root_result_persistence_misses"], 20);
        assert_eq!(json["root_result_persistence_rejections"], 24);
        assert_eq!(json["root_result_store_failures"], 30);
        assert_eq!(json["root_result_publications"], 40);
        assert_eq!(
            serde_json::from_value::<CodeQueryTypeFlowWork>(json)
                .expect("root-result work deserializes"),
            combined
        );

        let saturated = CodeQueryTypeFlowWork {
            root_result_persistence_hits: u64::MAX,
            root_result_persistence_misses: u64::MAX,
            root_result_persistence_rejections: u64::MAX,
            root_result_store_failures: u64::MAX,
            root_result_publications: u64::MAX,
            ..CodeQueryTypeFlowWork::default()
        }
        .saturating_add(CodeQueryTypeFlowWork {
            root_result_persistence_hits: 1,
            root_result_persistence_misses: 1,
            root_result_persistence_rejections: 1,
            root_result_store_failures: 1,
            root_result_publications: 1,
            ..CodeQueryTypeFlowWork::default()
        });
        assert_eq!(saturated.root_result_persistence_hits, u64::MAX);
        assert_eq!(saturated.root_result_persistence_misses, u64::MAX);
        assert_eq!(saturated.root_result_persistence_rejections, u64::MAX);
        assert_eq!(saturated.root_result_store_failures, u64::MAX);
        assert_eq!(saturated.root_result_publications, u64::MAX);
        assert_eq!(
            CodeQueryTypeFlowWork::default().saturating_sub(saturated),
            CodeQueryTypeFlowWork::default()
        );
    }
}
