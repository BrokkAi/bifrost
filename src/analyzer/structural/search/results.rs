//! The CodeQuery result/diagnostic type contract: the public and
//! `pub(crate)` types rendered by the query engine and consumed by
//! `src/lsp/server.rs`, `src/analyzer/policy/evaluator.rs`, and
//! `structural/execution/` -- moved verbatim out of `search.rs` (#1057
//! follow-up split), together with the small self-contained impls that
//! only reference these contract types.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnionExecutionStrategy {
    Auto,
    Sequential,
    Parallel,
}

#[derive(Debug, Default, Serialize)]
pub struct CodeQueryResult {
    pub results: Vec<CodeQueryResultItem>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<CodeQueryDiagnostic>,
}

/// The supported `query_code` response selected by the root execution mode.
///
/// The enum is deliberately untagged so the default `results` variant retains
/// the exact existing serialized `CodeQueryResult` shape. Versioned `format`
/// fields discriminate the two report variants.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum CodeQueryResponse {
    Results(CodeQueryResult),
    Explain(CodeQueryExplain),
    Profile(Box<CodeQueryProfile>),
}

impl CodeQueryResponse {
    pub const fn mode(&self) -> CodeQueryExecutionMode {
        match self {
            Self::Results(_) => CodeQueryExecutionMode::Results,
            Self::Explain(_) => CodeQueryExecutionMode::Explain,
            Self::Profile(_) => CodeQueryExecutionMode::Profile,
        }
    }

    /// Return the ordinary result when this response executed the query.
    pub fn result(&self) -> Option<&CodeQueryResult> {
        match self {
            Self::Results(result) => Some(result),
            Self::Profile(profile) => Some(&profile.result),
            Self::Explain(_) => None,
        }
    }

    /// Render the complete structured report without first erasing its typed
    /// field order through `serde_json::Value`.
    #[doc(hidden)]
    pub fn render_report_pretty(&self) -> Option<String> {
        match self {
            Self::Results(_) => None,
            Self::Explain(explain) => Some(
                serde_json::to_string_pretty(explain)
                    .expect("the public CodeQuery explain model is serializable"),
            ),
            Self::Profile(profile) => Some(
                serde_json::to_string_pretty(profile)
                    .expect("the public CodeQuery profile model is serializable"),
            ),
        }
    }

    /// Consume this response into the common pieces needed by transports.
    ///
    /// The report is serialized before a profiled result is moved out, so the
    /// structured profile keeps its complete nested `result` while callers can
    /// also expose ordinary rows through transport-specific fields.
    #[doc(hidden)]
    pub fn into_parts(
        self,
    ) -> (
        CodeQueryExecutionMode,
        Option<CodeQueryResult>,
        Option<serde_json::Value>,
    ) {
        match self {
            Self::Results(result) => (CodeQueryExecutionMode::Results, Some(result), None),
            Self::Explain(explain) => (
                CodeQueryExecutionMode::Explain,
                None,
                Some(
                    serde_json::to_value(explain)
                        .expect("the public CodeQuery explain model is serializable"),
                ),
            ),
            Self::Profile(profile) => {
                let report = serde_json::to_value(&profile)
                    .expect("the public CodeQuery profile model is serializable");
                (
                    CodeQueryExecutionMode::Profile,
                    Some(profile.result),
                    Some(report),
                )
            }
        }
    }

    /// Human/agent-readable rendering. Structured JSON remains the canonical
    /// report representation used by MCP, CLI, Python, and editor transports.
    pub fn render_text(&self) -> String {
        match self {
            Self::Results(result) => result.render_text(),
            Self::Explain(explain) => format!(
                "CodeQuery explain (planning only):\n{}\n",
                serde_json::to_string_pretty(explain)
                    .expect("the public CodeQuery explain model is serializable")
            ),
            Self::Profile(profile) => {
                let mut rendered = profile.result.render_text();
                rendered.push_str(&format!(
                    "\nCodeQuery profile: planning {} ns; execution {} ns; rendering {} ns; total {} ns; {} operator{}; peak concurrency {}.\n",
                    profile.timings_ns.planning,
                    profile.timings_ns.execution,
                    profile.timings_ns.rendering,
                    profile.timings_ns.total,
                    profile.operators.len(),
                    if profile.operators.len() == 1 { "" } else { "s" },
                    profile.scheduling.peak_concurrency,
                ));
                rendered
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeQueryCompletion {
    Complete,
    Incomplete { codes: Vec<CodeQueryDiagnosticCode> },
    Cancelled,
    Invalid { codes: Vec<CodeQueryDiagnosticCode> },
}

impl CodeQueryResult {
    /// Derive whether this result can support a complete negative conclusion.
    ///
    /// Completion is intentionally based only on typed diagnostic impact and
    /// the existing bounded-output flag. Diagnostic prose remains presentation
    /// and can change without changing this decision.
    pub fn completion(&self) -> CodeQueryCompletion {
        let invalid = self.diagnostic_codes_with_impact(CodeQueryDiagnosticImpact::Invalid);
        if !invalid.is_empty() {
            return CodeQueryCompletion::Invalid { codes: invalid };
        }
        if self
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::Cancelled)
        {
            return CodeQueryCompletion::Cancelled;
        }
        let incomplete = self.diagnostic_codes_with_impact(CodeQueryDiagnosticImpact::Incomplete);
        if self.truncated || !incomplete.is_empty() {
            return CodeQueryCompletion::Incomplete { codes: incomplete };
        }
        CodeQueryCompletion::Complete
    }

    fn diagnostic_codes_with_impact(
        &self,
        impact: CodeQueryDiagnosticImpact,
    ) -> Vec<CodeQueryDiagnosticCode> {
        let mut codes = Vec::new();
        for diagnostic in &self.diagnostics {
            if diagnostic.impact == impact && !codes.contains(&diagnostic.code) {
                codes.push(diagnostic.code);
            }
        }
        codes
    }
}

#[derive(Debug, Serialize)]
pub struct CodeQueryResultItem {
    #[serde(flatten)]
    pub value: CodeQueryResultValue,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<CodeQueryProvenance>,
    #[serde(skip_serializing_if = "is_false")]
    pub provenance_truncated: bool,
}

impl CodeQueryResultItem {
    /// Build the shared, unstyled provenance summary used by text transports.
    #[doc(hidden)]
    pub fn provenance_summary(&self) -> Option<String> {
        if self.provenance.is_empty() {
            return None;
        }

        let mut branch_labels = Vec::new();
        for trace in &self.provenance {
            let label = format_branch_path(&trace.branch);
            if !label.is_empty() && !branch_labels.contains(&label) {
                branch_labels.push(label);
            }
        }
        Some(format!(
            "provenance: {} path{}{}{}",
            self.provenance.len(),
            if self.provenance.len() == 1 { "" } else { "s" },
            if self.provenance_truncated {
                " (truncated)"
            } else {
                ""
            },
            if branch_labels.is_empty() {
                String::new()
            } else {
                format!("; branches {}", branch_labels.join(", "))
            },
        ))
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "result_type", rename_all = "snake_case")]
pub enum CodeQueryResultValue {
    StructuralMatch {
        #[serde(flatten)]
        value: CodeQueryMatch,
    },
    Declaration {
        #[serde(flatten)]
        value: CodeQueryDeclaration,
    },
    File {
        #[serde(flatten)]
        value: CodeQueryFile,
    },
    ReferenceSite {
        #[serde(flatten)]
        value: Box<CodeQueryReferenceSite>,
    },
    CallSite {
        #[serde(flatten)]
        value: Box<CodeQueryCallSite>,
    },
    ExpressionSite {
        #[serde(flatten)]
        value: Box<CodeQueryExpressionSite>,
    },
    ReceiverAnalysis {
        #[serde(flatten)]
        value: Box<CodeQueryReceiverAnalysis>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryMatch {
    pub path: String,
    pub language: &'static str,
    pub kind: &'static str,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_range: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decorated_range: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub decorator_ranges: Vec<CodeQueryRange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub captures: Vec<CodeQueryCapture>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryDeclaration {
    pub path: String,
    pub language: &'static str,
    pub kind: &'static str,
    pub fq_name: String,
    pub start_line: usize,
    pub end_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_range: Option<CodeQueryRange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryFile {
    pub path: String,
    pub language: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReferenceSite {
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub target: CodeQueryDeclaration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_declaration: Option<CodeQueryDeclaration>,
    pub usage_kind: &'static str,
    pub proof: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_kind: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallSite {
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub callee_range: CodeQueryRange,
    pub caller: CodeQueryDeclaration,
    pub callee: CodeQueryDeclaration,
    pub call_kind: &'static str,
    pub proof: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<CodeQueryCallArgument>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallArgument {
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_name: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub variadic: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub spread: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryExpressionSite {
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub text: String,
    pub input_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_name: Option<String>,
    pub caller_fq_name: String,
    pub callee_fq_name: String,
    pub call_range: CodeQueryRange,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReceiverAnalysis {
    pub analysis_kind: &'static str,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub text: String,
    pub input_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<String>,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<CodeQueryReceiverValue>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_targets: Vec<CodeQueryDeclaration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "receiver_value_kind", rename_all = "snake_case")]
pub enum CodeQueryReceiverValue {
    AllocationSite {
        type_declaration: CodeQueryDeclaration,
        allocation_site: CodeQuerySourceSite,
    },
    InstanceType {
        declaration: CodeQueryDeclaration,
    },
    ClassOrStaticObject {
        declaration: CodeQueryDeclaration,
    },
    ModuleOrExportObject {
        declaration: CodeQueryDeclaration,
    },
    CurrentReceiver {
        declaration: CodeQueryDeclaration,
    },
    FactoryReturn {
        factory: CodeQueryDeclaration,
        returned_value: Box<CodeQueryReceiverValue>,
    },
}

impl CodeQueryReceiverValue {
    pub fn render_text(&self) -> String {
        match self {
            Self::AllocationSite {
                type_declaration,
                allocation_site,
            } => format!(
                "allocation {} at {}:{}:{}",
                type_declaration.fq_name,
                allocation_site.path,
                allocation_site.range.start_line,
                allocation_site.range.start_column
            ),
            Self::InstanceType { declaration } => {
                format!("instance {}", declaration.fq_name)
            }
            Self::ClassOrStaticObject { declaration } => {
                format!("class/static {}", declaration.fq_name)
            }
            Self::ModuleOrExportObject { declaration } => {
                format!("module/export {}", declaration.fq_name)
            }
            Self::CurrentReceiver { declaration } => {
                format!("current receiver {}", declaration.fq_name)
            }
            Self::FactoryReturn {
                factory,
                returned_value,
            } => format!(
                "factory {} -> {}",
                factory.fq_name,
                returned_value.render_text()
            ),
        }
    }
}

impl CodeQueryReceiverAnalysis {
    pub fn render_detail_lines(&self) -> Vec<String> {
        let mut lines = self
            .values
            .iter()
            .map(|value| format!("value -> {}", value.render_text()))
            .collect::<Vec<_>>();
        lines.extend(
            self.member_targets
                .iter()
                .map(|target| format!("member -> {}", target.fq_name)),
        );
        if let Some(reason) = self.reason {
            lines.push(format!("reason -> {reason}"));
        }
        if let Some(limit) = self.limit {
            lines.push(format!("limit -> {limit}"));
        }
        lines
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQuerySourceSite {
    pub path: String,
    pub range: CodeQueryRange,
}

#[derive(Debug, Serialize)]
pub struct CodeQueryProvenance {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub branch: Vec<usize>,
    pub seed: CodeQueryResultRef,
    pub steps: Vec<CodeQueryProvenanceStep>,
}

#[derive(Debug, Serialize)]
pub struct CodeQueryProvenanceStep {
    pub op: &'static str,
    pub result: CodeQueryResultRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<CodeQueryResultRef>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "result_type", rename_all = "snake_case")]
pub enum CodeQueryResultRef {
    StructuralMatch {
        path: String,
        kind: &'static str,
        start_line: usize,
        end_line: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_range: Option<CodeQueryRange>,
    },
    Declaration {
        path: String,
        kind: &'static str,
        fq_name: String,
        start_line: usize,
        end_line: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_range: Option<CodeQueryRange>,
    },
    File {
        path: String,
    },
    ReferenceSite {
        path: String,
        range: CodeQueryRange,
        target_fq_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        usage_kind: Option<&'static str>,
        proof: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reference_kind: Option<&'static str>,
    },
    CallSite {
        path: String,
        range: CodeQueryRange,
        caller_fq_name: String,
        callee_fq_name: String,
        proof: &'static str,
    },
    ExpressionSite {
        path: String,
        range: CodeQueryRange,
        input_kind: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameter_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameter_name: Option<String>,
    },
    ReceiverAnalysis {
        path: String,
        range: CodeQueryRange,
        analysis_kind: &'static str,
        outcome: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        capture: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCapture {
    pub name: String,
    pub text: String,
    pub start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct CodeQueryRange {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryDiagnosticCode {
    InvalidPlan,
    Cancelled,
    UnsupportedStructuralFeature,
    MissingStructuralAdapter,
    UnsupportedImportAnalysis,
    SemanticResultsOmitted,
    ReceiverAnalysisPartial,
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
            Self::ReceiverAnalysisPartial => "receiver_analysis_partial",
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
            Self::ResultLimitReached => "result_limit_reached",
            Self::BroadQuery => "broad_query",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryDiagnosticImpact {
    Advisory,
    Incomplete,
    Invalid,
}

impl CodeQueryDiagnosticImpact {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CodeQueryExecutionWork {
    pub scanned_files: u64,
    pub scanned_source_bytes: u64,
    pub fact_nodes: u64,
    pub pipeline_rows: u64,
    pub examined_references: u64,
}

#[derive(Debug)]
pub(crate) struct DetailedCodeQueryResult {
    pub result: CodeQueryResult,
    pub work: CodeQueryExecutionWork,
    pub evidence: Vec<DetailedCodeQueryEvidence>,
    pub profile: Option<QueryExecutionProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetailedCodeQueryEvidence {
    pub result_index: usize,
    pub domain: DetailedCodeQueryDomain,
    pub key: DetailedCodeQueryKey,
    pub file: ProjectFile,
    pub byte_span: Option<std::ops::Range<usize>>,
    pub stable_owner_candidate: Option<CodeQueryStableOwnerCandidate>,
    pub identities: DetailedCodeQueryProvenanceIdentities,
    pub source_slice_sha256: Option<[u8; 32]>,
    pub provenance: Vec<DetailedCodeQueryProvenanceEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetailedCodeQueryProvenanceEvidence {
    pub branch: Vec<usize>,
    pub seed: DetailedCodeQueryProvenanceRefEvidence,
    pub steps: Vec<DetailedCodeQueryProvenanceStepEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetailedCodeQueryProvenanceStepEvidence {
    pub op: String,
    pub result: DetailedCodeQueryProvenanceRefEvidence,
    pub via: Option<DetailedCodeQueryProvenanceRefEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetailedCodeQueryProvenanceRefEvidence {
    pub domain: DetailedCodeQueryDomain,
    pub key: DetailedCodeQueryKey,
    pub file: ProjectFile,
    pub byte_span: Option<std::ops::Range<usize>>,
    pub display_range: Option<CodeQueryRange>,
    pub identities: DetailedCodeQueryProvenanceIdentities,
    pub source_slice_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DetailedCodeQueryProvenanceIdentities {
    None,
    Primary(Option<DetailedCodeQueryIdentityCandidate>),
    ReferenceTarget(Option<DetailedCodeQueryIdentityCandidate>),
    Call {
        caller: Option<DetailedCodeQueryIdentityCandidate>,
        callee: Option<DetailedCodeQueryIdentityCandidate>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetailedCodeQueryIdentityCandidate {
    pub file: ProjectFile,
    pub candidate: CodeQueryStableOwnerCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeQueryStableOwnerCandidate {
    pub namespace: String,
    pub derivation: CodeQueryStableOwnerDerivation,
    pub semantic_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodeQueryStableOwnerDerivation {
    AnalyzerDeclarationId,
    CanonicalAstIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetailedCodeQueryDomain {
    StructuralMatch,
    Declaration,
    File,
    ReferenceSite,
    CallSite,
    ExpressionSite,
    ReceiverAnalysis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DetailedCodeQueryKey {
    StructuralMatch {
        kind: String,
        analyzer_id: Option<String>,
    },
    Declaration {
        kind: String,
        fq_name: String,
        analyzer_id: Option<String>,
    },
    File,
    ReferenceSite {
        target_id: Option<String>,
        target_fq_name: String,
    },
    CallSite {
        caller_fq_name: String,
        callee_fq_name: String,
    },
    ExpressionSite {
        input_kind: String,
        parameter_index: Option<u32>,
        parameter_name: Option<String>,
    },
    ReceiverAnalysis {
        analysis_kind: String,
        outcome: String,
        capture: Option<String>,
    },
}

impl Default for CodeQueryExecutionLimits {
    fn default() -> Self {
        Self {
            max_scanned_files: MAX_SCANNED_FILES,
            max_scanned_source_bytes: MAX_SCANNED_SOURCE_BYTES,
            max_fact_nodes: MAX_FACT_NODES,
            max_pipeline_rows: MAX_PIPELINE_ROWS,
        }
    }
}

impl DetailedCodeQueryResult {
    pub(super) fn assert_invariants(&self) {
        if let Some(profile) = &self.profile {
            assert!(
                profile.peak_concurrency >= 1,
                "an executed CodeQuery profile must observe at least one active operator"
            );
            assert!(
                !profile.operators.is_empty(),
                "an executed CodeQuery profile must contain operator observations"
            );
        }
        assert_eq!(
            self.result.results.len(),
            self.evidence.len(),
            "detailed CodeQuery evidence must stay aligned with public results"
        );
        assert!(
            self.work.pipeline_rows
                >= u64::try_from(self.evidence.len())
                    .expect("usize fits in u64 on supported targets"),
            "retained CodeQuery results cannot exceed directly tracked pipeline rows"
        );
        for (result_index, evidence) in self.evidence.iter().enumerate() {
            let result = &self.result.results[result_index];
            assert_eq!(
                evidence.result_index, result_index,
                "detailed CodeQuery evidence index must equal its vector index"
            );
            assert!(
                matches!(
                    (evidence.domain, &evidence.key),
                    (
                        DetailedCodeQueryDomain::StructuralMatch,
                        DetailedCodeQueryKey::StructuralMatch { .. }
                    ) | (
                        DetailedCodeQueryDomain::Declaration,
                        DetailedCodeQueryKey::Declaration { .. }
                    ) | (DetailedCodeQueryDomain::File, DetailedCodeQueryKey::File)
                        | (
                            DetailedCodeQueryDomain::ReferenceSite,
                            DetailedCodeQueryKey::ReferenceSite { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::CallSite,
                            DetailedCodeQueryKey::CallSite { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ExpressionSite,
                            DetailedCodeQueryKey::ExpressionSite { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ReceiverAnalysis,
                            DetailedCodeQueryKey::ReceiverAnalysis { .. }
                        )
                ),
                "detailed CodeQuery domain and typed key must agree"
            );
            if evidence.source_slice_sha256.is_some() {
                assert!(
                    evidence.byte_span.is_some(),
                    "a source-slice digest requires a byte span"
                );
            }
            if evidence.domain == DetailedCodeQueryDomain::File {
                assert!(evidence.byte_span.is_none());
                assert!(evidence.source_slice_sha256.is_none());
                assert!(evidence.stable_owner_candidate.is_none());
            }
            if let Some(candidate) = &evidence.stable_owner_candidate {
                assert!(!candidate.namespace.is_empty());
                assert!(!candidate.semantic_key.is_empty());
                match candidate.derivation {
                    CodeQueryStableOwnerDerivation::AnalyzerDeclarationId
                    | CodeQueryStableOwnerDerivation::CanonicalAstIdentity => {}
                }
            }
            assert_detailed_terminal_identities(evidence.domain, &evidence.identities);
            let _ = &evidence.file;
            assert_eq!(
                result.provenance.len(),
                evidence.provenance.len(),
                "detailed provenance must align with public provenance"
            );
            for (public, detailed) in result.provenance.iter().zip(&evidence.provenance) {
                assert_eq!(public.branch, detailed.branch);
                assert_eq!(public.steps.len(), detailed.steps.len());
                assert_detailed_provenance_ref(&detailed.seed);
                for (public_step, detailed_step) in public.steps.iter().zip(&detailed.steps) {
                    assert_eq!(public_step.op, detailed_step.op);
                    assert_eq!(public_step.via.is_some(), detailed_step.via.is_some());
                    assert_detailed_provenance_ref(&detailed_step.result);
                    if let Some(via) = &detailed_step.via {
                        assert_detailed_provenance_ref(via);
                    }
                }
            }
        }
    }
}

fn assert_detailed_provenance_ref(evidence: &DetailedCodeQueryProvenanceRefEvidence) {
    if evidence.source_slice_sha256.is_some() {
        assert!(evidence.byte_span.is_some());
        assert!(evidence.display_range.is_some());
    }
    if evidence.domain == DetailedCodeQueryDomain::File {
        assert!(evidence.byte_span.is_none());
        assert!(evidence.display_range.is_none());
        assert!(evidence.source_slice_sha256.is_none());
        assert!(matches!(
            evidence.identities,
            DetailedCodeQueryProvenanceIdentities::None
        ));
    }
}

fn assert_detailed_terminal_identities(
    domain: DetailedCodeQueryDomain,
    identities: &DetailedCodeQueryProvenanceIdentities,
) {
    assert!(matches!(
        (domain, identities),
        (
            DetailedCodeQueryDomain::StructuralMatch | DetailedCodeQueryDomain::Declaration,
            DetailedCodeQueryProvenanceIdentities::Primary(_),
        ) | (
            DetailedCodeQueryDomain::File
                | DetailedCodeQueryDomain::ExpressionSite
                | DetailedCodeQueryDomain::ReceiverAnalysis,
            DetailedCodeQueryProvenanceIdentities::None,
        ) | (
            DetailedCodeQueryDomain::ReferenceSite,
            DetailedCodeQueryProvenanceIdentities::ReferenceTarget(_),
        ) | (
            DetailedCodeQueryDomain::CallSite,
            DetailedCodeQueryProvenanceIdentities::Call { .. },
        )
    ));
}

impl CodeQueryResult {
    pub fn structural_matches(&self) -> Vec<&CodeQueryMatch> {
        self.results
            .iter()
            .filter_map(|result| match &result.value {
                CodeQueryResultValue::StructuralMatch { value } => Some(value),
                CodeQueryResultValue::Declaration { .. }
                | CodeQueryResultValue::File { .. }
                | CodeQueryResultValue::ReferenceSite { .. }
                | CodeQueryResultValue::CallSite { .. }
                | CodeQueryResultValue::ExpressionSite { .. }
                | CodeQueryResultValue::ReceiverAnalysis { .. } => None,
            })
            .collect()
    }

    pub fn result_count_line(&self) -> String {
        format!(
            "{} result{}{}",
            self.results.len(),
            if self.results.len() == 1 { "" } else { "s" },
            if self.truncated {
                " (truncated; refine the query or raise limit)"
            } else {
                ""
            },
        )
    }

    /// Human/agent-readable rendering following SearchTools conventions:
    /// structured JSON stays canonical, this is the display form.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        if self.results.is_empty() {
            out.push_str("No query results.\n");
        } else {
            out.push_str(&format!("{}\n", self.result_count_line()));
            for result in &self.results {
                out.push('\n');
                match &result.value {
                    CodeQueryResultValue::StructuralMatch { value: m } => {
                        let lines = m.line_span_label();
                        out.push_str(&format!("{}:{} [{}] `{}`", m.path, lines, m.kind, m.text));
                        if let Some(enclosing) = &m.enclosing_symbol {
                            out.push_str(&format!(" in {enclosing}"));
                        }
                        out.push('\n');
                        for capture in &m.captures {
                            out.push_str(&format!(
                                "  ${} = `{}` (line {})\n",
                                capture.name, capture.text, capture.start_line
                            ));
                        }
                    }
                    CodeQueryResultValue::Declaration { value } => {
                        let lines = line_span_label(value.start_line, value.end_line);
                        out.push_str(&format!(
                            "{}:{} [{}] {}",
                            value.path, lines, value.kind, value.fq_name
                        ));
                        if let Some(signature) = &value.signature {
                            out.push_str(&format!(" `{signature}`"));
                        }
                        out.push('\n');
                    }
                    CodeQueryResultValue::File { value } => {
                        out.push_str(&format!("{} [file; {}]\n", value.path, value.language));
                    }
                    CodeQueryResultValue::ReferenceSite { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [reference; {}; {}] -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.usage_kind,
                            value.proof,
                            value.target.fq_name
                        ));
                    }
                    CodeQueryResultValue::CallSite { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [call; {}; {}] {} -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.call_kind,
                            value.proof,
                            value.caller.fq_name,
                            value.callee.fq_name
                        ));
                    }
                    CodeQueryResultValue::ExpressionSite { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [call input; {}] `{}` -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.input_kind,
                            value.text,
                            value.callee_fq_name
                        ));
                    }
                    CodeQueryResultValue::ReceiverAnalysis { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [receiver analysis; {}; {}] `{}`\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.analysis_kind,
                            value.outcome,
                            value.text
                        ));
                        for detail in value.render_detail_lines() {
                            out.push_str(&format!("  {detail}\n"));
                        }
                    }
                }
                if let Some(summary) = result.provenance_summary() {
                    out.push_str(&format!("  {summary}\n"));
                }
            }
        }
        for diagnostic in &self.diagnostics {
            out.push_str(&format!(
                "{}: {}\n",
                diagnostic.presentation_label(),
                diagnostic.message
            ));
        }
        out
    }
}

impl CodeQueryMatch {
    pub fn line_span_label(&self) -> String {
        if self.start_line == self.end_line {
            self.start_line.to_string()
        } else {
            format!("{}-{}", self.start_line, self.end_line)
        }
    }
}

fn line_span_label(start_line: usize, end_line: usize) -> String {
    if start_line == end_line {
        start_line.to_string()
    } else {
        format!("{start_line}-{end_line}")
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

fn format_branch_path(branch: &[usize]) -> String {
    branch
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(".")
}
