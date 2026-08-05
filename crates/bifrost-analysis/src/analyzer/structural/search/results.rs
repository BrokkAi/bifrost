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
    ProvenSubset { codes: Vec<CodeQueryDiagnosticCode> },
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
        let declared_non_exhaustive =
            self.diagnostic_codes_with_impact(CodeQueryDiagnosticImpact::DeclaredNonExhaustive);
        if !declared_non_exhaustive.is_empty() {
            return CodeQueryCompletion::ProvenSubset {
                codes: declared_non_exhaustive,
            };
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
    Procedure {
        #[serde(flatten)]
        value: CodeQueryProcedure,
    },
    ProgramPoint {
        #[serde(flatten)]
        value: CodeQueryProgramPoint,
    },
    ControlEdge {
        #[serde(flatten)]
        value: Box<CodeQueryControlEdge>,
    },
    TypestateFinding {
        #[serde(flatten)]
        value: Box<CodeQueryTypestateFinding>,
    },
    TypestateWitness {
        #[serde(flatten)]
        value: Box<CodeQueryTypestateWitness>,
    },
    FlowEndpoint {
        #[serde(flatten)]
        value: Box<CodeQueryFlowEndpoint>,
    },
    FlowWitness {
        #[serde(flatten)]
        value: Box<CodeQueryFlowWitness>,
    },
    TaintFinding {
        #[serde(flatten)]
        value: Box<CodeQueryTaintFinding>,
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
    Occurrence {
        #[serde(flatten)]
        value: Box<CodeQueryOccurrence>,
    },
    LexicalScope {
        #[serde(flatten)]
        value: Box<CodeQueryLexicalScope>,
    },
    Binding {
        #[serde(flatten)]
        value: Box<CodeQueryBinding>,
    },
    ResolutionCandidate {
        #[serde(flatten)]
        value: Box<CodeQueryResolutionCandidate>,
    },
    ReferenceEdge {
        #[serde(flatten)]
        value: Box<CodeQueryReferenceEdge>,
    },
    QualifiedPath {
        #[serde(flatten)]
        value: Box<CodeQueryQualifiedPath>,
    },
    PathSegment {
        #[serde(flatten)]
        value: Box<CodeQueryPathSegment>,
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
    /// Content-scoped identity of the matched facts-arena node; equal to the
    /// `ast_id` of every occurrence row at the same node.
    ///
    /// Full detail only: correlation is a full-detail concern (policy
    /// evaluation always requests it), and compact output exists to be small.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_model: Option<Box<crate::analyzer::semantic_model::SemanticModelProvenance>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryProcedure {
    pub id: String,
    pub artifact_id: String,
    pub path: String,
    pub language: &'static str,
    pub procedure_kind: &'static str,
    pub range: CodeQueryRange,
    pub evidence: CodeQuerySemanticEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryProgramPoint {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<CodeQueryProgramPointBoundary>,
    pub event_count: usize,
    pub evidence: CodeQuerySemanticEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryControlEdge {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub edge_kind: &'static str,
    pub source: CodeQueryProgramPointRef,
    pub target: CodeQueryProgramPointRef,
    pub evidence: CodeQuerySemanticEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTypestateSubject {
    pub class: String,
    pub identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeQueryTypestateFindingKind {
    ErrorTransition {
        event: String,
        from_state: String,
        to_state: String,
    },
    TerminalExpectation {
        expectation: String,
        actual_states: Vec<String>,
    },
}

impl CodeQueryTypestateFindingKind {
    fn presentation_label(&self) -> String {
        match self {
            Self::ErrorTransition {
                event,
                from_state,
                to_state,
            } => format!("{event}: {from_state} -> {to_state}"),
            Self::TerminalExpectation {
                expectation,
                actual_states,
            } => format!("{expectation}: actual {}", actual_states.join(", ")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryTypestateCertainty {
    May,
    Must,
    Inconclusive,
}

impl CodeQueryTypestateCertainty {
    const fn label(self) -> &'static str {
        match self {
            Self::May => "may",
            Self::Must => "must",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryTypestateUncertainty {
    AmbiguousDispatch,
    UnknownCall,
    ExternalCall,
    Escape,
    IncompleteAnalysis,
    UnmatchedEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTypestateFinding {
    pub id: String,
    pub protocol_ref: String,
    pub protocol_hash: String,
    pub binding_plan_hash: String,
    pub subject: CodeQueryTypestateSubject,
    pub finding_kind: CodeQueryTypestateFindingKind,
    pub certainty: CodeQueryTypestateCertainty,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub path_proven: bool,
    pub path_complete: bool,
    pub analysis_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uncertainty: Vec<CodeQueryTypestateUncertainty>,
    #[serde(skip_serializing_if = "is_false")]
    pub abstained: bool,
    pub retained_witnesses: usize,
    pub omitted_witnesses: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeQueryTypestateWitnessStepKind {
    Seed,
    Edge { edge_kind: &'static str },
    EndSummaryGap { return_kind: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTypestateWitnessStep {
    pub kind: CodeQueryTypestateWitnessStepKind,
    pub source: CodeQuerySourceSite,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<CodeQuerySourceSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<CodeQuerySourceSite>,
    pub evidence: CodeQuerySemanticEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTypestateWitness {
    pub id: String,
    pub finding_id: String,
    pub protocol_ref: String,
    pub protocol_hash: String,
    pub binding_plan_hash: String,
    pub subject: CodeQueryTypestateSubject,
    pub witness_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_state: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub quality: CodeQuerySemanticEvidence,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uncertainty: Vec<CodeQueryTypestateUncertainty>,
    #[serde(skip_serializing_if = "is_false")]
    pub abstained: bool,
    pub steps: Vec<CodeQueryTypestateWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub retention_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowReachability {
    Reached,
    NotReached,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowCertainty {
    Exact,
    May,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowMustStatus {
    NotEstablished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowCompletion {
    Complete,
    Incomplete,
    BudgetExhausted,
    Cancelled,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowSolverTermination {
    FixedPoint,
    BudgetExhausted,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryFlowEvent {
    pub id: String,
    pub site: CodeQueryFlowSymbolSite,
    pub path: String,
    pub range: CodeQueryRange,
    pub phase: &'static str,
    pub ordinal: u32,
    pub carrier: CodeQueryFlowCarrierSymbol,
}

/// One stable source-backed locator used by a public value-flow symbol.
///
/// `id` deliberately omits the workspace mount and every run-local dense ID.
/// The declaration path retains enough structure to distinguish anonymous or
/// same-named declarations that share a source range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryFlowSymbolSite {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub declaration: Vec<CodeQueryFlowDeclarationSegment>,
    pub role: &'static str,
    pub start_byte: u32,
    pub end_byte: u32,
    pub occurrence: u32,
    pub range: CodeQueryRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryFlowDeclarationSegment {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub start_byte: u32,
    pub end_byte: u32,
    pub occurrence: u32,
    pub sibling_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowPortSymbol {
    Receiver,
    Parameter { ordinal: u32 },
    NormalReturn,
    ExceptionalReturn,
    Capture { slot: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowSelectorSymbol {
    Field {
        field: CodeQueryFlowSymbolSite,
    },
    ExactIndex {
        index: Box<CodeQueryFlowCarrierSymbol>,
    },
    AnyIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowCarrierSymbol {
    Value {
        id: String,
        site: CodeQueryFlowSymbolSite,
        role: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ordinal: Option<u32>,
    },
    Port {
        id: String,
        procedure: CodeQueryFlowSymbolSite,
        port: CodeQueryFlowPortSymbol,
    },
    Allocation {
        id: String,
        site: CodeQueryFlowSymbolSite,
    },
    CallResult {
        id: String,
        call: CodeQueryFlowSymbolSite,
        result: Box<CodeQueryFlowCarrierSymbol>,
        callee: CodeQueryFlowSymbolSite,
    },
    ScopedRoot {
        id: String,
        root_kind: &'static str,
        site: CodeQueryFlowSymbolSite,
    },
    Location {
        id: String,
        root: Box<CodeQueryFlowCarrierSymbol>,
        selectors: Vec<CodeQueryFlowSelectorSymbol>,
        exact: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowFactSymbol {
    Zero,
    Carrier {
        source: Box<CodeQueryFlowEvent>,
        carrier: Box<CodeQueryFlowCarrierSymbol>,
        #[serde(skip_serializing_if = "is_false")]
        uncertain: bool,
    },
    Meeting {
        source: Box<CodeQueryFlowEvent>,
        sink: Box<CodeQueryFlowEvent>,
        #[serde(skip_serializing_if = "is_false")]
        uncertain: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryFlowEndpoint {
    pub id: String,
    pub plan_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CodeQueryFlowEvent>,
    pub sink: CodeQueryFlowEvent,
    pub reachability: CodeQueryFlowReachability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certainty: Option<CodeQueryFlowCertainty>,
    pub must: CodeQueryFlowMustStatus,
    #[serde(skip_serializing_if = "is_false")]
    pub ambiguous: bool,
    pub completion: CodeQueryFlowCompletion,
    pub semantic_status: &'static str,
    pub solver_termination: CodeQueryFlowSolverTermination,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path_qualities: Vec<CodeQuerySemanticEvidence>,
    pub retained_witnesses: usize,
    pub omitted_witnesses: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeQueryFlowWitnessStepKind {
    Seed,
    Edge { edge_kind: &'static str },
    EndSummaryGap { return_kind: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryFlowWitnessStep {
    pub kind: CodeQueryFlowWitnessStepKind,
    pub source: CodeQuerySourceSite,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_symbol: Option<CodeQueryFlowSymbolSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<CodeQuerySourceSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_symbol: Option<CodeQueryFlowSymbolSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<CodeQuerySourceSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_symbol: Option<CodeQueryFlowSymbolSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<CodeQueryFlowFactSymbol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<CodeQueryFlowFactSymbol>,
    pub evidence: CodeQuerySemanticEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryFlowWitness {
    pub id: String,
    pub endpoint_id: String,
    pub plan_ref: String,
    pub witness_index: usize,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub quality: CodeQuerySemanticEvidence,
    pub steps: Vec<CodeQueryFlowWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub retention_truncated: bool,
}

/// One bounded source occurrence contributing to an aggregated taint sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTaintOrigin {
    pub id: String,
    pub event_id: String,
    pub labels: Vec<String>,
    pub site: CodeQuerySourceSite,
}

/// One bounded witness owned by an aggregated taint finding.
///
/// Steps reuse the source-backed flow witness representation. The envelope is
/// taint-specific because one finding can aggregate several origins and is not
/// itself a registered value-flow endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTaintWitness {
    pub id: String,
    pub finding_id: String,
    pub witness_index: usize,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub quality: CodeQuerySemanticEvidence,
    pub steps: Vec<CodeQueryFlowWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub retention_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeQueryTaintProjectionLimits {
    pub max_origins_per_finding: usize,
    pub max_witnesses_per_finding: usize,
    pub max_steps_per_witness: usize,
    pub max_witness_bytes: usize,
}

impl CodeQueryTaintProjectionLimits {
    pub const fn new(
        max_origins_per_finding: usize,
        max_witnesses_per_finding: usize,
        max_steps_per_witness: usize,
        max_witness_bytes: usize,
    ) -> Self {
        Self {
            max_origins_per_finding,
            max_witnesses_per_finding,
            max_steps_per_witness,
            max_witness_bytes,
        }
    }
}

/// Diagnostic-neutral public projection of one retained taint finding.
///
/// Flow witness steps deliberately reuse [`CodeQueryFlowWitnessStep`]; this
/// envelope adds only taint-specific aggregation that a flow endpoint cannot
/// represent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTaintFinding {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub sink_event_id: String,
    pub sink: CodeQuerySourceSite,
    pub reached_labels: Vec<String>,
    pub origins: Vec<CodeQueryTaintOrigin>,
    #[serde(skip_serializing_if = "is_false")]
    pub origins_truncated: bool,
    pub witnesses: Vec<CodeQueryTaintWitness>,
    #[serde(skip_serializing_if = "is_false")]
    pub witnesses_truncated: bool,
    pub evidence: CodeQuerySemanticEvidence,
    #[serde(skip_serializing_if = "is_false")]
    pub ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryProgramPointRef {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<CodeQueryProgramPointBoundary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryProgramPointBoundary {
    Entry,
    NormalExit,
    ExceptionalExit,
}

impl CodeQueryProgramPointBoundary {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::NormalExit => "normal_exit",
            Self::ExceptionalExit => "exceptional_exit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQuerySemanticEvidence {
    pub proof: CodeQuerySemanticProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_reason: Option<String>,
    pub completeness: CodeQuerySemanticCompleteness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completeness_reason: Option<String>,
}

impl CodeQuerySemanticEvidence {
    pub const fn status_label(&self) -> &'static str {
        match (self.proof, self.completeness) {
            (CodeQuerySemanticProof::Proven, CodeQuerySemanticCompleteness::Complete) => {
                "proven/complete"
            }
            (CodeQuerySemanticProof::Proven, CodeQuerySemanticCompleteness::Partial) => {
                "proven/partial"
            }
            (CodeQuerySemanticProof::Unproven, CodeQuerySemanticCompleteness::Complete) => {
                "unproven/complete"
            }
            (CodeQuerySemanticProof::Unproven, CodeQuerySemanticCompleteness::Partial) => {
                "unproven/partial"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQuerySemanticProof {
    Proven,
    Unproven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQuerySemanticCompleteness {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryFile {
    pub path: String,
    pub language: &'static str,
    /// The package or module this file belongs to, when the workspace can name
    /// one (#1474). The package clause is one row per file, so it is exposed as
    /// fields on the file row rather than as a fourth row kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_fq: Option<String>,
    /// `Some(true)` when the language spells the package in the source (Java's
    /// `package a.b;`), `Some(false)` when it is derived from the file's path,
    /// and `None` when no package could be named at all -- which is not the
    /// same as "the file is in the root package".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_syntactic: Option<bool>,
}

/// One lexical scope of a file (#1474).
///
/// `ast_id` is absent for exactly one scope per file: the synthesized whole-file
/// scope, which no grammar gives an arena node. Every other scope is a fact, so
/// its `ast_id` joins with a structural capture over the same node.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryLexicalScope {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    /// Dense per-file scope index; 0 is always the file scope.
    pub index: u32,
    /// The normalized kind of the anchoring fact, or `null` for the file scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_index: Option<u32>,
}

/// One name a scope introduces (#1474).
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryBinding {
    pub id: String,
    /// Absent when the binder's local name is not spelled by a classified
    /// token, which is how a wildcard import and an adapter without a
    /// structured import path surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub name: String,
    pub kind: &'static str,
    pub hoisting: &'static str,
    pub namespace: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    /// Byte interval over which the binding is in effect.
    pub activation_start_byte: usize,
    pub activation_end_byte: usize,
    /// Dense index of the declaring scope, which `scope-of` projects to a row.
    pub declaring_scope_index: u32,
    pub source_order: u32,
    pub visibility: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import: Option<CodeQueryImportBinder>,
    /// `true` when this row was emitted as a binding the reaching binding
    /// shadows rather than as the winner. Only `reaching-binding
    /// :include-shadowed` produces such rows.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub shadowed: bool,
    /// The AST identity of the occurrence this row is the reaching binding
    /// *of*, present exactly on rows the `reaching-binding` step produced.
    ///
    /// Without it the step's answer is unjoinable: a correlated consumer that
    /// captured one token cannot tell which of several returned bindings
    /// belongs to it. A binding reached from two different occurrences is two
    /// rows, because it is two answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reached_from_ast_id: Option<String>,
}

/// What an import binder contributes, as far as the adapter can state it.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryImportBinder {
    pub local_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Empty when the adapter records no parser-derived import path. That is a
    /// stated gap, not a claim that the import has no target.
    pub target_segments: Vec<String>,
    pub wildcard: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard_ambiguous: Option<bool>,
    pub boundary: &'static str,
}

/// One candidate the resolver considered for one reference (#1474).
///
/// `tier` is optional by construction: the shared outcome constructors receive
/// a bare candidate list and cannot name the tier that produced it, so an
/// absent tier means *unattributed*, never "the weakest tier".
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryResolutionCandidate {
    pub id: String,
    /// The AST identity of the *reference* the candidate was considered for,
    /// which is what a capture over that token joins on.
    pub ast_id: String,
    pub path: String,
    pub language: &'static str,
    /// The reference occurrence's source range, so a candidate row points at
    /// the position whose resolution it explains.
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    /// Ordinal of this candidate within its reference's trace, so two
    /// otherwise identical rows stay separately addressable.
    pub ordinal: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<&'static str>,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<&'static str>,
    pub boundary: &'static str,
    pub visibility: &'static str,
    /// How much of the candidate story the language's resolver reports.
    /// `selection_only` means an absent rejection row says nothing.
    pub trace_completeness: &'static str,
    pub candidate: CodeQueryCandidateRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_target: Option<String>,
}

/// One canonical reference edge (#1479).
///
/// The same row shape whichever producer derived it: `provenance` says which
/// one did, and every classification the parity comparison depends on (kind,
/// proof, usage kind, site class, owner relation) is an explicit field, never
/// inferred from counts. `ast_id` is the site token's content-scoped AST
/// identity when the producer can address it as a facts-arena node; string
/// equality with a capture's or occurrence's `ast_id` is the correlation join.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReferenceEdge {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    pub target: CodeQueryDeclaration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_declaration: Option<CodeQueryDeclaration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_kind: Option<&'static str>,
    pub proof: &'static str,
    pub usage_kind: &'static str,
    pub site_class: &'static str,
    pub owner_relation: &'static str,
    /// Which producer derived the row. Serialized as `edge_provenance`
    /// because the result item that flattens this row already owns the
    /// `provenance` key for its pipeline trace, and a colliding key would let
    /// the trace silently shadow the producer label under full detail.
    #[serde(rename = "edge_provenance")]
    pub provenance: &'static str,
    /// The workspace generation the edge was derived in. A parity comparison
    /// refuses to relate rows from two generations.
    pub generation: u64,
}

/// One qualified-path chain (#1475): a linear sequence of segments the
/// grammar records, anchored at its terminal segment token.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryQualifiedPath {
    pub id: String,
    /// The terminal segment token's AST identity — the equijoin key with
    /// captures and occurrence rows over the same token.
    pub ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    pub segment_count: u32,
}

/// One segment of one qualified path (#1475).
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryPathSegment {
    pub id: String,
    /// The segment token's AST identity; absent for a segment the kind table
    /// does not admit as a fact (Rust's `crate`/`self`/`super` path
    /// keywords), whose position in the path is real but whose structural
    /// identity is genuinely absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    /// The owning path's terminal AST identity — the group key back to its
    /// qualified-path row.
    pub path_ast_id: String,
    /// 0-based position within the path, counting every spelled segment.
    pub ordinal: u32,
    /// Decoded identifier text: a quoted or punctuation-bearing identifier is
    /// one segment and is never re-split.
    pub text: String,
    /// Stated by the adapter's classification or decided by resolution;
    /// absent means "not stated", never a guessed value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<&'static str>,
    /// The generic argument count the source spells at this segment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_arity: Option<u32>,
    /// Present exactly when segment resolution was derived; `null` means
    /// "not derived", never "nothing considered".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_count: Option<usize>,
}

/// What a candidate row points at. Two of the five shapes carry no workspace
/// declaration, which is why `candidate-target` is partial by construction.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "candidate_kind", rename_all = "snake_case")]
pub enum CodeQueryCandidateRef {
    Unit {
        unit: Box<CodeQueryDeclaration>,
    },
    Lexical {
        name: String,
        kind: &'static str,
        range: CodeQueryRange,
    },
    Binding {
        name: String,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
    },
    ImportBinder {
        name: String,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        /// The parser-derived path the route pointed at. Empty when the
        /// adapter or seam recorded no structured target. That is a stated
        /// gap, not a claim that the import has no target.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        target_segments: Vec<String>,
    },
    ExternalRoute {
        name: String,
    },
}

impl CodeQueryCandidateRef {
    /// The stable label of the shape, used in rendering and in the detailed
    /// terminal key.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unit { .. } => "unit",
            Self::Lexical { .. } => "lexical",
            Self::Binding { .. } => "binding",
            Self::ImportBinder { .. } => "import_binder",
            Self::ExternalRoute { .. } => "external_route",
        }
    }

    /// The candidate's name, for rendering.
    pub fn name(&self) -> &str {
        match self {
            Self::Unit { unit } => &unit.fq_name,
            Self::Lexical { name, .. }
            | Self::Binding { name, .. }
            | Self::ImportBinder { name, .. }
            | Self::ExternalRoute { name } => name,
        }
    }
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

/// One classified identifier position.
///
/// `ast_id` is the content-scoped identity of the underlying facts-arena node
/// and is minted with the same recipe a structural capture uses, so string
/// equality of two `ast_id`s *is* the correlation join between a capture and
/// the occurrence at that node. `id` additionally distinguishes the role, so a
/// node classified twice yields two addressable rows.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryOccurrence {
    pub id: String,
    pub ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub class: &'static str,
    pub role: &'static str,
    pub namespace: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_symbol: Option<String>,
    pub raw_spelling: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_spelling: Option<String>,
    pub target: CodeQueryOccurrenceTarget,
}

/// What a reference-class occurrence resolves to. A non-reference row is
/// always `none`, and a reference row never is: `unresolved` carries the exact
/// resolver status so an empty target is never mistaken for "not attempted".
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "target_kind", rename_all = "snake_case")]
pub enum CodeQueryOccurrenceTarget {
    None,
    Resolved {
        units: Vec<CodeQueryDeclaration>,
    },
    Lexical {
        name: String,
        kind: &'static str,
        range: CodeQueryRange,
    },
    Unresolved {
        status: &'static str,
    },
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    Procedure {
        id: String,
        path: String,
        procedure_kind: &'static str,
        range: CodeQueryRange,
    },
    FlowEndpoint {
        id: String,
        plan_ref: String,
        path: String,
        range: CodeQueryRange,
    },
    FlowWitness {
        id: String,
        endpoint_id: String,
        path: String,
        range: CodeQueryRange,
    },
    TaintFinding {
        id: String,
        path: String,
        range: CodeQueryRange,
    },
    ProgramPoint {
        id: String,
        procedure_id: String,
        path: String,
        range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        boundary: Option<CodeQueryProgramPointBoundary>,
    },
    ControlEdge {
        id: String,
        procedure_id: String,
        path: String,
        range: CodeQueryRange,
        edge_kind: &'static str,
        source_id: String,
        target_id: String,
    },
    TypestateFinding {
        id: String,
        path: String,
        range: CodeQueryRange,
        protocol_ref: String,
    },
    TypestateWitness {
        id: String,
        finding_id: String,
        path: String,
        range: CodeQueryRange,
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
    Occurrence {
        id: String,
        ast_id: String,
        path: String,
        range: CodeQueryRange,
        class: &'static str,
        role: &'static str,
        namespace: &'static str,
    },
    LexicalScope {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        index: u32,
    },
    Binding {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        name: String,
        kind: &'static str,
    },
    ResolutionCandidate {
        id: String,
        ast_id: String,
        path: String,
        range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        tier: Option<&'static str>,
        outcome: &'static str,
    },
    ReferenceEdge {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        target_fq_name: String,
        provenance: &'static str,
    },
    QualifiedPath {
        id: String,
        ast_id: String,
        path: String,
        range: CodeQueryRange,
        segment_count: u32,
    },
    PathSegment {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        ordinal: u32,
        text: String,
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
    /// Content-scoped identity of the captured facts-arena node, equal to the
    /// `ast_id` of every occurrence row at that node. Absent only when the
    /// capture came from a match whose facts identity was unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
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

#[derive(Debug)]
pub struct DetailedCodeQueryResult {
    pub result: CodeQueryResult,
    pub work: CodeQueryExecutionWork,
    pub evidence: Vec<DetailedCodeQueryEvidence>,
    pub profile: Option<QueryExecutionProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryEvidence {
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
pub struct DetailedCodeQueryProvenanceEvidence {
    pub branch: Vec<usize>,
    pub seed: DetailedCodeQueryProvenanceRefEvidence,
    pub steps: Vec<DetailedCodeQueryProvenanceStepEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryProvenanceStepEvidence {
    pub op: String,
    pub result: DetailedCodeQueryProvenanceRefEvidence,
    pub via: Option<DetailedCodeQueryProvenanceRefEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryProvenanceRefEvidence {
    pub domain: DetailedCodeQueryDomain,
    pub key: DetailedCodeQueryKey,
    pub file: ProjectFile,
    pub byte_span: Option<std::ops::Range<usize>>,
    pub display_range: Option<CodeQueryRange>,
    pub identities: DetailedCodeQueryProvenanceIdentities,
    pub source_slice_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailedCodeQueryProvenanceIdentities {
    None,
    Primary(Option<DetailedCodeQueryIdentityCandidate>),
    ReferenceTarget(Option<DetailedCodeQueryIdentityCandidate>),
    Call {
        caller: Option<DetailedCodeQueryIdentityCandidate>,
        callee: Option<DetailedCodeQueryIdentityCandidate>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryIdentityCandidate {
    pub file: ProjectFile,
    pub candidate: CodeQueryStableOwnerCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeQueryStableOwnerCandidate {
    pub namespace: String,
    pub derivation: CodeQueryStableOwnerDerivation,
    pub semantic_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeQueryStableOwnerDerivation {
    AnalyzerDeclarationId,
    CanonicalAstIdentity,
    SemanticWireId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailedCodeQueryDomain {
    StructuralMatch,
    Declaration,
    Procedure,
    ProgramPoint,
    ControlEdge,
    TypestateFinding,
    TypestateWitness,
    FlowEndpoint,
    FlowWitness,
    TaintFinding,
    File,
    ReferenceSite,
    CallSite,
    ExpressionSite,
    ReceiverAnalysis,
    Occurrence,
    LexicalScope,
    Binding,
    ResolutionCandidate,
    ReferenceEdge,
    QualifiedPath,
    PathSegment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailedCodeQueryKey {
    StructuralMatch {
        kind: String,
        analyzer_id: Option<String>,
    },
    Declaration {
        kind: String,
        fq_name: String,
        analyzer_id: Option<String>,
    },
    Procedure {
        id: String,
    },
    ProgramPoint {
        id: String,
        procedure_id: String,
    },
    ControlEdge {
        id: String,
        procedure_id: String,
    },
    TypestateFinding {
        id: String,
    },
    TypestateWitness {
        id: String,
        finding_id: String,
    },
    FlowEndpoint {
        id: String,
    },
    FlowWitness {
        id: String,
        endpoint_id: String,
    },
    TaintFinding {
        id: String,
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
    Occurrence {
        id: String,
        ast_id: String,
        role: String,
    },
    LexicalScope {
        id: String,
        ast_id: Option<String>,
        index: u32,
    },
    Binding {
        id: String,
        ast_id: Option<String>,
        name: String,
    },
    ResolutionCandidate {
        id: String,
        ast_id: String,
        ordinal: usize,
    },
    ReferenceEdge {
        id: String,
        ast_id: Option<String>,
        target_fq_name: String,
        provenance: String,
    },
    QualifiedPath {
        id: String,
        ast_id: String,
    },
    PathSegment {
        id: String,
        ast_id: Option<String>,
        ordinal: u32,
    },
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
            if let Some((expected_domain, expected_key)) = detailed_semantic_identity(&result.value)
            {
                assert_eq!(evidence.domain, expected_domain);
                assert_eq!(evidence.key, expected_key);
            }
            assert!(
                matches!(
                    (evidence.domain, &evidence.key),
                    (
                        DetailedCodeQueryDomain::StructuralMatch,
                        DetailedCodeQueryKey::StructuralMatch { .. }
                    ) | (
                        DetailedCodeQueryDomain::Declaration,
                        DetailedCodeQueryKey::Declaration { .. }
                    ) | (
                        DetailedCodeQueryDomain::Procedure,
                        DetailedCodeQueryKey::Procedure { .. }
                    ) | (
                        DetailedCodeQueryDomain::ProgramPoint,
                        DetailedCodeQueryKey::ProgramPoint { .. }
                    ) | (
                        DetailedCodeQueryDomain::ControlEdge,
                        DetailedCodeQueryKey::ControlEdge { .. }
                    ) | (
                        DetailedCodeQueryDomain::TypestateFinding,
                        DetailedCodeQueryKey::TypestateFinding { .. }
                    ) | (
                        DetailedCodeQueryDomain::TypestateWitness,
                        DetailedCodeQueryKey::TypestateWitness { .. }
                    ) | (
                        DetailedCodeQueryDomain::FlowEndpoint,
                        DetailedCodeQueryKey::FlowEndpoint { .. }
                    ) | (
                        DetailedCodeQueryDomain::FlowWitness,
                        DetailedCodeQueryKey::FlowWitness { .. }
                    ) | (
                        DetailedCodeQueryDomain::TaintFinding,
                        DetailedCodeQueryKey::TaintFinding { .. }
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
                        | (
                            DetailedCodeQueryDomain::Occurrence,
                            DetailedCodeQueryKey::Occurrence { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::LexicalScope,
                            DetailedCodeQueryKey::LexicalScope { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::Binding,
                            DetailedCodeQueryKey::Binding { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ResolutionCandidate,
                            DetailedCodeQueryKey::ResolutionCandidate { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ReferenceEdge,
                            DetailedCodeQueryKey::ReferenceEdge { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::QualifiedPath,
                            DetailedCodeQueryKey::QualifiedPath { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::PathSegment,
                            DetailedCodeQueryKey::PathSegment { .. }
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
                    | CodeQueryStableOwnerDerivation::CanonicalAstIdentity
                    | CodeQueryStableOwnerDerivation::SemanticWireId => {}
                }
            }
            if let Some(wire_id) = semantic_wire_id(&evidence.key) {
                let candidate = evidence
                    .stable_owner_candidate
                    .as_ref()
                    .expect("semantic CodeQuery evidence requires its wire identity");
                assert_eq!(
                    candidate.derivation,
                    CodeQueryStableOwnerDerivation::SemanticWireId
                );
                assert_eq!(candidate.semantic_key, wire_id);
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

fn detailed_semantic_identity(
    value: &CodeQueryResultValue,
) -> Option<(DetailedCodeQueryDomain, DetailedCodeQueryKey)> {
    match value {
        CodeQueryResultValue::Procedure { value } => Some((
            DetailedCodeQueryDomain::Procedure,
            DetailedCodeQueryKey::Procedure {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::ProgramPoint { value } => Some((
            DetailedCodeQueryDomain::ProgramPoint,
            DetailedCodeQueryKey::ProgramPoint {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::ControlEdge { value } => Some((
            DetailedCodeQueryDomain::ControlEdge,
            DetailedCodeQueryKey::ControlEdge {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::TypestateFinding { value } => Some((
            DetailedCodeQueryDomain::TypestateFinding,
            DetailedCodeQueryKey::TypestateFinding {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::TypestateWitness { value } => Some((
            DetailedCodeQueryDomain::TypestateWitness,
            DetailedCodeQueryKey::TypestateWitness {
                id: value.id.clone(),
                finding_id: value.finding_id.clone(),
            },
        )),
        CodeQueryResultValue::FlowEndpoint { value } => Some((
            DetailedCodeQueryDomain::FlowEndpoint,
            DetailedCodeQueryKey::FlowEndpoint {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::FlowWitness { value } => Some((
            DetailedCodeQueryDomain::FlowWitness,
            DetailedCodeQueryKey::FlowWitness {
                id: value.id.clone(),
                endpoint_id: value.endpoint_id.clone(),
            },
        )),
        CodeQueryResultValue::TaintFinding { value } => Some((
            DetailedCodeQueryDomain::TaintFinding,
            DetailedCodeQueryKey::TaintFinding {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::StructuralMatch { .. }
        | CodeQueryResultValue::Declaration { .. }
        | CodeQueryResultValue::File { .. }
        | CodeQueryResultValue::ReferenceSite { .. }
        | CodeQueryResultValue::CallSite { .. }
        | CodeQueryResultValue::ExpressionSite { .. }
        | CodeQueryResultValue::ReceiverAnalysis { .. }
        | CodeQueryResultValue::Occurrence { .. }
        | CodeQueryResultValue::LexicalScope { .. }
        | CodeQueryResultValue::Binding { .. }
        | CodeQueryResultValue::ResolutionCandidate { .. }
        | CodeQueryResultValue::ReferenceEdge { .. } => None,
        CodeQueryResultValue::QualifiedPath { .. } | CodeQueryResultValue::PathSegment { .. } => {
            None
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
            DetailedCodeQueryDomain::StructuralMatch
                | DetailedCodeQueryDomain::Declaration
                | DetailedCodeQueryDomain::Procedure
                | DetailedCodeQueryDomain::ProgramPoint
                | DetailedCodeQueryDomain::ControlEdge
                | DetailedCodeQueryDomain::TypestateFinding
                | DetailedCodeQueryDomain::TypestateWitness
                | DetailedCodeQueryDomain::FlowEndpoint
                | DetailedCodeQueryDomain::FlowWitness
                | DetailedCodeQueryDomain::TaintFinding,
            DetailedCodeQueryProvenanceIdentities::Primary(_),
        ) | (
            DetailedCodeQueryDomain::File
                | DetailedCodeQueryDomain::ExpressionSite
                | DetailedCodeQueryDomain::ReceiverAnalysis
                // An occurrence's identity is its own content-scoped digest,
                // carried in the typed key rather than in a semantic-artifact
                // identity candidate. The three lexical-environment domains
                // are identified the same way, for the same reason.
                | DetailedCodeQueryDomain::Occurrence
                | DetailedCodeQueryDomain::LexicalScope
                | DetailedCodeQueryDomain::Binding
                | DetailedCodeQueryDomain::ResolutionCandidate
                // A reference edge's identity is its own content-scoped
                // digest, carried in the typed key like the environment
                // domains above.
                | DetailedCodeQueryDomain::ReferenceEdge
                // A path and its segments are likewise identified by their
                // own content-scoped digests in the typed key.
                | DetailedCodeQueryDomain::QualifiedPath
                | DetailedCodeQueryDomain::PathSegment,
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

fn semantic_wire_id(key: &DetailedCodeQueryKey) -> Option<&str> {
    match key {
        DetailedCodeQueryKey::Procedure { id }
        | DetailedCodeQueryKey::ProgramPoint { id, .. }
        | DetailedCodeQueryKey::ControlEdge { id, .. }
        | DetailedCodeQueryKey::TypestateFinding { id }
        | DetailedCodeQueryKey::TypestateWitness { id, .. }
        | DetailedCodeQueryKey::FlowEndpoint { id }
        | DetailedCodeQueryKey::FlowWitness { id, .. }
        | DetailedCodeQueryKey::TaintFinding { id } => Some(id),
        DetailedCodeQueryKey::StructuralMatch { .. }
        | DetailedCodeQueryKey::Declaration { .. }
        | DetailedCodeQueryKey::File
        | DetailedCodeQueryKey::ReferenceSite { .. }
        | DetailedCodeQueryKey::CallSite { .. }
        | DetailedCodeQueryKey::ExpressionSite { .. }
        | DetailedCodeQueryKey::ReceiverAnalysis { .. }
        | DetailedCodeQueryKey::Occurrence { .. }
        | DetailedCodeQueryKey::LexicalScope { .. }
        | DetailedCodeQueryKey::Binding { .. }
        | DetailedCodeQueryKey::ResolutionCandidate { .. }
        | DetailedCodeQueryKey::ReferenceEdge { .. } => None,
        DetailedCodeQueryKey::QualifiedPath { .. } | DetailedCodeQueryKey::PathSegment { .. } => {
            None
        }
    }
}

impl CodeQueryResult {
    pub fn structural_matches(&self) -> Vec<&CodeQueryMatch> {
        self.results
            .iter()
            .filter_map(|result| match &result.value {
                CodeQueryResultValue::StructuralMatch { value } => Some(value),
                CodeQueryResultValue::Declaration { .. }
                | CodeQueryResultValue::Procedure { .. }
                | CodeQueryResultValue::ProgramPoint { .. }
                | CodeQueryResultValue::ControlEdge { .. }
                | CodeQueryResultValue::TypestateFinding { .. }
                | CodeQueryResultValue::TypestateWitness { .. }
                | CodeQueryResultValue::FlowEndpoint { .. }
                | CodeQueryResultValue::FlowWitness { .. }
                | CodeQueryResultValue::TaintFinding { .. }
                | CodeQueryResultValue::File { .. }
                | CodeQueryResultValue::ReferenceSite { .. }
                | CodeQueryResultValue::CallSite { .. }
                | CodeQueryResultValue::ExpressionSite { .. }
                | CodeQueryResultValue::ReceiverAnalysis { .. }
                | CodeQueryResultValue::Occurrence { .. }
                | CodeQueryResultValue::LexicalScope { .. }
                | CodeQueryResultValue::Binding { .. }
                | CodeQueryResultValue::ResolutionCandidate { .. }
                | CodeQueryResultValue::ReferenceEdge { .. } => None,
                CodeQueryResultValue::QualifiedPath { .. }
                | CodeQueryResultValue::PathSegment { .. } => None,
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
                    CodeQueryResultValue::Procedure { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [procedure; {}; {}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.procedure_kind,
                            value.evidence.status_label(),
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::ProgramPoint { value } => {
                        let boundary = value
                            .boundary
                            .map_or("interior", CodeQueryProgramPointBoundary::label);
                        out.push_str(&format!(
                            "{}:{}:{} [program point; {}; {}; {} event{}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            boundary,
                            value.evidence.status_label(),
                            value.event_count,
                            if value.event_count == 1 { "" } else { "s" },
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::ControlEdge { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [control edge; {}; {}] {} -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.edge_kind,
                            value.evidence.status_label(),
                            value.source.id,
                            value.target.id,
                        ));
                    }
                    CodeQueryResultValue::TypestateFinding { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [typestate finding; {}; {}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.certainty.label(),
                            value.finding_kind.presentation_label(),
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::TypestateWitness { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [typestate witness; {} step{}{}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.steps.len(),
                            if value.steps.len() == 1 { "" } else { "s" },
                            if value.truncated { "; truncated" } else { "" },
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::FlowEndpoint { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [flow endpoint; {:?}; {:?}; {:?}{}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.reachability,
                            value.certainty,
                            value.completion,
                            if value.ambiguous { "; ambiguous" } else { "" },
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::FlowWitness { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [flow witness; {} step{}{}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.steps.len(),
                            if value.steps.len() == 1 { "" } else { "s" },
                            if value.truncated { "; truncated" } else { "" },
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::TaintFinding { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [taint finding; {} label{}; {} origin{}; {} witness{}{}] {}\n",
                            value.sink.path,
                            value.sink.range.start_line,
                            value.sink.range.start_column,
                            value.reached_labels.len(),
                            if value.reached_labels.len() == 1 { "" } else { "s" },
                            value.origins.len(),
                            if value.origins.len() == 1 { "" } else { "s" },
                            value.witnesses.len(),
                            if value.witnesses.len() == 1 { "" } else { "es" },
                            if value.ambiguous { "; ambiguous" } else { "" },
                            value.id,
                        ));
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
                    CodeQueryResultValue::Occurrence { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [occurrence; {}; {}; {}] `{}`",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.class,
                            value.role,
                            value.namespace,
                            value.raw_spelling
                        ));
                        if let Some(decoded) = &value.decoded_spelling {
                            out.push_str(&format!(" (decodes to `{decoded}`)"));
                        }
                        if let Some(enclosing) = &value.enclosing_symbol {
                            out.push_str(&format!(" in {enclosing}"));
                        }
                        out.push('\n');
                        for line in value.target.render_detail_lines() {
                            out.push_str(&format!("  {line}\n"));
                        }
                    }
                    CodeQueryResultValue::LexicalScope { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [lexical_scope #{}; {}]\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.index,
                            value.kind.unwrap_or("file"),
                        ));
                        if let Some(parent) = value.parent_index {
                            out.push_str(&format!("  inside scope #{parent}\n"));
                        }
                    }
                    CodeQueryResultValue::Binding { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [binding; {}; {}] `{}`{}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.kind,
                            value.hoisting,
                            value.name,
                            if value.shadowed { " (shadowed)" } else { "" },
                        ));
                        out.push_str(&format!(
                            "  declared in scope #{}, active over bytes {}..{}\n",
                            value.declaring_scope_index,
                            value.activation_start_byte,
                            value.activation_end_byte
                        ));
                        if let Some(import) = &value.import {
                            out.push_str(&format!(
                                "  import {} -> {}{}\n",
                                import.local_name,
                                if import.target_segments.is_empty() {
                                    "<target not recorded by this adapter>".to_string()
                                } else {
                                    import.target_segments.join(".")
                                },
                                if import.wildcard { " (wildcard)" } else { "" }
                            ));
                        }
                    }
                    CodeQueryResultValue::ResolutionCandidate { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [resolution_candidate; {}; {}] {} `{}`\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.tier.unwrap_or("unattributed"),
                            value.outcome,
                            value.candidate.label(),
                            value.candidate.name(),
                        ));
                        if let Some(reason) = value.rejection_reason {
                            out.push_str(&format!("  rejected: {reason}\n"));
                        }
                        out.push_str(&format!(
                            "  boundary {}, trace {}\n",
                            value.boundary, value.trace_completeness
                        ));
                    }
                    CodeQueryResultValue::ReferenceEdge { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [reference_edge; {}; {}; {}] -> {} [{}]\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.provenance,
                            value.proof,
                            value.usage_kind,
                            value.target.fq_name,
                            value.target.kind,
                        ));
                        out.push_str(&format!(
                            "  kind {}, site {}, relation {}, generation {}\n",
                            value.reference_kind.unwrap_or("unclassified"),
                            value.site_class,
                            value.owner_relation,
                            value.generation,
                        ));
                    }
                    CodeQueryResultValue::QualifiedPath { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [qualified_path; {} segments]\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.segment_count,
                        ));
                    }
                    CodeQueryResultValue::PathSegment { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [path_segment #{}] `{}`{}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.ordinal,
                            value.text,
                            match value.generic_arity {
                                Some(arity) => format!(" <{arity} generic args>"),
                                None => String::new(),
                            },
                        ));
                        if let Some(namespace) = value.namespace {
                            out.push_str(&format!("  namespace {namespace}\n"));
                        }
                        if let Some(status) = value.resolution_status {
                            out.push_str(&format!(
                                "  resolves: {status}{}\n",
                                match value.target_count {
                                    Some(count) if count > 0 => format!(" ({count} target(s))"),
                                    _ => String::new(),
                                }
                            ));
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

impl CodeQueryOccurrenceTarget {
    /// Human-readable detail lines; an empty vector for `none` so a
    /// non-reference row renders as one line.
    pub fn render_detail_lines(&self) -> Vec<String> {
        match self {
            Self::None => Vec::new(),
            Self::Resolved { units } => units
                .iter()
                .map(|unit| format!("-> {} [{}] {}", unit.fq_name, unit.kind, unit.path))
                .collect(),
            Self::Lexical { name, kind, range } => vec![format!(
                "-> lexical binder `{name}` [{kind}] at line {}",
                range.start_line
            )],
            Self::Unresolved { status } => vec![format!("-> unresolved ({status})")],
        }
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
