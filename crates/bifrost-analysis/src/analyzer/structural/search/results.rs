//! The CodeQuery result/diagnostic type contract: the public and
//! `pub(crate)` types rendered by the query engine and consumed by
//! `src/lsp/server.rs`, `src/analyzer/policy/evaluator.rs`, and
//! `structural/execution/` -- moved verbatim out of `search.rs` (#1057
//! follow-up split), together with the small self-contained impls that
//! only reference these contract types.

use super::*;
use crate::analyzer::structural::query::QueryValueKind;

mod diagnostics;
mod environment;
mod provenance;
mod render;
mod rows;
mod semantic;
mod sites;

pub use diagnostics::*;
pub use environment::*;
pub use provenance::*;
pub use rows::*;
pub use semantic::*;
pub use sites::*;

fn is_false(value: &bool) -> bool {
    !*value
}

fn format_branch_path(branch: &[usize]) -> String {
    branch
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

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
    ReceiverOutcome {
        #[serde(flatten)]
        value: Box<CodeQueryReceiverOutcome>,
    },
    ReceiverEvidence {
        #[serde(flatten)]
        value: Box<CodeQueryReceiverEvidence>,
    },
    CallShape {
        #[serde(flatten)]
        value: Box<CodeQueryCallShape>,
    },
    CallArgumentGroup {
        #[serde(flatten)]
        value: Box<CodeQueryCallArgumentGroup>,
    },
    CallArgument {
        #[serde(flatten)]
        value: Box<CodeQueryCallShapeArgument>,
    },
    MemberSelection {
        #[serde(flatten)]
        value: Box<CodeQueryMemberSelection>,
    },
    DispatchOutcome {
        #[serde(flatten)]
        value: Box<CodeQueryDispatchOutcome>,
    },
    DispatchTarget {
        #[serde(flatten)]
        value: Box<CodeQueryDispatchTarget>,
    },
    MemberFamily {
        #[serde(flatten)]
        value: Box<CodeQueryMemberFamily>,
    },
    MemberFamilyEdge {
        #[serde(flatten)]
        value: Box<CodeQueryMemberFamilyEdge>,
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
    CandidateHop {
        #[serde(flatten)]
        value: Box<CodeQueryCandidateHop>,
    },
    GenerationSite {
        #[serde(flatten)]
        value: Box<CodeQueryGenerationSite>,
    },
    Export {
        #[serde(flatten)]
        value: Box<CodeQueryExport>,
    },
    DeclarationState {
        #[serde(flatten)]
        value: Box<CodeQueryDeclarationState>,
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
