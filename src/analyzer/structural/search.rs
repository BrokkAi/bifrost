//! Workspace-level execution of a structural query (`query_code`): scope by
//! path globs and languages, derive the planner's positive anchors and query
//! requirements, run the matcher over deterministic candidates until `limit+1`
//! global matches prove truncation (facts come from the per-analyzer cache,
//! extraction happens on miss from in-memory source), then render the first
//! `limit` matches with captures, enclosing symbols, and capability
//! diagnostics.

use super::execution::plan::{
    LogicalQueryOperator, LogicalQueryPlan, PhysicalQueryNodeId, PhysicalQueryOperator,
    PhysicalQueryPlan,
};
use super::execution::profile::{
    QueryExecutionProfile, QueryOperatorDisposition, QueryOperatorProfile,
};
use super::facts::{FileFacts, Span};
use super::kinds::{NormalizedKind, Role};
use super::matcher::FactMatch;
use super::planner::QueryPlan;
use super::query::schema::{reference_kind_label, usage_proof_label};
use super::query::{
    CallInputSelector, CallSiteTraversalFilter, CallTraversalFilter, CodeQuery,
    CodeQueryResultDetail, CodeQuerySeed, HierarchyTraversal, QueryStep, ReferenceTraversalFilter,
    SetOperator,
};
use crate::analyzer::reference_candidates::{
    ReferenceCandidateRanges, reference_candidate_ranges, reference_candidate_ranges_cancellable,
};
use crate::analyzer::structural::capabilities::QueryFeature;
#[cfg(test)]
use crate::analyzer::usages::CallArgument;
use crate::analyzer::usages::get_definition::{
    CallSyntaxKind, DefinitionLookupOutcome, DefinitionLookupRequest, DefinitionLookupStatus,
    parse_tree_for_language, resolve_definition_batch_with_source,
    resolve_definition_batch_with_source_and_cancellation,
};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverValue,
};
use crate::analyzer::usages::receiver_query::{
    ReceiverQueryAnalysis, ReceiverQueryInput, ReceiverQueryOperation, ReceiverQueryReport,
    ReceiverQueryService,
};
use crate::analyzer::usages::{
    CallBindingCache, CallBindingStatus, CallRelationDiagnostic, CallRelationDiagnosticCode,
    CallRelationLimits, CallRelationResult, CallRelationService, CallSite, DEFAULT_MAX_FILES,
    ExplicitCandidateProvider, FuzzyResult, ReferenceHit, ReferenceKind, UsageFinder, UsageHit,
    UsageHitKind, UsageProof, bind_call_site_arguments,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::compact_graph::CompactDirectedGraph;
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

/// Longest match/capture snippet reported inline; full content is always
/// reachable via the returned line range.
const SNIPPET_MAX_CHARS: usize = 160;
const MAX_SCANNED_FILES: usize = 20_000;
const MAX_SCANNED_SOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_FACT_NODES: usize = 2_000_000;
const MAX_PIPELINE_ROWS: usize = 50_000;
const MAX_PROVENANCE_TRACES: usize = 16;
const BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD: usize = 100;

#[derive(Debug, Serialize)]
pub struct CodeQueryResult {
    pub results: Vec<CodeQueryResultItem>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<CodeQueryDiagnostic>,
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

/// A match found before rendering, held until the rendering pass (which
/// truncates at `limit` and does enclosing-symbol lookups).
type PendingMatch = (Language, ProjectFile, Arc<FileFacts>, FactMatch);

#[derive(Debug)]
struct SeedMatch {
    language: Language,
    file: ProjectFile,
    facts: Arc<FileFacts>,
    fact_match: FactMatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeclarationValue {
    unit: CodeUnit,
    range: Range,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReferenceSiteValue {
    file: ProjectFile,
    range: Range,
    target: DeclarationValue,
    enclosing: Option<DeclarationValue>,
    usage_kind: UsageHitKind,
    proof: UsageProof,
    reference_kind: Option<ReferenceKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallSiteValue(CallSite, CallBindingStatus);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ExpressionInput {
    Receiver,
    Parameter { index: usize, name: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExpressionSiteValue {
    call_site: CallSiteValue,
    range: Range,
    input: ExpressionInput,
}

#[derive(Debug, Clone)]
struct ReceiverAnalysisValue {
    report: ReceiverQueryReport,
    capture: Option<String>,
}

#[derive(Default)]
struct IndexedDeclarations {
    by_file: HashMap<ProjectFile, BTreeSet<CodeUnit>>,
    by_unit: HashMap<CodeUnit, Option<DeclarationValue>>,
    owner_by_member: HashMap<CodeUnit, CodeUnit>,
}

impl IndexedDeclarations {
    fn get(&mut self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<DeclarationValue> {
        if let Some(value) = self.by_unit.get(unit) {
            return value.clone();
        }

        let value = if unit.is_synthetic() || unit.is_file_scope() {
            None
        } else {
            let declarations = self
                .by_file
                .entry(unit.source().clone())
                .or_insert_with(|| analyzer.declarations(unit.source()));
            declarations.contains(unit).then(|| {
                analyzer
                    .ranges_of(unit)
                    .into_iter()
                    .min_by_key(primary_range_key)
                    .map(|range| DeclarationValue {
                        unit: unit.clone(),
                        range,
                    })
            })?
        };
        self.by_unit.insert(unit.clone(), value.clone());
        value
    }

    fn record_owner(&mut self, member: &CodeUnit, owner: &CodeUnit) {
        self.owner_by_member
            .entry(member.clone())
            .or_insert_with(|| owner.clone());
    }

    fn owner_of(
        &mut self,
        analyzer: &dyn IAnalyzer,
        member: &CodeUnit,
        work: &mut usize,
        max_work: usize,
    ) -> (Option<DeclarationValue>, bool) {
        if let Some(owner) = self.owner_by_member.get(member).cloned() {
            if *work >= max_work {
                return (None, true);
            }
            *work += 1;
            return (self.get(analyzer, &owner), false);
        }

        let owner = {
            let declarations = self
                .by_file
                .entry(member.source().clone())
                .or_insert_with(|| analyzer.declarations(member.source()));
            let mut found = None;
            'owners: for candidate in declarations.iter() {
                if *work >= max_work {
                    return (None, true);
                }
                *work += 1;
                if !is_type_declaration(analyzer, candidate) {
                    continue;
                }
                for child in analyzer.direct_children(candidate) {
                    if *work >= max_work {
                        return (None, true);
                    }
                    *work += 1;
                    if &child == member {
                        found = Some(candidate.clone());
                        break 'owners;
                    }
                }
            }
            found
        };
        if let Some(owner) = owner {
            self.record_owner(member, &owner);
            return (self.get(analyzer, &owner), false);
        }
        (None, false)
    }
}

fn primary_range_key(range: &Range) -> (usize, usize, usize, usize) {
    (
        range.start_line,
        range.start_byte,
        range.end_line,
        range.end_byte,
    )
}

struct PipelineExpansion {
    value: PipelineValue,
    trace: Vec<(PipelineTraceValue, Option<PipelineVia>)>,
    budgeted: bool,
}

#[derive(Debug, Clone)]
enum PipelineValue {
    StructuralMatch(Arc<SeedMatch>),
    Declaration(DeclarationValue),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    ReceiverAnalysis(ReceiverAnalysisValue),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PipelineKey {
    StructuralMatch(ProjectFile, u32),
    Declaration(DeclarationValue),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    ReceiverAnalysis(ReceiverQueryOperation, ProjectFile, Range),
}

impl PipelineValue {
    fn key(&self) -> PipelineKey {
        match self {
            Self::StructuralMatch(seed) => {
                PipelineKey::StructuralMatch(seed.file.clone(), seed.fact_match.node)
            }
            Self::Declaration(declaration) => PipelineKey::Declaration(declaration.clone()),
            Self::File(file) => PipelineKey::File(file.clone()),
            Self::ReferenceSite(site) => PipelineKey::ReferenceSite(site.clone()),
            Self::CallSite(site) => PipelineKey::CallSite(site.clone()),
            Self::ExpressionSite(site) => PipelineKey::ExpressionSite(site.clone()),
            Self::ReceiverAnalysis(value) => PipelineKey::ReceiverAnalysis(
                value.report.operation,
                value.report.site.file.clone(),
                value.report.site.range,
            ),
        }
    }
}

#[derive(Debug, Clone)]
struct PipelineTrace {
    branch: Vec<usize>,
    seed: Arc<SeedMatch>,
    steps: Vec<PipelineTraceStep>,
}

#[derive(Debug, Clone)]
struct PipelineTraceStep {
    op: QueryStep,
    value: PipelineTraceValue,
    via: Option<PipelineVia>,
}

#[derive(Debug, Clone)]
enum PipelineTraceValue {
    Declaration(DeclarationValue),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
    ReceiverAnalysis(ReceiverAnalysisValue),
}

#[derive(Debug, Clone)]
enum PipelineVia {
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
}

#[derive(Default)]
struct ReferenceTraversalCache {
    inbound: HashMap<CodeUnit, Vec<ReferenceHit>>,
    outbound: HashMap<ProjectFile, Vec<ReferenceHit>>,
    reported_inbound: HashSet<CodeUnit>,
}

#[derive(Default)]
struct CallTraversalCache {
    incoming: HashMap<CodeUnit, CallRelationResult>,
    outgoing: HashMap<CodeUnit, CallRelationResult>,
    reported_incoming: HashSet<CodeUnit>,
    reported_outgoing: HashSet<CodeUnit>,
    bindings: CallBindingCache,
}

#[derive(Debug, Clone)]
struct PipelineRow {
    value: PipelineValue,
    traces: Vec<PipelineTrace>,
    provenance_truncated: bool,
}

struct CachedSourceCoordinates {
    source: String,
    line_starts: Vec<usize>,
}

#[derive(Default)]
struct PipelineRenderCache {
    sources: HashMap<ProjectFile, Option<CachedSourceCoordinates>>,
    conflicting_sources: HashSet<ProjectFile>,
    declaration_ranges: HashMap<DeclarationValue, Option<CodeQueryRange>>,
    enclosing_units: HashMap<(ProjectFile, usize, usize), Option<CodeUnit>>,
    source_loads_sealed: bool,
}

impl PipelineRenderCache {
    fn retain_source_snapshot(&mut self, file: &ProjectFile, source: &str) -> bool {
        if self.conflicting_sources.contains(file) {
            return false;
        }
        if let Some(existing) = self.sources.get(file) {
            match existing {
                Some(coordinates) if coordinates.source == source => return true,
                Some(_) => {
                    // Conflicting snapshots cannot support exact evidence or
                    // rendering. Retain the negative cache entry so a later
                    // renderer cannot silently hydrate a third source version.
                    self.sources.insert(file.clone(), None);
                    self.conflicting_sources.insert(file.clone());
                    return false;
                }
                None => {
                    // A held fact snapshot has already been charged by seed
                    // execution and may safely replace an earlier negative
                    // hydration entry.
                    self.sources.remove(file);
                }
            }
        }
        self.sources.insert(
            file.clone(),
            Some(CachedSourceCoordinates {
                line_starts: compute_line_starts(source),
                source: source.to_string(),
            }),
        );
        true
    }

    fn coordinates_for<F>(
        &mut self,
        file: &ProjectFile,
        load: F,
    ) -> Option<&CachedSourceCoordinates>
    where
        F: FnOnce() -> Option<String>,
    {
        if self.source_loads_sealed && !self.sources.contains_key(file) {
            self.sources.insert(file.clone(), None);
        }
        self.sources
            .entry(file.clone())
            .or_insert_with(|| {
                load().map(|source| CachedSourceCoordinates {
                    line_starts: compute_line_starts(&source),
                    source,
                })
            })
            .as_ref()
    }

    fn retain_loaded_source(&mut self, file: &ProjectFile, source: Option<String>) {
        self.sources.entry(file.clone()).or_insert_with(|| {
            source.map(|source| CachedSourceCoordinates {
                line_starts: compute_line_starts(&source),
                source,
            })
        });
    }

    fn seal_source_loads(&mut self) {
        self.source_loads_sealed = true;
    }

    fn source_snapshot(&self, file: &ProjectFile) -> Option<&str> {
        self.sources
            .get(file)
            .and_then(Option::as_ref)
            .map(|coordinates| coordinates.source.as_str())
    }

    fn range_for_declaration(
        &mut self,
        analyzer: &dyn IAnalyzer,
        declaration: &DeclarationValue,
    ) -> Option<CodeQueryRange> {
        if let Some(range) = self.declaration_ranges.get(declaration) {
            return *range;
        }

        let file = declaration.unit.source();
        let range = {
            self.coordinates_for(file, || analyzer.indexed_source(file))
                .map(|coordinates| {
                    range_for_offsets(
                        &coordinates.source,
                        &coordinates.line_starts,
                        declaration.range.start_byte,
                        declaration.range.end_byte,
                    )
                })
        };
        self.declaration_ranges.insert(declaration.clone(), range);
        range
    }

    fn enclosing_unit_for_lines(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.enclosing_units
            .entry((file.clone(), start_line, end_line))
            .or_insert_with(|| analyzer.enclosing_code_unit_for_lines(file, start_line, end_line))
            .clone()
    }
}

#[derive(Debug, Default)]
struct DirectImportGraph {
    forward: HashMap<ProjectFile, Vec<ProjectFile>>,
    compact: Option<CompactDirectedGraph<ProjectFile>>,
    unsupported: HashSet<ProjectFile>,
    all_files: Vec<ProjectFile>,
    analyzed: HashSet<ProjectFile>,
    resolved_files: usize,
    resolved_edges: usize,
    complete: bool,
}

impl DirectImportGraph {
    fn new(analyzer: &dyn IAnalyzer) -> Self {
        let mut all_files: Vec<_> = analyzer.analyzed_files().into_iter().collect();
        all_files.sort_by_key(rel_path_string);
        let analyzed = all_files.iter().cloned().collect();
        Self {
            all_files,
            analyzed,
            ..Self::default()
        }
    }

    fn freeze(&mut self) {
        if self.compact.is_some() {
            return;
        }
        let nodes = self.all_files.clone();
        let index_by_file: HashMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(index, file)| (file.clone(), index as u32))
            .collect();
        let mut edges = Vec::with_capacity(self.resolved_edges);
        for (source, targets) in &self.forward {
            let Some(source) = index_by_file.get(source).copied() else {
                continue;
            };
            edges.extend(targets.iter().filter_map(|target| {
                index_by_file
                    .get(target)
                    .copied()
                    .map(|target| (source, target))
            }));
        }
        self.compact = Some(CompactDirectedGraph::from_indexed_nodes(
            nodes,
            index_by_file,
            edges,
        ));
    }

    fn imports_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        if let Some(compact) = &self.compact {
            return compact
                .node_id(file)
                .into_iter()
                .flat_map(|source| compact.outgoing(source))
                .map(|target| compact.nodes()[*target as usize].clone())
                .collect();
        }
        self.forward.get(file).cloned().unwrap_or_default()
    }

    fn importers_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        let Some(compact) = &self.compact else {
            return Vec::new();
        };
        compact
            .node_id(file)
            .into_iter()
            .flat_map(|target| compact.incoming(target))
            .map(|source| compact.nodes()[*source as usize].clone())
            .collect()
    }
}

/// Run `query` across every language provider the analyzer exposes.
pub fn execute(analyzer: &dyn IAnalyzer, query: &CodeQuery) -> CodeQueryResult {
    execute_with_limits(analyzer, query, CodeQueryExecutionLimits::default())
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

#[derive(Debug, Default, Clone, Copy)]
struct CodeQueryExecutionBudget {
    scanned_files: usize,
    scanned_source_bytes: usize,
    fact_nodes: usize,
    examined_references: usize,
    pipeline_rows: usize,
    provenance_steps: usize,
}

#[derive(Clone)]
struct CachedSeedExecution {
    rows: Vec<PipelineRow>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    truncated: bool,
}

struct QueryExecutionState<'a> {
    analyzer: &'a dyn IAnalyzer,
    cancellation: Option<&'a CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    budget: CodeQueryExecutionBudget,
    seed_cache: HashMap<String, CachedSeedExecution>,
    indexed_declarations: IndexedDeclarations,
    reference_cache: ReferenceTraversalCache,
    call_cache: CallTraversalCache,
    import_graph: Option<DirectImportGraph>,
    profile: Option<QueryExecutionProfile>,
}

struct PlanExecution {
    rows: Vec<PipelineRow>,
    truncated: bool,
    cancelled: bool,
    /// An intermediate authored pipeline step exhausted its budget, so the
    /// remaining steps in that same suffix must not run.
    pipeline_halted: bool,
}

#[doc(hidden)]
pub fn execute_with_limits(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResult {
    execute_code_query_detailed(analyzer, query, limits, None).result
}

pub(crate) fn execute_with_cancellation(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResult {
    execute_code_query_detailed(analyzer, query, limits, Some(cancellation)).result
}

pub(crate) fn execute_code_query_detailed(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> DetailedCodeQueryResult {
    execute_internal(analyzer, query, limits, cancellation, None, false)
}

#[cfg(test)]
fn execute_with_receiver_budget_for_test(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    receiver_budget: ReceiverAnalysisBudget,
) -> CodeQueryResult {
    execute_internal(
        analyzer,
        query,
        CodeQueryExecutionLimits::default(),
        None,
        Some(receiver_budget),
        false,
    )
    .result
}

fn execute_internal(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    capture_profile: bool,
) -> DetailedCodeQueryResult {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return detailed_result_without_evidence(
            cancelled_query_result(),
            CodeQueryExecutionBudget::default(),
        );
    }
    let logical_plan = match LogicalQueryPlan::lower(query) {
        Ok(plan) => plan,
        Err(error) => {
            return detailed_result_without_evidence(
                CodeQueryResult {
                    results: Vec::new(),
                    truncated: false,
                    diagnostics: vec![CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::InvalidPlan,
                        impact: CodeQueryDiagnosticImpact::Invalid,
                        branch: Vec::new(),
                        language: "workspace",
                        message: error.to_string(),
                    }],
                },
                CodeQueryExecutionBudget::default(),
            );
        }
    };
    let physical_plan = PhysicalQueryPlan::select(logical_plan);
    let mut diagnostics = Vec::new();
    let mut state = QueryExecutionState {
        analyzer,
        cancellation,
        receiver_budget_override,
        budget: CodeQueryExecutionBudget::default(),
        seed_cache: HashMap::default(),
        indexed_declarations: IndexedDeclarations::default(),
        reference_cache: ReferenceTraversalCache::default(),
        call_cache: CallTraversalCache::default(),
        import_graph: None,
        profile: capture_profile.then(|| QueryExecutionProfile::sequential(&physical_plan)),
    };
    let mut profile_branch = state.profile.as_ref().map(|_| Vec::new());
    let mut execution = execute_plan(
        &physical_plan,
        physical_plan.root(),
        &mut state,
        limits,
        None,
        &mut diagnostics,
        &mut profile_branch,
    );
    let mut cancelled = execution.cancelled;
    let mut truncated = execution.truncated;
    // Preserve the pre-composition response shape for a plain structural
    // query. Set plans retain their seed-only traces because the branch path
    // is meaningful provenance even when no semantic step follows the set.
    if query.seed().is_some() && query.plan.steps.is_empty() {
        for row in &mut execution.rows {
            row.traces.clear();
            row.provenance_truncated = false;
        }
    }
    if let Some(seed) = query.seed() {
        let plan = QueryPlan::for_query(seed);
        if should_report_broad_query(&plan, seed, &state.budget, truncated) {
            push_broad_query_diagnostic(&mut diagnostics, &state.budget);
        }
    }
    let mut render_cache = PipelineRenderCache::default();
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        cancelled = true;
        push_cancelled_diagnostic(&mut diagnostics);
    }
    let mut results = Vec::with_capacity(execution.rows.len());
    let mut evidence = Vec::with_capacity(execution.rows.len());
    for (result_index, row) in execution.rows.into_iter().enumerate() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            cancelled = true;
            truncated = true;
            push_cancelled_diagnostic(&mut diagnostics);
            break;
        }
        if retain_budgeted_pipeline_sources(
            analyzer,
            &row,
            &mut render_cache,
            &mut state.budget,
            limits,
            &mut diagnostics,
        ) {
            truncated = true;
        }
        render_cache.seal_source_loads();
        let terminal_source_file = terminal_source_file(&row.value);
        let retained_source =
            terminal_source_file.and_then(|file| render_cache.source_snapshot(file));
        let mut row_evidence =
            detailed_evidence_for_pipeline_value(result_index, &row.value, retained_source);
        row_evidence.provenance = detailed_provenance_for_row(&row, &render_cache);
        evidence.push(row_evidence);
        results.push(render_pipeline_item(
            analyzer,
            row,
            query.result_detail,
            &mut render_cache,
        ));
    }
    let work = execution_work(state.budget);
    let profile = state.profile;
    let detailed = DetailedCodeQueryResult {
        result: CodeQueryResult {
            results,
            truncated: truncated || cancelled,
            diagnostics,
        },
        work,
        evidence,
        profile,
    };
    detailed.assert_invariants();
    detailed
}

impl DetailedCodeQueryResult {
    fn assert_invariants(&self) {
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

fn detailed_result_without_evidence(
    result: CodeQueryResult,
    budget: CodeQueryExecutionBudget,
) -> DetailedCodeQueryResult {
    let detailed = DetailedCodeQueryResult {
        result,
        work: execution_work(budget),
        evidence: Vec::new(),
        profile: None,
    };
    detailed.assert_invariants();
    detailed
}

fn execution_work(budget: CodeQueryExecutionBudget) -> CodeQueryExecutionWork {
    let as_u64 = |value| u64::try_from(value).expect("usize fits in u64 on supported targets");
    CodeQueryExecutionWork {
        scanned_files: as_u64(budget.scanned_files),
        scanned_source_bytes: as_u64(budget.scanned_source_bytes),
        fact_nodes: as_u64(budget.fact_nodes),
        pipeline_rows: as_u64(budget.pipeline_rows),
        examined_references: as_u64(budget.examined_references),
    }
}

fn detailed_evidence_for_pipeline_value(
    result_index: usize,
    value: &PipelineValue,
    retained_source: Option<&str>,
) -> DetailedCodeQueryEvidence {
    match value {
        PipelineValue::StructuralMatch(seed) => {
            let fact = seed.facts.node(seed.fact_match.node);
            let span = fact.span();
            let byte_span = span.start_byte..span.end_byte;
            let path = rel_path_string(&seed.file);
            let stable_owner_candidate = canonical_ast_candidate(seed);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::StructuralMatch,
                key: DetailedCodeQueryKey::StructuralMatch {
                    kind: fact.kind.label().to_string(),
                    analyzer_id: Some(match_id(&path, fact.kind.label(), span)),
                },
                file: seed.file.clone(),
                source_slice_sha256: source_slice_sha256(seed.facts.source(), &byte_span),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Primary(
                    stable_owner_candidate.clone().map(|candidate| {
                        DetailedCodeQueryIdentityCandidate {
                            file: seed.file.clone(),
                            candidate,
                        }
                    }),
                ),
                stable_owner_candidate,
                provenance: Vec::new(),
            }
        }
        PipelineValue::Declaration(declaration) => {
            let file = declaration.unit.source().clone();
            let path = rel_path_string(&file);
            let kind = declaration.unit.kind().display_lowercase();
            let fq_name = declaration.unit.fq_name();
            let byte_span = range_byte_span(declaration.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::Declaration,
                key: DetailedCodeQueryKey::Declaration {
                    kind: kind.to_string(),
                    fq_name: fq_name.clone(),
                    analyzer_id: Some(declaration_id(&path, kind, &fq_name, declaration.range)),
                },
                file: file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Primary(
                    detailed_identity_candidate_for_unit(&declaration.unit),
                ),
                stable_owner_candidate: stable_owner_candidate_for_unit(&file, &declaration.unit),
                provenance: Vec::new(),
            }
        }
        PipelineValue::File(file) => DetailedCodeQueryEvidence {
            result_index,
            domain: DetailedCodeQueryDomain::File,
            key: DetailedCodeQueryKey::File,
            file: file.clone(),
            byte_span: None,
            identities: DetailedCodeQueryProvenanceIdentities::None,
            stable_owner_candidate: None,
            source_slice_sha256: None,
            provenance: Vec::new(),
        },
        PipelineValue::ReferenceSite(site) => {
            let target_path = rel_path_string(site.target.unit.source());
            let target_kind = site.target.unit.kind().display_lowercase();
            let target_fq_name = site.target.unit.fq_name();
            let byte_span = range_byte_span(site.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReferenceSite,
                key: DetailedCodeQueryKey::ReferenceSite {
                    target_id: Some(declaration_id(
                        &target_path,
                        target_kind,
                        &target_fq_name,
                        site.target.range,
                    )),
                    target_fq_name,
                },
                file: site.file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::ReferenceTarget(
                    detailed_identity_candidate_for_unit(&site.target.unit),
                ),
                stable_owner_candidate: site.enclosing.as_ref().and_then(|declaration| {
                    stable_owner_candidate_for_unit(&site.file, &declaration.unit)
                }),
                provenance: Vec::new(),
            }
        }
        PipelineValue::CallSite(site) => {
            let file = &site.0.file;
            let byte_span = range_byte_span(site.0.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::CallSite,
                key: DetailedCodeQueryKey::CallSite {
                    caller_fq_name: site.0.caller.fq_name(),
                    callee_fq_name: site.0.callee.fq_name(),
                },
                file: file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::Call {
                    caller: detailed_identity_candidate_for_unit(&site.0.caller),
                    callee: detailed_identity_candidate_for_unit(&site.0.callee),
                },
                stable_owner_candidate: stable_owner_candidate_for_unit(file, &site.0.caller),
                provenance: Vec::new(),
            }
        }
        PipelineValue::ExpressionSite(site) => {
            let file = &site.call_site.0.file;
            let byte_span = range_byte_span(site.range);
            let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ExpressionSite,
                key: DetailedCodeQueryKey::ExpressionSite {
                    input_kind: input_kind.to_string(),
                    parameter_index: parameter_index.map(|index| {
                        u32::try_from(index).expect("query parameter indexes fit in u32")
                    }),
                    parameter_name,
                },
                file: file.clone(),
                source_slice_sha256: retained_source
                    .and_then(|source| source_slice_sha256(source, &byte_span)),
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: stable_owner_candidate_for_unit(
                    file,
                    &site.call_site.0.caller,
                ),
                provenance: Vec::new(),
            }
        }
        PipelineValue::ReceiverAnalysis(value) => {
            let site = &value.report.site;
            let byte_span = range_byte_span(site.range);
            DetailedCodeQueryEvidence {
                result_index,
                domain: DetailedCodeQueryDomain::ReceiverAnalysis,
                key: DetailedCodeQueryKey::ReceiverAnalysis {
                    analysis_kind: value.report.operation.as_str().to_string(),
                    outcome: receiver_query_outcome_label(&value.report.analysis).to_string(),
                    capture: value.capture.clone(),
                },
                file: site.file.clone(),
                source_slice_sha256: None,
                byte_span: Some(byte_span),
                identities: DetailedCodeQueryProvenanceIdentities::None,
                stable_owner_candidate: None,
                provenance: Vec::new(),
            }
        }
    }
}

fn range_byte_span(range: Range) -> std::ops::Range<usize> {
    range.start_byte..range.end_byte
}

fn source_slice_sha256(source: &str, byte_span: &std::ops::Range<usize>) -> Option<[u8; 32]> {
    source
        .as_bytes()
        .get(byte_span.clone())
        .map(|bytes| Sha256::digest(bytes).into())
}

fn terminal_source_file(value: &PipelineValue) -> Option<&ProjectFile> {
    match value {
        PipelineValue::StructuralMatch(seed) => Some(&seed.file),
        PipelineValue::Declaration(declaration) => Some(declaration.unit.source()),
        PipelineValue::ReferenceSite(site) => Some(&site.file),
        PipelineValue::CallSite(site) => Some(&site.0.file),
        PipelineValue::ExpressionSite(site) => Some(&site.call_site.0.file),
        PipelineValue::File(_) | PipelineValue::ReceiverAnalysis(_) => None,
    }
}

/// Retain every source that full-detail terminal and provenance rendering can
/// consult, before rendering is sealed against untracked cache misses.
fn retain_budgeted_pipeline_sources(
    analyzer: &dyn IAnalyzer,
    row: &PipelineRow,
    cache: &mut PipelineRenderCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    let mut files = BTreeSet::new();
    let mut exhausted = false;
    collect_pipeline_value_source_files(&row.value, &mut files);
    if let PipelineValue::StructuralMatch(seed) = &row.value {
        exhausted |= retain_held_source_snapshot(
            cache,
            &seed.file,
            seed.facts.source(),
            seed.language,
            Vec::new(),
            diagnostics,
        );
    }
    for trace in &row.traces {
        exhausted |= retain_held_source_snapshot(
            cache,
            &trace.seed.file,
            trace.seed.facts.source(),
            trace.seed.language,
            trace.branch.clone(),
            diagnostics,
        );
        for step in &trace.steps {
            collect_trace_value_source_files(&step.value, &mut files);
            if let Some(via) = &step.via {
                collect_via_source_files(via, &mut files);
            }
        }
    }

    for file in files {
        exhausted |=
            retain_budgeted_source_snapshot(analyzer, &file, cache, budget, limits, diagnostics);
    }
    exhausted
}

fn retain_held_source_snapshot(
    cache: &mut PipelineRenderCache,
    file: &ProjectFile,
    source: &str,
    language: Language,
    branch: Vec<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    let conflict_before = cache.conflicting_sources.contains(file);
    if cache.retain_source_snapshot(file, source) {
        return false;
    }
    if !conflict_before {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch,
            language: language.config_label(),
            message: format!(
                "conflicting analyzer-generation source snapshots for {} prevent exact result evidence",
                rel_path_string(file)
            ),
        });
    }
    true
}

fn collect_pipeline_value_source_files(value: &PipelineValue, files: &mut BTreeSet<ProjectFile>) {
    match value {
        PipelineValue::StructuralMatch(seed) => {
            files.insert(seed.file.clone());
        }
        PipelineValue::Declaration(declaration) => {
            files.insert(declaration.unit.source().clone());
        }
        PipelineValue::File(_) => {}
        PipelineValue::ReferenceSite(site) => collect_reference_source_files(site, files),
        PipelineValue::CallSite(site) => collect_call_source_files(site, files),
        PipelineValue::ExpressionSite(site) => collect_call_source_files(&site.call_site, files),
        PipelineValue::ReceiverAnalysis(value) => collect_receiver_source_files(value, files),
    }
}

fn collect_trace_value_source_files(value: &PipelineTraceValue, files: &mut BTreeSet<ProjectFile>) {
    match value {
        PipelineTraceValue::Declaration(declaration) => {
            files.insert(declaration.unit.source().clone());
        }
        PipelineTraceValue::File(_) => {}
        PipelineTraceValue::ReferenceSite(site) => collect_reference_source_files(site, files),
        PipelineTraceValue::CallSite(site) => collect_call_source_files(site, files),
        PipelineTraceValue::ExpressionSite(site) => {
            collect_call_source_files(&site.call_site, files);
        }
        PipelineTraceValue::ReceiverAnalysis(value) => collect_receiver_source_files(value, files),
    }
}

fn collect_via_source_files(via: &PipelineVia, files: &mut BTreeSet<ProjectFile>) {
    match via {
        PipelineVia::ReferenceSite(site) => collect_reference_source_files(site, files),
        PipelineVia::CallSite(site) => collect_call_source_files(site, files),
    }
}

fn collect_reference_source_files(site: &ReferenceSiteValue, files: &mut BTreeSet<ProjectFile>) {
    files.insert(site.file.clone());
    files.insert(site.target.unit.source().clone());
    if let Some(enclosing) = &site.enclosing {
        files.insert(enclosing.unit.source().clone());
    }
}

fn collect_call_source_files(site: &CallSiteValue, files: &mut BTreeSet<ProjectFile>) {
    files.insert(site.0.file.clone());
    files.insert(site.0.caller.source().clone());
    files.insert(site.0.callee.source().clone());
}

fn collect_receiver_source_files(value: &ReceiverAnalysisValue, files: &mut BTreeSet<ProjectFile>) {
    files.insert(value.report.site.file.clone());
    match &value.report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => {
            let mut stack = outcome.values().into_iter().flatten().collect::<Vec<_>>();
            while let Some(value) = stack.pop() {
                match value {
                    ReceiverValue::AllocationSite { ty, file, .. } => {
                        files.insert(ty.source().clone());
                        files.insert(file.clone());
                    }
                    ReceiverValue::InstanceType(unit)
                    | ReceiverValue::ClassOrStaticObject(unit)
                    | ReceiverValue::ModuleOrExportObject(unit)
                    | ReceiverValue::CurrentReceiver(unit) => {
                        files.insert(unit.source().clone());
                    }
                    ReceiverValue::FactoryReturn { factory, value } => {
                        files.insert(factory.source().clone());
                        stack.push(value);
                    }
                }
            }
        }
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            for unit in outcome.values().into_iter().flatten() {
                files.insert(unit.source().clone());
            }
        }
    }
}

/// Hydrate one source through the execution budget.
///
/// Returns `true` when a hard query limit prevented retaining the snapshot.
/// The cache receives a negative entry in that case so public full-detail
/// rendering cannot retry the same read outside the tracker.
fn retain_budgeted_source_snapshot(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cache: &mut PipelineRenderCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> bool {
    if cache.sources.contains_key(file) {
        return false;
    }

    let mut projected = *budget;
    projected.scanned_files = projected.scanned_files.saturating_add(1);
    if projected.scanned_files > limits.max_scanned_files {
        cache.retain_loaded_source(file, None);
        push_budget_diagnostic(diagnostics, &projected);
        return true;
    }

    let source = analyzer.indexed_source(file);
    projected.scanned_source_bytes = projected
        .scanned_source_bytes
        .saturating_add(source.as_ref().map_or(0, String::len));
    if projected.scanned_source_bytes > limits.max_scanned_source_bytes {
        cache.retain_loaded_source(file, None);
        push_budget_diagnostic(diagnostics, &projected);
        return true;
    }

    budget.scanned_files = projected.scanned_files;
    budget.scanned_source_bytes = projected.scanned_source_bytes;
    cache.retain_loaded_source(file, source);
    false
}

fn detailed_provenance_for_row(
    row: &PipelineRow,
    cache: &PipelineRenderCache,
) -> Vec<DetailedCodeQueryProvenanceEvidence> {
    row.traces
        .iter()
        .map(|trace| DetailedCodeQueryProvenanceEvidence {
            branch: trace.branch.clone(),
            seed: detailed_seed_provenance_ref(&trace.seed),
            steps: trace
                .steps
                .iter()
                .map(|step| DetailedCodeQueryProvenanceStepEvidence {
                    op: step.op.label().to_string(),
                    result: detailed_trace_provenance_ref(&step.value, cache),
                    via: step
                        .via
                        .as_ref()
                        .map(|via| detailed_via_provenance_ref(via, cache)),
                })
                .collect(),
        })
        .collect()
}

fn detailed_seed_provenance_ref(seed: &SeedMatch) -> DetailedCodeQueryProvenanceRefEvidence {
    let fact = seed.facts.node(seed.fact_match.node);
    let span = fact.span();
    let byte_span = span.start_byte..span.end_byte;
    let path = rel_path_string(&seed.file);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::StructuralMatch,
        key: DetailedCodeQueryKey::StructuralMatch {
            kind: fact.kind.label().to_string(),
            analyzer_id: Some(match_id(&path, fact.kind.label(), span)),
        },
        file: seed.file.clone(),
        source_slice_sha256: source_slice_sha256(seed.facts.source(), &byte_span),
        byte_span: Some(byte_span),
        display_range: Some(range_for_span(&seed.facts, fact.span())),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(
            canonical_ast_candidate(seed).map(|candidate| DetailedCodeQueryIdentityCandidate {
                file: seed.file.clone(),
                candidate,
            }),
        ),
    }
}

fn detailed_trace_provenance_ref(
    value: &PipelineTraceValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    match value {
        PipelineTraceValue::Declaration(value) => detailed_declaration_provenance_ref(value, cache),
        PipelineTraceValue::File(file) => DetailedCodeQueryProvenanceRefEvidence {
            domain: DetailedCodeQueryDomain::File,
            key: DetailedCodeQueryKey::File,
            file: file.clone(),
            byte_span: None,
            display_range: None,
            identities: DetailedCodeQueryProvenanceIdentities::None,
            source_slice_sha256: None,
        },
        PipelineTraceValue::ReferenceSite(value) => detailed_reference_provenance_ref(value, cache),
        PipelineTraceValue::CallSite(value) => detailed_call_provenance_ref(value, cache),
        PipelineTraceValue::ExpressionSite(value) => {
            detailed_expression_provenance_ref(value, cache)
        }
        PipelineTraceValue::ReceiverAnalysis(value) => {
            detailed_receiver_provenance_ref(value, cache)
        }
    }
}

fn detailed_via_provenance_ref(
    value: &PipelineVia,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    match value {
        PipelineVia::ReferenceSite(value) => detailed_reference_provenance_ref(value, cache),
        PipelineVia::CallSite(value) => detailed_call_provenance_ref(value, cache),
    }
}

fn detailed_declaration_provenance_ref(
    declaration: &DeclarationValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let file = declaration.unit.source().clone();
    let path = rel_path_string(&file);
    let kind = declaration.unit.kind().display_lowercase();
    let fq_name = declaration.unit.fq_name();
    let byte_span = range_byte_span(declaration.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::Declaration,
        key: DetailedCodeQueryKey::Declaration {
            kind: kind.to_string(),
            fq_name: fq_name.clone(),
            analyzer_id: Some(declaration_id(&path, kind, &fq_name, declaration.range)),
        },
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, &file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, &file, declaration.range),
        identities: DetailedCodeQueryProvenanceIdentities::Primary(
            detailed_identity_candidate_for_unit(&declaration.unit),
        ),
    }
}

fn detailed_reference_provenance_ref(
    site: &ReferenceSiteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let target_path = rel_path_string(site.target.unit.source());
    let target_kind = site.target.unit.kind().display_lowercase();
    let target_fq_name = site.target.unit.fq_name();
    let byte_span = range_byte_span(site.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::ReferenceSite,
        key: DetailedCodeQueryKey::ReferenceSite {
            target_id: Some(declaration_id(
                &target_path,
                target_kind,
                &target_fq_name,
                site.target.range,
            )),
            target_fq_name,
        },
        file: site.file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, &site.file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, &site.file, site.range),
        identities: DetailedCodeQueryProvenanceIdentities::ReferenceTarget(
            detailed_identity_candidate_for_unit(&site.target.unit),
        ),
    }
}

fn detailed_call_provenance_ref(
    site: &CallSiteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let file = &site.0.file;
    let byte_span = range_byte_span(site.0.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::CallSite,
        key: DetailedCodeQueryKey::CallSite {
            caller_fq_name: site.0.caller.fq_name(),
            callee_fq_name: site.0.callee.fq_name(),
        },
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, file, site.0.range),
        identities: DetailedCodeQueryProvenanceIdentities::Call {
            caller: detailed_identity_candidate_for_unit(&site.0.caller),
            callee: detailed_identity_candidate_for_unit(&site.0.callee),
        },
    }
}

fn detailed_expression_provenance_ref(
    site: &ExpressionSiteValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let file = &site.call_site.0.file;
    let byte_span = range_byte_span(site.range);
    let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::ExpressionSite,
        key: DetailedCodeQueryKey::ExpressionSite {
            input_kind: input_kind.to_string(),
            parameter_index: parameter_index
                .map(|index| u32::try_from(index).expect("query parameter indexes fit in u32")),
            parameter_name,
        },
        file: file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, file, site.range),
        identities: DetailedCodeQueryProvenanceIdentities::None,
    }
}

fn detailed_receiver_provenance_ref(
    value: &ReceiverAnalysisValue,
    cache: &PipelineRenderCache,
) -> DetailedCodeQueryProvenanceRefEvidence {
    let site = &value.report.site;
    let byte_span = range_byte_span(site.range);
    DetailedCodeQueryProvenanceRefEvidence {
        domain: DetailedCodeQueryDomain::ReceiverAnalysis,
        key: DetailedCodeQueryKey::ReceiverAnalysis {
            analysis_kind: value.report.operation.as_str().to_string(),
            outcome: receiver_query_outcome_label(&value.report.analysis).to_string(),
            capture: value.capture.clone(),
        },
        file: site.file.clone(),
        source_slice_sha256: cached_source_slice_sha256(cache, &site.file, &byte_span),
        byte_span: Some(byte_span),
        display_range: cached_display_range(cache, &site.file, site.range),
        identities: DetailedCodeQueryProvenanceIdentities::None,
    }
}

fn cached_source_slice_sha256(
    cache: &PipelineRenderCache,
    file: &ProjectFile,
    byte_span: &std::ops::Range<usize>,
) -> Option<[u8; 32]> {
    cache
        .source_snapshot(file)
        .and_then(|source| source_slice_sha256(source, byte_span))
}

fn cached_display_range(
    cache: &PipelineRenderCache,
    file: &ProjectFile,
    range: Range,
) -> Option<CodeQueryRange> {
    let coordinates = cache.sources.get(file)?.as_ref()?;
    Some(range_for_offsets(
        &coordinates.source,
        &coordinates.line_starts,
        range.start_byte,
        range.end_byte,
    ))
}

fn detailed_identity_candidate_for_unit(
    unit: &CodeUnit,
) -> Option<DetailedCodeQueryIdentityCandidate> {
    stable_identity_candidate_for_unit(unit).map(|candidate| DetailedCodeQueryIdentityCandidate {
        file: unit.source().clone(),
        candidate,
    })
}

fn stable_owner_candidate_for_unit(
    evidence_file: &ProjectFile,
    unit: &CodeUnit,
) -> Option<CodeQueryStableOwnerCandidate> {
    if unit.source() != evidence_file {
        return None;
    }
    stable_identity_candidate_for_unit(unit)
}

fn stable_identity_candidate_for_unit(unit: &CodeUnit) -> Option<CodeQueryStableOwnerCandidate> {
    if unit.is_synthetic() || unit.is_file_scope() || unit.is_anonymous() {
        return None;
    }
    let kind = unit.kind().display_lowercase();
    let mut semantic_key = format!("{kind}:{}", unit.fq_name());
    if let Some(signature) = unit.signature() {
        semantic_key.push_str(signature);
    }
    Some(CodeQueryStableOwnerCandidate {
        namespace: crate::analyzer::common::language_for_file(unit.source())
            .config_label()
            .to_string(),
        derivation: CodeQueryStableOwnerDerivation::AnalyzerDeclarationId,
        semantic_key,
    })
}

fn canonical_ast_candidate(seed: &SeedMatch) -> Option<CodeQueryStableOwnerCandidate> {
    let mut segments = Vec::new();
    let mut current = Some(seed.fact_match.node);
    while let Some(node_id) = current {
        let node = seed.facts.node(node_id);
        segments.push((
            node.kind.label(),
            node.name.map(|name| name.text(seed.facts.source())),
        ));
        current = node.parent;
    }
    segments.reverse();
    let semantic_key = serde_json::to_string(&segments).ok()?;
    Some(CodeQueryStableOwnerCandidate {
        namespace: seed.language.config_label().to_string(),
        derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
        semantic_key,
    })
}

fn execute_plan(
    plan: &PhysicalQueryPlan,
    node_id: PhysicalQueryNodeId,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    profile_branch: &mut Option<Vec<usize>>,
) -> PlanExecution {
    let mut started = state.profile.as_ref().map(|_| Instant::now());
    let physical_node = plan.node(node_id);
    let physical_operator = physical_node.operator();
    let logical_operator = plan.logical_node(node_id).operator();
    let mut input_rows = 0;
    let mut disposition = QueryOperatorDisposition::Completed;
    let mut self_truncated = false;

    let execution = match (physical_operator, logical_operator) {
        (PhysicalQueryOperator::SeedScan, LogicalQueryOperator::Seed(seed)) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                cancelled_plan_execution()
            } else {
                let execution = execute_seed(seed, terminal_cap, state, limits, diagnostics);
                self_truncated = execution.truncated;
                if execution.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                execution
            }
        }
        (
            PhysicalQueryOperator::PipelineStep,
            LogicalQueryOperator::Step {
                step,
                final_in_authored_suffix,
                ..
            },
        ) => {
            let dependency = physical_node.dependencies()[0];
            let child = execute_plan(
                plan,
                dependency,
                state,
                limits,
                None,
                diagnostics,
                profile_branch,
            );
            input_rows = child.rows.len();
            if started.is_some() {
                started = Some(Instant::now());
            }
            if child.cancelled {
                disposition = QueryOperatorDisposition::Skipped;
                child
            } else if child.pipeline_halted {
                disposition = QueryOperatorDisposition::Skipped;
                PlanExecution {
                    pipeline_halted: !final_in_authored_suffix,
                    ..child
                }
            } else {
                let mut stepped = apply_plan_step(
                    step,
                    *final_in_authored_suffix,
                    child.rows,
                    state,
                    limits,
                    terminal_cap,
                    diagnostics,
                );
                self_truncated = stepped.truncated;
                if stepped.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                stepped.truncated |= child.truncated;
                stepped
            }
        }
        (
            PhysicalQueryOperator::SequentialUnion
            | PhysicalQueryOperator::SequentialIntersection
            | PhysicalQueryOperator::SequentialExcept,
            LogicalQueryOperator::Set { op, .. },
        ) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                cancelled_plan_execution()
            } else {
                debug_assert_eq!(
                    physical_operator,
                    match op {
                        SetOperator::Union => PhysicalQueryOperator::SequentialUnion,
                        SetOperator::Intersect => PhysicalQueryOperator::SequentialIntersection,
                        SetOperator::Except => PhysicalQueryOperator::SequentialExcept,
                    }
                );
                let dependencies = physical_node.dependencies();
                let mut branch_rows = Vec::with_capacity(dependencies.len());
                let mut cancelled_child = None;
                let mut truncated = false;
                for (index, dependency) in dependencies.iter().copied().enumerate() {
                    let branch_limits = fair_branch_limits(
                        &state.budget,
                        limits,
                        dependencies.len().saturating_sub(index),
                    );
                    let diagnostic_start = diagnostics.len();
                    if let Some(branch) = profile_branch.as_mut() {
                        branch.push(index);
                    }
                    let mut child = execute_plan(
                        plan,
                        dependency,
                        state,
                        branch_limits,
                        None,
                        diagnostics,
                        profile_branch,
                    );
                    if let Some(branch) = profile_branch.as_mut() {
                        let popped = branch.pop();
                        debug_assert_eq!(popped, Some(index));
                    }
                    input_rows = input_rows.saturating_add(child.rows.len());
                    prefix_branch_rows(&mut child.rows, index);
                    prefix_branch_diagnostics(&mut diagnostics[diagnostic_start..], index);
                    truncated |= child.truncated;
                    if child.cancelled {
                        cancelled_child = Some(child);
                        break;
                    }
                    branch_rows.push(child.rows);
                }
                if started.is_some() {
                    started = Some(Instant::now());
                }
                if let Some(child) = cancelled_child {
                    disposition = QueryOperatorDisposition::Skipped;
                    child
                } else {
                    let mut rows = combine_set_rows(*op, branch_rows);
                    if let Some(cap) = terminal_cap
                        && rows.len() > cap
                    {
                        self_truncated = true;
                        rows.truncate(cap);
                    }
                    PlanExecution {
                        rows,
                        truncated,
                        cancelled: false,
                        pipeline_halted: false,
                    }
                }
            }
        }
        (PhysicalQueryOperator::Limit, LogicalQueryOperator::Limit { count, .. }) => {
            let dependency = physical_node.dependencies()[0];
            let mut child = execute_plan(
                plan,
                dependency,
                state,
                limits,
                Some(count.saturating_add(1)),
                diagnostics,
                profile_branch,
            );
            input_rows = child.rows.len();
            if started.is_some() {
                started = Some(Instant::now());
            }
            let dependency_cancelled = child.cancelled;
            let token_cancelled = state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled);
            if dependency_cancelled || token_cancelled {
                if token_cancelled && !dependency_cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                child.cancelled = true;
                child.truncated = true;
                push_cancelled_diagnostic(diagnostics);
            }
            if child.rows.len() > *count {
                self_truncated = true;
                push_truncation_diagnostic(diagnostics, &state.budget, *count);
                child.rows.truncate(*count);
                child.truncated = true;
            }
            child
        }
        _ => unreachable!("physical operator must implement its logical query node"),
    };

    if let (Some(profile), Some(started)) = (&mut state.profile, started) {
        profile.record(QueryOperatorProfile {
            node: node_id,
            branch: profile_branch.as_deref().unwrap_or_default().to_vec(),
            operator: physical_operator,
            disposition,
            elapsed_ns: u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
            input_rows,
            output_rows: execution.rows.len(),
            operator_truncated: self_truncated,
            result_truncated: execution.truncated,
            result_cancelled: execution.cancelled,
        });
    }
    execution
}

fn cancelled_plan_execution() -> PlanExecution {
    PlanExecution {
        rows: Vec::new(),
        truncated: true,
        cancelled: true,
        pipeline_halted: false,
    }
}

fn execute_seed(
    seed: &CodeQuerySeed,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let cache_key = seed.canonical_cache_key();
    let budget_cap = limits
        .max_pipeline_rows
        .saturating_sub(state.budget.pipeline_rows);
    let desired_rows = terminal_cap.unwrap_or(budget_cap).min(budget_cap);
    let capped_by_budget = terminal_cap.is_none_or(|cap| budget_cap <= cap);
    if let Some(cached) = state.seed_cache.get(&cache_key).cloned() {
        diagnostics.extend(cached.diagnostics);
        let mut rows = cached.rows;
        let locally_capped = capped_by_budget && rows.len() > desired_rows;
        let truncated = cached.truncated || locally_capped;
        rows.truncate(desired_rows);
        state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(rows.len());
        if locally_capped {
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        }
        return PlanExecution {
            rows,
            truncated,
            cancelled: false,
            pipeline_halted: false,
        };
    }
    if desired_rows == 0 {
        push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: false,
            pipeline_halted: false,
        };
    }

    let diagnostic_start = diagnostics.len();
    let plan = QueryPlan::for_query(seed);
    let source_index = plan.build_source_index();
    let mut providers = state.analyzer.structural_search_providers();
    providers.sort_by_key(|provider| provider.structural_language());
    providers.retain(|provider| {
        seed.languages.is_empty() || seed.languages.contains(&provider.structural_language())
    });

    let mut scoped_languages = BTreeSet::new();
    for file in state.analyzer.analyzed_files() {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return PlanExecution {
                rows: Vec::new(),
                truncated: true,
                cancelled: true,
                pipeline_halted: false,
            };
        }
        let language = crate::analyzer::common::language_for_file(&file);
        let requested = seed.languages.is_empty() || seed.languages.contains(&language);
        if requested && file_matches_globs(&file, seed) {
            scoped_languages.insert(language);
        }
    }

    let mut supported = BTreeSet::new();
    let mut provider_scopes = Vec::new();
    for provider in providers {
        let language = provider.structural_language();
        supported.insert(language);
        let mut files = provider.structural_files();
        files.retain(|file| file_matches_globs(file, seed));
        files.sort();
        let explicitly_requested = seed.languages.contains(&language);
        if !files.is_empty() || explicitly_requested {
            diagnostics.extend(
                plan.features()
                    .unsupported_by(|feature| provider_supports_feature(provider, feature))
                    .into_diagnostics(language)
                    .into_iter()
                    .map(|diagnostic| CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::UnsupportedStructuralFeature,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: diagnostic.language().config_label(),
                        message: diagnostic.message(),
                    }),
            );
        }
        provider_scopes.push((language, provider, files));
    }
    for language in state.analyzer.languages() {
        let explicitly_requested = seed.languages.contains(&language);
        let requested = seed.languages.is_empty() || explicitly_requested;
        if requested
            && !supported.contains(&language)
            && (explicitly_requested || scoped_languages.contains(&language))
        {
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::MissingStructuralAdapter,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "no structural adapter for {} yet; its files were not searched",
                    language.config_label()
                ),
            });
        }
    }

    let mut candidates = Vec::new();
    for (language, provider, files) in provider_scopes {
        candidates.extend(
            files
                .into_iter()
                .map(|file| (rel_path_string(&file), language, provider, file)),
        );
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let probing_budget = capped_by_budget;
    let match_cap = desired_rows.saturating_add(usize::from(probing_budget));
    let mut pending: Vec<PendingMatch> = Vec::new();
    let mut truncated = false;
    for (_path, language, provider, file) in candidates {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return PlanExecution {
                rows: Vec::new(),
                truncated: true,
                cancelled: true,
                pipeline_halted: false,
            };
        }
        let Some(source) = provider.structural_source(&file) else {
            push_seed_provider_omission(diagnostics, language, &file, "indexed source snapshot");
            truncated = true;
            continue;
        };
        let mut projected = state.budget;
        projected.scanned_files = projected.scanned_files.saturating_add(1);
        projected.scanned_source_bytes =
            projected.scanned_source_bytes.saturating_add(source.len());
        if projected.scanned_files > limits.max_scanned_files
            || projected.scanned_source_bytes > limits.max_scanned_source_bytes
        {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            break;
        }
        state.budget.scanned_files = projected.scanned_files;
        state.budget.scanned_source_bytes = projected.scanned_source_bytes;
        if !source_index.may_match(&source) {
            continue;
        }
        let Some(facts) = provider.structural_facts(&file) else {
            push_seed_provider_omission(
                diagnostics,
                language,
                &file,
                "normalized structural facts",
            );
            truncated = true;
            continue;
        };
        projected = state.budget;
        projected.fact_nodes = projected.fact_nodes.saturating_add(facts.nodes().len());
        if projected
            .fact_nodes
            .saturating_add(projected.examined_references)
            > limits.max_fact_nodes
        {
            push_budget_diagnostic(diagnostics, &projected);
            truncated = true;
            break;
        }
        state.budget.fact_nodes = projected.fact_nodes;
        let remaining = match_cap.saturating_sub(pending.len());
        pending.extend(
            super::matcher::match_query(seed, &facts, remaining)
                .into_iter()
                .map(|fact_match| (language, file.clone(), Arc::clone(&facts), fact_match)),
        );
        if pending.len() >= match_cap {
            break;
        }
    }
    if pending.len() > desired_rows {
        pending.truncate(desired_rows);
        if capped_by_budget {
            truncated = true;
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        }
    }
    let rows = pending
        .into_iter()
        .map(|(language, file, facts, fact_match)| {
            let seed = Arc::new(SeedMatch {
                language,
                file,
                facts,
                fact_match,
            });
            PipelineRow {
                value: PipelineValue::StructuralMatch(Arc::clone(&seed)),
                traces: vec![PipelineTrace {
                    branch: Vec::new(),
                    seed,
                    steps: Vec::new(),
                }],
                provenance_truncated: false,
            }
        })
        .collect::<Vec<_>>();
    state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(rows.len());
    state.seed_cache.insert(
        cache_key,
        CachedSeedExecution {
            rows: rows.clone(),
            diagnostics: diagnostics[diagnostic_start..].to_vec(),
            truncated,
        },
    );
    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
}

fn push_seed_provider_omission(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    language: Language,
    file: &ProjectFile,
    unavailable: &str,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: language.config_label(),
        message: format!(
            "structural seed omitted {} because its provider returned no {unavailable}",
            rel_path_string(file)
        ),
    });
}

fn apply_plan_step(
    step: &QueryStep,
    final_in_authored_suffix: bool,
    rows: Vec<PipelineRow>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let mut truncated = false;
    if state
        .cancellation
        .is_some_and(CancellationToken::is_cancelled)
    {
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: true,
            pipeline_halted: false,
        };
    }
    if !rows.is_empty() && matches!(step, QueryStep::ImportsOf | QueryStep::ImportersOf) {
        let graph = state
            .import_graph
            .get_or_insert_with(|| DirectImportGraph::new(state.analyzer));
        let graph_exhausted = if step == &QueryStep::ImportersOf {
            ensure_complete_import_graph(
                state.analyzer,
                graph,
                limits.max_scanned_files,
                limits.max_pipeline_rows,
            )
        } else {
            let mut frontier = rows
                .iter()
                .filter_map(|row| match &row.value {
                    PipelineValue::File(file) => Some(file.clone()),
                    PipelineValue::StructuralMatch(_)
                    | PipelineValue::Declaration(_)
                    | PipelineValue::ReferenceSite(_)
                    | PipelineValue::CallSite(_)
                    | PipelineValue::ExpressionSite(_)
                    | PipelineValue::ReceiverAnalysis(_) => None,
                })
                .collect::<Vec<_>>();
            frontier.sort_by_key(rel_path_string);
            frontier.dedup();
            ensure_forward_import_edges(
                state.analyzer,
                graph,
                &frontier,
                limits.max_scanned_files,
                limits.max_pipeline_rows,
            )
        };
        if graph_exhausted {
            truncated = true;
            push_import_graph_budget_diagnostic(diagnostics, graph);
        }
    }
    let max_step_outputs = if final_in_authored_suffix {
        terminal_cap.unwrap_or(limits.max_pipeline_rows)
    } else {
        limits.max_pipeline_rows
    };
    let (mut rows, exhausted, step_truncated) = apply_pipeline_step(
        state.analyzer,
        step,
        rows,
        state.import_graph.as_ref(),
        Some(&mut state.indexed_declarations),
        &mut state.reference_cache,
        &mut state.call_cache,
        &mut state.budget,
        limits,
        max_step_outputs,
        state.cancellation,
        diagnostics,
        state.receiver_budget_override,
    );
    truncated |= step_truncated;
    if state
        .cancellation
        .is_some_and(CancellationToken::is_cancelled)
    {
        // A partially produced row is usable only after the final step:
        // before then its value belongs to an intermediate domain and
        // cannot satisfy the query's validated terminal contract.
        if !final_in_authored_suffix {
            rows.clear();
        }
        return PlanExecution {
            rows,
            truncated: true,
            cancelled: true,
            pipeline_halted: false,
        };
    }
    if exhausted {
        truncated = true;
        if state.budget.pipeline_rows >= limits.max_pipeline_rows
            || state.budget.provenance_steps >= limits.max_pipeline_rows
        {
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        }
        if !final_in_authored_suffix {
            rows.clear();
        }
    }
    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: exhausted && !final_in_authored_suffix,
    }
}

fn fair_branch_limits(
    budget: &CodeQueryExecutionBudget,
    parent: CodeQueryExecutionLimits,
    remaining_branches: usize,
) -> CodeQueryExecutionLimits {
    fn fair_cap(current: usize, maximum: usize, remaining: usize) -> usize {
        current.saturating_add(maximum.saturating_sub(current).div_ceil(remaining.max(1)))
    }
    CodeQueryExecutionLimits {
        max_scanned_files: fair_cap(
            budget.scanned_files,
            parent.max_scanned_files,
            remaining_branches,
        ),
        max_scanned_source_bytes: fair_cap(
            budget.scanned_source_bytes,
            parent.max_scanned_source_bytes,
            remaining_branches,
        ),
        max_fact_nodes: fair_cap(
            budget.fact_nodes.saturating_add(budget.examined_references),
            parent.max_fact_nodes,
            remaining_branches,
        ),
        max_pipeline_rows: fair_cap(
            budget.pipeline_rows.max(budget.provenance_steps),
            parent.max_pipeline_rows,
            remaining_branches,
        ),
    }
}

fn prefix_branch_rows(rows: &mut [PipelineRow], branch: usize) {
    for row in rows {
        for trace in &mut row.traces {
            trace.branch.insert(0, branch);
        }
    }
}

fn prefix_branch_diagnostics(diagnostics: &mut [CodeQueryDiagnostic], branch: usize) {
    for diagnostic in diagnostics {
        diagnostic.branch.insert(0, branch);
    }
}

fn combine_set_rows(op: SetOperator, mut branches: Vec<Vec<PipelineRow>>) -> Vec<PipelineRow> {
    match op {
        SetOperator::Union => {
            let mut output = Vec::new();
            let mut indexes = HashMap::default();
            for branch in branches {
                for row in branch {
                    insert_pipeline_row(
                        &mut output,
                        &mut indexes,
                        row.value,
                        row.traces,
                        row.provenance_truncated,
                    );
                }
            }
            output
        }
        SetOperator::Intersect => {
            let first = branches.remove(0);
            let mut later = branches
                .into_iter()
                .map(|branch| {
                    branch
                        .into_iter()
                        .map(|row| (row.value.key(), row))
                        .collect::<HashMap<_, _>>()
                })
                .collect::<Vec<_>>();
            let mut output = Vec::new();
            let mut indexes = HashMap::default();
            for mut row in first {
                let key = row.value.key();
                let mut contributions = Vec::with_capacity(later.len());
                let mut present = true;
                for branch in &mut later {
                    if let Some(contribution) = branch.remove(&key) {
                        contributions.push(contribution);
                    } else {
                        present = false;
                        break;
                    }
                }
                if present {
                    for contribution in contributions {
                        row.traces.extend(contribution.traces);
                        row.provenance_truncated |= contribution.provenance_truncated;
                    }
                    insert_pipeline_row(
                        &mut output,
                        &mut indexes,
                        row.value,
                        row.traces,
                        row.provenance_truncated,
                    );
                }
            }
            output
        }
        SetOperator::Except => {
            let first = branches.remove(0);
            let excluded = branches
                .into_iter()
                .flatten()
                .map(|row| row.value.key())
                .collect::<HashSet<_>>();
            first
                .into_iter()
                .filter(|row| !excluded.contains(&row.value.key()))
                .collect()
        }
    }
}

fn cancelled_query_result() -> CodeQueryResult {
    let mut diagnostics = Vec::new();
    push_cancelled_diagnostic(&mut diagnostics);
    CodeQueryResult {
        results: Vec::new(),
        truncated: true,
        diagnostics,
    }
}

fn push_cancelled_diagnostic(diagnostics: &mut Vec<CodeQueryDiagnostic>) {
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::Cancelled)
    {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::Cancelled,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: "query_code cancelled; any already-produced results are partial".to_string(),
    });
}

fn ensure_complete_import_graph(
    analyzer: &dyn IAnalyzer,
    graph: &mut DirectImportGraph,
    max_files: usize,
    max_edges: usize,
) -> bool {
    if graph.complete {
        graph.freeze();
        return false;
    }
    let files = graph.all_files.clone();
    let exhausted = ensure_forward_import_edges(analyzer, graph, &files, max_files, max_edges);
    if !exhausted {
        graph.complete = true;
    }
    graph.freeze();
    exhausted
}

fn ensure_forward_import_edges(
    analyzer: &dyn IAnalyzer,
    graph: &mut DirectImportGraph,
    files: &[ProjectFile],
    max_files: usize,
    max_edges: usize,
) -> bool {
    let mut pending = files
        .iter()
        .filter(|file| !graph.forward.contains_key(*file) && !graph.unsupported.contains(*file))
        .cloned()
        .collect::<Vec<_>>();
    pending.sort_by_key(rel_path_string);
    pending.dedup();
    if pending.is_empty() {
        return false;
    }

    let available_files = max_files.saturating_sub(graph.resolved_files);
    let mut exhausted = pending.len() > available_files;
    if pending.len() > available_files {
        pending.truncate(available_files);
    }

    let mut groups: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
    for file in pending {
        if analyzer.import_analysis_provider_for_file(&file).is_some() {
            groups
                .entry(crate::analyzer::common::language_for_file(&file))
                .or_default()
                .push(file);
        } else {
            graph.resolved_files += 1;
            graph.unsupported.insert(file);
            graph.compact = None;
        }
    }

    for files in groups.values_mut() {
        files.sort_by_key(rel_path_string);
        let Some(provider) = files
            .first()
            .and_then(|file| analyzer.import_analysis_provider_for_file(file))
        else {
            continue;
        };
        let bulk_infos = provider.import_infos_for_files(files);
        for file in files.iter() {
            let imports = bulk_infos
                .as_ref()
                .and_then(|infos| infos.get(file))
                .cloned()
                .unwrap_or_else(|| provider.import_info_of(file));
            let mut targets =
                crate::analyzer::resolve_imported_files_from_infos(provider, file, &imports)
                    .into_iter()
                    .filter(|target| graph.analyzed.contains(target))
                    .collect::<Vec<_>>();
            targets.sort_by_key(rel_path_string);
            targets.dedup();

            let available_edges = max_edges.saturating_sub(graph.resolved_edges);
            if targets.len() > available_edges {
                exhausted = true;
                continue;
            }
            graph.resolved_files += 1;
            graph.resolved_edges += targets.len();
            graph.forward.insert(file.clone(), targets);
            graph.compact = None;
        }
    }
    exhausted
}

#[allow(clippy::too_many_arguments)]
fn apply_pipeline_step(
    analyzer: &dyn IAnalyzer,
    step: &QueryStep,
    rows: Vec<PipelineRow>,
    import_graph: Option<&DirectImportGraph>,
    indexed_declarations: Option<&mut IndexedDeclarations>,
    reference_cache: &mut ReferenceTraversalCache,
    call_cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_step_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
) -> (Vec<PipelineRow>, bool, bool) {
    let max_pipeline_rows = limits.max_pipeline_rows;
    let mut output = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut unsupported_languages = BTreeSet::new();
    let mut semantic_omissions: BTreeMap<(Language, &'static str), usize> = BTreeMap::new();
    let mut receiver_diagnostics: BTreeMap<(Language, &'static str, String), usize> =
        BTreeMap::new();
    let mut enclosing_declarations: HashMap<ProjectFile, EnclosingDeclarationIndex> =
        HashMap::default();
    let mut exhausted = false;
    let mut receiver_truncated = false;
    let receiver_service = matches!(
        step,
        QueryStep::ReceiverTargets(_) | QueryStep::PointsTo(_) | QueryStep::MemberTargets(_)
    )
    .then(|| ReceiverQueryService::new(analyzer));

    let mut indexed_declarations = indexed_declarations;
    'rows: for row in rows {
        if output.len() >= max_step_outputs {
            break;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (output, true, receiver_truncated);
        }
        let mut row_exhausted = false;
        if let (
            PipelineValue::StructuralMatch(_),
            QueryStep::ReceiverTargets(filter)
            | QueryStep::PointsTo(filter)
            | QueryStep::MemberTargets(filter),
        ) = (&row.value, step)
            && filter.capture.is_some()
        {
            let operation = receiver_operation(step);
            for trace in &row.traces {
                if output.len() >= max_step_outputs {
                    break;
                }
                let (ranges, input) =
                    structural_receiver_ranges(&trace.seed, operation, filter.capture.as_deref());
                let mut trace_exhausted = false;
                let expansions = receiver_analysis_expansions(
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    operation,
                    &trace.seed.file,
                    ranges,
                    input,
                    filter.capture.clone(),
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    &mut receiver_diagnostics,
                    &mut trace_exhausted,
                    &mut receiver_truncated,
                );
                for expansion in expansions {
                    insert_pipeline_row(
                        &mut output,
                        &mut indexes,
                        expansion.value,
                        vec![advance_pipeline_trace(
                            trace.clone(),
                            step,
                            &expansion.trace,
                        )],
                        row.provenance_truncated,
                    );
                }
                if trace_exhausted {
                    exhausted = true;
                    break 'rows;
                }
            }
            continue;
        }
        let expansions = match (&row.value, step) {
            (PipelineValue::StructuralMatch(seed), QueryStep::EnclosingDecl) => {
                let (enclosing, projection_omitted) =
                    enclosing_declaration_value(analyzer, seed, &mut enclosing_declarations);
                if projection_omitted {
                    record_semantic_omission(
                        &mut semantic_omissions,
                        &CodeUnit::file_scope(seed.file.clone()),
                        "a real declaration in the seed file had no exact indexed range",
                    );
                    row_exhausted = true;
                }
                enclosing
                    .map(PipelineValue::Declaration)
                    .into_iter()
                    .map(pipeline_expansion)
                    .collect()
            }
            (PipelineValue::StructuralMatch(seed), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(seed.file.clone()))]
            }
            (PipelineValue::Declaration(declaration), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    declaration.unit.source().clone(),
                ))]
            }
            (PipelineValue::ReferenceSite(site), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(site.file.clone()))]
            }
            (PipelineValue::CallSite(site), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(site.0.file.clone()))]
            }
            (PipelineValue::ExpressionSite(site), QueryStep::FileOf) => vec![pipeline_expansion(
                PipelineValue::File(site.call_site.0.file.clone()),
            )],
            (PipelineValue::ReceiverAnalysis(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.report.site.file.clone(),
                ))]
            }
            (PipelineValue::File(file), QueryStep::ImportsOf) => {
                let graph = import_graph.expect("import graph exists for import steps");
                if graph.unsupported.contains(file) {
                    unsupported_languages.insert(crate::analyzer::common::language_for_file(file));
                    Vec::new()
                } else {
                    graph
                        .imports_of(file)
                        .into_iter()
                        .map(PipelineValue::File)
                        .map(pipeline_expansion)
                        .collect()
                }
            }
            (PipelineValue::File(file), QueryStep::ImportersOf) => import_graph
                .expect("import graph exists for import steps")
                .importers_of(file)
                .into_iter()
                .map(PipelineValue::File)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Declaration(declaration),
                QueryStep::Supertypes(traversal) | QueryStep::Subtypes(traversal),
            ) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, hierarchy_exhausted) = expand_hierarchy(
                    analyzer,
                    declaration,
                    step,
                    *traversal,
                    indexed,
                    budget,
                    max_pipeline_rows,
                    &mut semantic_omissions,
                );
                row_exhausted = hierarchy_exhausted;
                expansions
            }
            (PipelineValue::Declaration(declaration), QueryStep::Members) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                if !is_type_declaration(analyzer, &declaration.unit) {
                    record_semantic_omission(
                        &mut semantic_omissions,
                        &declaration.unit,
                        "input is not a type declaration",
                    );
                    Vec::new()
                } else {
                    let (expansions, members_exhausted) = direct_member_expansions(
                        analyzer,
                        declaration,
                        analyzer.direct_children(&declaration.unit),
                        indexed,
                        budget,
                        max_pipeline_rows,
                        &mut semantic_omissions,
                    );
                    row_exhausted = members_exhausted;
                    expansions
                }
            }
            (PipelineValue::Declaration(declaration), QueryStep::Owner) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (owner, owner_exhausted) = indexed.owner_of(
                    analyzer,
                    &declaration.unit,
                    &mut budget.pipeline_rows,
                    max_pipeline_rows,
                );
                row_exhausted = owner_exhausted;
                match owner {
                    Some(owner) => vec![budgeted_declaration_expansion(owner)],
                    None if !owner_exhausted => {
                        record_semantic_omission(
                            &mut semantic_omissions,
                            &declaration.unit,
                            "input is not a direct member declaration",
                        );
                        Vec::new()
                    }
                    None => Vec::new(),
                }
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::ReferencesOf(filter) | QueryStep::UsedBy(filter),
            ) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, reference_exhausted) = inbound_reference_expansions(
                    analyzer,
                    declaration,
                    step,
                    filter,
                    indexed,
                    reference_cache,
                    budget,
                    limits,
                    diagnostics,
                    max_pipeline_rows.saturating_sub(budget.pipeline_rows),
                    cancellation,
                );
                row_exhausted = reference_exhausted;
                expansions
            }
            (PipelineValue::Declaration(declaration), QueryStep::Uses(filter)) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, reference_exhausted) = outbound_reference_expansions(
                    analyzer,
                    declaration,
                    filter,
                    indexed,
                    reference_cache,
                    budget,
                    limits,
                    max_step_outputs,
                    cancellation,
                    diagnostics,
                );
                row_exhausted = reference_exhausted;
                expansions
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::Callers(filter) | QueryStep::Callees(filter),
            ) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, call_exhausted) = call_declaration_expansions(
                    analyzer,
                    declaration,
                    step,
                    filter,
                    indexed,
                    call_cache,
                    budget,
                    limits,
                    max_step_outputs,
                    cancellation,
                    diagnostics,
                );
                row_exhausted = call_exhausted;
                expansions
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::CallSitesTo(filter) | QueryStep::CallSitesFrom(filter),
            ) => {
                let (expansions, call_exhausted) = call_site_expansions(
                    analyzer,
                    declaration,
                    step,
                    filter,
                    call_cache,
                    budget,
                    limits,
                    max_step_outputs,
                    cancellation,
                    diagnostics,
                );
                row_exhausted = call_exhausted;
                expansions
            }
            (PipelineValue::CallSite(site), QueryStep::CallInput(selector)) => {
                let (expansions, binding_incomplete) = call_input_expansions(site, selector);
                if binding_incomplete {
                    record_semantic_omission(
                        &mut semantic_omissions,
                        &site.0.callee,
                        "a retained call site had no exact formal-parameter binding layout",
                    );
                    row_exhausted = true;
                }
                expansions
            }
            (
                PipelineValue::StructuralMatch(seed),
                QueryStep::ReceiverTargets(filter)
                | QueryStep::PointsTo(filter)
                | QueryStep::MemberTargets(filter),
            ) => {
                let operation = receiver_operation(step);
                let (ranges, input) =
                    structural_receiver_ranges(seed, operation, filter.capture.as_deref());
                receiver_analysis_expansions(
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    operation,
                    &seed.file,
                    ranges,
                    input,
                    filter.capture.clone(),
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    &mut receiver_diagnostics,
                    &mut row_exhausted,
                    &mut receiver_truncated,
                )
            }
            (
                PipelineValue::ReferenceSite(site),
                QueryStep::ReceiverTargets(_)
                | QueryStep::PointsTo(_)
                | QueryStep::MemberTargets(_),
            ) => receiver_analysis_expansions(
                receiver_service
                    .as_ref()
                    .expect("receiver query service exists for receiver steps"),
                receiver_operation(step),
                &site.file,
                vec![site.range],
                if matches!(step, QueryStep::PointsTo(_)) {
                    ReceiverQueryInput::Expression
                } else {
                    ReceiverQueryInput::ContainingSite
                },
                None,
                budget,
                limits,
                receiver_budget_override,
                max_step_outputs.saturating_sub(output.len()),
                cancellation,
                &mut receiver_diagnostics,
                &mut row_exhausted,
                &mut receiver_truncated,
            ),
            (PipelineValue::CallSite(site), QueryStep::ReceiverTargets(_)) => {
                receiver_analysis_expansions(
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    ReceiverQueryOperation::ReceiverTargets,
                    &site.0.file,
                    vec![site.0.range],
                    ReceiverQueryInput::ContainingSite,
                    None,
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    &mut receiver_diagnostics,
                    &mut row_exhausted,
                    &mut receiver_truncated,
                )
            }
            (
                PipelineValue::ExpressionSite(site),
                QueryStep::ReceiverTargets(_) | QueryStep::PointsTo(_),
            ) => receiver_analysis_expansions(
                receiver_service
                    .as_ref()
                    .expect("receiver query service exists for receiver steps"),
                receiver_operation(step),
                &site.call_site.0.file,
                vec![site.range],
                ReceiverQueryInput::Expression,
                None,
                budget,
                limits,
                receiver_budget_override,
                max_step_outputs.saturating_sub(output.len()),
                cancellation,
                &mut receiver_diagnostics,
                &mut row_exhausted,
                &mut receiver_truncated,
            ),
            _ => unreachable!("query step domains are validated before execution"),
        };

        for expansion in expansions {
            if !expansion.budgeted && budget.pipeline_rows >= max_pipeline_rows {
                exhausted = true;
                break 'rows;
            }
            if !expansion.budgeted {
                budget.pipeline_rows += 1;
            }
            let traces = row
                .traces
                .iter()
                .cloned()
                .map(|trace| advance_pipeline_trace(trace, step, &expansion.trace))
                .collect();
            insert_pipeline_row(
                &mut output,
                &mut indexes,
                expansion.value,
                traces,
                row.provenance_truncated,
            );
        }
        if row_exhausted {
            exhausted = true;
            break;
        }
    }

    if step == &QueryStep::ImportersOf
        && let Some(graph) = import_graph
    {
        unsupported_languages.extend(
            graph
                .unsupported
                .iter()
                .map(crate::analyzer::common::language_for_file),
        );
    }

    for language in unsupported_languages {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UnsupportedImportAnalysis,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{} does not provide structured import analysis; {} omitted its affected files",
                language.config_label(),
                step.label()
            ),
        });
    }
    append_semantic_omission_diagnostics(diagnostics, step, semantic_omissions);
    for ((language, operation, reason), count) in receiver_diagnostics {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{operation} returned {count} analysis row{} with {reason}",
                if count == 1 { "" } else { "s" }
            ),
        });
    }
    (output, exhausted, receiver_truncated)
}

fn advance_pipeline_trace(
    mut trace: PipelineTrace,
    step: &QueryStep,
    expansion: &[(PipelineTraceValue, Option<PipelineVia>)],
) -> PipelineTrace {
    trace.steps.extend(
        expansion
            .iter()
            .cloned()
            .map(|(value, via)| PipelineTraceStep {
                op: step.clone(),
                value,
                via,
            }),
    );
    trace
}

fn receiver_operation(step: &QueryStep) -> ReceiverQueryOperation {
    match step {
        QueryStep::ReceiverTargets(_) => ReceiverQueryOperation::ReceiverTargets,
        QueryStep::PointsTo(_) => ReceiverQueryOperation::PointsTo,
        QueryStep::MemberTargets(_) => ReceiverQueryOperation::MemberTargets,
        _ => unreachable!("receiver operation requested for a non-receiver step"),
    }
}

fn structural_receiver_ranges(
    seed: &SeedMatch,
    operation: ReceiverQueryOperation,
    capture: Option<&str>,
) -> (Vec<Range>, ReceiverQueryInput) {
    let (spans, input) = if let Some(capture) = capture {
        let spans = seed
            .fact_match
            .captures
            .iter()
            .filter(|binding| binding.name == capture)
            .map(|binding| binding.span)
            .collect::<Vec<_>>();
        (spans, ReceiverQueryInput::Expression)
    } else {
        let fact_id = seed.fact_match.node;
        let fact = seed.facts.node(fact_id);
        let normalized = match operation {
            ReceiverQueryOperation::PointsTo => seed
                .facts
                .role_targets(fact_id, Role::Right)
                .next()
                .map(|target| target.span),
            ReceiverQueryOperation::ReceiverTargets => match fact.kind {
                NormalizedKind::Call => seed
                    .facts
                    .role_targets(fact_id, Role::Receiver)
                    .next()
                    .map(|target| target.span),
                NormalizedKind::FieldAccess => seed
                    .facts
                    .role_targets(fact_id, Role::Object)
                    .next()
                    .map(|target| target.span),
                _ => None,
            },
            ReceiverQueryOperation::MemberTargets => None,
        };
        let input = match operation {
            ReceiverQueryOperation::PointsTo => ReceiverQueryInput::Expression,
            ReceiverQueryOperation::ReceiverTargets if normalized.is_some() => {
                ReceiverQueryInput::Expression
            }
            ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::MemberTargets => {
                ReceiverQueryInput::ContainingSite
            }
        };
        (vec![normalized.unwrap_or_else(|| fact.span())], input)
    };
    let mut seen = HashSet::default();
    let ranges = spans
        .into_iter()
        .filter(|span| seen.insert((span.start_byte, span.end_byte)))
        .map(|span| Range {
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_line: seed.facts.line_of_byte(span.start_byte),
            end_line: seed.facts.line_of_byte(span.end_byte),
        })
        .collect();
    (ranges, input)
}

#[allow(clippy::too_many_arguments)]
fn receiver_analysis_expansions(
    service: &ReceiverQueryService<'_>,
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    mut ranges: Vec<Range>,
    input: ReceiverQueryInput,
    capture: Option<String>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    max_outputs: usize,
    cancellation: Option<&CancellationToken>,
    receiver_diagnostics: &mut BTreeMap<(Language, &'static str, String), usize>,
    shared_budget_exhausted: &mut bool,
    receiver_truncated: &mut bool,
) -> Vec<PipelineExpansion> {
    ranges.sort_by_key(primary_range_key);
    ranges.dedup();
    ranges.truncate(max_outputs);
    let mut expansions = Vec::with_capacity(ranges.len());
    for range in ranges {
        let remaining_facts = limits
            .max_fact_nodes
            .saturating_sub(budget.fact_nodes.saturating_add(budget.examined_references));
        let remaining_rows = limits
            .max_pipeline_rows
            .saturating_sub(budget.pipeline_rows);
        let base = receiver_budget_override.unwrap_or_default();
        let receiver_budget = ReceiverAnalysisBudget {
            context_depth: base.context_depth,
            max_targets: base.max_targets.min(remaining_rows.saturating_sub(1)),
            max_summary_expansions: base.max_summary_expansions.min(remaining_facts),
            max_scope_nodes: base.max_scope_nodes.min(remaining_facts),
        };
        let Ok(report) =
            service.analyze(operation, file, range, input, receiver_budget, cancellation)
        else {
            *shared_budget_exhausted = true;
            break;
        };

        let candidate_count = receiver_candidate_count(&report);
        budget.fact_nodes = budget
            .fact_nodes
            .saturating_add(report.work.setup_nodes)
            .saturating_add(report.work.scope_nodes)
            .saturating_add(report.work.summary_expansions);
        budget.pipeline_rows = budget
            .pipeline_rows
            .saturating_add(1)
            .saturating_add(candidate_count);
        if budget.fact_nodes.saturating_add(budget.examined_references) > limits.max_fact_nodes
            || budget.pipeline_rows > limits.max_pipeline_rows
        {
            *shared_budget_exhausted = true;
        }

        let language = report.site.language;
        match &report.analysis {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported { reason })
            | ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unsupported {
                reason,
            }) => {
                *receiver_diagnostics
                    .entry((
                        language,
                        operation.as_str(),
                        format!("unsupported provider or shape: {reason}"),
                    ))
                    .or_default() += 1;
            }
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::ExceededBudget { limit })
            | ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit,
            }) => {
                *receiver_truncated = true;
                *receiver_diagnostics
                    .entry((
                        language,
                        operation.as_str(),
                        format!("exceeded receiver limit {limit}"),
                    ))
                    .or_default() += 1;
            }
            ReceiverQueryAnalysis::Values(
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown,
            )
            | ReceiverQueryAnalysis::MemberTargets(
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown,
            ) => {}
        }
        if report.candidates_truncated {
            *receiver_truncated = true;
            *receiver_diagnostics
                .entry((
                    language,
                    operation.as_str(),
                    "truncated candidates at max_targets".to_string(),
                ))
                .or_default() += 1;
        }
        let value = ReceiverAnalysisValue {
            report,
            capture: capture.clone(),
        };
        expansions.push(PipelineExpansion {
            value: PipelineValue::ReceiverAnalysis(value.clone()),
            trace: vec![(PipelineTraceValue::ReceiverAnalysis(value), None)],
            budgeted: true,
        });
    }
    expansions
}

fn receiver_candidate_count(report: &ReceiverQueryReport) -> usize {
    match &report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => outcome.values().map_or(0, <[_]>::len),
        ReceiverQueryAnalysis::MemberTargets(outcome) => outcome.values().map_or(0, <[_]>::len),
    }
}

fn pipeline_expansion(value: PipelineValue) -> PipelineExpansion {
    let trace_value =
        pipeline_trace_value(&value).expect("every semantic query step produces a semantic value");
    PipelineExpansion {
        value,
        trace: vec![(trace_value, None)],
        budgeted: false,
    }
}

fn budgeted_declaration_expansion(declaration: DeclarationValue) -> PipelineExpansion {
    PipelineExpansion {
        value: PipelineValue::Declaration(declaration.clone()),
        trace: vec![(PipelineTraceValue::Declaration(declaration), None)],
        budgeted: true,
    }
}

fn direct_member_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    mut children: Vec<CodeUnit>,
    indexed: &mut IndexedDeclarations,
    budget: &mut CodeQueryExecutionBudget,
    max_pipeline_rows: usize,
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
) -> (Vec<PipelineExpansion>, bool) {
    children.sort();
    children.dedup();
    let mut expansions = Vec::new();
    let mut exhausted = false;
    for unit in children {
        if budget.pipeline_rows >= max_pipeline_rows {
            exhausted = true;
            break;
        }
        budget.pipeline_rows += 1;
        let Some(child) = indexed.get(analyzer, &unit) else {
            record_semantic_omission(
                omissions,
                &unit,
                "a direct member declaration had no exact indexed range",
            );
            exhausted = true;
            continue;
        };
        indexed.record_owner(&unit, &declaration.unit);
        expansions.push(budgeted_declaration_expansion(child));
    }
    (expansions, exhausted)
}

fn reference_expansion(value: PipelineValue, site: ReferenceSiteValue) -> PipelineExpansion {
    let trace_value =
        pipeline_trace_value(&value).expect("reference steps produce a semantic value");
    PipelineExpansion {
        value,
        trace: vec![(trace_value, Some(PipelineVia::ReferenceSite(site)))],
        budgeted: false,
    }
}

#[derive(Clone)]
struct CallTraversalWork {
    unit: CodeUnit,
    depth: usize,
    path_tail: Option<usize>,
}

struct CallPathNode {
    value: DeclarationValue,
    via: CallSiteValue,
    parent: Option<usize>,
}

fn finish_call_declaration_expansions(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    diagnostic_start: usize,
    declaration: &DeclarationValue,
    incoming: bool,
    omitted: usize,
    expansions: Vec<PipelineExpansion>,
    exhausted: bool,
) -> (Vec<PipelineExpansion>, bool) {
    if omitted == 0 {
        return (expansions, exhausted);
    }
    let mut traversal_diagnostics = diagnostics.split_off(diagnostic_start.min(diagnostics.len()));
    traversal_diagnostics.retain(|diagnostic| {
        diagnostic.code != CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous
    });
    diagnostics.extend(traversal_diagnostics);
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::CallRelationCandidatesOmitted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: crate::analyzer::common::language_for_file(declaration.unit.source())
            .config_label(),
        message: format!(
            "{} omitted {omitted} retained call-relation candidate{} for {} because the related declaration had no exact indexed range",
            if incoming { "callers" } else { "callees" },
            if omitted == 1 { "" } else { "s" },
            declaration.unit.fq_name()
        ),
    });
    (expansions, true)
}

#[allow(clippy::too_many_arguments)]
fn call_declaration_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    filter: &CallTraversalFilter,
    indexed: &mut IndexedDeclarations,
    cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> (Vec<PipelineExpansion>, bool) {
    let incoming = matches!(step, QueryStep::Callers(_));
    let diagnostic_start = diagnostics.len();
    let mut queue = VecDeque::from([CallTraversalWork {
        unit: declaration.unit.clone(),
        depth: 0,
        path_tail: None,
    }]);
    let mut paths = Vec::new();
    let mut emitted = HashSet::default();
    let mut expansions = Vec::new();
    let mut exhausted = false;
    let mut omitted = 0usize;
    while let Some(work) = queue.pop_front() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return finish_call_declaration_expansions(
                diagnostics,
                diagnostic_start,
                declaration,
                incoming,
                omitted,
                expansions,
                true,
            );
        }
        let result = cached_call_relation(
            analyzer,
            &work.unit,
            incoming,
            cache,
            budget,
            limits,
            cancellation,
            diagnostics,
        );
        exhausted |= result.truncated || result.cancelled;
        for site in result
            .sites
            .into_iter()
            .filter(|site| filter.proof.is_none_or(|proof| proof == site.proof))
        {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    omitted,
                    expansions,
                    true,
                );
            }
            let next_unit = if incoming {
                site.caller.clone()
            } else {
                site.callee.clone()
            };
            let Some(next) = indexed.get(analyzer, &next_unit) else {
                omitted = omitted.saturating_add(1);
                continue;
            };
            if !emitted.contains(&next_unit) && emitted.len() >= max_outputs {
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    omitted,
                    expansions,
                    true,
                );
            }
            if budget.pipeline_rows >= limits.max_pipeline_rows {
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    omitted,
                    expansions,
                    true,
                );
            }
            let cycle = match call_path_contains(
                &paths,
                work.path_tail,
                &declaration.unit,
                &next_unit,
                &mut budget.provenance_steps,
                limits.max_pipeline_rows,
            ) {
                Some(cycle) => cycle,
                None => {
                    return finish_call_declaration_expansions(
                        diagnostics,
                        diagnostic_start,
                        declaration,
                        incoming,
                        omitted,
                        expansions,
                        true,
                    );
                }
            };
            let next_depth = work.depth + 1;
            if budget.provenance_steps.saturating_add(next_depth) > limits.max_pipeline_rows {
                budget.provenance_steps = limits.max_pipeline_rows;
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    omitted,
                    expansions,
                    true,
                );
            }
            budget.provenance_steps += next_depth;
            budget.pipeline_rows += 1;
            let call_site = CallSiteValue(site, CallBindingStatus::Unavailable);
            let path_tail = paths.len();
            paths.push(CallPathNode {
                value: next.clone(),
                via: call_site,
                parent: work.path_tail,
            });
            expansions.push(PipelineExpansion {
                value: PipelineValue::Declaration(next),
                trace: call_trace_values(&paths, path_tail, next_depth),
                budgeted: true,
            });
            emitted.insert(next_unit.clone());
            if !cycle && next_depth < filter.depth.get() {
                queue.push_back(CallTraversalWork {
                    unit: next_unit,
                    depth: next_depth,
                    path_tail: Some(path_tail),
                });
            }
        }
    }
    finish_call_declaration_expansions(
        diagnostics,
        diagnostic_start,
        declaration,
        incoming,
        omitted,
        expansions,
        exhausted,
    )
}

#[allow(clippy::too_many_arguments)]
fn call_site_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    filter: &CallSiteTraversalFilter,
    cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> (Vec<PipelineExpansion>, bool) {
    let incoming = matches!(step, QueryStep::CallSitesTo(_));
    let result = cached_call_relation(
        analyzer,
        &declaration.unit,
        incoming,
        cache,
        budget,
        limits,
        cancellation,
        diagnostics,
    );
    let mut sites = result
        .sites
        .into_iter()
        .filter(|site| filter.proof.is_none_or(|proof| proof == site.proof))
        .collect::<Vec<_>>();
    let truncated = result.truncated || result.cancelled || sites.len() > max_outputs;
    sites.truncate(max_outputs);
    let expansions = sites
        .into_iter()
        .map(|mut site| {
            let binding = bind_call_site_arguments(analyzer, &mut site, &mut cache.bindings);
            pipeline_expansion(PipelineValue::CallSite(CallSiteValue(site, binding)))
        })
        .collect();
    (expansions, truncated)
}

#[allow(clippy::too_many_arguments)]
fn cached_call_relation(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    incoming: bool,
    cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> CallRelationResult {
    let results = if incoming {
        &mut cache.incoming
    } else {
        &mut cache.outgoing
    };
    let result = if let Some(result) = results.get(unit) {
        result.clone()
    } else {
        let relation_limits = CallRelationLimits {
            max_files: limits
                .max_scanned_files
                .saturating_sub(budget.scanned_files)
                .min(DEFAULT_MAX_FILES),
            max_source_bytes: limits
                .max_scanned_source_bytes
                .saturating_sub(budget.scanned_source_bytes),
            max_candidates: limits
                .max_fact_nodes
                .saturating_sub(budget.fact_nodes.saturating_add(budget.examined_references)),
        };
        let result = if relation_limits.max_files == 0
            || relation_limits.max_source_bytes == 0
            || relation_limits.max_candidates == 0
        {
            push_budget_diagnostic(diagnostics, budget);
            CallRelationResult {
                truncated: true,
                ..CallRelationResult::default()
            }
        } else if incoming {
            CallRelationService::incoming_bounded(analyzer, unit, relation_limits, cancellation)
        } else {
            CallRelationService::outgoing_bounded(analyzer, unit, relation_limits, cancellation)
        };
        let budget_exhausted = charge_reference_scan(
            budget,
            limits,
            result.work.scanned_files,
            result.work.scanned_source_bytes,
            result.work.examined_candidates,
        );
        let mut result = result;
        result.truncated |= budget_exhausted;
        if budget_exhausted {
            push_budget_diagnostic(diagnostics, budget);
        }
        results.insert(unit.clone(), result.clone());
        result
    };
    let reported = if incoming {
        &mut cache.reported_incoming
    } else {
        &mut cache.reported_outgoing
    };
    if reported.insert(unit.clone()) {
        let language = crate::analyzer::common::language_for_file(unit.source()).config_label();
        diagnostics.extend(
            result
                .diagnostics
                .iter()
                .cloned()
                .map(|diagnostic| map_call_relation_diagnostic(language, diagnostic)),
        );
    }
    result
}

fn map_call_relation_diagnostic(
    language: &'static str,
    diagnostic: CallRelationDiagnostic,
) -> CodeQueryDiagnostic {
    debug_assert!(!diagnostic.context.is_empty());
    debug_assert_eq!(
        diagnostic.reason_kind.is_some(),
        diagnostic.code == CallRelationDiagnosticCode::AnalysisFailed
    );
    let (code, impact) = match diagnostic.code {
        CallRelationDiagnosticCode::BudgetExhausted => (
            CodeQueryDiagnosticCode::CallRelationBudgetExhausted,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::ParseFailed => (
            CodeQueryDiagnosticCode::CallRelationParseFailed,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::CandidatesOmitted => (
            CodeQueryDiagnosticCode::CallRelationCandidatesOmitted,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::TargetsAmbiguous => (
            CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous,
            CodeQueryDiagnosticImpact::Advisory,
        ),
        CallRelationDiagnosticCode::CandidateLimit => (
            CodeQueryDiagnosticCode::CallRelationCandidateLimit,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::AnalysisFailed => (
            CodeQueryDiagnosticCode::CallRelationAnalysisFailed,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
    };
    CodeQueryDiagnostic {
        code,
        impact,
        branch: Vec::new(),
        language,
        message: diagnostic.message,
    }
}

fn call_path_contains(
    paths: &[CallPathNode],
    mut tail: Option<usize>,
    seed: &CodeUnit,
    candidate: &CodeUnit,
    work: &mut usize,
    max_work: usize,
) -> Option<bool> {
    if seed == candidate {
        return Some(true);
    }
    while let Some(index) = tail {
        if *work >= max_work {
            return None;
        }
        *work += 1;
        let node = &paths[index];
        if &node.value.unit == candidate {
            return Some(true);
        }
        tail = node.parent;
    }
    Some(false)
}

fn call_trace_values(
    paths: &[CallPathNode],
    mut tail: usize,
    depth: usize,
) -> Vec<(PipelineTraceValue, Option<PipelineVia>)> {
    let mut values = Vec::with_capacity(depth);
    loop {
        let node = &paths[tail];
        values.push((
            PipelineTraceValue::Declaration(node.value.clone()),
            Some(PipelineVia::CallSite(node.via.clone())),
        ));
        let Some(parent) = node.parent else {
            break;
        };
        tail = parent;
    }
    values.reverse();
    values
}

fn call_input_expansions(
    site: &CallSiteValue,
    selector: &CallInputSelector,
) -> (Vec<PipelineExpansion>, bool) {
    let formal_binding_required =
        !matches!(selector, CallInputSelector::Receiver) && !site.0.arguments.is_empty();
    if formal_binding_required && site.1 == CallBindingStatus::Unavailable {
        return (Vec::new(), true);
    }
    let expressions = match selector {
        CallInputSelector::Receiver => site
            .0
            .receiver
            .map(|range| ExpressionSiteValue {
                call_site: site.clone(),
                range,
                input: ExpressionInput::Receiver,
            })
            .into_iter()
            .collect::<Vec<_>>(),
        CallInputSelector::ParameterIndex(index) => site
            .0
            .arguments
            .iter()
            .filter(|argument| argument.formal_index == Some(*index))
            .map(|argument| ExpressionSiteValue {
                call_site: site.clone(),
                range: argument.range,
                input: ExpressionInput::Parameter {
                    index: *index,
                    name: argument.formal_name.clone(),
                },
            })
            .collect(),
        CallInputSelector::ParameterName(name) => site
            .0
            .arguments
            .iter()
            .filter(|argument| argument.formal_name.as_deref() == Some(name))
            .filter_map(|argument| {
                Some(ExpressionSiteValue {
                    call_site: site.clone(),
                    range: argument.range,
                    input: ExpressionInput::Parameter {
                        index: argument.formal_index?,
                        name: argument.formal_name.clone(),
                    },
                })
            })
            .collect(),
    };
    let expansions = expressions
        .into_iter()
        .map(|expression| pipeline_expansion(PipelineValue::ExpressionSite(expression)))
        .collect();
    let spread_binding_incomplete =
        formal_binding_required && site.0.arguments.iter().any(|argument| argument.spread);
    (expansions, spread_binding_incomplete)
}

#[allow(clippy::too_many_arguments)]
fn inbound_reference_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    filter: &ReferenceTraversalFilter,
    indexed: &mut IndexedDeclarations,
    cache: &mut ReferenceTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    max_hits: usize,
    cancellation: Option<&CancellationToken>,
) -> (Vec<PipelineExpansion>, bool) {
    let mut exhausted = false;
    if !cache.inbound.contains_key(&declaration.unit) {
        let remaining_files = limits
            .max_scanned_files
            .saturating_sub(budget.scanned_files);
        if remaining_files == 0 {
            push_budget_diagnostic(diagnostics, budget);
            return (Vec::new(), true);
        }
        let remaining_source_bytes = limits
            .max_scanned_source_bytes
            .saturating_sub(budget.scanned_source_bytes);
        if remaining_source_bytes == 0 {
            push_budget_diagnostic(diagnostics, budget);
            return (Vec::new(), true);
        }
        let mut finder = UsageFinder::new();
        if let Some(cancellation) = cancellation {
            finder = finder.with_cancellation(cancellation.clone());
        }
        let query = finder.query_with_source_budget(
            analyzer,
            std::slice::from_ref(&declaration.unit),
            MAX_SCANNED_FILES.min(remaining_files),
            max_hits.max(1),
            remaining_source_bytes,
        );
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (Vec::new(), true);
        }
        let examined_references = fuzzy_result_examination_count(&query.result);
        if charge_reference_scan(
            budget,
            limits,
            query.candidate_files.len(),
            query.scanned_source_bytes,
            examined_references,
        ) {
            push_budget_diagnostic(diagnostics, budget);
            cache.inbound.insert(declaration.unit.clone(), Vec::new());
            return (Vec::new(), true);
        }
        let mut hits = Vec::new();
        let report = cache.reported_inbound.insert(declaration.unit.clone());
        if report && query.source_bytes_truncated {
            exhausted = true;
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::ReferenceSourceBytesTruncated,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: crate::analyzer::common::language_for_file(declaration.unit.source())
                    .config_label(),
                message: format!(
                    "references_of source-byte budget truncated candidate files for {}",
                    declaration.unit.fq_name()
                ),
            });
        } else if report && query.candidate_files_truncated {
            exhausted = true;
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::ReferenceCandidateFilesTruncated,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: crate::analyzer::common::language_for_file(declaration.unit.source())
                    .config_label(),
                message: format!(
                    "references_of candidate files were truncated for {}",
                    declaration.unit.fq_name()
                ),
            });
        }
        match query.result {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
            } => {
                hits.extend(hits_by_overload.into_values().flatten().map(|hit| {
                    reference_hit_for_target(
                        analyzer,
                        hit,
                        declaration.unit.clone(),
                        UsageProof::Proven,
                    )
                }));
                hits.extend(unproven_by_overload.into_values().flatten().map(|hit| {
                    reference_hit_for_target(
                        analyzer,
                        hit,
                        declaration.unit.clone(),
                        UsageProof::Unproven,
                    )
                }));
                if report {
                    let omitted = unproven_total_by_overload
                        .values()
                        .sum::<usize>()
                        .saturating_sub(
                            hits.iter()
                                .filter(|hit| hit.proof == UsageProof::Unproven)
                                .count(),
                        );
                    if omitted > 0 {
                        diagnostics.push(CodeQueryDiagnostic {
                            code: CodeQueryDiagnosticCode::ReferenceCandidatesOmitted,
                            impact: CodeQueryDiagnosticImpact::Incomplete,
                            branch: Vec::new(),
                            language: crate::analyzer::common::language_for_file(
                                declaration.unit.source(),
                            )
                            .config_label(),
                            message: format!(
                                "references_of omitted {omitted} unproven reference candidates for {}",
                                declaration.unit.fq_name()
                            ),
                        });
                    }
                }
            }
            FuzzyResult::Ambiguous {
                hits_by_overload, ..
            } => {
                hits.extend(hits_by_overload.into_values().flatten().map(|hit| {
                    reference_hit_for_target(
                        analyzer,
                        hit,
                        declaration.unit.clone(),
                        UsageProof::Unproven,
                    )
                }));
                if report {
                    diagnostics.push(CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous,
                        impact: CodeQueryDiagnosticImpact::Advisory,
                        branch: Vec::new(),
                        language: crate::analyzer::common::language_for_file(
                            declaration.unit.source(),
                        )
                        .config_label(),
                        message: format!(
                            "references_of emitted ambiguous candidates for {} as unproven",
                            declaration.unit.fq_name()
                        ),
                    });
                }
            }
            FuzzyResult::TooManyCallsites {
                total_callsites,
                limit,
                sample_hits,
                ..
            } => {
                hits.extend(reference_hits_from_bounded_sample(
                    analyzer,
                    sample_hits,
                    declaration.unit.clone(),
                    limit,
                ));
                exhausted = true;
                if report {
                    diagnostics.push(CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::ReferenceCallsiteLimit,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: crate::analyzer::common::language_for_file(
                            declaration.unit.source(),
                        )
                        .config_label(),
                        message: format!(
                            "references_of found {total_callsites} call sites for {}, exceeding limit {limit}",
                            declaration.unit.fq_name()
                        ),
                    });
                }
            }
            FuzzyResult::Failure { reason, .. } => {
                if report {
                    diagnostics.push(CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::ReferenceAnalysisFailed,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: crate::analyzer::common::language_for_file(
                            declaration.unit.source(),
                        )
                        .config_label(),
                        message: format!(
                            "references_of does not support {}: {reason}",
                            declaration.unit.fq_name()
                        ),
                    });
                }
            }
        }
        cache.inbound.insert(declaration.unit.clone(), hits);
    }

    let mut sites = Vec::new();
    let mut omitted_enclosing_declarations = 0usize;
    for hit in cache
        .inbound
        .get(&declaration.unit)
        .into_iter()
        .flatten()
        .filter(|hit| reference_hit_matches(hit, filter))
    {
        let (site, enclosing_projection_omitted) =
            reference_site_value(analyzer, hit, declaration.clone(), indexed, None);
        omitted_enclosing_declarations = omitted_enclosing_declarations
            .saturating_add(usize::from(enclosing_projection_omitted));
        sites.push(site);
    }
    if omitted_enclosing_declarations > 0 {
        exhausted = true;
        diagnostics.retain(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous
        });
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::ReferenceCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(declaration.unit.source())
                .config_label(),
            message: format!(
                "{} could not project the exact enclosing declaration for {omitted_enclosing_declarations} retained reference candidate{} of {}",
                step.label(),
                if omitted_enclosing_declarations == 1 {
                    ""
                } else {
                    "s"
                },
                declaration.unit.fq_name()
            ),
        });
    }
    sort_reference_sites(&mut sites);
    sites.dedup();
    let expansions = sites
        .into_iter()
        .filter_map(|site| match step {
            QueryStep::ReferencesOf(_) => {
                Some(pipeline_expansion(PipelineValue::ReferenceSite(site)))
            }
            QueryStep::UsedBy(_) => site
                .enclosing
                .clone()
                .map(|enclosing| reference_expansion(PipelineValue::Declaration(enclosing), site)),
            _ => unreachable!("inbound helper is only used by inbound reference steps"),
        })
        .collect::<Vec<_>>();
    (expansions, exhausted)
}

fn fuzzy_result_examination_count(result: &FuzzyResult) -> usize {
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            hits_by_overload.values().map(BTreeSet::len).sum::<usize>()
                + unproven_total_by_overload.values().sum::<usize>()
        }
        FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => hits_by_overload.values().map(BTreeSet::len).sum(),
        FuzzyResult::TooManyCallsites {
            total_callsites, ..
        } => *total_callsites,
        FuzzyResult::Failure { .. } => 0,
    }
}

fn charge_reference_scan(
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    scanned_files: usize,
    scanned_source_bytes: usize,
    examined_references: usize,
) -> bool {
    budget.scanned_files = budget.scanned_files.saturating_add(scanned_files);
    budget.scanned_source_bytes = budget
        .scanned_source_bytes
        .saturating_add(scanned_source_bytes);
    budget.examined_references = budget
        .examined_references
        .saturating_add(examined_references);
    budget.scanned_files > limits.max_scanned_files
        || budget.scanned_source_bytes > limits.max_scanned_source_bytes
        || budget.fact_nodes.saturating_add(budget.examined_references) > limits.max_fact_nodes
}

fn reference_hit_for_target(
    analyzer: &dyn IAnalyzer,
    hit: crate::analyzer::usages::UsageHit,
    target: CodeUnit,
    proof: UsageProof,
) -> ReferenceHit {
    let kind = hit.reference_kind.or_else(|| {
        classify_reference_kind(
            analyzer,
            &hit.file,
            hit.start_offset,
            hit.end_offset,
            &target,
        )
    });
    ReferenceHit {
        file: hit.file,
        range: Range {
            start_byte: hit.start_offset,
            end_byte: hit.end_offset,
            start_line: hit.line,
            end_line: hit.line,
        },
        enclosing_unit: hit.enclosing,
        kind,
        resolved: target,
        confidence: (hit.confidence.clamp(0.0, 1.0) * 1_000_000.0) as u32,
        usage_kind: hit.kind,
        proof,
    }
}

fn reference_hits_from_bounded_sample(
    analyzer: &dyn IAnalyzer,
    sample_hits: impl IntoIterator<Item = UsageHit>,
    target: CodeUnit,
    limit: usize,
) -> Vec<ReferenceHit> {
    sample_hits
        .into_iter()
        .take(limit)
        .map(|hit| reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Proven))
        .collect()
}

fn reference_hits_for_target(
    analyzer: &dyn IAnalyzer,
    result: FuzzyResult,
    target: &CodeUnit,
) -> (Vec<ReferenceHit>, bool) {
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        } => (
            hits_by_overload
                .into_values()
                .flatten()
                .map(|hit| {
                    reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Proven)
                })
                .chain(unproven_by_overload.into_values().flatten().map(|hit| {
                    reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Unproven)
                }))
                .collect(),
            false,
        ),
        FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => (
            hits_by_overload
                .into_values()
                .flatten()
                .map(|hit| {
                    reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Unproven)
                })
                .collect(),
            false,
        ),
        FuzzyResult::TooManyCallsites {
            sample_hits, limit, ..
        } => (
            reference_hits_from_bounded_sample(analyzer, sample_hits, target.clone(), limit),
            true,
        ),
        FuzzyResult::Failure { .. } => (Vec::new(), false),
    }
}

fn reference_hit_matches(hit: &ReferenceHit, filter: &ReferenceTraversalFilter) -> bool {
    hit.usage_kind.included_in(filter.surface)
        && filter.proof.is_none_or(|proof| proof == hit.proof)
        && (filter.reference_kinds.is_empty()
            || hit
                .kind
                .is_some_and(|kind| filter.reference_kinds.contains(&kind)))
}

fn reference_site_value(
    analyzer: &dyn IAnalyzer,
    hit: &ReferenceHit,
    target: DeclarationValue,
    indexed: &mut IndexedDeclarations,
    known_enclosing: Option<&DeclarationValue>,
) -> (ReferenceSiteValue, bool) {
    let (enclosing, enclosing_projection_omitted) =
        if let Some(known) = known_enclosing.filter(|known| known.unit == hit.enclosing_unit) {
            (Some(known.clone()), false)
        } else if hit.enclosing_unit.is_synthetic() || hit.enclosing_unit.is_file_scope() {
            (None, false)
        } else {
            let enclosing = indexed.get(analyzer, &hit.enclosing_unit);
            let omitted = enclosing.is_none();
            (enclosing, omitted)
        };
    (
        ReferenceSiteValue {
            file: hit.file.clone(),
            range: hit.range,
            target,
            enclosing,
            usage_kind: hit.usage_kind,
            proof: hit.proof,
            reference_kind: hit.kind,
        },
        enclosing_projection_omitted,
    )
}

#[allow(clippy::too_many_arguments)]
fn outbound_reference_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    filter: &ReferenceTraversalFilter,
    indexed: &mut IndexedDeclarations,
    cache: &mut ReferenceTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_step_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> (Vec<PipelineExpansion>, bool) {
    let mut exhausted = false;
    if !cache.outbound.contains_key(declaration.unit.source()) {
        let (hits, scan_exhausted) = scan_outbound_reference_hits(
            analyzer,
            declaration.unit.source(),
            budget,
            limits,
            max_step_outputs,
            cancellation,
            diagnostics,
        );
        exhausted = scan_exhausted;
        cache
            .outbound
            .insert(declaration.unit.source().clone(), hits);
    }
    let mut sites = Vec::new();
    let mut omitted = 0usize;
    for hit in cache
        .outbound
        .get(declaration.unit.source())
        .into_iter()
        .flatten()
        .filter(|hit| hit.enclosing_unit == declaration.unit)
        .filter(|hit| reference_hit_matches(hit, filter))
    {
        let Some(target) = indexed.get(analyzer, &hit.resolved) else {
            omitted = omitted.saturating_add(1);
            continue;
        };
        let (site, enclosing_projection_omitted) =
            reference_site_value(analyzer, hit, target, indexed, Some(declaration));
        debug_assert!(
            !enclosing_projection_omitted,
            "outbound hits are filtered to the already projected input declaration"
        );
        sites.push(site);
    }
    if omitted > 0 {
        exhausted = true;
        diagnostics
            .retain(|diagnostic| diagnostic.code != CodeQueryDiagnosticCode::UsesTargetsAmbiguous);
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(declaration.unit.source())
                .config_label(),
            message: format!(
                "uses omitted {omitted} retained reference candidate{} from {} because the resolved target had no exact indexed range",
                if omitted == 1 { "" } else { "s" },
                declaration.unit.fq_name()
            ),
        });
    }
    sort_reference_sites(&mut sites);
    sites.dedup();
    let expansions = sites
        .into_iter()
        .map(|site| reference_expansion(PipelineValue::Declaration(site.target.clone()), site))
        .collect();
    (expansions, exhausted)
}

#[derive(Default)]
struct OutboundReferenceSiteExpectation {
    targets: BTreeSet<CodeUnit>,
    ambiguous: bool,
}

struct OutboundLookupCandidates {
    by_target: BTreeMap<CodeUnit, BTreeSet<(usize, usize)>>,
    sites: BTreeMap<(usize, usize), OutboundReferenceSiteExpectation>,
    ambiguous_sites: usize,
    ambiguous_candidates_complete: bool,
    omitted_sites: usize,
}

fn group_outbound_lookup_candidates(
    outcomes: Vec<DefinitionLookupOutcome>,
) -> OutboundLookupCandidates {
    let mut grouped = OutboundLookupCandidates {
        by_target: BTreeMap::new(),
        sites: BTreeMap::new(),
        ambiguous_sites: 0,
        ambiguous_candidates_complete: true,
        omitted_sites: 0,
    };

    for outcome in outcomes {
        let ambiguous = outcome.status == DefinitionLookupStatus::Ambiguous;
        match outcome.status {
            DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Ambiguous => {}
            _ => {
                grouped.omitted_sites = grouped.omitted_sites.saturating_add(1);
                continue;
            }
        }
        if ambiguous {
            grouped.ambiguous_sites = grouped.ambiguous_sites.saturating_add(1);
        }
        let Some(reference) = outcome.reference else {
            grouped.omitted_sites = grouped.omitted_sites.saturating_add(1);
            grouped.ambiguous_candidates_complete &= !ambiguous;
            continue;
        };
        if outcome.definitions.is_empty() {
            grouped.omitted_sites = grouped.omitted_sites.saturating_add(1);
            grouped.ambiguous_candidates_complete &= !ambiguous;
            continue;
        }

        let range = (reference.focus_start_byte, reference.focus_end_byte);
        let site = grouped.sites.entry(range).or_default();
        site.ambiguous |= ambiguous;
        for resolved in outcome.definitions {
            site.targets.insert(resolved.clone());
            grouped.by_target.entry(resolved).or_default().insert(range);
        }
    }
    grouped
}

fn append_outbound_lookup_diagnostics(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    language: Language,
    file: &ProjectFile,
    ambiguous_sites: usize,
    ambiguous_candidates_complete: bool,
    omitted: usize,
) {
    if ambiguous_sites > 0 && ambiguous_candidates_complete {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesTargetsAmbiguous,
            impact: CodeQueryDiagnosticImpact::Advisory,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses emitted {ambiguous_sites} ambiguous reference site{} in {} as unproven",
                if ambiguous_sites == 1 { "" } else { "s" },
                rel_path_string(file)
            ),
        });
    }
    if omitted > 0 {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses omitted {omitted} candidate reference site{} in {} because the structured usage analyzer did not confirm every exact edge",
                if omitted == 1 { "" } else { "s" },
                rel_path_string(file)
            ),
        });
    }
}

fn scan_outbound_reference_hits(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_step_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> (Vec<ReferenceHit>, bool) {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return (Vec::new(), true);
    }
    let language = crate::analyzer::common::language_for_file(file);
    let Some(source) = analyzer.indexed_source(file) else {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses could not inspect {} because its indexed source snapshot was unavailable",
                rel_path_string(file)
            ),
        });
        return (Vec::new(), true);
    };
    let remaining_source_bytes = limits
        .max_scanned_source_bytes
        .saturating_sub(budget.scanned_source_bytes);
    if budget.scanned_files >= limits.max_scanned_files || source.len() > remaining_source_bytes {
        push_budget_diagnostic(diagnostics, budget);
        return (Vec::new(), true);
    }
    budget.scanned_files += 1;
    budget.scanned_source_bytes += source.len();
    let source = Arc::new(source);
    let Some(tree) = parse_tree_for_language(file, language, &source) else {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesParserUnsupported,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!("uses does not support parsing {}", rel_path_string(file)),
        });
        return (Vec::new(), false);
    };
    const MAX_OUTBOUND_SITES_PER_FILE: usize = 50_000;
    let remaining_reference_budget = limits
        .max_fact_nodes
        .saturating_sub(budget.fact_nodes.saturating_add(budget.examined_references));
    if remaining_reference_budget == 0 {
        push_budget_diagnostic(diagnostics, budget);
        return (Vec::new(), true);
    }
    let retained_work_budget = max_step_outputs.saturating_mul(64).max(256);
    let candidate_limit = MAX_OUTBOUND_SITES_PER_FILE
        .min(remaining_reference_budget)
        .min(retained_work_budget);
    let candidate_ranges = match cancellation {
        Some(cancellation) => reference_candidate_ranges_cancellable(
            tree.root_node(),
            language,
            candidate_limit,
            &|| cancellation.is_cancelled(),
        ),
        None => Some(reference_candidate_ranges(
            tree.root_node(),
            language,
            candidate_limit,
        )),
    };
    let Some(candidate_ranges) = candidate_ranges else {
        return (Vec::new(), true);
    };
    let (ranges, mut exhausted) = match candidate_ranges {
        ReferenceCandidateRanges::Complete(ranges) => (ranges, false),
        ReferenceCandidateRanges::LimitExceeded { ranges, .. } => (ranges, true),
    };
    budget.examined_references = budget.examined_references.saturating_add(ranges.len());
    if exhausted {
        if candidate_limit == remaining_reference_budget {
            push_budget_diagnostic(diagnostics, budget);
        } else {
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::UsesCandidateLimit,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "uses returned a bounded partial scan of {} after reaching the structured reference-candidate limit of {candidate_limit}",
                    rel_path_string(file)
                ),
            });
        }
    }
    if candidate_limit == 0 {
        exhausted = true;
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesCandidateLimit,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses has no reference-candidate capacity for {}",
                rel_path_string(file)
            ),
        });
    }
    let requests = ranges
        .into_iter()
        .map(|range| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(range.start_byte),
            end_byte: Some(range.end_byte),
        })
        .collect();
    let outcomes = match cancellation {
        Some(cancellation) => resolve_definition_batch_with_source_and_cancellation(
            analyzer,
            requests,
            file.clone(),
            Arc::clone(&source),
            cancellation,
        ),
        None => resolve_definition_batch_with_source(
            analyzer,
            requests,
            file.clone(),
            Arc::clone(&source),
        ),
    };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return (Vec::new(), true);
    }
    let grouped = group_outbound_lookup_candidates(outcomes);
    let mut retained_candidates = BTreeSet::new();

    let mut candidate_files = HashSet::default();
    candidate_files.insert(file.clone());
    let provider = ExplicitCandidateProvider::new(Arc::new(candidate_files));
    let mut hits = Vec::new();
    for (target, candidate_ranges) in &grouped.by_target {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (Vec::new(), true);
        }
        let mut finder = UsageFinder::new();
        if let Some(cancellation) = cancellation {
            finder = finder.with_cancellation(cancellation.clone());
        }
        let result = finder.query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            candidate_ranges.len().max(1),
        );
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (Vec::new(), true);
        }
        let (target_hits, target_truncated) =
            reference_hits_for_target(analyzer, result.result, target);
        if target_truncated {
            exhausted = true;
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::UsesCandidateLimit,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "uses retained a bounded positive reference sample for {} after the usage analyzer reached its candidate limit",
                    target.fq_name()
                ),
            });
        }
        for hit in target_hits {
            let range = (hit.range.start_byte, hit.range.end_byte);
            if hit.file == *file && candidate_ranges.contains(&range) {
                retained_candidates.insert((target.clone(), range));
                hits.push(hit);
            }
        }
    }

    let mut omitted = grouped.omitted_sites;
    let mut ambiguous_candidates_complete = grouped.ambiguous_candidates_complete;
    for (range, expectation) in &grouped.sites {
        let fully_retained = expectation
            .targets
            .iter()
            .all(|target| retained_candidates.contains(&(target.clone(), *range)));
        if !fully_retained {
            omitted = omitted.saturating_add(1);
            if expectation.ambiguous {
                ambiguous_candidates_complete = false;
            }
        }
    }
    append_outbound_lookup_diagnostics(
        diagnostics,
        language,
        file,
        grouped.ambiguous_sites,
        ambiguous_candidates_complete,
        omitted,
    );
    (hits, exhausted)
}

fn sort_reference_sites(sites: &mut [ReferenceSiteValue]) {
    sites.sort_by(|left, right| {
        rel_path_string(&left.file)
            .cmp(&rel_path_string(&right.file))
            .then_with(|| primary_range_key(&left.range).cmp(&primary_range_key(&right.range)))
            .then_with(|| left.target.unit.cmp(&right.target.unit))
            .then_with(|| {
                left.enclosing
                    .as_ref()
                    .map(|value| &value.unit)
                    .cmp(&right.enclosing.as_ref().map(|value| &value.unit))
            })
            .then_with(|| {
                left.usage_kind
                    .wire_label()
                    .cmp(right.usage_kind.wire_label())
            })
            .then_with(|| usage_proof_label(left.proof).cmp(usage_proof_label(right.proof)))
            .then_with(|| {
                left.reference_kind
                    .map(reference_kind_label)
                    .cmp(&right.reference_kind.map(reference_kind_label))
            })
    });
}

fn classify_reference_kind(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start_byte: usize,
    end_byte: usize,
    target: &CodeUnit,
) -> Option<ReferenceKind> {
    let language = crate::analyzer::common::language_for_file(file);
    let facts = analyzer
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)?
        .structural_facts(file)?;
    let covers = |span: Span| span.start_byte <= start_byte && end_byte <= span.end_byte;
    let mut candidates = facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            node.name.is_some_and(covers)
                && matches!(
                    node.kind,
                    NormalizedKind::Call | NormalizedKind::FieldAccess
                )
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(_, node)| {
        (
            usize::from(node.kind != NormalizedKind::Call),
            node.range.end_byte - node.range.start_byte,
        )
    });
    if let Some((id, node)) = candidates.first().copied() {
        let receiver_role = if node.kind == NormalizedKind::FieldAccess {
            Role::Object
        } else {
            Role::Receiver
        };
        let receiver = facts
            .role_targets(id as u32, receiver_role)
            .next()
            .map(|role| role.span.text(facts.source()).trim());
        if receiver.is_some_and(|text| matches!(text, "super" | "base")) {
            return Some(ReferenceKind::SuperCall);
        }
        let static_receiver = analyzer
            .parent_of(target)
            .filter(|owner| owner.is_class())
            .is_some_and(|owner| receiver == Some(owner.short_name()));
        if static_receiver {
            return Some(ReferenceKind::StaticReference);
        }
        if node.kind == NormalizedKind::Call {
            return Some(
                if target.is_class() || target.kind().display_lowercase() == "constructor" {
                    ReferenceKind::ConstructorCall
                } else {
                    ReferenceKind::MethodCall
                },
            );
        }
        let mut parent = Some(id as u32);
        while let Some(current) = parent {
            let fact = facts.node(current);
            if fact.kind == NormalizedKind::Assignment {
                return Some(
                    if facts
                        .role_targets(current, Role::Left)
                        .any(|role| covers(role.span))
                    {
                        ReferenceKind::FieldWrite
                    } else {
                        ReferenceKind::FieldRead
                    },
                );
            }
            parent = fact.parent;
        }
        return Some(ReferenceKind::FieldRead);
    }
    if target.is_class() {
        let nearest = facts
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, node)| {
                node.range.start_byte <= start_byte && end_byte <= node.range.end_byte
            })
            .min_by_key(|(_, node)| node.range.end_byte - node.range.start_byte)
            .map(|(id, _)| id as u32);
        let mut current = nearest;
        while let Some(id) = current {
            let node = facts.node(id);
            if node.kind.satisfies(NormalizedKind::Declaration) {
                if node.kind == NormalizedKind::Class && node.name.is_none_or(|name| !covers(name))
                {
                    return Some(ReferenceKind::Inheritance);
                }
                break;
            }
            current = node.parent;
        }
    }
    target.is_class().then_some(ReferenceKind::TypeReference)
}

#[allow(clippy::too_many_arguments)]
fn expand_hierarchy(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    traversal: HierarchyTraversal,
    indexed: &mut IndexedDeclarations,
    budget: &mut CodeQueryExecutionBudget,
    max_pipeline_rows: usize,
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
) -> (Vec<PipelineExpansion>, bool) {
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        record_semantic_omission(
            omissions,
            &declaration.unit,
            "its language does not provide type hierarchy analysis",
        );
        return (Vec::new(), false);
    };
    if !provider.supports_type_hierarchy(&declaration.unit) {
        record_semantic_omission(
            omissions,
            &declaration.unit,
            "input is not a supported type declaration",
        );
        return (Vec::new(), false);
    }

    let max_depth = match traversal {
        HierarchyTraversal::Direct => 1,
        HierarchyTraversal::Depth(depth) => depth.get(),
        HierarchyTraversal::Transitive => usize::MAX,
    };
    let mut queue = VecDeque::from([HierarchyWork {
        unit: declaration.unit.clone(),
        depth: 0,
        path_tail: None,
    }]);
    let mut paths = Vec::new();
    let mut expansions = Vec::new();
    let mut exhausted = false;

    while let Some(work) = queue.pop_front() {
        let mut related = match step {
            QueryStep::Supertypes(_) => provider.get_direct_ancestors(&work.unit),
            QueryStep::Subtypes(_) => provider
                .get_direct_descendants(&work.unit)
                .into_iter()
                .collect(),
            _ => unreachable!("hierarchy expansion requires a hierarchy step"),
        };
        related.sort();
        related.dedup();
        for unit in related {
            if budget.pipeline_rows >= max_pipeline_rows {
                return (expansions, true);
            }
            budget.pipeline_rows += 1;
            match hierarchy_path_contains(
                &paths,
                work.path_tail,
                &declaration.unit,
                &unit,
                &mut budget.provenance_steps,
                max_pipeline_rows,
            ) {
                Some(true) => continue,
                Some(false) => {}
                None => return (expansions, true),
            }
            let Some(value) =
                project_hierarchy_declaration(analyzer, &unit, indexed, omissions, &mut exhausted)
            else {
                continue;
            };
            let next_depth = work.depth + 1;
            if budget.provenance_steps.saturating_add(next_depth) > max_pipeline_rows {
                return (expansions, true);
            }
            budget.provenance_steps += next_depth;
            let path_tail = paths.len();
            paths.push(HierarchyPathNode {
                value: value.clone(),
                parent: work.path_tail,
            });
            expansions.push(PipelineExpansion {
                value: PipelineValue::Declaration(value),
                trace: hierarchy_trace_values(&paths, path_tail, next_depth)
                    .into_iter()
                    .map(|value| (value, None))
                    .collect(),
                budgeted: true,
            });

            if next_depth < max_depth {
                queue.push_back(HierarchyWork {
                    unit,
                    depth: next_depth,
                    path_tail: Some(path_tail),
                });
            }
        }
    }
    (expansions, exhausted)
}

fn project_hierarchy_declaration(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    indexed: &mut IndexedDeclarations,
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
    exhausted: &mut bool,
) -> Option<DeclarationValue> {
    let value = indexed.get(analyzer, unit);
    if value.is_none() {
        record_semantic_omission(
            omissions,
            unit,
            "a related hierarchy declaration had no exact indexed range",
        );
        *exhausted = true;
    }
    value
}

struct HierarchyWork {
    unit: CodeUnit,
    depth: usize,
    path_tail: Option<usize>,
}

struct HierarchyPathNode {
    value: DeclarationValue,
    parent: Option<usize>,
}

fn hierarchy_path_contains(
    paths: &[HierarchyPathNode],
    mut tail: Option<usize>,
    root: &CodeUnit,
    candidate: &CodeUnit,
    work: &mut usize,
    max_work: usize,
) -> Option<bool> {
    if *work >= max_work {
        return None;
    }
    *work += 1;
    if candidate == root {
        return Some(true);
    }
    while let Some(index) = tail {
        if *work >= max_work {
            return None;
        }
        *work += 1;
        let node = &paths[index];
        if &node.value.unit == candidate {
            return Some(true);
        }
        tail = node.parent;
    }
    Some(false)
}

fn hierarchy_trace_values(
    paths: &[HierarchyPathNode],
    mut tail: usize,
    depth: usize,
) -> Vec<PipelineTraceValue> {
    let mut values = Vec::with_capacity(depth);
    loop {
        let node = &paths[tail];
        values.push(PipelineTraceValue::Declaration(node.value.clone()));
        let Some(parent) = node.parent else {
            break;
        };
        tail = parent;
    }
    values.reverse();
    values
}

fn is_type_declaration(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.is_class()
        || analyzer
            .type_hierarchy_provider()
            .is_some_and(|provider| provider.supports_type_hierarchy(unit))
}

fn record_semantic_omission(
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
    unit: &CodeUnit,
    reason: &'static str,
) {
    let language = crate::analyzer::common::language_for_file(unit.source());
    *omissions.entry((language, reason)).or_default() += 1;
}

fn append_semantic_omission_diagnostics(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    step: &QueryStep,
    omissions: BTreeMap<(Language, &'static str), usize>,
) {
    for ((language, reason), count) in omissions {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{} omitted {count} input{} because {reason}",
                step.label(),
                if count == 1 { "" } else { "s" }
            ),
        });
    }
}

#[derive(Default)]
struct EnclosingDeclarationIndex {
    exact: Vec<DeclarationValue>,
    projection_omitted: bool,
}

impl EnclosingDeclarationIndex {
    fn retain(&mut self, unit: CodeUnit, ranges: impl IntoIterator<Item = Range>) {
        if unit.is_synthetic() || unit.is_file_scope() {
            return;
        }
        let mut retained = false;
        for range in ranges {
            retained = true;
            self.exact.push(DeclarationValue {
                unit: unit.clone(),
                range,
            });
        }
        if !retained {
            self.projection_omitted = true;
        }
    }

    fn sort(&mut self) {
        self.exact.sort_by(|left, right| {
            let left_span = left.range.end_byte.saturating_sub(left.range.start_byte);
            let right_span = right.range.end_byte.saturating_sub(right.range.start_byte);
            left_span
                .cmp(&right_span)
                .then_with(|| left.unit.cmp(&right.unit))
                .then_with(|| left.range.start_byte.cmp(&right.range.start_byte))
                .then_with(|| left.range.end_byte.cmp(&right.range.end_byte))
        });
    }

    fn enclosing(&self, seed_range: Range) -> Option<DeclarationValue> {
        self.exact
            .iter()
            .find(|declaration| {
                declaration.range.start_byte <= seed_range.start_byte
                    && declaration.range.end_byte >= seed_range.end_byte
            })
            .cloned()
    }
}

fn enclosing_declaration_value(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    declarations_by_file: &mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
) -> (Option<DeclarationValue>, bool) {
    let fact = seed.facts.node(seed.fact_match.node);
    let span = fact.span();
    let seed_range = Range {
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
    };
    let declarations = declarations_by_file
        .entry(seed.file.clone())
        .or_insert_with(|| {
            let mut declarations = EnclosingDeclarationIndex::default();
            for unit in analyzer.get_declarations(&seed.file) {
                declarations.retain(unit.clone(), analyzer.ranges_of(&unit));
            }
            declarations.sort();
            declarations
        });
    (
        declarations.enclosing(seed_range),
        declarations.projection_omitted,
    )
}

fn pipeline_trace_value(value: &PipelineValue) -> Option<PipelineTraceValue> {
    match value {
        PipelineValue::StructuralMatch(_) => None,
        PipelineValue::Declaration(declaration) => {
            Some(PipelineTraceValue::Declaration(declaration.clone()))
        }
        PipelineValue::File(file) => Some(PipelineTraceValue::File(file.clone())),
        PipelineValue::ReferenceSite(site) => Some(PipelineTraceValue::ReferenceSite(site.clone())),
        PipelineValue::CallSite(site) => Some(PipelineTraceValue::CallSite(site.clone())),
        PipelineValue::ExpressionSite(site) => {
            Some(PipelineTraceValue::ExpressionSite(site.clone()))
        }
        PipelineValue::ReceiverAnalysis(value) => {
            Some(PipelineTraceValue::ReceiverAnalysis(value.clone()))
        }
    }
}

fn insert_pipeline_row(
    rows: &mut Vec<PipelineRow>,
    indexes: &mut HashMap<PipelineKey, usize>,
    value: PipelineValue,
    mut traces: Vec<PipelineTrace>,
    provenance_truncated: bool,
) {
    let key = value.key();
    if let Some(&index) = indexes.get(&key) {
        let row = &mut rows[index];
        let remaining = MAX_PROVENANCE_TRACES.saturating_sub(row.traces.len());
        if traces.len() > remaining {
            row.provenance_truncated = true;
        }
        row.traces.extend(traces.into_iter().take(remaining));
        row.provenance_truncated |= provenance_truncated;
        return;
    }

    let truncated = provenance_truncated || traces.len() > MAX_PROVENANCE_TRACES;
    traces.truncate(MAX_PROVENANCE_TRACES);
    indexes.insert(key, rows.len());
    rows.push(PipelineRow {
        value,
        traces,
        provenance_truncated: truncated,
    });
}

fn render_pipeline_item(
    analyzer: &dyn IAnalyzer,
    row: PipelineRow,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultItem {
    let provenance = row
        .traces
        .iter()
        .map(|trace| render_provenance(analyzer, trace, detail, cache))
        .collect();
    let value = match row.value {
        PipelineValue::StructuralMatch(seed) => CodeQueryResultValue::StructuralMatch {
            value: render_match(
                analyzer,
                seed.language,
                &seed.file,
                &seed.facts,
                &seed.fact_match,
                detail,
                cache,
            ),
        },
        PipelineValue::Declaration(declaration) => CodeQueryResultValue::Declaration {
            value: render_declaration(analyzer, &declaration, detail, cache),
        },
        PipelineValue::File(file) => CodeQueryResultValue::File {
            value: render_file(&file),
        },
        PipelineValue::ReferenceSite(site) => CodeQueryResultValue::ReferenceSite {
            value: Box::new(render_reference_site(analyzer, &site, detail, cache)),
        },
        PipelineValue::CallSite(site) => CodeQueryResultValue::CallSite {
            value: Box::new(render_call_site(analyzer, &site, detail, cache)),
        },
        PipelineValue::ExpressionSite(site) => CodeQueryResultValue::ExpressionSite {
            value: Box::new(render_expression_site(analyzer, &site, cache)),
        },
        PipelineValue::ReceiverAnalysis(value) => CodeQueryResultValue::ReceiverAnalysis {
            value: Box::new(render_receiver_analysis(analyzer, &value, detail, cache)),
        },
    };
    CodeQueryResultItem {
        value,
        provenance,
        provenance_truncated: row.provenance_truncated,
    }
}

fn render_provenance(
    analyzer: &dyn IAnalyzer,
    trace: &PipelineTrace,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryProvenance {
    CodeQueryProvenance {
        branch: trace.branch.clone(),
        seed: render_seed_ref(&trace.seed, detail),
        steps: trace
            .steps
            .iter()
            .map(|step| CodeQueryProvenanceStep {
                op: step.op.label(),
                result: match &step.value {
                    PipelineTraceValue::Declaration(declaration) => {
                        render_declaration_ref(analyzer, declaration, detail, cache)
                    }
                    PipelineTraceValue::File(file) => render_file_ref(file),
                    PipelineTraceValue::ReferenceSite(site) => {
                        render_reference_site_ref(analyzer, site, detail, cache)
                    }
                    PipelineTraceValue::CallSite(site) => {
                        render_call_site_ref(analyzer, site, cache)
                    }
                    PipelineTraceValue::ExpressionSite(site) => {
                        render_expression_site_ref(analyzer, site, cache)
                    }
                    PipelineTraceValue::ReceiverAnalysis(value) => {
                        render_receiver_analysis_ref(analyzer, value, cache)
                    }
                },
                via: step.via.as_ref().map(|via| match via {
                    PipelineVia::ReferenceSite(site) => {
                        render_reference_site_ref(analyzer, site, detail, cache)
                    }
                    PipelineVia::CallSite(site) => render_call_site_ref(analyzer, site, cache),
                }),
            })
            .collect(),
    }
}

fn render_seed_ref(seed: &SeedMatch, detail: CodeQueryResultDetail) -> CodeQueryResultRef {
    let fact = seed.facts.node(seed.fact_match.node);
    let full = !detail.is_compact();
    let path = rel_path_string(&seed.file);
    CodeQueryResultRef::StructuralMatch {
        id: full.then(|| match_id(&path, fact.kind.label(), fact.span())),
        path,
        kind: fact.kind.label(),
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
        node_range: full.then(|| range_for_span(&seed.facts, fact.span())),
    }
}

fn render_declaration_ref(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let path = rel_path_string(declaration.unit.source());
    let fq_name = declaration.unit.fq_name();
    let kind = declaration.unit.kind().display_lowercase();
    let full = !detail.is_compact();
    CodeQueryResultRef::Declaration {
        id: full.then(|| declaration_id(&path, kind, &fq_name, declaration.range)),
        path,
        kind,
        fq_name,
        start_line: declaration.range.start_line,
        end_line: declaration.range.end_line,
        node_range: full
            .then(|| cache.range_for_declaration(analyzer, declaration))
            .flatten(),
    }
}

fn render_file_ref(file: &ProjectFile) -> CodeQueryResultRef {
    CodeQueryResultRef::File {
        path: rel_path_string(file),
    }
}

fn render_reference_site_ref(
    analyzer: &dyn IAnalyzer,
    site: &ReferenceSiteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let target_path = rel_path_string(site.target.unit.source());
    let target_fq_name = site.target.unit.fq_name();
    let target_kind = site.target.unit.kind().display_lowercase();
    CodeQueryResultRef::ReferenceSite {
        path: rel_path_string(&site.file),
        range: render_reference_range(analyzer, site, cache),
        target_id: (!detail.is_compact()).then(|| {
            declaration_id(
                &target_path,
                target_kind,
                &target_fq_name,
                site.target.range,
            )
        }),
        target_fq_name,
        usage_kind: (site.usage_kind != UsageHitKind::Reference)
            .then(|| site.usage_kind.wire_label()),
        proof: usage_proof_label(site.proof),
        reference_kind: site.reference_kind.map(reference_kind_label),
    }
}

fn render_call_site_ref(
    analyzer: &dyn IAnalyzer,
    site: &CallSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    CodeQueryResultRef::CallSite {
        path: rel_path_string(&site.0.file),
        range: render_source_range(analyzer, &site.0.file, &site.0.range, cache),
        caller_fq_name: site.0.caller.fq_name(),
        callee_fq_name: site.0.callee.fq_name(),
        proof: usage_proof_label(site.0.proof),
    }
}

fn render_expression_site_ref(
    analyzer: &dyn IAnalyzer,
    site: &ExpressionSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
    CodeQueryResultRef::ExpressionSite {
        path: rel_path_string(&site.call_site.0.file),
        range: render_source_range(analyzer, &site.call_site.0.file, &site.range, cache),
        input_kind,
        parameter_index,
        parameter_name,
    }
}

fn render_receiver_analysis_ref(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    CodeQueryResultRef::ReceiverAnalysis {
        path: rel_path_string(&value.report.site.file),
        range: render_source_range(
            analyzer,
            &value.report.site.file,
            &value.report.site.range,
            cache,
        ),
        analysis_kind: value.report.operation.as_str(),
        outcome: receiver_query_outcome_label(&value.report.analysis),
        capture: value.capture.clone(),
    }
}

fn render_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryDeclaration {
    let path = rel_path_string(declaration.unit.source());
    let fq_name = declaration.unit.fq_name();
    let kind = declaration.unit.kind().display_lowercase();
    let full = !detail.is_compact();
    let signature = declaration
        .unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures_of(&declaration.unit).into_iter().next());
    CodeQueryDeclaration {
        id: full.then(|| declaration_id(&path, kind, &fq_name, declaration.range)),
        path,
        language: crate::analyzer::common::language_for_file(declaration.unit.source())
            .config_label(),
        kind,
        fq_name,
        start_line: declaration.range.start_line,
        end_line: declaration.range.end_line,
        signature,
        node_range: full
            .then(|| cache.range_for_declaration(analyzer, declaration))
            .flatten(),
    }
}

fn render_file(file: &ProjectFile) -> CodeQueryFile {
    CodeQueryFile {
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
    }
}

fn render_reference_site(
    analyzer: &dyn IAnalyzer,
    site: &ReferenceSiteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReferenceSite {
    CodeQueryReferenceSite {
        path: rel_path_string(&site.file),
        language: crate::analyzer::common::language_for_file(&site.file).config_label(),
        range: render_reference_range(analyzer, site, cache),
        target: render_declaration(analyzer, &site.target, detail, cache),
        enclosing_declaration: site
            .enclosing
            .as_ref()
            .map(|declaration| render_declaration(analyzer, declaration, detail, cache)),
        usage_kind: site.usage_kind.wire_label(),
        proof: usage_proof_label(site.proof),
        reference_kind: site.reference_kind.map(reference_kind_label),
    }
}

fn render_call_site(
    analyzer: &dyn IAnalyzer,
    site: &CallSiteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallSite {
    let caller = declaration_value_for_unit(analyzer, &site.0.caller, site.0.range);
    let callee = declaration_value_for_unit(analyzer, &site.0.callee, site.0.callee_range);
    CodeQueryCallSite {
        path: rel_path_string(&site.0.file),
        language: crate::analyzer::common::language_for_file(&site.0.file).config_label(),
        range: render_source_range(analyzer, &site.0.file, &site.0.range, cache),
        callee_range: render_source_range(analyzer, &site.0.file, &site.0.callee_range, cache),
        caller: render_declaration(analyzer, &caller, detail, cache),
        callee: render_declaration(analyzer, &callee, detail, cache),
        call_kind: call_syntax_kind_label(site.0.kind),
        proof: usage_proof_label(site.0.proof),
        receiver: site
            .0
            .receiver
            .as_ref()
            .map(|range| render_source_range(analyzer, &site.0.file, range, cache)),
        arguments: site
            .0
            .arguments
            .iter()
            .map(|argument| CodeQueryCallArgument {
                range: render_source_range(analyzer, &site.0.file, &argument.range, cache),
                name: argument.name.clone(),
                position: argument.position,
                formal_index: argument.formal_index,
                formal_name: argument.formal_name.clone(),
                variadic: argument.variadic,
                spread: argument.spread,
            })
            .collect(),
    }
}

fn render_expression_site(
    analyzer: &dyn IAnalyzer,
    site: &ExpressionSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryExpressionSite {
    let file = &site.call_site.0.file;
    let text = cache
        .coordinates_for(file, || analyzer.indexed_source(file))
        .and_then(|coordinates| {
            coordinates
                .source
                .get(site.range.start_byte..site.range.end_byte)
        })
        .map(snippet)
        .unwrap_or_default();
    let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
    CodeQueryExpressionSite {
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
        range: render_source_range(analyzer, file, &site.range, cache),
        text,
        input_kind,
        parameter_index,
        parameter_name,
        caller_fq_name: site.call_site.0.caller.fq_name(),
        callee_fq_name: site.call_site.0.callee.fq_name(),
        call_range: render_source_range(analyzer, file, &site.call_site.0.range, cache),
    }
}

fn render_receiver_analysis(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReceiverAnalysis {
    let fallback = value.report.site.range;
    let (outcome, values, member_targets, reason, limit) = match &value.report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => {
            let rendered = outcome
                .values()
                .into_iter()
                .flatten()
                .map(|value| render_receiver_value(analyzer, value, fallback, detail, cache))
                .collect();
            let (label, reason, limit) = receiver_outcome_metadata(outcome);
            (label, rendered, Vec::new(), reason, limit)
        }
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            let rendered = outcome
                .values()
                .into_iter()
                .flatten()
                .map(|unit| {
                    let declaration = declaration_value_for_unit(analyzer, unit, fallback);
                    render_declaration(analyzer, &declaration, detail, cache)
                })
                .collect();
            let (label, reason, limit) = receiver_outcome_metadata(outcome);
            (label, Vec::new(), rendered, reason, limit)
        }
    };
    CodeQueryReceiverAnalysis {
        analysis_kind: value.report.operation.as_str(),
        path: rel_path_string(&value.report.site.file),
        language: value.report.site.language.config_label(),
        range: render_source_range(
            analyzer,
            &value.report.site.file,
            &value.report.site.range,
            cache,
        ),
        text: snippet(&value.report.site.text),
        input_kind: value.report.site.syntax_kind.clone(),
        capture: value.capture.clone(),
        outcome,
        values,
        member_targets,
        reason,
        limit,
    }
}

fn render_receiver_value(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverValue,
    fallback: Range,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReceiverValue {
    let declaration = |unit: &CodeUnit, cache: &mut PipelineRenderCache| {
        let value = declaration_value_for_unit(analyzer, unit, fallback);
        render_declaration(analyzer, &value, detail, cache)
    };
    match value {
        ReceiverValue::AllocationSite { ty, file, range } => {
            CodeQueryReceiverValue::AllocationSite {
                type_declaration: declaration(ty, cache),
                allocation_site: CodeQuerySourceSite {
                    path: rel_path_string(file),
                    range: render_source_range(analyzer, file, range, cache),
                },
            }
        }
        ReceiverValue::InstanceType(unit) => CodeQueryReceiverValue::InstanceType {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::ClassOrStaticObject(unit) => CodeQueryReceiverValue::ClassOrStaticObject {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::ModuleOrExportObject(unit) => CodeQueryReceiverValue::ModuleOrExportObject {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::CurrentReceiver(unit) => CodeQueryReceiverValue::CurrentReceiver {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::FactoryReturn { factory, value } => CodeQueryReceiverValue::FactoryReturn {
            factory: declaration(factory, cache),
            returned_value: Box::new(render_receiver_value(
                analyzer, value, fallback, detail, cache,
            )),
        },
    }
}

fn receiver_query_outcome_label(analysis: &ReceiverQueryAnalysis) -> &'static str {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => receiver_outcome_metadata(outcome).0,
        ReceiverQueryAnalysis::MemberTargets(outcome) => receiver_outcome_metadata(outcome).0,
    }
}

fn receiver_outcome_metadata<T>(
    outcome: &ReceiverAnalysisOutcome<T>,
) -> (&'static str, Option<&'static str>, Option<&'static str>) {
    match outcome {
        ReceiverAnalysisOutcome::Precise(_) => ("precise", None, None),
        ReceiverAnalysisOutcome::Ambiguous(_) => ("ambiguous", None, None),
        ReceiverAnalysisOutcome::Unknown => ("unknown", None, None),
        ReceiverAnalysisOutcome::Unsupported { reason } => ("unsupported", Some(*reason), None),
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            ("exceeded_budget", None, Some(*limit))
        }
    }
}

fn expression_input_parts(
    input: &ExpressionInput,
) -> (&'static str, Option<usize>, Option<String>) {
    match input {
        ExpressionInput::Receiver => ("receiver", None, None),
        ExpressionInput::Parameter { index, name } => ("parameter", Some(*index), name.clone()),
    }
}

fn declaration_value_for_unit(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    fallback: Range,
) -> DeclarationValue {
    DeclarationValue {
        unit: unit.clone(),
        range: analyzer
            .ranges_of(unit)
            .into_iter()
            .min_by_key(primary_range_key)
            .unwrap_or(fallback),
    }
}

fn call_syntax_kind_label(kind: CallSyntaxKind) -> &'static str {
    match kind {
        CallSyntaxKind::Function => "function",
        CallSyntaxKind::Method => "method",
        CallSyntaxKind::Constructor => "constructor",
        CallSyntaxKind::Super => "super",
    }
}

fn render_reference_range(
    analyzer: &dyn IAnalyzer,
    site: &ReferenceSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryRange {
    render_source_range(analyzer, &site.file, &site.range, cache)
}

fn render_source_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    range: &Range,
    cache: &mut PipelineRenderCache,
) -> CodeQueryRange {
    cache
        .coordinates_for(file, || analyzer.indexed_source(file))
        .map(|coordinates| {
            range_for_offsets(
                &coordinates.source,
                &coordinates.line_starts,
                range.start_byte,
                range.end_byte,
            )
        })
        .unwrap_or(CodeQueryRange {
            start_line: range.start_line,
            start_column: 1,
            end_line: range.end_line,
            end_column: 1,
        })
}

fn declaration_id(path: &str, kind: &str, fq_name: &str, range: Range) -> String {
    format!(
        "{path}:{kind}:{fq_name}:{}-{}",
        range.start_byte, range.end_byte
    )
}

fn range_for_offsets(
    source: &str,
    line_starts: &[usize],
    start_byte: usize,
    end_byte: usize,
) -> CodeQueryRange {
    let (start_line, start_column) = line_column_for_offset(source, line_starts, start_byte);
    let (end_line, end_column) = line_column_for_offset(source, line_starts, end_byte);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

fn provider_supports_feature(
    provider: &dyn super::StructuralSearchProvider,
    feature: QueryFeature,
) -> bool {
    match feature {
        QueryFeature::Kind(kind) => provider.structural_supports_kind(kind),
        QueryFeature::Role(role) => provider.structural_supports_role(role),
    }
}

fn push_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code execution budget exhausted after scanning {} files, {} bytes, {} facts, and examining {} references; refine the query with where, languages, kind/name anchors, or a narrower pattern",
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.examined_references
        ),
    });
}

fn push_pipeline_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.branch.is_empty()
            && diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::PipelineBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code pipeline budget exhausted after producing {} seed and edge rows; refine the match, where, or languages filters",
            budget.pipeline_rows
        ),
    });
}

fn push_import_graph_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    graph: &DirectImportGraph,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code import graph budget exhausted after resolving {} files and {} direct edges; import traversal results are partial",
            graph.resolved_files, graph.resolved_edges
        ),
    });
}

fn push_truncation_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
    limit: usize,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ResultLimitReached,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code returned the first {limit} results after scanning {} files, {} bytes, {} facts, and examining {} references; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern",
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.examined_references
        ),
    });
}

fn should_report_broad_query(
    plan: &QueryPlan,
    query: &CodeQuerySeed,
    budget: &CodeQueryExecutionBudget,
    truncated: bool,
) -> bool {
    !plan.has_source_anchors()
        && query.where_globs.is_empty()
        && query.languages.is_empty()
        && (truncated || budget.scanned_files >= BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD)
}

fn push_broad_query_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::BroadQuery,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "broad unanchored query_code query scanned {} files, {} bytes, {} facts, and examined {} references; add where, languages, exact name predicates, or a more specific pattern to reduce work and output",
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.examined_references
        ),
    });
}

fn file_matches_globs(file: &ProjectFile, query: &CodeQuerySeed) -> bool {
    if query.where_globs.is_empty() {
        return true;
    }
    let rel_path = rel_path_string(file);
    query.where_globs.iter().any(|glob| glob.matches(&rel_path))
}

fn render_match(
    analyzer: &dyn IAnalyzer,
    language: Language,
    file: &ProjectFile,
    facts: &FileFacts,
    fact_match: &FactMatch,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryMatch {
    let fact = facts.node(fact_match.node);
    let full_detail = matches!(detail, CodeQueryResultDetail::Full);
    let path = rel_path_string(file);
    let captures = fact_match
        .captures
        .iter()
        .map(|capture| CodeQueryCapture {
            name: capture.name.clone(),
            text: snippet(capture.span.text(facts.source())),
            start_line: facts.line_of_byte(capture.span.start_byte),
            range: full_detail.then(|| range_for_span(facts, capture.span)),
            kind: if full_detail {
                capture.kind.map(|kind| kind.label())
            } else {
                None
            },
        })
        .collect();
    let node_range = full_detail.then(|| range_for_span(facts, fact.span()));
    let decorator_spans: Vec<_> = if full_detail {
        facts
            .role_targets(fact_match.node, Role::Decorator)
            .map(|target| target.span)
            .collect()
    } else {
        Vec::new()
    };
    let decorator_ranges = decorator_spans
        .iter()
        .map(|&span| range_for_span(facts, span))
        .collect::<Vec<_>>();
    let decorated_range = if full_detail && !decorator_spans.is_empty() {
        let mut decorated = fact.span();
        for span in decorator_spans {
            decorated.start_byte = decorated.start_byte.min(span.start_byte);
            decorated.end_byte = decorated.end_byte.max(span.end_byte);
        }
        Some(range_for_span(facts, decorated))
    } else {
        None
    };
    CodeQueryMatch {
        id: full_detail.then(|| match_id(&path, fact.kind.label(), fact.span())),
        path,
        language: language.config_label(),
        kind: fact.kind.label(),
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
        text: snippet(fact.span().text(facts.source())),
        node_range,
        decorated_range,
        decorator_ranges,
        captures,
        enclosing_symbol: cache
            .enclosing_unit_for_lines(analyzer, file, fact.range.start_line, fact.range.end_line)
            .map(|code_unit| code_unit.fq_name()),
    }
}

fn match_id(path: &str, kind: &str, span: Span) -> String {
    format!("{path}:{kind}:{}-{}", span.start_byte, span.end_byte)
}

fn range_for_span(facts: &FileFacts, span: Span) -> CodeQueryRange {
    let (start_line, start_column) = facts.line_column_of_byte(span.start_byte);
    let (end_line, end_column) = facts.line_column_of_byte(span.end_byte);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

/// First line of `text`, truncated to [`SNIPPET_MAX_CHARS`] on a char
/// boundary, with an ellipsis when anything was dropped.
fn snippet(text: &str) -> String {
    let first_line = text.lines().next().unwrap_or("");
    let mut end = first_line.len().min(SNIPPET_MAX_CHARS);
    while !first_line.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = first_line[..end].to_string();
    if end < text.len() {
        result.push('…');
    }
    result
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
                if !result.provenance.is_empty() {
                    let mut branch_labels = Vec::new();
                    for trace in &result.provenance {
                        let label = format_branch_path(&trace.branch);
                        if !label.is_empty() && !branch_labels.contains(&label) {
                            branch_labels.push(label);
                        }
                    }
                    out.push_str(&format!(
                        "  provenance: {} path{}{}{}\n",
                        result.provenance.len(),
                        if result.provenance.len() == 1 {
                            ""
                        } else {
                            "s"
                        },
                        if result.provenance_truncated {
                            " (truncated)"
                        } else {
                            ""
                        },
                        if branch_labels.is_empty() {
                            String::new()
                        } else {
                            format!("; branches {}", branch_labels.join(", "))
                        },
                    ));
                }
            }
        }
        for diagnostic in &self.diagnostics {
            let label = format!(
                "{} [{}]",
                diagnostic.impact.as_str(),
                diagnostic.code.as_str()
            );
            if diagnostic.branch.is_empty() {
                out.push_str(&format!("{label}: {}\n", diagnostic.message));
            } else {
                out.push_str(&format!(
                    "{label} [branch {}]: {}\n",
                    format_branch_path(&diagnostic.branch),
                    diagnostic.message
                ));
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::CodeQuery;
    use crate::analyzer::usages::get_definition::ResolvedReferenceSite;
    use crate::analyzer::{CodeUnitType, TestProject, TypescriptAnalyzer};
    use serde_json::json;
    use std::cell::Cell;
    use std::path::PathBuf;

    fn diagnostic(
        code: CodeQueryDiagnosticCode,
        impact: CodeQueryDiagnosticImpact,
    ) -> CodeQueryDiagnostic {
        CodeQueryDiagnostic {
            code,
            impact,
            branch: Vec::new(),
            language: "workspace",
            message: "prose deliberately carries no classification words".to_string(),
        }
    }

    #[test]
    fn diagnostic_codes_have_exhaustive_stable_impacts_and_completion() {
        use CodeQueryDiagnosticCode as Code;
        use CodeQueryDiagnosticImpact as Impact;

        let cases = [
            (Code::InvalidPlan, Impact::Invalid),
            (Code::Cancelled, Impact::Incomplete),
            (Code::UnsupportedStructuralFeature, Impact::Incomplete),
            (Code::MissingStructuralAdapter, Impact::Incomplete),
            (Code::UnsupportedImportAnalysis, Impact::Incomplete),
            (Code::SemanticResultsOmitted, Impact::Incomplete),
            (Code::ReceiverAnalysisPartial, Impact::Incomplete),
            (Code::CallRelationBudgetExhausted, Impact::Incomplete),
            (Code::CallRelationParseFailed, Impact::Incomplete),
            (Code::CallRelationCandidatesOmitted, Impact::Incomplete),
            (Code::CallRelationTargetsAmbiguous, Impact::Advisory),
            (Code::CallRelationCandidateLimit, Impact::Incomplete),
            (Code::CallRelationAnalysisFailed, Impact::Incomplete),
            (Code::ReferenceSourceBytesTruncated, Impact::Incomplete),
            (Code::ReferenceCandidateFilesTruncated, Impact::Incomplete),
            (Code::ReferenceCandidatesOmitted, Impact::Incomplete),
            (Code::ReferenceTargetsAmbiguous, Impact::Advisory),
            (Code::ReferenceCallsiteLimit, Impact::Incomplete),
            (Code::ReferenceAnalysisFailed, Impact::Incomplete),
            (Code::UsesParserUnsupported, Impact::Incomplete),
            (Code::UsesCandidateLimit, Impact::Incomplete),
            (Code::UsesTargetsAmbiguous, Impact::Advisory),
            (Code::UsesCandidatesOmitted, Impact::Incomplete),
            (Code::ExecutionBudgetExhausted, Impact::Incomplete),
            (Code::PipelineBudgetExhausted, Impact::Incomplete),
            (Code::ImportGraphBudgetExhausted, Impact::Incomplete),
            (Code::ResultLimitReached, Impact::Incomplete),
            (Code::BroadQuery, Impact::Advisory),
        ];

        for (code, impact) in cases {
            let result = CodeQueryResult {
                results: Vec::new(),
                truncated: false,
                diagnostics: vec![diagnostic(code, impact)],
            };
            let serialized = serde_json::to_value(&result).expect("serialize query result");
            assert_eq!(serialized["diagnostics"][0]["code"], code.as_str());
            assert_eq!(serialized["diagnostics"][0]["impact"], impact.as_str());
            assert!(
                result
                    .render_text()
                    .contains(&format!("{} [{}]", impact.as_str(), code.as_str())),
                "code {code:?} did not retain its typed label in text output"
            );
            let expected = match (code, impact) {
                (Code::InvalidPlan, _) => CodeQueryCompletion::Invalid {
                    codes: vec![Code::InvalidPlan],
                },
                (Code::Cancelled, _) => CodeQueryCompletion::Cancelled,
                (_, Impact::Incomplete) => CodeQueryCompletion::Incomplete { codes: vec![code] },
                (_, Impact::Advisory) => CodeQueryCompletion::Complete,
                (_, Impact::Invalid) => unreachable!("only InvalidPlan is invalid"),
            };
            assert_eq!(result.completion(), expected, "code {code:?}");
        }

        assert_eq!(
            CodeQueryResult {
                results: Vec::new(),
                truncated: true,
                diagnostics: Vec::new(),
            }
            .completion(),
            CodeQueryCompletion::Incomplete { codes: Vec::new() }
        );
    }

    #[test]
    fn typed_diagnostic_producers_cover_budget_output_and_cancellation() {
        let mut diagnostics = Vec::new();
        let budget = CodeQueryExecutionBudget::default();
        push_budget_diagnostic(&mut diagnostics, &budget);
        push_pipeline_budget_diagnostic(&mut diagnostics, &budget);
        push_import_graph_budget_diagnostic(&mut diagnostics, &DirectImportGraph::default());
        push_truncation_diagnostic(&mut diagnostics, &budget, 1);
        push_broad_query_diagnostic(&mut diagnostics, &budget);

        assert_eq!(
            diagnostics
                .iter()
                .map(|diagnostic| (diagnostic.code, diagnostic.impact))
                .collect::<Vec<_>>(),
            vec![
                (
                    CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
                    CodeQueryDiagnosticImpact::Incomplete,
                ),
                (
                    CodeQueryDiagnosticCode::PipelineBudgetExhausted,
                    CodeQueryDiagnosticImpact::Incomplete,
                ),
                (
                    CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
                    CodeQueryDiagnosticImpact::Incomplete,
                ),
                (
                    CodeQueryDiagnosticCode::ResultLimitReached,
                    CodeQueryDiagnosticImpact::Incomplete,
                ),
                (
                    CodeQueryDiagnosticCode::BroadQuery,
                    CodeQueryDiagnosticImpact::Advisory,
                ),
            ]
        );
        assert!(matches!(
            cancelled_query_result().completion(),
            CodeQueryCompletion::Cancelled
        ));
    }

    #[test]
    fn call_relation_diagnostics_map_without_inspecting_messages() {
        use CallRelationDiagnosticCode as Lower;
        use CodeQueryDiagnosticCode as Code;
        use CodeQueryDiagnosticImpact as Impact;

        let cases = [
            (
                Lower::BudgetExhausted,
                Code::CallRelationBudgetExhausted,
                Impact::Incomplete,
            ),
            (
                Lower::ParseFailed,
                Code::CallRelationParseFailed,
                Impact::Incomplete,
            ),
            (
                Lower::CandidatesOmitted,
                Code::CallRelationCandidatesOmitted,
                Impact::Incomplete,
            ),
            (
                Lower::TargetsAmbiguous,
                Code::CallRelationTargetsAmbiguous,
                Impact::Advisory,
            ),
            (
                Lower::CandidateLimit,
                Code::CallRelationCandidateLimit,
                Impact::Incomplete,
            ),
            (
                Lower::AnalysisFailed,
                Code::CallRelationAnalysisFailed,
                Impact::Incomplete,
            ),
        ];
        for (lower, code, impact) in cases {
            let mapped = map_call_relation_diagnostic(
                "rust",
                CallRelationDiagnostic {
                    code: lower,
                    message: "same prose for every producer".to_string(),
                    context: "crate::function".to_string(),
                    reason_kind: (lower == Lower::AnalysisFailed)
                        .then(|| "unsupported_target_shape".to_string()),
                },
            );
            assert_eq!((mapped.code, mapped.impact), (code, impact));
        }
    }

    #[test]
    fn outbound_uses_missing_reference_or_definitions_is_typed_incomplete() {
        let root = std::env::temp_dir().join("bifrost-outbound-lookup-completeness");
        let file = ProjectFile::new(root, "src/app.ts");
        let definition = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let reference = ResolvedReferenceSite {
            path: "src/app.ts".to_string(),
            text: "target".to_string(),
            range: Range {
                start_byte: 10,
                end_byte: 16,
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: 10,
            focus_end_byte: 16,
        };
        let grouped = group_outbound_lookup_candidates(vec![
            DefinitionLookupOutcome {
                status: DefinitionLookupStatus::Ambiguous,
                reference: None,
                definitions: vec![definition],
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
            DefinitionLookupOutcome {
                status: DefinitionLookupStatus::Ambiguous,
                reference: Some(reference),
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
        ]);

        assert_eq!(grouped.omitted_sites, 2);
        assert_eq!(grouped.ambiguous_sites, 2);
        assert!(!grouped.ambiguous_candidates_complete);
        let mut diagnostics = Vec::new();
        append_outbound_lookup_diagnostics(
            &mut diagnostics,
            Language::TypeScript,
            &file,
            grouped.ambiguous_sites,
            grouped.ambiguous_candidates_complete,
            grouped.omitted_sites,
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::UsesCandidatesOmitted
        );
        assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
        assert!(matches!(
            CodeQueryResult {
                results: Vec::new(),
                truncated: false,
                diagnostics,
            }
            .completion(),
            CodeQueryCompletion::Incomplete { codes }
                if codes == vec![CodeQueryDiagnosticCode::UsesCandidatesOmitted]
        ));
    }

    #[test]
    fn outbound_uses_ambiguity_is_advisory_only_when_every_target_survives() {
        let root = std::env::temp_dir().join("bifrost-outbound-lookup-advisory");
        let file = ProjectFile::new(root, "src/app.ts");
        let mut diagnostics = Vec::new();
        append_outbound_lookup_diagnostics(
            &mut diagnostics,
            Language::TypeScript,
            &file,
            1,
            true,
            0,
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::UsesTargetsAmbiguous
        );
        assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Advisory);
    }

    #[test]
    fn call_declaration_projection_reports_retained_file_scope_target_as_omitted() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/app.ts");
        let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
        let unprojectable = CodeUnit::file_scope(file.clone());
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        };
        let declaration = DeclarationValue {
            unit: caller.clone(),
            range,
        };
        let site = CallSite {
            file,
            range,
            callee_range: range,
            caller: caller.clone(),
            callee: unprojectable,
            kind: CallSyntaxKind::Function,
            proof: UsageProof::Unproven,
            receiver: None,
            arguments: Vec::new(),
        };
        let mut cache = CallTraversalCache::default();
        cache.outgoing.insert(
            caller,
            CallRelationResult {
                sites: vec![site],
                diagnostics: vec![CallRelationDiagnostic {
                    code: CallRelationDiagnosticCode::TargetsAmbiguous,
                    message: "ambiguous".to_string(),
                    context: "caller".to_string(),
                    reason_kind: None,
                }],
                ..CallRelationResult::default()
            },
        );
        let mut diagnostics = Vec::new();

        let (expansions, exhausted) = call_declaration_expansions(
            &analyzer,
            &declaration,
            &QueryStep::Callees(CallTraversalFilter::default()),
            &CallTraversalFilter::default(),
            &mut IndexedDeclarations::default(),
            &mut cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            8,
            None,
            &mut diagnostics,
        );

        assert!(expansions.is_empty());
        assert!(exhausted);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::CallRelationCandidatesOmitted
        );
        assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    }

    #[test]
    fn outbound_uses_projection_reports_unindexed_target_and_suppresses_advisory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/app.ts");
        let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
        let declaration = DeclarationValue {
            unit: caller.clone(),
            range: Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            },
        };
        let mut cache = ReferenceTraversalCache::default();
        cache.outbound.insert(
            file.clone(),
            vec![ReferenceHit {
                file,
                range: declaration.range,
                enclosing_unit: caller,
                kind: None,
                resolved: CodeUnit::file_scope(declaration.unit.source().clone()),
                confidence: 1_000_000,
                usage_kind: UsageHitKind::Reference,
                proof: UsageProof::Unproven,
            }],
        );
        let mut diagnostics = vec![diagnostic(
            CodeQueryDiagnosticCode::UsesTargetsAmbiguous,
            CodeQueryDiagnosticImpact::Advisory,
        )];

        let (expansions, exhausted) = outbound_reference_expansions(
            &analyzer,
            &declaration,
            &ReferenceTraversalFilter::default(),
            &mut IndexedDeclarations::default(),
            &mut cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            8,
            None,
            &mut diagnostics,
        );

        assert!(expansions.is_empty());
        assert!(exhausted);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::UsesCandidatesOmitted
        );
        assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    }

    fn formal_call_site_value(binding: CallBindingStatus) -> CallSiteValue {
        let root = std::env::temp_dir().join("bifrost-call-input-completeness");
        let file = ProjectFile::new(root, "src/app.ts");
        let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
        let callee = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "callee");
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        };
        CallSiteValue(
            CallSite {
                file,
                range,
                callee_range: range,
                caller,
                callee,
                kind: CallSyntaxKind::Function,
                proof: UsageProof::Proven,
                receiver: None,
                arguments: vec![CallArgument {
                    range,
                    name: None,
                    position: Some(0),
                    formal_index: (binding == CallBindingStatus::Complete).then_some(0),
                    formal_name: (binding == CallBindingStatus::Complete)
                        .then(|| "payload".to_string()),
                    variadic: false,
                    spread: false,
                }],
            },
            binding,
        )
    }

    #[test]
    fn formal_call_input_with_unavailable_binding_is_incomplete() {
        let site = formal_call_site_value(CallBindingStatus::Unavailable);

        let (expansions, incomplete) =
            call_input_expansions(&site, &CallInputSelector::ParameterIndex(0));

        assert!(expansions.is_empty());
        assert!(incomplete);
    }

    #[test]
    fn formal_call_input_with_known_nonmatching_binding_is_complete() {
        let site = formal_call_site_value(CallBindingStatus::Complete);

        let (missing, incomplete) =
            call_input_expansions(&site, &CallInputSelector::ParameterIndex(1));
        let (exact, exact_incomplete) = call_input_expansions(
            &site,
            &CallInputSelector::ParameterName("payload".to_string()),
        );

        assert!(missing.is_empty());
        assert!(!incomplete);
        assert_eq!(exact.len(), 1, "known exact bindings remain positive");
        assert!(!exact_incomplete);
    }

    #[test]
    fn formal_call_input_with_spread_argument_is_incomplete() {
        let mut site = formal_call_site_value(CallBindingStatus::Complete);
        site.0.arguments[0].formal_index = None;
        site.0.arguments[0].formal_name = None;
        site.0.arguments[0].spread = true;

        let (expansions, incomplete) =
            call_input_expansions(&site, &CallInputSelector::ParameterIndex(0));

        assert!(expansions.is_empty());
        assert!(incomplete);
    }

    #[test]
    fn m3_inbound_reference_distinguishes_missing_real_owner_from_file_scope() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/app.ts");
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let missing_owner = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        };
        let declaration = DeclarationValue {
            unit: target.clone(),
            range,
        };
        let reference_hit = |enclosing_unit| ReferenceHit {
            file: file.clone(),
            range,
            enclosing_unit,
            kind: None,
            resolved: target.clone(),
            confidence: 1_000_000,
            usage_kind: UsageHitKind::Reference,
            proof: UsageProof::Unproven,
        };
        let filter = ReferenceTraversalFilter::default();
        let step = QueryStep::UsedBy(filter.clone());

        let mut missing_cache = ReferenceTraversalCache::default();
        missing_cache
            .inbound
            .insert(target.clone(), vec![reference_hit(missing_owner)]);
        let mut diagnostics = vec![diagnostic(
            CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous,
            CodeQueryDiagnosticImpact::Advisory,
        )];
        let (expansions, exhausted) = inbound_reference_expansions(
            &analyzer,
            &declaration,
            &step,
            &filter,
            &mut IndexedDeclarations::default(),
            &mut missing_cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            &mut diagnostics,
            8,
            None,
        );

        assert!(expansions.is_empty());
        assert!(exhausted);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::ReferenceCandidatesOmitted
        );
        assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);

        let mut file_scope_cache = ReferenceTraversalCache::default();
        file_scope_cache.inbound.insert(
            target.clone(),
            vec![reference_hit(CodeUnit::file_scope(file.clone()))],
        );
        let mut diagnostics = Vec::new();
        let (expansions, exhausted) = inbound_reference_expansions(
            &analyzer,
            &declaration,
            &step,
            &filter,
            &mut IndexedDeclarations::default(),
            &mut file_scope_cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            &mut diagnostics,
            8,
            None,
        );

        assert!(expansions.is_empty());
        assert!(!exhausted);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn m3_inbound_reference_bounded_samples_remain_positive_and_incomplete() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/app.ts");
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let caller = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "caller");
        let sample_hits = [
            UsageHit::new(file.clone(), 1, 0, 6, caller.clone(), 1.0, "target"),
            UsageHit::new(file, 2, 8, 14, caller, 1.0, "target"),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();

        let (hits, incomplete) = reference_hits_for_target(
            &analyzer,
            FuzzyResult::TooManyCallsites {
                short_name: "target".to_string(),
                total_callsites: 2,
                limit: 1,
                sample_hits,
            },
            &target,
        );

        assert!(incomplete);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].resolved, target);
        assert_eq!(hits[0].proof, UsageProof::Proven);
    }

    #[test]
    fn outbound_uses_scan_without_indexed_source_is_incomplete() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/missing.ts");
        let mut diagnostics = Vec::new();

        let (hits, exhausted) = scan_outbound_reference_hits(
            &analyzer,
            &file,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            8,
            None,
            &mut diagnostics,
        );

        assert!(hits.is_empty());
        assert!(exhausted);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::UsesCandidatesOmitted
        );
        assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
    }

    #[test]
    fn members_projection_reports_unindexed_direct_child_as_semantic_omission() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let file = ProjectFile::new(root, "src/app.ts");
        let declaration = DeclarationValue {
            unit: CodeUnit::new(file.clone(), CodeUnitType::Class, "", "Owner"),
            range: Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            },
        };
        let mut omissions = BTreeMap::new();

        let (expansions, exhausted) = direct_member_expansions(
            &analyzer,
            &declaration,
            vec![CodeUnit::file_scope(file)],
            &mut IndexedDeclarations::default(),
            &mut CodeQueryExecutionBudget::default(),
            8,
            &mut omissions,
        );
        let mut diagnostics = Vec::new();
        append_semantic_omission_diagnostics(&mut diagnostics, &QueryStep::Members, omissions);

        assert!(expansions.is_empty());
        assert!(exhausted);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::SemanticResultsOmitted
        );
        assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
        assert!(matches!(
            CodeQueryResult {
                results: Vec::new(),
                truncated: exhausted,
                diagnostics,
            }
            .completion(),
            CodeQueryCompletion::Incomplete { .. }
        ));
    }

    #[test]
    fn hierarchy_projection_keeps_exact_rows_and_reports_unindexed_relations() {
        let source = "class Exact {}\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/app.ts");
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root.clone(), Language::TypeScript));
        let exact = analyzer
            .all_declarations()
            .find(|unit| unit.short_name() == "Exact")
            .expect("exact class declaration");
        let missing_file = ProjectFile::new(root, "src/missing.ts");
        let missing = CodeUnit::new(missing_file, CodeUnitType::Class, "", "Missing");
        let mut indexed = IndexedDeclarations::default();
        let mut omissions = BTreeMap::new();
        let mut exhausted = false;

        let retained = project_hierarchy_declaration(
            &analyzer,
            &exact,
            &mut indexed,
            &mut omissions,
            &mut exhausted,
        );
        let omitted = project_hierarchy_declaration(
            &analyzer,
            &missing,
            &mut indexed,
            &mut omissions,
            &mut exhausted,
        );
        let mut diagnostics = Vec::new();
        append_semantic_omission_diagnostics(
            &mut diagnostics,
            &QueryStep::Supertypes(HierarchyTraversal::Direct),
            omissions,
        );

        assert!(retained.is_some(), "an exact hierarchy row must survive");
        assert!(omitted.is_none());
        assert!(exhausted);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::SemanticResultsOmitted
        );
        assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
        assert!(matches!(
            CodeQueryResult {
                results: Vec::new(),
                truncated: exhausted,
                diagnostics,
            }
            .completion(),
            CodeQueryCompletion::Incomplete { .. }
        ));
    }

    #[test]
    fn enclosing_declaration_index_retains_exact_owner_and_reports_missing_real_range() {
        let root = std::env::temp_dir().join("bifrost-enclosing-declaration-completeness");
        let file = ProjectFile::new(root, "src/app.ts");
        let exact = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "exact");
        let missing = CodeUnit::new(file, CodeUnitType::Function, "", "missing");
        let exact_range = Range {
            start_byte: 0,
            end_byte: 20,
            start_line: 1,
            end_line: 2,
        };
        let seed_range = Range {
            start_byte: 5,
            end_byte: 10,
            start_line: 1,
            end_line: 1,
        };
        let mut index = EnclosingDeclarationIndex::default();
        index.retain(exact.clone(), [exact_range]);
        index.retain(missing, std::iter::empty());
        index.sort();

        let retained = index.enclosing(seed_range).expect("exact owner survives");

        assert_eq!(retained.unit, exact);
        assert!(index.projection_omitted);
        let mut diagnostics = Vec::new();
        append_semantic_omission_diagnostics(
            &mut diagnostics,
            &QueryStep::EnclosingDecl,
            BTreeMap::from([(
                (
                    Language::TypeScript,
                    "a real declaration in the seed file had no exact indexed range",
                ),
                1,
            )]),
        );
        assert!(matches!(
            CodeQueryResult {
                results: Vec::new(),
                truncated: index.projection_omitted,
                diagnostics,
            }
            .completion(),
            CodeQueryCompletion::Incomplete { .. }
        ));
    }

    #[test]
    fn enclosing_declaration_index_treats_file_scope_no_owner_as_complete() {
        let root = std::env::temp_dir().join("bifrost-enclosing-file-scope");
        let file = ProjectFile::new(root, "src/app.ts");
        let mut index = EnclosingDeclarationIndex::default();
        index.retain(CodeUnit::file_scope(file), std::iter::empty());

        assert!(index.exact.is_empty());
        assert!(!index.projection_omitted);
        assert!(
            index
                .enclosing(Range {
                    start_byte: 0,
                    end_byte: 1,
                    start_line: 1,
                    end_line: 1,
                })
                .is_none()
        );
    }

    #[test]
    fn where_globs_match_slash_normalized_paths() {
        let query = CodeQuery::from_json(&json!({
            "where": ["src/**/*.py"],
            "match": { "kind": "call" }
        }))
        .expect("query should parse");
        let file = ProjectFile::new(
            std::env::temp_dir().join("bifrost-structural-search"),
            std::path::PathBuf::from("src\\app.py"),
        );

        assert!(file_matches_globs(&file, query.seed().unwrap()));
    }

    #[test]
    fn pipeline_render_cache_loads_each_source_once() {
        let file = ProjectFile::new(
            std::env::temp_dir().join("bifrost-pipeline-render-cache"),
            std::path::PathBuf::from("src/app.rs"),
        );
        let loads = Cell::new(0);
        let mut cache = PipelineRenderCache::default();

        for _ in 0..2 {
            let coordinates = cache
                .coordinates_for(&file, || {
                    loads.set(loads.get() + 1);
                    Some("fn demo() {}\n".to_string())
                })
                .expect("cached coordinates");
            assert_eq!(coordinates.line_starts, vec![0, 13]);
        }
        assert_eq!(loads.get(), 1);
    }

    #[test]
    fn retained_execution_snapshot_wins_over_a_later_changed_source() {
        let file = ProjectFile::new(
            std::env::temp_dir().join("bifrost-retained-query-snapshot"),
            PathBuf::from("src/app.rs"),
        );
        let original = "fn before() {}\n";
        let changed = "// shifted\nfn before() {}\n";
        let loads = Cell::new(0);
        let mut cache = PipelineRenderCache::default();

        let coordinates = cache
            .coordinates_for(&file, || {
                loads.set(loads.get() + 1);
                Some(if loads.get() == 1 { original } else { changed }.to_string())
            })
            .expect("retained coordinates");

        assert_eq!(coordinates.source, original);
        let digest = source_slice_sha256(coordinates.source.as_str(), &(0..2));
        let coordinates = cache
            .coordinates_for(&file, || {
                loads.set(loads.get() + 1);
                Some(changed.to_string())
            })
            .expect("retained coordinates");
        assert_eq!(coordinates.source, original);
        assert_eq!(
            digest,
            source_slice_sha256(coordinates.source.as_str(), &(0..2))
        );
        assert_eq!(loads.get(), 1, "a later source loader must not run");
        assert!(
            !cache.retain_source_snapshot(&file, changed),
            "conflicting snapshots must not be treated as exact evidence"
        );
    }

    #[test]
    fn conflicting_held_snapshots_are_negative_cached_and_typed_incomplete() {
        let file = ProjectFile::new(
            std::env::temp_dir().join("bifrost-conflicting-query-snapshot"),
            PathBuf::from("src/app.ts"),
        );
        let mut cache = PipelineRenderCache::default();
        let mut diagnostics = Vec::new();

        assert!(!retain_held_source_snapshot(
            &mut cache,
            &file,
            "fn before() {}\n",
            Language::Rust,
            Vec::new(),
            &mut diagnostics,
        ));
        assert!(retain_held_source_snapshot(
            &mut cache,
            &file,
            "// shifted\nfn before() {}\n",
            Language::Rust,
            vec![1],
            &mut diagnostics,
        ));
        assert!(cache.source_snapshot(&file).is_none());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            CodeQueryDiagnosticCode::SemanticResultsOmitted
        );
        assert_eq!(diagnostics[0].impact, CodeQueryDiagnosticImpact::Incomplete);
        assert!(diagnostics[0].branch == vec![1]);
    }

    #[test]
    fn sequential_profile_replays_a_shared_seed_for_each_union_branch() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
            .write("export function shared() {}\n")
            .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let branch = json!({ "match": { "kind": "function", "name": "shared" } });
        let query = CodeQuery::from_json(&json!({
            "union": [branch.clone(), branch],
            "limit": 10
        }))
        .expect("query");

        let detailed = execute_internal(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            None,
            true,
        );

        assert_eq!(detailed.result.results.len(), 1);
        let profile = detailed
            .profile
            .expect("valid execution should be profiled");
        assert_eq!(profile.peak_concurrency, 1);
        assert_eq!(
            profile
                .operators
                .iter()
                .filter(|observation| {
                    observation.operator == PhysicalQueryOperator::SequentialUnion
                })
                .count(),
            1
        );
        assert_eq!(
            profile
                .operators
                .iter()
                .filter(|observation| observation.operator == PhysicalQueryOperator::Limit)
                .count(),
            1
        );
        let seed_observations = profile
            .operators
            .iter()
            .filter(|observation| observation.operator == PhysicalQueryOperator::SeedScan)
            .collect::<Vec<_>>();
        assert_eq!(seed_observations.len(), 2);
        assert_eq!(seed_observations[0].node, seed_observations[1].node);
        assert_eq!(seed_observations[0].branch, vec![0]);
        assert_eq!(seed_observations[1].branch, vec![1]);
        assert!(
            seed_observations.iter().all(|observation| {
                observation.disposition == QueryOperatorDisposition::Completed
            })
        );
    }

    #[test]
    fn profile_attributes_root_limit_probe_to_the_limit_operator() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
            .write(
                "function one() {}\nfunction two() {}\nfunction three() {}\nfunction four() {}\n",
            )
            .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let branch = json!({ "match": { "kind": "function" } });
        let query = CodeQuery::from_json(&json!({
            "union": [branch.clone(), branch],
            "limit": 2
        }))
        .expect("query");

        let detailed = execute_internal(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            None,
            true,
        );

        assert_eq!(detailed.result.results.len(), 2);
        assert!(detailed.result.truncated);
        let profile = detailed.profile.expect("profile");
        let limit = profile
            .operators
            .iter()
            .find(|observation| observation.operator == PhysicalQueryOperator::Limit)
            .expect("limit observation");
        assert!(limit.branch.is_empty());
        assert_eq!(limit.disposition, QueryOperatorDisposition::Completed);
        assert_eq!(limit.input_rows, 3);
        assert_eq!(limit.output_rows, 2);
        assert!(limit.operator_truncated);
        assert!(limit.result_truncated);
        assert!(!limit.result_cancelled);
        let union = profile
            .operators
            .iter()
            .find(|observation| observation.operator == PhysicalQueryOperator::SequentialUnion)
            .expect("union observation");
        assert_eq!(union.input_rows, 8);
        assert_eq!(union.output_rows, 3);
        assert!(union.operator_truncated);
        assert!(!union.result_truncated);
    }

    #[test]
    fn skipped_set_profile_forwards_cancellation_safe_partial_cardinality() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), PathBuf::from("app.ts"))
            .write(
                "function one() { sink(); }\nfunction two() { sink(); }\nfunction three() { sink(); }\n",
            )
            .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let branch = json!({
            "match": { "kind": "call" },
            "steps": [{ "op": "enclosing_decl" }]
        });
        let query = CodeQuery::from_json(&json!({
            "union": [branch.clone(), branch]
        }))
        .expect("query");

        let detailed = (2..256)
            .find_map(|checks| {
                let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
                let detailed = execute_internal(
                    &analyzer,
                    &query,
                    CodeQueryExecutionLimits::default(),
                    Some(&cancellation),
                    None,
                    true,
                );
                let profile = detailed.profile.as_ref()?;
                let union = profile.operators.iter().find(|observation| {
                    observation.operator == PhysicalQueryOperator::SequentialUnion
                })?;
                let limit = profile
                    .operators
                    .iter()
                    .find(|observation| observation.operator == PhysicalQueryOperator::Limit)?;
                (union.disposition == QueryOperatorDisposition::Skipped
                    && union.output_rows > 0
                    && union.output_rows == limit.input_rows)
                    .then_some(detailed)
            })
            .expect("cancellation should interrupt a final branch step after a partial row");

        let profile = detailed.profile.expect("profile");
        let union = profile
            .operators
            .iter()
            .find(|observation| observation.operator == PhysicalQueryOperator::SequentialUnion)
            .expect("union observation");
        let limit = profile
            .operators
            .iter()
            .find(|observation| observation.operator == PhysicalQueryOperator::Limit)
            .expect("limit observation");
        assert_eq!(union.disposition, QueryOperatorDisposition::Skipped);
        assert!(union.result_cancelled);
        assert_eq!(union.output_rows, limit.input_rows);
        assert!(limit.result_cancelled);
        assert_eq!(detailed.result.completion(), CodeQueryCompletion::Cancelled);
    }

    #[test]
    fn detailed_execution_aligns_evidence_hashes_owners_and_direct_work() {
        let source = r#"export function handler(input: string) {
    sink(input);
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let query = CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "sink" } },
            "result_detail": "full"
        }))
        .expect("query");

        let detailed = execute_code_query_detailed(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
        );

        assert_eq!(detailed.result.results.len(), 1);
        assert!(
            detailed.profile.is_none(),
            "ordinary detailed execution should not pay profiling overhead"
        );
        assert_eq!(detailed.evidence.len(), 1);
        let evidence = &detailed.evidence[0];
        assert_eq!(evidence.result_index, 0);
        assert_eq!(evidence.domain, DetailedCodeQueryDomain::StructuralMatch);
        assert!(matches!(
            &evidence.key,
            DetailedCodeQueryKey::StructuralMatch {
                kind,
                analyzer_id: Some(_),
            } if kind == "call"
        ));
        let byte_span = evidence.byte_span.clone().expect("match byte span");
        assert_eq!(&source[byte_span.clone()], "sink(input)");
        assert_eq!(
            evidence.source_slice_sha256,
            Some(Sha256::digest(&source.as_bytes()[byte_span]).into())
        );
        assert!(matches!(
            &evidence.stable_owner_candidate,
            Some(CodeQueryStableOwnerCandidate {
                derivation: CodeQueryStableOwnerDerivation::CanonicalAstIdentity,
                semantic_key,
                ..
            }) if semantic_key.contains("handler") && semantic_key.contains("sink")
        ));
        assert_eq!(detailed.work.scanned_files, 1);
        assert_eq!(
            detailed.work.scanned_source_bytes,
            u64::try_from(source.len()).expect("source length")
        );
        assert!(detailed.work.fact_nodes > 0);
        assert!(detailed.work.pipeline_rows >= 1);
        assert_eq!(detailed.work.examined_references, 0);
    }

    #[test]
    fn detailed_file_terminal_is_artifact_only() {
        let source = "export function handler() { sink(); }\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let query = CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "sink" } },
            "steps": [{ "op": "file_of" }],
            "result_detail": "full"
        }))
        .expect("query");

        let detailed = execute_code_query_detailed(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
        );

        assert!(matches!(
            detailed.result.results[0].value,
            CodeQueryResultValue::File { ref value } if value.path == "app.ts"
        ));
        assert_eq!(detailed.evidence[0].domain, DetailedCodeQueryDomain::File);
        assert_eq!(detailed.evidence[0].key, DetailedCodeQueryKey::File);
        assert!(detailed.evidence[0].byte_span.is_none());
        assert!(detailed.evidence[0].source_slice_sha256.is_none());
        assert!(detailed.evidence[0].stable_owner_candidate.is_none());
    }

    #[test]
    fn detailed_execution_covers_every_semantic_terminal_domain() {
        let source = r#"export function target(payload: string) { return payload; }
export function caller() { return target("secret"); }
class Service { run() {} }
export function invoke(service: Service) { service.run(); }
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let cases = [
            (
                DetailedCodeQueryDomain::Declaration,
                json!({
                    "match": { "kind": "function", "name": "target" },
                    "steps": [{ "op": "enclosing_decl" }],
                    "result_detail": "full"
                }),
            ),
            (
                DetailedCodeQueryDomain::ReferenceSite,
                json!({
                    "match": { "kind": "function", "name": "target" },
                    "steps": [
                        { "op": "enclosing_decl" },
                        { "op": "references_of", "proof": "proven" }
                    ],
                    "result_detail": "full"
                }),
            ),
            (
                DetailedCodeQueryDomain::CallSite,
                json!({
                    "match": { "kind": "function", "name": "target" },
                    "steps": [
                        { "op": "enclosing_decl" },
                        { "op": "call_sites_to", "proof": "proven" }
                    ],
                    "result_detail": "full"
                }),
            ),
            (
                DetailedCodeQueryDomain::ExpressionSite,
                json!({
                    "match": { "kind": "function", "name": "target" },
                    "steps": [
                        { "op": "enclosing_decl" },
                        { "op": "call_sites_to", "proof": "proven" },
                        { "op": "call_input", "parameter_index": 0 }
                    ],
                    "result_detail": "full"
                }),
            ),
            (
                DetailedCodeQueryDomain::ReceiverAnalysis,
                json!({
                    "match": { "kind": "call", "callee": { "name": "run" } },
                    "steps": [{ "op": "receiver_targets" }],
                    "result_detail": "full"
                }),
            ),
        ];

        for (expected_domain, query) in cases {
            let query = CodeQuery::from_json(&query).expect("query");
            let detailed = execute_code_query_detailed(
                &analyzer,
                &query,
                CodeQueryExecutionLimits::default(),
                None,
            );
            assert_eq!(
                detailed.result.results.len(),
                1,
                "terminal domain {expected_domain:?}: {}",
                detailed.result.render_text()
            );
            let evidence = &detailed.evidence[0];
            assert_eq!(evidence.domain, expected_domain);
            assert_eq!(evidence.result_index, 0);
            assert_eq!(evidence.file, file);
            assert!(evidence.byte_span.is_some());
            if expected_domain == DetailedCodeQueryDomain::ReceiverAnalysis {
                assert!(evidence.source_slice_sha256.is_none());
                assert!(evidence.stable_owner_candidate.is_none());
            } else {
                let byte_span = evidence.byte_span.clone().expect("byte span");
                assert_eq!(
                    evidence.source_slice_sha256,
                    Some(Sha256::digest(&source.as_bytes()[byte_span]).into())
                );
                assert!(matches!(
                    evidence.stable_owner_candidate,
                    Some(CodeQueryStableOwnerCandidate {
                        derivation: CodeQueryStableOwnerDerivation::AnalyzerDeclarationId,
                        ..
                    })
                ));
            }
        }
    }

    #[test]
    fn cross_file_declaration_hydration_is_charged_or_degrades_to_weak_evidence() {
        let target_source = "export function target() {}\n";
        let caller_source =
            "import { target } from './target';\nexport function caller() { target(); }\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let target_file = ProjectFile::new(root.clone(), PathBuf::from("target.ts"));
        let caller_file = ProjectFile::new(root.clone(), PathBuf::from("caller.ts"));
        target_file.write(target_source).expect("write target");
        caller_file.write(caller_source).expect("write caller");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let query = CodeQuery::from_json(&json!({
            "where": ["target.ts"],
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "callers", "proof": "proven" }
            ],
            "result_detail": "full"
        }))
        .expect("query");

        let complete = execute_code_query_detailed(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
        );
        assert_eq!(complete.result.results.len(), 1);
        assert_eq!(
            complete.evidence[0].domain,
            DetailedCodeQueryDomain::Declaration
        );
        assert_eq!(complete.evidence[0].file, caller_file);
        assert!(complete.evidence[0].source_slice_sha256.is_some());
        assert!(complete.work.scanned_source_bytes >= caller_source.len() as u64);

        let tight_limit = usize::try_from(complete.work.scanned_source_bytes)
            .expect("work fits usize")
            .saturating_sub(1);
        let partial = execute_code_query_detailed(
            &analyzer,
            &query,
            CodeQueryExecutionLimits {
                max_scanned_source_bytes: tight_limit,
                ..CodeQueryExecutionLimits::default()
            },
            None,
        );
        assert_eq!(
            partial.result.results.len(),
            1,
            "the already-produced declaration remains available"
        );
        assert_eq!(partial.evidence[0].file, caller_file);
        assert!(partial.evidence[0].source_slice_sha256.is_none());
        assert!(partial.result.truncated);
        assert!(partial.result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
                && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
        }));
        assert!(partial.work.scanned_source_bytes <= tight_limit as u64);
    }

    #[test]
    fn cross_file_call_nested_rendering_cannot_retry_an_exhausted_source() {
        let target_source = "export function target() {}\n";
        let caller_source =
            "import { target } from './target';\nexport function caller() { target(); }\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), PathBuf::from("target.ts"))
            .write(target_source)
            .expect("write target");
        let caller_file = ProjectFile::new(root.clone(), PathBuf::from("caller.ts"));
        caller_file.write(caller_source).expect("write caller");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let query = CodeQuery::from_json(&json!({
            "where": ["target.ts"],
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "call_sites_to", "proof": "proven" }
            ],
            "result_detail": "full"
        }))
        .expect("query");

        let complete = execute_code_query_detailed(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
        );
        assert_eq!(complete.result.results.len(), 1);
        assert_eq!(complete.evidence[0].file, caller_file);
        assert!(complete.evidence[0].source_slice_sha256.is_some());
        let tight_limit = usize::try_from(complete.work.scanned_source_bytes)
            .expect("work fits usize")
            .saturating_sub(1);

        let partial = execute_code_query_detailed(
            &analyzer,
            &query,
            CodeQueryExecutionLimits {
                max_scanned_source_bytes: tight_limit,
                ..CodeQueryExecutionLimits::default()
            },
            None,
        );
        assert_eq!(partial.result.results.len(), 1);
        assert!(partial.evidence[0].source_slice_sha256.is_none());
        assert!(partial.work.scanned_source_bytes <= tight_limit as u64);
        let CodeQueryResultValue::CallSite { value } = &partial.result.results[0].value else {
            panic!("expected call-site result");
        };
        assert!(
            value.caller.node_range.is_none(),
            "nested caller rendering must use the negative cache rather than retrying"
        );
        assert!(value.callee.node_range.is_some());
        assert!(partial.result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
        }));
    }

    #[test]
    fn tiny_receiver_budget_returns_an_explicit_exceeded_row() {
        let source = r#"class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
    const service = makeService();
    service.run();
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let query = CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "receiver_targets" }]
        }))
        .expect("query");

        let result = execute_with_receiver_budget_for_test(
            &analyzer,
            &query,
            ReceiverAnalysisBudget::tiny(),
        );

        assert!(result.truncated);
        assert!(result.render_text().contains("limit -> scope_nodes"));
        assert!(matches!(
            result.results[0].value,
            CodeQueryResultValue::ReceiverAnalysis { ref value }
                if value.outcome == "exceeded_budget" && value.limit == Some("scope_nodes")
        ));

        let file_query = CodeQuery::from_json(&json!({
            "match": { "kind": "call", "callee": { "name": "run" } },
            "steps": [{ "op": "receiver_targets" }, { "op": "file_of" }]
        }))
        .expect("file query");
        let file_result = execute_with_receiver_budget_for_test(
            &analyzer,
            &file_query,
            ReceiverAnalysisBudget::tiny(),
        );
        assert!(file_result.truncated);
        assert!(matches!(
            file_result.results[0].value,
            CodeQueryResultValue::File { ref value } if value.path == "app.ts"
        ));
    }

    #[test]
    fn cancelled_composed_query_retains_no_partial_rows() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write("function alpha() {}\nfunction beta() {}\n")
            .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let query = CodeQuery::from_json(&json!({
            "union": [
                { "match": { "kind": "function", "name": "alpha" } },
                { "match": { "kind": "function", "name": "beta" } }
            ]
        }))
        .expect("query");
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let result = execute_with_cancellation(
            &analyzer,
            &query,
            CodeQueryExecutionLimits::default(),
            &cancellation,
        );

        assert!(result.results.is_empty());
        assert!(result.truncated);
        assert_eq!(result.diagnostics.len(), 1);
        assert!(result.diagnostics[0].branch.is_empty());
        assert!(result.diagnostics[0].message.contains("cancelled"));
    }

    #[test]
    fn cancellation_after_positive_rows_retains_aligned_partial_evidence() {
        let source = r#"export function caller() {
    alpha();
    beta();
    gamma();
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        let query = CodeQuery::from_json(&json!({
            "match": { "kind": "call" },
            "result_detail": "full"
        }))
        .expect("query");

        let detailed = (2..64)
            .find_map(|checks| {
                let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
                let detailed = execute_code_query_detailed(
                    &analyzer,
                    &query,
                    CodeQueryExecutionLimits::default(),
                    Some(&cancellation),
                );
                (detailed
                    .result
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::Cancelled)
                    && detailed.work.pipeline_rows >= 3
                    && !detailed.result.results.is_empty()
                    && detailed.result.results.len() < 3)
                    .then_some(detailed)
            })
            .expect("a deterministic cancellation checkpoint during detailed row rendering");

        assert!(detailed.result.truncated);
        assert!(detailed.result.results.len() < 3);
        assert_eq!(detailed.result.results.len(), detailed.evidence.len());
        assert!(
            detailed
                .evidence
                .iter()
                .enumerate()
                .all(|(index, evidence)| evidence.result_index == index
                    && evidence.source_slice_sha256.is_some())
        );
        assert!(detailed.work.pipeline_rows >= detailed.evidence.len() as u64);
        assert_eq!(detailed.result.completion(), CodeQueryCompletion::Cancelled);
    }
}
