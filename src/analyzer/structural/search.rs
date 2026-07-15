//! Workspace-level execution of a structural query (`query_code`): scope by
//! path globs and languages, derive the planner's positive anchors and query
//! requirements, run the matcher over deterministic candidates until `limit+1`
//! global matches prove truncation (facts come from the per-analyzer cache,
//! extraction happens on miss from in-memory source), then render the first
//! `limit` matches with captures, enclosing symbols, and capability
//! diagnostics.

use super::facts::{FileFacts, Span};
use super::kinds::{NormalizedKind, Role};
use super::matcher::FactMatch;
use super::planner::QueryPlan;
use super::query::schema::{reference_kind_label, usage_proof_label};
use super::query::{
    CallInputSelector, CallSiteTraversalFilter, CallTraversalFilter, CodeQuery,
    CodeQueryResultDetail, HierarchyTraversal, QueryStep, ReferenceTraversalFilter,
};
use crate::analyzer::reference_candidates::{
    ReferenceCandidateRanges, reference_candidate_ranges, reference_candidate_ranges_cancellable,
};
use crate::analyzer::structural::capabilities::QueryFeature;
use crate::analyzer::usages::get_definition::{
    CallSyntaxKind, DefinitionLookupRequest, DefinitionLookupStatus, parse_tree_for_language,
    resolve_definition_batch_with_source, resolve_definition_batch_with_source_and_cancellation,
};
use crate::analyzer::usages::{
    CallBindingCache, CallRelationLimits, CallRelationResult, CallRelationService, CallSite,
    DEFAULT_MAX_FILES, ExplicitCandidateProvider, FuzzyResult, ReferenceHit, ReferenceKind,
    UsageFinder, UsageHitKind, UsageProof, bind_call_site_arguments,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::compact_graph::CompactDirectedGraph;
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

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

#[derive(Debug, Serialize)]
pub struct CodeQueryProvenance {
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

#[derive(Debug, Serialize)]
pub struct CodeQueryDiagnostic {
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
struct CallSiteValue(CallSite);

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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PipelineKey {
    StructuralMatch(ProjectFile, u32),
    Declaration(DeclarationValue),
    File(ProjectFile),
    ReferenceSite(ReferenceSiteValue),
    CallSite(CallSiteValue),
    ExpressionSite(ExpressionSiteValue),
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
        }
    }
}

#[derive(Debug, Clone)]
struct PipelineTrace {
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

#[derive(Debug)]
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
    declaration_ranges: HashMap<DeclarationValue, Option<CodeQueryRange>>,
}

impl PipelineRenderCache {
    fn coordinates_for<F>(
        &mut self,
        file: &ProjectFile,
        load: F,
    ) -> Option<&CachedSourceCoordinates>
    where
        F: FnOnce() -> Option<String>,
    {
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
    truncated: bool,
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
        let nodes = std::mem::take(&mut self.all_files);
        let index_by_file: HashMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(index, file)| (file.clone(), index as u32))
            .collect();
        let mut edges = Vec::with_capacity(self.resolved_edges);
        for (source, targets) in std::mem::take(&mut self.forward) {
            let Some(source) = index_by_file.get(&source).copied() else {
                continue;
            };
            edges.extend(targets.into_iter().filter_map(|target| {
                index_by_file
                    .get(&target)
                    .copied()
                    .map(|target| (source, target))
            }));
        }
        self.compact = Some(CompactDirectedGraph::from_indexed_nodes(
            nodes,
            index_by_file,
            edges,
        ));
        self.analyzed.clear();
        self.analyzed.shrink_to_fit();
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

#[derive(Debug, Default)]
struct CodeQueryExecutionBudget {
    scanned_files: usize,
    scanned_source_bytes: usize,
    fact_nodes: usize,
    examined_references: usize,
    pipeline_rows: usize,
    provenance_steps: usize,
}

#[doc(hidden)]
pub fn execute_with_limits(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
) -> CodeQueryResult {
    execute_internal(analyzer, query, limits, None)
}

pub(crate) fn execute_with_cancellation(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: &CancellationToken,
) -> CodeQueryResult {
    execute_internal(analyzer, query, limits, Some(cancellation))
}

fn execute_internal(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> CodeQueryResult {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_query_result();
    }
    if let Err(error) = query.validate_steps() {
        return CodeQueryResult {
            results: Vec::new(),
            truncated: false,
            diagnostics: vec![CodeQueryDiagnostic {
                language: "workspace",
                message: error.to_string(),
            }],
        };
    }

    let plan = QueryPlan::for_query(query);
    let source_index = plan.build_source_index();
    let mut providers = analyzer.structural_search_providers();
    providers.sort_by_key(|provider| provider.structural_language());
    providers.retain(|provider| {
        query.languages.is_empty() || query.languages.contains(&provider.structural_language())
    });

    let mut diagnostics = Vec::new();
    let mut scoped_languages = BTreeSet::new();
    for file in analyzer.analyzed_files() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_query_result();
        }
        let language = crate::analyzer::common::language_for_file(&file);
        let requested = query.languages.is_empty() || query.languages.contains(&language);
        if requested && file_matches_globs(&file, query) {
            scoped_languages.insert(language);
        }
    }

    let mut supported = BTreeSet::new();
    let mut provider_scopes: Vec<(
        Language,
        &dyn super::StructuralSearchProvider,
        Vec<ProjectFile>,
    )> = Vec::new();

    for provider in providers {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_query_result();
        }
        let language = provider.structural_language();
        supported.insert(language);
        let mut files = provider.structural_files();
        files.retain(|file| file_matches_globs(file, query));
        files.sort();

        let explicitly_requested = query.languages.contains(&language);
        if !files.is_empty() || explicitly_requested {
            diagnostics.extend(
                plan.features()
                    .unsupported_by(|feature| provider_supports_feature(provider, feature))
                    .into_diagnostics(language)
                    .into_iter()
                    .map(|diagnostic| CodeQueryDiagnostic {
                        language: diagnostic.language().config_label(),
                        message: diagnostic.message(),
                    }),
            );
        }

        provider_scopes.push((language, provider, files));
    }

    for language in analyzer.languages() {
        let explicitly_requested = query.languages.contains(&language);
        let requested = query.languages.is_empty() || explicitly_requested;
        if requested
            && !supported.contains(&language)
            && (explicitly_requested || scoped_languages.contains(&language))
        {
            diagnostics.push(CodeQueryDiagnostic {
                language: language.config_label(),
                message: format!(
                    "no structural adapter for {} yet; its files were not searched",
                    language.config_label()
                ),
            });
        }
    }

    // Deterministic candidate order: global project-relative path order, with
    // language only as a tiebreaker for providers that share a path.
    let mut candidates: Vec<(
        String,
        Language,
        &dyn super::StructuralSearchProvider,
        ProjectFile,
    )> = Vec::new();
    for (language, provider, files) in provider_scopes {
        candidates.extend(
            files
                .into_iter()
                .map(|file| (rel_path_string(&file), language, provider, file)),
        );
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let pipeline_query = !query.steps.is_empty();
    let global_cap = if pipeline_query {
        limits.max_pipeline_rows.saturating_add(1)
    } else {
        query.limit.saturating_add(1)
    };
    let mut pending: Vec<PendingMatch> = Vec::new();
    let mut budget = CodeQueryExecutionBudget::default();
    let mut budget_exhausted = false;
    let mut pipeline_budget_diagnostic_emitted = false;
    for (_path, language, provider, file) in candidates {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_query_result();
        }
        let Some(source) = provider.structural_source(&file) else {
            continue;
        };
        budget.scanned_files += 1;
        budget.scanned_source_bytes = budget.scanned_source_bytes.saturating_add(source.len());
        if budget.scanned_files > limits.max_scanned_files
            || budget.scanned_source_bytes > limits.max_scanned_source_bytes
        {
            push_budget_diagnostic(&mut diagnostics, &budget);
            budget_exhausted = true;
            break;
        }
        if !source_index.may_match(&source) {
            continue;
        }
        let Some(facts) = provider.structural_facts(&file) else {
            continue;
        };
        budget.fact_nodes = budget.fact_nodes.saturating_add(facts.nodes().len());
        if budget.fact_nodes > limits.max_fact_nodes {
            push_budget_diagnostic(&mut diagnostics, &budget);
            budget_exhausted = true;
            break;
        }
        let remaining = global_cap - pending.len();
        for fact_match in super::matcher::match_query(query, &facts, remaining) {
            pending.push((language, file.clone(), Arc::clone(&facts), fact_match));
        }
        if pending.len() >= global_cap {
            break;
        }
    }

    let match_truncated = !pipeline_query && pending.len() > query.limit;
    let seed_budget_exhausted = pipeline_query && pending.len() > limits.max_pipeline_rows;
    budget_exhausted |= seed_budget_exhausted;
    if match_truncated {
        push_truncation_diagnostic(&mut diagnostics, &budget, query.limit);
    }
    if seed_budget_exhausted {
        pending.truncate(limits.max_pipeline_rows);
        budget.pipeline_rows = pending.len();
        push_pipeline_budget_diagnostic(&mut diagnostics, &budget);
        pipeline_budget_diagnostic_emitted = true;
    }

    if !pipeline_query {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_query_result();
        }
        let truncated = match_truncated || budget_exhausted;
        if should_report_broad_query(&plan, query, &budget, truncated) {
            push_broad_query_diagnostic(&mut diagnostics, &budget);
        }
        pending.truncate(query.limit);
        let matches: Vec<_> = pending
            .into_iter()
            .map(|(language, file, facts, fact_match)| {
                render_match(
                    analyzer,
                    language,
                    &file,
                    &facts,
                    &fact_match,
                    query.result_detail,
                )
            })
            .collect();
        let results = matches
            .iter()
            .cloned()
            .map(|value| CodeQueryResultItem {
                value: CodeQueryResultValue::StructuralMatch { value },
                provenance: Vec::new(),
                provenance_truncated: false,
            })
            .collect();
        return CodeQueryResult {
            results,
            truncated,
            diagnostics,
        };
    }

    let mut rows = pending
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
                    seed,
                    steps: Vec::new(),
                }],
                provenance_truncated: false,
            }
        })
        .collect::<Vec<_>>();
    budget.pipeline_rows = rows.len();

    let mut indexed_declarations = None;
    let mut reference_cache = ReferenceTraversalCache::default();
    let mut call_cache = CallTraversalCache::default();

    let mut import_graph = None;
    let mut import_graph_budget_diagnostic_emitted = false;
    for (step_index, step) in query.steps.iter().enumerate() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_query_result();
        }
        if !rows.is_empty()
            && indexed_declarations.is_none()
            && matches!(
                step,
                QueryStep::Supertypes(_)
                    | QueryStep::Subtypes(_)
                    | QueryStep::Members
                    | QueryStep::Owner
                    | QueryStep::ReferencesOf(_)
                    | QueryStep::UsedBy(_)
                    | QueryStep::Uses(_)
                    | QueryStep::Callers(_)
                    | QueryStep::Callees(_)
                    | QueryStep::CallSitesTo(_)
                    | QueryStep::CallSitesFrom(_)
            )
        {
            indexed_declarations = Some(IndexedDeclarations::default());
        }
        if !rows.is_empty() && matches!(step, QueryStep::ImportsOf | QueryStep::ImportersOf) {
            let graph = import_graph.get_or_insert_with(|| DirectImportGraph::new(analyzer));
            let graph_exhausted = if step == &QueryStep::ImportersOf {
                ensure_complete_import_graph(
                    analyzer,
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
                        | PipelineValue::ExpressionSite(_) => None,
                    })
                    .collect::<Vec<_>>();
                frontier.sort_by_key(rel_path_string);
                frontier.dedup();
                ensure_forward_import_edges(
                    analyzer,
                    graph,
                    &frontier,
                    limits.max_scanned_files,
                    limits.max_pipeline_rows,
                )
            };
            if graph_exhausted {
                budget_exhausted = true;
                if !import_graph_budget_diagnostic_emitted {
                    push_import_graph_budget_diagnostic(&mut diagnostics, graph);
                    import_graph_budget_diagnostic_emitted = true;
                }
            }
        }
        let (next, exhausted) = apply_pipeline_step(
            analyzer,
            step,
            rows,
            import_graph.as_ref(),
            indexed_declarations.as_mut(),
            &mut reference_cache,
            &mut call_cache,
            &mut budget,
            limits,
            if step_index + 1 == query.steps.len() {
                query.limit.saturating_add(1)
            } else {
                limits.max_pipeline_rows
            },
            cancellation,
            &mut diagnostics,
        );
        rows = next;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return cancelled_query_result();
        }
        if exhausted {
            budget_exhausted = true;
            if (budget.pipeline_rows >= limits.max_pipeline_rows
                || budget.provenance_steps >= limits.max_pipeline_rows)
                && !pipeline_budget_diagnostic_emitted
            {
                push_pipeline_budget_diagnostic(&mut diagnostics, &budget);
            }
            if step_index + 1 < query.steps.len() {
                // A partial intermediate stage does not satisfy the statically
                // validated terminal domain. Preserve only complete terminal
                // values when the final stage itself exhausts the budget.
                rows.clear();
            }
            break;
        }
    }

    let terminal_truncated = rows.len() > query.limit;
    if terminal_truncated {
        push_truncation_diagnostic(&mut diagnostics, &budget, query.limit);
        rows.truncate(query.limit);
    }
    let truncated = terminal_truncated || budget_exhausted;
    if should_report_broad_query(&plan, query, &budget, truncated) {
        push_broad_query_diagnostic(&mut diagnostics, &budget);
    }
    let mut render_cache = PipelineRenderCache::default();
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_query_result();
    }
    let results = rows
        .into_iter()
        .map(|row| render_pipeline_item(analyzer, row, query.result_detail, &mut render_cache))
        .collect();
    CodeQueryResult {
        results,
        truncated,
        diagnostics,
    }
}

fn cancelled_query_result() -> CodeQueryResult {
    CodeQueryResult {
        results: Vec::new(),
        truncated: true,
        diagnostics: vec![CodeQueryDiagnostic {
            language: "workspace",
            message: "query_code cancelled; no partial results were retained".to_string(),
        }],
    }
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
    if graph.truncated {
        graph.freeze();
        return graph.truncated;
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
    if graph.truncated {
        return true;
    }

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
    if pending.len() > available_files {
        pending.truncate(available_files);
        graph.truncated = true;
    }

    let mut groups: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
    for file in pending {
        graph.resolved_files += 1;
        if analyzer.import_analysis_provider_for_file(&file).is_some() {
            groups
                .entry(crate::analyzer::common::language_for_file(&file))
                .or_default()
                .push(file);
        } else {
            graph.unsupported.insert(file);
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
                targets.truncate(available_edges);
                graph.truncated = true;
            }
            graph.resolved_edges += targets.len();
            graph.forward.insert(file.clone(), targets);
        }
    }
    graph.truncated
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
) -> (Vec<PipelineRow>, bool) {
    let max_pipeline_rows = limits.max_pipeline_rows;
    let mut output = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut unsupported_languages = BTreeSet::new();
    let mut semantic_omissions: BTreeMap<(Language, &'static str), usize> = BTreeMap::new();
    let mut enclosing_declarations: HashMap<ProjectFile, Vec<DeclarationValue>> =
        HashMap::default();
    let mut exhausted = false;

    let mut indexed_declarations = indexed_declarations;
    'rows: for row in rows {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (Vec::new(), true);
        }
        let mut row_exhausted = false;
        let expansions = match (&row.value, step) {
            (PipelineValue::StructuralMatch(seed), QueryStep::EnclosingDecl) => {
                enclosing_declaration_value(analyzer, seed, &mut enclosing_declarations)
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
                    let mut children = analyzer.direct_children(&declaration.unit);
                    children.sort();
                    children.dedup();
                    let mut expansions = Vec::new();
                    for unit in children {
                        if budget.pipeline_rows >= max_pipeline_rows {
                            row_exhausted = true;
                            break;
                        }
                        budget.pipeline_rows += 1;
                        if let Some(child) = indexed.get(analyzer, &unit) {
                            indexed.record_owner(&unit, &declaration.unit);
                            expansions.push(budgeted_declaration_expansion(child));
                        }
                    }
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
                call_input_expansions(site, selector)
            }
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
                .map(|mut trace| {
                    trace
                        .steps
                        .extend(expansion.trace.iter().cloned().map(|(value, via)| {
                            PipelineTraceStep {
                                op: step.clone(),
                                value,
                                via,
                            }
                        }));
                    trace
                })
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
            language: language.config_label(),
            message: format!(
                "{} does not provide structured import analysis; {} omitted its affected files",
                language.config_label(),
                step.label()
            ),
        });
    }
    for ((language, reason), count) in semantic_omissions {
        diagnostics.push(CodeQueryDiagnostic {
            language: language.config_label(),
            message: format!(
                "{} omitted {count} input{} because {reason}",
                step.label(),
                if count == 1 { "" } else { "s" }
            ),
        });
    }
    (output, exhausted)
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
    let mut queue = VecDeque::from([CallTraversalWork {
        unit: declaration.unit.clone(),
        depth: 0,
        path_tail: None,
    }]);
    let mut paths = Vec::new();
    let mut emitted = HashSet::default();
    let mut expansions = Vec::new();
    let mut exhausted = false;
    while let Some(work) = queue.pop_front() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (expansions, true);
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
                return (expansions, true);
            }
            let next_unit = if incoming {
                site.caller.clone()
            } else {
                site.callee.clone()
            };
            let Some(next) = indexed.get(analyzer, &next_unit) else {
                continue;
            };
            if !emitted.contains(&next_unit) && emitted.len() >= max_outputs {
                return (expansions, true);
            }
            if budget.pipeline_rows >= limits.max_pipeline_rows {
                return (expansions, true);
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
                None => return (expansions, true),
            };
            let next_depth = work.depth + 1;
            if budget.provenance_steps.saturating_add(next_depth) > limits.max_pipeline_rows {
                budget.provenance_steps = limits.max_pipeline_rows;
                return (expansions, true);
            }
            budget.provenance_steps += next_depth;
            budget.pipeline_rows += 1;
            let call_site = CallSiteValue(site);
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
    (expansions, exhausted)
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
            bind_call_site_arguments(analyzer, &mut site, &mut cache.bindings);
            pipeline_expansion(PipelineValue::CallSite(CallSiteValue(site)))
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
                .map(|message| CodeQueryDiagnostic { language, message }),
        );
    }
    result
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
) -> Vec<PipelineExpansion> {
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
    expressions
        .into_iter()
        .map(|expression| pipeline_expansion(PipelineValue::ExpressionSite(expression)))
        .collect()
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
                ..
            } => {
                exhausted = true;
                if report {
                    diagnostics.push(CodeQueryDiagnostic {
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

    let mut sites = cache
        .inbound
        .get(&declaration.unit)
        .into_iter()
        .flatten()
        .filter(|hit| reference_hit_matches(hit, filter))
        .filter_map(|hit| reference_site_value(analyzer, hit, declaration.clone(), indexed))
        .collect::<Vec<_>>();
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

fn reference_hits_for_target(
    analyzer: &dyn IAnalyzer,
    result: FuzzyResult,
    target: &CodeUnit,
) -> Vec<ReferenceHit> {
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        } => hits_by_overload
            .into_values()
            .flatten()
            .map(|hit| reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Proven))
            .chain(unproven_by_overload.into_values().flatten().map(|hit| {
                reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Unproven)
            }))
            .collect(),
        FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flatten()
            .map(|hit| {
                reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Unproven)
            })
            .collect(),
        FuzzyResult::Failure { .. } | FuzzyResult::TooManyCallsites { .. } => Vec::new(),
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
) -> Option<ReferenceSiteValue> {
    let enclosing = indexed.get(analyzer, &hit.enclosing_unit);
    Some(ReferenceSiteValue {
        file: hit.file.clone(),
        range: hit.range,
        target,
        enclosing,
        usage_kind: hit.usage_kind,
        proof: hit.proof,
        reference_kind: hit.kind,
    })
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
    let mut sites = cache
        .outbound
        .get(declaration.unit.source())
        .into_iter()
        .flatten()
        .filter(|hit| hit.enclosing_unit == declaration.unit)
        .filter(|hit| reference_hit_matches(hit, filter))
        .filter_map(|hit| {
            let target = indexed.get(analyzer, &hit.resolved)?;
            reference_site_value(analyzer, hit, target, indexed)
        })
        .collect::<Vec<_>>();
    sort_reference_sites(&mut sites);
    sites.dedup();
    let expansions = sites
        .into_iter()
        .map(|site| reference_expansion(PipelineValue::Declaration(site.target.clone()), site))
        .collect();
    (expansions, exhausted)
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
        return (Vec::new(), false);
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
    let mut candidates_by_target: BTreeMap<CodeUnit, BTreeSet<(usize, usize)>> = BTreeMap::new();
    let mut ambiguous = 0usize;
    for outcome in outcomes {
        match outcome.status {
            DefinitionLookupStatus::Resolved => {}
            DefinitionLookupStatus::Ambiguous => {
                ambiguous += 1;
            }
            _ => continue,
        }
        let Some(reference) = outcome.reference else {
            continue;
        };
        for resolved in outcome.definitions {
            candidates_by_target
                .entry(resolved)
                .or_default()
                .insert((reference.focus_start_byte, reference.focus_end_byte));
        }
    }

    let mut candidate_files = HashSet::default();
    candidate_files.insert(file.clone());
    let provider = ExplicitCandidateProvider::new(Arc::new(candidate_files));
    let mut hits = Vec::new();
    let mut omitted = 0usize;
    for (target, candidate_ranges) in candidates_by_target {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (Vec::new(), true);
        }
        let mut finder = UsageFinder::new();
        if let Some(cancellation) = cancellation {
            finder = finder.with_cancellation(cancellation.clone());
        }
        let result = finder.query_with_provider(
            analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            candidate_ranges.len().max(1),
        );
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (Vec::new(), true);
        }
        let target_hits = reference_hits_for_target(analyzer, result.result, &target);
        let before = hits.len();
        hits.extend(target_hits.into_iter().filter(|hit| {
            hit.file == *file
                && candidate_ranges.contains(&(hit.range.start_byte, hit.range.end_byte))
        }));
        omitted += candidate_ranges.len().saturating_sub(hits.len() - before);
    }
    if ambiguous > 0 {
        diagnostics.push(CodeQueryDiagnostic {
            language: language.config_label(),
            message: format!(
                "uses emitted {ambiguous} ambiguous reference site{} in {} as unproven",
                if ambiguous == 1 { "" } else { "s" },
                rel_path_string(file)
            ),
        });
    }
    if omitted > 0 {
        diagnostics.push(CodeQueryDiagnostic {
            language: language.config_label(),
            message: format!(
                "uses omitted {omitted} candidate reference site{} in {} because the structured usage analyzer did not confirm the exact edge",
                if omitted == 1 { "" } else { "s" },
                rel_path_string(file)
            ),
        });
    }
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
            let Some(value) = indexed.get(analyzer, &unit) else {
                // Structured relations may observe an external name, but this
                // pipeline only returns declarations indexed by this analyzer.
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
    (expansions, false)
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

fn enclosing_declaration_value(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    declarations_by_file: &mut HashMap<ProjectFile, Vec<DeclarationValue>>,
) -> Option<DeclarationValue> {
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
            let mut declarations = analyzer
                .get_declarations(&seed.file)
                .into_iter()
                .filter(|unit| !unit.is_synthetic() && !unit.is_file_scope())
                .flat_map(|unit| {
                    analyzer
                        .ranges_of(&unit)
                        .into_iter()
                        .map(move |range| DeclarationValue {
                            unit: unit.clone(),
                            range,
                        })
                })
                .collect::<Vec<_>>();
            declarations.sort_by(|left, right| {
                let left_span = left.range.end_byte.saturating_sub(left.range.start_byte);
                let right_span = right.range.end_byte.saturating_sub(right.range.start_byte);
                left_span
                    .cmp(&right_span)
                    .then_with(|| left.unit.cmp(&right.unit))
                    .then_with(|| left.range.start_byte.cmp(&right.range.start_byte))
                    .then_with(|| left.range.end_byte.cmp(&right.range.end_byte))
            });
            declarations
        });
    declarations
        .iter()
        .find(|declaration| {
            declaration.range.start_byte <= seed_range.start_byte
                && declaration.range.end_byte >= seed_range.end_byte
        })
        .cloned()
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
    diagnostics.push(CodeQueryDiagnostic {
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
    query: &CodeQuery,
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

fn file_matches_globs(file: &ProjectFile, query: &CodeQuery) -> bool {
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
        enclosing_symbol: analyzer
            .enclosing_code_unit_for_lines(file, fact.range.start_line, fact.range.end_line)
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
                | CodeQueryResultValue::ExpressionSite { .. } => None,
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
                }
                if !result.provenance.is_empty() {
                    out.push_str(&format!(
                        "  provenance: {} path{}{}\n",
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
                        }
                    ));
                }
            }
        }
        for diagnostic in &self.diagnostics {
            out.push_str(&format!("note: {}\n", diagnostic.message));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::CodeQuery;
    use serde_json::json;
    use std::cell::Cell;

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

        assert!(file_matches_globs(&file, &query));
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
}
