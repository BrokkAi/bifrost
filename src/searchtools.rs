use crate::analyzer::common::{
    display_identifier_for_target, display_symbol_for_target, display_symbol_name,
    is_scala_object_like, language_for_target,
};
use crate::analyzer::symbol_lookup::{
    CodeUnitResolution, resolve_codeunit_exact, resolve_codeunit_fuzzy,
    resolve_typeish_codeunit_fuzzy, strip_trailing_call_suffix,
};
use crate::analyzer::usages::{
    CONFIDENCE_THRESHOLD, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, RegexUsageAnalyzer,
    UsageAnalyzer, UsageFinder, UsageHit,
};
use crate::analyzer::{CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};
use crate::model_context;
use crate::path_utils::{
    AmbiguousPathInput, ResolvedFileInput, WorkspaceFileResolver, normalize_pattern,
    rel_path_string,
};
use crate::profiling;
use crate::relevance::{
    DEFAULT_RECENCY_HALF_LIFE, most_important_project_files, most_relevant_project_files,
    most_relevant_project_files_with_half_life,
};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use glob::MatchOptions;
use glob::Pattern;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const FILE_SEARCH_LIMIT: usize = 100;
const FILE_SKIM_LIMIT: usize = 20;
// Keep MCP structured JSON below Codex's default 10 KB function-output
// truncation limit after JSON escaping and tool wrapper overhead.
pub const SCAN_USAGES_RESPONSE_BUDGET_BYTES: usize = 8_192;
const SCAN_USAGES_MAX_CALLSITES: usize = DEFAULT_MAX_USAGES;
const SCAN_USAGES_SUMMARY_FILE_LIMIT: usize = 20;
const SCAN_USAGES_TOP_ENCLOSING_LIMIT: usize = 10;
const SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT: usize = 3;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshParams {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivateWorkspaceParams {
    pub workspace_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetActiveWorkspaceParams {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSymbolsParams {
    pub patterns: Vec<String>,
    #[serde(default)]
    pub include_tests: bool,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolLookupParams {
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePatternsParams {
    pub file_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummariesParams {
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MostRelevantFilesParams {
    pub seed_file_paths: Vec<String>,
    #[serde(default)]
    pub seed_weights: Option<Vec<f64>>,
    #[serde(default = "default_recency_half_life")]
    pub recency_half_life: Option<f64>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUsagesParams {
    #[serde(default)]
    pub symbols: Option<Vec<String>>,
    #[serde(default)]
    pub targets: Vec<ScanUsagesTarget>,
    #[serde(default)]
    pub include_tests: bool,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUsagesTarget {
    pub path: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
    #[serde(default)]
    pub start_byte: Option<usize>,
    #[serde(default)]
    pub end_byte: Option<usize>,
}

/// Parameters for [`usage_graph`].
///
/// Both fields mirror [`ScanUsagesParams`] so the whole-workspace graph can be
/// scoped the same way a single-symbol scan is: callers can drop test files or
/// restrict the search to a subset of paths. Both default off, so an empty
/// `{}` request returns the full workspace graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageGraphParams {
    /// Include references that live in detected test files.
    #[serde(default)]
    pub include_tests: bool,
    /// Optional project-relative file paths or globs that bound where references
    /// are searched. `None` searches the whole workspace.
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDefinitionParams {
    pub references: Vec<DefinitionReferenceQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionReferenceQuery {
    pub path: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
    #[serde(default)]
    pub start_byte: Option<usize>,
    #[serde(default)]
    pub end_byte: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDefinitionByReferenceParams {
    pub references: Vec<DefinitionContextReferenceQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionContextReferenceQuery {
    pub symbol: String,
    pub context: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefreshResult {
    pub languages: Vec<String>,
    pub analyzed_files: usize,
    pub declarations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveWorkspaceResult {
    pub workspace_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSymbolsResult {
    pub patterns: Vec<String>,
    pub truncated: bool,
    pub total_files: usize,
    pub files: Vec<SearchSymbolsFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSymbolsFile {
    pub path: String,
    pub loc: usize,
    pub classes: Vec<SearchSymbolHit>,
    pub functions: Vec<SearchSymbolHit>,
    pub fields: Vec<SearchSymbolHit>,
    pub modules: Vec<SearchSymbolHit>,
    pub macros: Vec<SearchSymbolHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSymbolHit {
    pub symbol: String,
    pub signature: String,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchPatternKind {
    LiteralIdentifier,
    LiteralQualified,
    RegexLike,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolMatchScore {
    tier: u8,
    exact_patterns: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolCandidateScore {
    match_score: SymbolMatchScore,
    path_tier: u8,
    implementation_tier: u8,
    source_quality_tier: u8,
    synthetic_tier: u8,
}

#[derive(Debug, Clone)]
struct RankedSearchCandidate {
    code_unit: CodeUnit,
    score: SymbolCandidateScore,
    line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FileRankingKey {
    top1: SymbolCandidateScore,
    cohesion_tier: u8,
    focus_tier: u8,
    top2: SymbolCandidateScore,
    top3: SymbolCandidateScore,
    git_tier: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolLocationsResult {
    pub locations: Vec<SymbolLocation>,
    pub not_found: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolAncestorsResult {
    pub ancestors: Vec<SymbolAncestors>,
    pub not_found: Vec<String>,
    pub ambiguous: Vec<AmbiguousSymbol>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolAncestors {
    pub symbol: String,
    pub ancestors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolLocation {
    pub symbol: String,
    pub path: String,
    pub loc: usize,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetDefinitionResult {
    pub results: Vec<DefinitionLookupResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionLookupResult {
    pub query: DefinitionReferenceQuery,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<DefinitionReferenceSite>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub definitions: Vec<DefinitionCandidate>,
    #[serde(default)]
    pub diagnostics: Vec<DefinitionDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionReferenceSite {
    pub path: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetDefinitionByReferenceResult {
    pub results: Vec<DefinitionByReferenceLookupResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionByReferenceLookupResult {
    pub query: DefinitionContextReferenceQuery,
    pub status: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub definitions: Vec<DefinitionCandidate>,
    #[serde(default)]
    pub diagnostics: Vec<DefinitionDiagnostic>,
}

type DefinitionCandidateKey = (String, String, usize, usize, String, Option<String>, String);
type DefinitionOutcomeKey = (String, Vec<DefinitionCandidateKey>);

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionCandidate {
    pub fqn: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub language: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionDiagnostic {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryResult {
    pub summaries: Vec<SummaryBlock>,
    pub not_found: Vec<String>,
    pub ambiguous: Vec<AmbiguousSymbol>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousSymbol {
    pub target: String,
    pub matches: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryBlock {
    pub label: String,
    pub path: String,
    pub preamble: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    pub elements: Vec<SummaryElement>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryElement {
    pub path: String,
    pub symbol: String,
    pub kind: String,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolSourcesResult {
    pub sources: Vec<SourceBlock>,
    pub not_found: Vec<String>,
    pub ambiguous: Vec<AmbiguousSymbol>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceBlock {
    pub label: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFilesResult {
    pub truncated: bool,
    pub total_files: usize,
    pub files: Vec<SkimFile>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MostRelevantFilesResult {
    pub files: Vec<String>,
    pub not_found: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub duplicates: Vec<String>,
}

fn default_recency_half_life() -> Option<f64> {
    Some(DEFAULT_RECENCY_HALF_LIFE)
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFile {
    pub path: String,
    pub loc: usize,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesResult {
    pub summary: ScanUsagesSummary,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub usages: Vec<SymbolUsages>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub not_found: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub fallbacks: Vec<UsageFallbackInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub failures: Vec<UsageFailureInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous: Vec<AmbiguousUsageSymbol>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub too_many_callsites: Vec<TooManyCallsitesInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesSummary {
    pub requested_symbols: usize,
    pub resolved_symbols: usize,
    pub total_hits: usize,
    pub partial: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub symbols: Vec<ScanUsagesSymbolSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_next_call: Option<ScanUsagesRecommendedNextCall>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesSymbolSummary {
    pub symbol: String,
    pub total_hits: usize,
    pub rendering: UsageRendering,
    pub files_returned: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_truncated: Option<usize>,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_files_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub top_files: Vec<ScanUsagesFileSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub top_enclosing: Vec<UsageEnclosingCount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesFileSummary {
    pub path: String,
    pub hit_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesRecommendedNextCall {
    pub tool: String,
    pub arguments: serde_json::Value,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum UsageRendering {
    Full,
    Lines,
    Summary,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolUsages {
    pub symbol: String,
    pub total_hits: usize,
    pub rendering: UsageRendering,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned. Results are partial when set.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_files_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_sites_excluded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_truncated: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub top_enclosing: Vec<UsageEnclosingCount>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub files: Vec<UsageFileGroup>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageFileGroup {
    pub path: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hits: Vec<UsageLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageLocation {
    pub line: usize,
    pub enclosing: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "is_full_confidence")]
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousUsageSymbol {
    pub symbol: String,
    pub short_name: String,
    pub candidate_targets: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidate_details: Vec<AmbiguousUsageCandidateDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_details_total: Option<usize>,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_details_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidates: Vec<AmbiguousUsageCandidate>,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned. Results are partial when set.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_files_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_sites_excluded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousUsageCandidate {
    pub target: String,
    pub total_hits: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousUsageCandidateDetail {
    pub target: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub scan_usages_target: ScanUsagesTargetSuggestion,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesTargetSuggestion {
    pub path: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageEnclosingCount {
    pub enclosing: String,
    pub hits: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageFailureInfo {
    /// Symbol requested by the caller.
    pub symbol: String,
    /// Fully qualified symbol reported by the analyzer failure, when available.
    pub fq_name: String,
    /// Graph strategy that produced the failure, when available.
    pub strategy: String,
    /// Stable machine-readable failure category, when available.
    pub reason_kind: String,
    /// Analyzer-provided reason. This is separate from `not_found` because the symbol
    /// resolved, but usage analysis could not produce a trustworthy answer.
    pub reason: String,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned before the failure was produced.
    pub candidate_files_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageFallbackInfo {
    /// Symbol requested by the caller.
    pub symbol: String,
    /// Fully qualified symbol reported by the graph strategy.
    pub fq_name: String,
    /// Graph strategy that requested fallback.
    pub strategy: String,
    /// Stable machine-readable fallback category.
    pub reason_kind: String,
    /// Human-readable fallback reason.
    pub reason: String,
    /// Fallback policy used by `UsageFinder`.
    pub fallback_policy: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TooManyCallsitesInfo {
    pub symbol: String,
    pub short_name: String,
    pub total_callsites: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn refresh_result(analyzer: &dyn IAnalyzer) -> RefreshResult {
    let mut languages: Vec<_> = analyzer
        .languages()
        .into_iter()
        .map(language_name)
        .collect();
    languages.sort();

    let metrics = analyzer.metrics();
    RefreshResult {
        languages,
        analyzed_files: metrics.file_count,
        declarations: metrics.declaration_count,
    }
}

pub fn search_symbols(
    analyzer: &dyn IAnalyzer,
    params: SearchSymbolsParams,
) -> SearchSymbolsResult {
    let patterns: Vec<String> = strip_params(params.patterns)
        .into_iter()
        .filter(|pattern| !pattern.trim().is_empty())
        .collect();

    let definitions = patterns
        .par_iter()
        .map(|pattern| analyzer.search_definitions(pattern, false))
        .reduce(BTreeSet::new, |mut acc, definitions| {
            acc.extend(definitions);
            acc
        });

    let filtered: Vec<_> = definitions
        .into_par_iter()
        .filter(|code_unit| {
            params.include_tests || !is_test_candidate(analyzer, code_unit.source())
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect();

    let ranked = rank_search_symbol_candidates(analyzer, &patterns, filtered);

    let mut grouped: HashMap<ProjectFile, Vec<RankedSearchCandidate>> = HashMap::default();
    for candidate in ranked {
        grouped
            .entry(candidate.code_unit.source().clone())
            .or_default()
            .push(candidate);
    }

    let effective_limit = params.limit.clamp(1, FILE_SEARCH_LIMIT);
    let total_files = grouped.len();
    let truncated = total_files > effective_limit;
    let mut file_entries: Vec<_> = grouped.into_iter().collect();
    let git_tiers = search_symbol_git_tiers(
        analyzer,
        &file_entries
            .iter()
            .map(|(file, _)| file.clone())
            .collect::<Vec<_>>(),
    );
    file_entries.sort_by(
        |(left_file, left_candidates), (right_file, right_candidates)| {
            compare_search_symbol_files(
                left_file,
                left_candidates,
                right_file,
                right_candidates,
                &git_tiers,
            )
        },
    );
    file_entries.truncate(effective_limit);

    let files = file_entries
        .into_iter()
        .map(|(file, code_units)| SearchSymbolsFile {
            path: rel_path_string(&file),
            loc: file
                .read_to_string()
                .map(|content| line_count(&content))
                .unwrap_or(0),
            classes: collect_ranked_kind_names(analyzer, &code_units, CodeUnitType::Class),
            functions: collect_ranked_kind_names(analyzer, &code_units, CodeUnitType::Function),
            fields: collect_ranked_kind_names(analyzer, &code_units, CodeUnitType::Field),
            modules: collect_ranked_kind_names(analyzer, &code_units, CodeUnitType::Module),
            macros: collect_ranked_kind_names(analyzer, &code_units, CodeUnitType::Macro),
        })
        .collect();

    SearchSymbolsResult {
        patterns,
        truncated,
        total_files,
        files,
    }
}

pub fn get_symbol_locations(
    analyzer: &dyn IAnalyzer,
    params: SymbolLookupParams,
) -> SymbolLocationsResult {
    let mut outcomes: Vec<_> = params
        .symbols
        .into_par_iter()
        .enumerate()
        .filter_map(|(index, symbol)| {
            if symbol.trim().is_empty() {
                return None;
            }

            let code_units = match resolve_codeunit_fuzzy(analyzer, &symbol) {
                CodeUnitResolution::Resolved(code_units) => Some(code_units),
                CodeUnitResolution::Ambiguous(_) | CodeUnitResolution::NotFound => None,
            };
            let Some(code_units) = code_units else {
                return Some((index, Err(symbol)));
            };
            let locations: Vec<_> = code_units
                .into_iter()
                .filter_map(|code_unit| {
                    let primary_range = primary_range(analyzer, &code_unit)?;
                    let loc = code_unit
                        .source()
                        .read_to_string()
                        .map(|content| line_count(&content))
                        .unwrap_or(0);
                    Some(SymbolLocation {
                        symbol: display_symbol_for_target(&code_unit),
                        path: rel_path_string(code_unit.source()),
                        loc,
                        start_line: primary_range.start_line,
                        end_line: primary_range.end_line,
                    })
                })
                .collect();
            if locations.is_empty() {
                Some((index, Err(symbol)))
            } else {
                Some((index, Ok(locations)))
            }
        })
        .collect();
    outcomes.sort_by_key(|(index, _)| *index);

    let mut locations = Vec::new();
    let mut not_found = Vec::new();
    for (_, outcome) in outcomes {
        match outcome {
            Ok(found) => locations.extend(found),
            Err(symbol) => not_found.push(symbol),
        }
    }

    SymbolLocationsResult {
        locations,
        not_found,
    }
}

pub fn get_definition_by_location(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionParams,
) -> GetDefinitionResult {
    let _scope = profiling::scope("searchtools::get_definition_by_location");

    let resolver = WorkspaceFileResolver::new(analyzer.project());
    let mut pending = Vec::new();
    let mut results: Vec<Option<DefinitionLookupResult>> = vec![None; params.references.len()];

    for (index, query) in params.references.into_iter().enumerate() {
        match resolver.resolve_literal(&query.path) {
            ResolvedFileInput::File(file) => {
                pending.push((
                    index,
                    query.clone(),
                    crate::analyzer::usages::get_definition::DefinitionLookupRequest {
                        file,
                        line: query.line,
                        column: query.column,
                        start_byte: query.start_byte,
                        end_byte: query.end_byte,
                    },
                ));
            }
            ResolvedFileInput::Ambiguous(item) => {
                results[index] = Some(DefinitionLookupResult {
                    query,
                    status: "not_found".to_string(),
                    reference: None,
                    definitions: Vec::new(),
                    diagnostics: vec![DefinitionDiagnostic {
                        kind: "ambiguous_path".to_string(),
                        message: format!(
                            "`{}` is ambiguous; matches: {}",
                            item.input,
                            item.matches.join(", ")
                        ),
                    }],
                });
            }
            ResolvedFileInput::NotFound(path) => {
                results[index] = Some(DefinitionLookupResult {
                    query,
                    status: "not_found".to_string(),
                    reference: None,
                    definitions: Vec::new(),
                    diagnostics: vec![DefinitionDiagnostic {
                        kind: "path_not_found".to_string(),
                        message: format!("`{path}` does not resolve to a workspace file"),
                    }],
                });
            }
        }
    }

    let requests: Vec<_> = pending
        .iter()
        .map(|(_, _, request)| request.clone())
        .collect();
    let outcomes =
        crate::analyzer::usages::get_definition::resolve_definition_batch(analyzer, requests);

    for ((index, query, _), outcome) in pending.into_iter().zip(outcomes) {
        results[index] = Some(render_definition_lookup(analyzer, query, outcome));
    }

    GetDefinitionResult {
        results: results.into_iter().flatten().collect(),
    }
}

pub fn get_definition_by_reference(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionByReferenceParams,
) -> GetDefinitionByReferenceResult {
    let _scope = profiling::scope("searchtools::get_definition_by_reference");

    let mut results = Vec::with_capacity(params.references.len());

    for query in params.references {
        results.push(resolve_definition_context_query(analyzer, query));
    }

    GetDefinitionByReferenceResult { results }
}

fn resolve_definition_context_query(
    analyzer: &dyn IAnalyzer,
    query: DefinitionContextReferenceQuery,
) -> DefinitionByReferenceLookupResult {
    let units = match resolve_definition_context_symbol(analyzer, &query.symbol) {
        Ok(units) => units,
        Err(diagnostics) => {
            return DefinitionByReferenceLookupResult {
                query,
                status: "not_found".to_string(),
                definitions: Vec::new(),
                diagnostics,
            };
        }
    };
    if query.context.is_empty() {
        return invalid_context_lookup(query, "empty_context", "context must not be empty");
    }
    if query.target.is_empty() {
        return invalid_context_lookup(query, "empty_target", "target must not be empty");
    }

    let mut requests = Vec::new();
    for unit in units {
        let Some(range) = primary_range(analyzer, &unit) else {
            continue;
        };
        let source = match unit.source().read_to_string() {
            Ok(source) => source,
            Err(err) => {
                return DefinitionByReferenceLookupResult {
                    query,
                    status: "not_found".to_string(),
                    definitions: Vec::new(),
                    diagnostics: vec![DefinitionDiagnostic {
                        kind: "read_failed".to_string(),
                        message: format!("failed to read source file: {err}"),
                    }],
                };
            }
        };
        let Some(symbol_source) = source.get(range.start_byte..range.end_byte) else {
            continue;
        };
        for (context_offset, context) in symbol_source.match_indices(&query.context) {
            for (target_offset, _) in context.match_indices(&query.target) {
                let start_byte = range.start_byte + context_offset + target_offset;
                requests.push(
                    crate::analyzer::usages::get_definition::DefinitionLookupRequest {
                        file: unit.source().clone(),
                        line: None,
                        column: None,
                        start_byte: Some(start_byte),
                        end_byte: Some(start_byte + query.target.len()),
                    },
                );
            }
        }
    }

    if requests.is_empty() {
        return invalid_context_lookup(
            query,
            "target_not_found",
            "target was not found inside any exact context match",
        );
    }

    let outcomes =
        crate::analyzer::usages::get_definition::resolve_definition_batch(analyzer, requests);
    collapse_context_outcomes(analyzer, query, outcomes)
}

fn resolve_definition_context_symbol(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
) -> Result<Vec<CodeUnit>, Vec<DefinitionDiagnostic>> {
    if symbol.trim().is_empty() {
        return Err(vec![DefinitionDiagnostic {
            kind: "empty_symbol".to_string(),
            message: "symbol must not be empty".to_string(),
        }]);
    }

    let exact = resolve_codeunit_exact(analyzer, symbol);
    if !exact.is_empty() {
        return Ok(exact);
    }

    match resolve_codeunit_fuzzy(analyzer, symbol) {
        CodeUnitResolution::Resolved(units) => Ok(units),
        CodeUnitResolution::Ambiguous(matches) => Err(vec![DefinitionDiagnostic {
            kind: "ambiguous_symbol".to_string(),
            message: format!(
                "`{symbol}` is ambiguous; matches: {}",
                code_unit_match_names(matches).join(", ")
            ),
        }]),
        CodeUnitResolution::NotFound => Err(vec![DefinitionDiagnostic {
            kind: "symbol_not_found".to_string(),
            message: format!("`{symbol}` does not resolve to a workspace symbol"),
        }]),
    }
}

fn invalid_context_lookup(
    query: DefinitionContextReferenceQuery,
    kind: &str,
    message: &str,
) -> DefinitionByReferenceLookupResult {
    DefinitionByReferenceLookupResult {
        query,
        status: "invalid_location".to_string(),
        definitions: Vec::new(),
        diagnostics: vec![DefinitionDiagnostic {
            kind: kind.to_string(),
            message: message.to_string(),
        }],
    }
}

fn collapse_context_outcomes(
    analyzer: &dyn IAnalyzer,
    query: DefinitionContextReferenceQuery,
    outcomes: Vec<crate::analyzer::usages::get_definition::DefinitionLookupOutcome>,
) -> DefinitionByReferenceLookupResult {
    let Some(first) = outcomes.first() else {
        return invalid_context_lookup(query, "target_not_found", "no target candidates found");
    };
    let first_key = semantic_outcome_key(analyzer, first);
    if outcomes
        .iter()
        .all(|outcome| semantic_outcome_key(analyzer, outcome) == first_key)
    {
        return render_definition_reference_lookup(analyzer, query, first.clone());
    }

    DefinitionByReferenceLookupResult {
        query,
        status: "ambiguous".to_string(),
        definitions: Vec::new(),
        diagnostics: vec![DefinitionDiagnostic {
            kind: "ambiguous_reference_target".to_string(),
            message: "target appears multiple times in context and resolves to different semantic outcomes"
                .to_string(),
        }],
    }
}

fn render_definition_reference_lookup(
    analyzer: &dyn IAnalyzer,
    query: DefinitionContextReferenceQuery,
    outcome: crate::analyzer::usages::get_definition::DefinitionLookupOutcome,
) -> DefinitionByReferenceLookupResult {
    DefinitionByReferenceLookupResult {
        query,
        status: outcome.status.as_str().to_string(),
        definitions: definition_candidates(analyzer, &outcome.definitions),
        diagnostics: outcome
            .diagnostics
            .into_iter()
            .map(|diagnostic| DefinitionDiagnostic {
                kind: diagnostic.kind,
                message: diagnostic.message,
            })
            .collect(),
    }
}

fn semantic_outcome_key(
    analyzer: &dyn IAnalyzer,
    outcome: &crate::analyzer::usages::get_definition::DefinitionLookupOutcome,
) -> DefinitionOutcomeKey {
    let definition = outcome
        .definitions
        .iter()
        .filter_map(|unit| definition_candidate(analyzer, unit))
        .map(|candidate| definition_candidate_key(&candidate))
        .collect();
    (outcome.status.as_str().to_string(), definition)
}

fn definition_candidate_key(candidate: &DefinitionCandidate) -> DefinitionCandidateKey {
    (
        candidate.fqn.clone(),
        candidate.path.clone(),
        candidate.start_line,
        candidate.end_line,
        candidate.kind.clone(),
        candidate.signature.clone(),
        candidate.language.clone(),
    )
}

fn render_definition_lookup(
    analyzer: &dyn IAnalyzer,
    query: DefinitionReferenceQuery,
    outcome: crate::analyzer::usages::get_definition::DefinitionLookupOutcome,
) -> DefinitionLookupResult {
    DefinitionLookupResult {
        query,
        status: outcome.status.as_str().to_string(),
        reference: outcome.reference.map(|site| DefinitionReferenceSite {
            path: site.path,
            target: site.text,
        }),
        definitions: definition_candidates(analyzer, &outcome.definitions),
        diagnostics: outcome
            .diagnostics
            .into_iter()
            .map(|diagnostic| DefinitionDiagnostic {
                kind: diagnostic.kind,
                message: diagnostic.message,
            })
            .collect(),
    }
}

fn definition_candidates(analyzer: &dyn IAnalyzer, units: &[CodeUnit]) -> Vec<DefinitionCandidate> {
    units
        .iter()
        .filter_map(|unit| definition_candidate(analyzer, unit))
        .collect()
}

fn definition_candidate(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<DefinitionCandidate> {
    let range = primary_range(analyzer, unit)?;
    Some(DefinitionCandidate {
        fqn: unit.fq_name(),
        path: rel_path_string(unit.source()),
        start_line: range.start_line,
        end_line: range.end_line,
        kind: code_unit_kind_name(unit.kind()).to_string(),
        signature: unit.signature().map(str::to_string),
        language: language_name(language_for_target(unit)),
    })
}

pub fn get_symbol_ancestors(
    analyzer: &dyn IAnalyzer,
    params: SymbolLookupParams,
) -> Result<SymbolAncestorsResult, String> {
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        return Ok(SymbolAncestorsResult {
            ancestors: Vec::new(),
            not_found: params
                .symbols
                .into_iter()
                .filter(|symbol| !symbol.trim().is_empty())
                .collect(),
            ambiguous: Vec::new(),
        });
    };

    let mut ancestors = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();

    for symbol in params
        .symbols
        .into_iter()
        .filter(|symbol| !symbol.trim().is_empty())
    {
        match resolve_codeunit_fuzzy(analyzer, &symbol) {
            CodeUnitResolution::Resolved(code_units) => {
                let Some(code_unit) = code_units.into_iter().next() else {
                    not_found.push(symbol);
                    continue;
                };
                if !is_ancestor_target(&code_unit) {
                    return Err(format!(
                        "get_symbol_ancestors only accepts class/module/type symbols; `{symbol}` resolved to a {}",
                        code_unit_kind_name(code_unit.kind())
                    ));
                }
                ancestors.push(SymbolAncestors {
                    symbol: display_symbol_for_target(&code_unit),
                    ancestors: provider
                        .get_ancestors(&code_unit)
                        .into_iter()
                        .map(|ancestor| display_symbol_for_target(&ancestor))
                        .collect(),
                });
            }
            CodeUnitResolution::Ambiguous(matches) => {
                ambiguous.push(AmbiguousSymbol {
                    target: symbol,
                    matches: code_unit_match_names(matches),
                });
            }
            CodeUnitResolution::NotFound => not_found.push(symbol),
        }
    }

    Ok(SymbolAncestorsResult {
        ancestors,
        not_found,
        ambiguous,
    })
}

#[derive(Debug)]
struct SummaryTargets {
    file_targets: Vec<ProjectFile>,
    directory_targets: Vec<ProjectFile>,
    directory_target_inputs: Vec<String>,
    unmatched_file_targets: Vec<String>,
    symbol_targets: Vec<String>,
    ambiguous_paths: Vec<AmbiguousPathInput>,
}

struct ResolvedFilePatterns {
    files: Vec<ProjectFile>,
    ambiguous_paths: Vec<AmbiguousPathInput>,
}

enum SourceLookupOutcome {
    Found(Vec<SourceBlock>),
    NotFound(String),
    Ambiguous(AmbiguousSymbol),
    AmbiguousPath(AmbiguousPathInput),
}

fn route_summary_targets(analyzer: &dyn IAnalyzer, targets: &[String]) -> SummaryTargets {
    let mut file_targets = BTreeSet::new();
    let mut directory_targets = BTreeSet::new();
    let mut directory_target_inputs = Vec::new();
    let mut unmatched_file_targets = Vec::new();
    let mut symbol_targets = Vec::new();
    let mut ambiguous_paths = Vec::new();

    for target in targets
        .iter()
        .map(|target| target.trim())
        .filter(|target| !target.is_empty())
    {
        let directory_matches = resolve_directory_target(analyzer, target);
        if !directory_matches.is_empty() {
            directory_targets.extend(directory_matches);
            directory_target_inputs.push(target.to_string());
            continue;
        }

        let matches = resolve_file_patterns(analyzer, &[target.to_string()]);
        if !matches.ambiguous_paths.is_empty() {
            ambiguous_paths.extend(matches.ambiguous_paths);
            continue;
        }
        if !matches.files.is_empty() {
            file_targets.extend(matches.files);
            continue;
        }

        if looks_like_file_target(target) {
            unmatched_file_targets.push(target.to_string());
            continue;
        }

        symbol_targets.push(target.to_string());
    }

    SummaryTargets {
        file_targets: file_targets.into_iter().collect(),
        directory_targets: directory_targets.into_iter().collect(),
        directory_target_inputs,
        unmatched_file_targets,
        symbol_targets,
        ambiguous_paths,
    }
}

fn summarize_symbol_targets(analyzer: &dyn IAnalyzer, targets: Vec<String>) -> SummaryResult {
    let mut summaries = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();

    for target in targets {
        match resolve_typeish_codeunit_fuzzy(analyzer, &target) {
            CodeUnitResolution::Resolved(code_units) => {
                let start_len = summaries.len();
                for code_unit in code_units {
                    if let Some(block) = summary_block_for_code_unit(analyzer, &code_unit) {
                        summaries.push(block);
                    }
                }
                if summaries.len() == start_len {
                    not_found.push(target);
                }
            }
            CodeUnitResolution::Ambiguous(matches) => ambiguous.push(AmbiguousSymbol {
                target,
                matches: code_unit_match_names(matches),
            }),
            CodeUnitResolution::NotFound => not_found.push(target),
        }
    }

    SummaryResult {
        summaries,
        not_found,
        ambiguous,
        ambiguous_paths: Vec::new(),
    }
}

pub(crate) fn summarize_targets_with_directory_inventory(
    analyzer: &dyn IAnalyzer,
    targets: &[String],
) -> (SummaryResult, Option<SkimFilesResult>, Vec<String>) {
    let summary_targets = route_summary_targets(analyzer, targets);
    let summary_result = summarize_routed_targets(analyzer, &summary_targets);
    let directory_symbols = (!summary_targets.directory_targets.is_empty())
        .then(|| skim_files_for_files(analyzer, summary_targets.directory_targets));
    (
        summary_result,
        directory_symbols,
        summary_targets.directory_target_inputs,
    )
}

fn source_blocks_for_resolved_units(
    analyzer: &dyn IAnalyzer,
    code_units: &[CodeUnit],
) -> Vec<SourceBlock> {
    code_units
        .iter()
        .flat_map(|code_unit| {
            if is_file_listing_target(code_unit) {
                module_file_listing_blocks(code_unit)
            } else {
                source_blocks_for_code_unit(analyzer, code_unit, true)
            }
        })
        .collect()
}

pub fn get_symbol_sources(
    analyzer: &dyn IAnalyzer,
    params: SymbolLookupParams,
) -> SymbolSourcesResult {
    let selected_symbols: Vec<_> = params
        .symbols
        .into_iter()
        .filter(|symbol| !symbol.trim().is_empty())
        .collect();

    let mut outcomes: Vec<_> = selected_symbols
        .into_par_iter()
        .enumerate()
        .map(|(index, symbol)| {
            // Exact fully-qualified lookup wins before file patterns, so a
            // canonical symbol containing `/` (e.g. a Go import path) is never
            // misrouted as a filesystem path.
            let exact = resolve_codeunit_exact(analyzer, &symbol);
            if !exact.is_empty() {
                let sources = source_blocks_for_resolved_units(analyzer, &exact);
                return if sources.is_empty() {
                    (index, SourceLookupOutcome::NotFound(symbol))
                } else {
                    (index, SourceLookupOutcome::Found(sources))
                };
            }

            let file_matches = resolve_file_patterns(analyzer, std::slice::from_ref(&symbol));
            if let Some(item) = file_matches.ambiguous_paths.first() {
                return (index, SourceLookupOutcome::AmbiguousPath(item.clone()));
            }
            if !file_matches.files.is_empty() {
                let sources = source_blocks_for_files(analyzer, file_matches.files);
                return if sources.is_empty() {
                    (index, SourceLookupOutcome::NotFound(symbol))
                } else {
                    (index, SourceLookupOutcome::Found(sources))
                };
            }

            if looks_like_file_target(&symbol) {
                return (index, SourceLookupOutcome::NotFound(symbol));
            }

            match resolve_codeunit_fuzzy(analyzer, &symbol) {
                CodeUnitResolution::Resolved(code_units) => {
                    let sources = source_blocks_for_resolved_units(analyzer, &code_units);
                    if sources.is_empty() {
                        (index, SourceLookupOutcome::NotFound(symbol))
                    } else {
                        (index, SourceLookupOutcome::Found(sources))
                    }
                }
                CodeUnitResolution::Ambiguous(matches) => (
                    index,
                    SourceLookupOutcome::Ambiguous(AmbiguousSymbol {
                        target: symbol,
                        matches: code_unit_match_names(matches),
                    }),
                ),
                CodeUnitResolution::NotFound => (index, SourceLookupOutcome::NotFound(symbol)),
            }
        })
        .collect();
    outcomes.sort_by_key(|(index, _)| *index);

    let mut sources = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();
    let mut ambiguous_paths = Vec::new();
    for (_, outcome) in outcomes {
        match outcome {
            SourceLookupOutcome::Found(blocks) => sources.extend(dedup_source_blocks(blocks)),
            SourceLookupOutcome::NotFound(symbol) => not_found.push(symbol),
            SourceLookupOutcome::Ambiguous(item) => ambiguous.push(item),
            SourceLookupOutcome::AmbiguousPath(item) => ambiguous_paths.push(item),
        }
    }

    SymbolSourcesResult {
        sources,
        not_found,
        ambiguous,
        ambiguous_paths,
    }
}

pub fn get_summaries(analyzer: &dyn IAnalyzer, params: SummariesParams) -> SummaryResult {
    let (mut summaries, _directory_symbols, directory_target_inputs) =
        summarize_targets_with_directory_inventory(analyzer, &params.targets);
    summaries.not_found.extend(directory_target_inputs);
    summaries
}

fn skim_files_for_files(analyzer: &dyn IAnalyzer, files: Vec<ProjectFile>) -> SkimFilesResult {
    let total_files = files.len();
    let truncated = total_files > FILE_SKIM_LIMIT;
    let selected = select_files_for_display(analyzer, files, FILE_SKIM_LIMIT);
    let mut files: Vec<_> = selected
        .into_par_iter()
        .map(|file| {
            let lines: Vec<_> = analyzer
                .list_symbols(&file)
                .lines()
                .map(str::to_string)
                .collect();
            let path = rel_path_string(&file);
            let loc = file
                .read_to_string()
                .map(|content| line_count(&content))
                .unwrap_or(0);
            SkimFile { path, loc, lines }
        })
        .collect();
    files.sort_by(|left, right| left.path.cmp(&right.path));

    SkimFilesResult {
        truncated,
        total_files,
        files,
        ambiguous_paths: Vec::new(),
    }
}

pub(crate) fn summarize_files(analyzer: &dyn IAnalyzer, files: Vec<ProjectFile>) -> SummaryResult {
    let mut summaries: Vec<_> = files
        .into_par_iter()
        .filter_map(|file| {
            let mut elements = Vec::new();
            for code_unit in analyzer.top_level_declarations(&file) {
                elements.extend(summary_elements_for_code_unit_in_file(
                    analyzer, code_unit, &file,
                ));
            }

            let (elements, fallback_reason) = if elements.is_empty() {
                summary_fallback_for_file(analyzer, &file)?
            } else {
                (elements, None)
            };

            Some(SummaryBlock {
                label: rel_path_string(&file),
                path: rel_path_string(&file),
                preamble: file_preamble(&file, &elements),
                fallback_reason,
                elements,
            })
        })
        .collect();
    summaries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.label.cmp(&right.label))
    });

    SummaryResult {
        summaries,
        not_found: Vec::new(),
        ambiguous: Vec::new(),
        ambiguous_paths: Vec::new(),
    }
}

fn summary_fallback_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<(Vec<SummaryElement>, Option<String>)> {
    let include_elements = include_fallback_elements(analyzer, file);
    if !include_elements.is_empty() {
        return Some((
            include_elements,
            Some("no indexed declarations found; showing top-level includes".to_string()),
        ));
    }

    excerpt_fallback_elements(file).map(|elements| {
        (
            elements,
            Some(
                "no indexed declarations or top-level includes found; showing head/tail sample"
                    .to_string(),
            ),
        )
    })
}

fn include_fallback_elements(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Vec<SummaryElement> {
    let include_lines: Vec<_> = analyzer
        .import_statements(file)
        .iter()
        .filter(|statement| is_include_statement(statement))
        .cloned()
        .collect();
    if include_lines.is_empty() {
        return Vec::new();
    }

    let Ok(content) = file.read_to_string() else {
        return Vec::new();
    };
    let path = rel_path_string(file);
    let physical_lines: Vec<&str> = content.lines().collect();
    let normalized_lines: Vec<String> = physical_lines
        .iter()
        .map(|line| normalize_include_line(line))
        .collect();

    let mut next_search_index = 0usize;
    let mut elements = Vec::new();
    for include in include_lines {
        let Some((line_index, line_text)) = normalized_lines
            .iter()
            .enumerate()
            .skip(next_search_index)
            .find_map(|(line_index, normalized)| {
                (normalized == &include).then(|| {
                    (
                        line_index,
                        physical_lines.get(line_index).copied().unwrap_or(""),
                    )
                })
            })
        else {
            continue;
        };
        next_search_index = line_index + 1;
        elements.push(SummaryElement {
            path: path.clone(),
            symbol: extract_include_target(&include),
            kind: "include".to_string(),
            start_line: line_index + 1,
            end_line: line_index + 1,
            text: line_text.trim_end().to_string(),
            presentation: None,
        });
    }
    elements
}

fn excerpt_fallback_elements(file: &ProjectFile) -> Option<Vec<SummaryElement>> {
    let content = file.read_to_string().ok()?;
    let sampled = model_context::sample(&content);
    if sampled.text.is_empty() {
        return None;
    }
    Some(vec![SummaryElement {
        path: rel_path_string(file),
        symbol: rel_path_string(file),
        kind: "excerpt".to_string(),
        start_line: 1,
        end_line: sampled.total_lines,
        text: sampled.text,
        presentation: Some("sampled_excerpt".to_string()),
    }])
}

fn is_include_statement(statement: &str) -> bool {
    statement.trim_start().starts_with("#include")
}

fn normalize_include_line(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_include_target(statement: &str) -> String {
    let trimmed = statement.trim();
    let rest = trimmed.strip_prefix("#include").unwrap_or(trimmed).trim();
    if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
        return rest[1..rest.len() - 1].to_string();
    }
    if rest.starts_with('<') && rest.ends_with('>') && rest.len() >= 2 {
        return rest[1..rest.len() - 1].to_string();
    }
    rest.to_string()
}

fn summarize_routed_targets(
    analyzer: &dyn IAnalyzer,
    summary_targets: &SummaryTargets,
) -> SummaryResult {
    let mut file_output = summarize_files(analyzer, summary_targets.file_targets.clone());
    let symbol_output = summarize_symbol_targets(analyzer, summary_targets.symbol_targets.clone());

    file_output.summaries.extend(symbol_output.summaries);
    file_output
        .not_found
        .extend(summary_targets.unmatched_file_targets.clone());
    file_output.not_found.extend(symbol_output.not_found);
    file_output.ambiguous.extend(symbol_output.ambiguous);
    file_output
        .ambiguous_paths
        .extend(symbol_output.ambiguous_paths);
    file_output
        .ambiguous_paths
        .extend(summary_targets.ambiguous_paths.clone());
    file_output.summaries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.label.cmp(&right.label))
    });
    file_output
}

pub fn list_symbols(analyzer: &dyn IAnalyzer, params: FilePatternsParams) -> SkimFilesResult {
    let expanded = resolve_file_patterns(analyzer, &params.file_patterns);
    let mut result = skim_files_for_files(analyzer, expanded.files);
    result.ambiguous_paths = expanded.ambiguous_paths;
    result
}

pub fn most_relevant_files(
    analyzer: &dyn IAnalyzer,
    params: MostRelevantFilesParams,
) -> Result<MostRelevantFilesResult, String> {
    let _scope = profiling::scope("searchtools::most_relevant_files");
    validate_most_relevant_files_params(&params)?;
    let resolver = WorkspaceFileResolver::new(analyzer.project());
    let mut seeds = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous_paths = Vec::new();
    let mut duplicates = Vec::new();
    let seed_weights = params
        .seed_weights
        .unwrap_or_else(|| vec![1.0; params.seed_file_paths.len()]);
    let recency_half_life = params.recency_half_life;
    let mut resolved_by_file = HashMap::default();

    {
        let _scope = profiling::scope("searchtools::most_relevant_files.resolve_seeds");
        for (input, weight) in params.seed_file_paths.into_iter().zip(seed_weights) {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                continue;
            }

            match resolver.resolve_literal(trimmed) {
                ResolvedFileInput::File(file) => {
                    let display_path = rel_path_string(&file);
                    if resolved_by_file.insert(file.clone(), ()).is_some() {
                        duplicates.push(display_path);
                        continue;
                    }
                    seeds.push((file, weight));
                }
                ResolvedFileInput::Ambiguous(item) => ambiguous_paths.push(item),
                ResolvedFileInput::NotFound(item) => not_found.push(item),
            }
        }
    }

    duplicates.sort();
    duplicates.dedup();
    if !duplicates.is_empty() {
        return Ok(MostRelevantFilesResult {
            files: Vec::new(),
            not_found,
            ambiguous_paths,
            duplicates,
        });
    }

    let files = {
        let _scope = profiling::scope("searchtools::most_relevant_files.rank");
        let ranked = if recency_half_life == Some(DEFAULT_RECENCY_HALF_LIFE) {
            most_relevant_project_files(analyzer, &seeds, params.limit)
        } else {
            most_relevant_project_files_with_half_life(
                analyzer,
                &seeds,
                params.limit,
                recency_half_life,
            )
        };
        ranked
            .into_iter()
            .map(|file| rel_path_string(&file))
            .collect()
    };

    Ok(MostRelevantFilesResult {
        files,
        not_found,
        ambiguous_paths,
        duplicates,
    })
}

fn validate_most_relevant_files_params(params: &MostRelevantFilesParams) -> Result<(), String> {
    if let Some(seed_weights) = params.seed_weights.as_ref() {
        if seed_weights.len() != params.seed_file_paths.len() {
            return Err(format!(
                "seed_weights length {} must match seed_file_paths length {}",
                seed_weights.len(),
                params.seed_file_paths.len()
            ));
        }

        for (index, weight) in seed_weights.iter().enumerate() {
            if !weight.is_finite() || *weight <= 0.0 {
                return Err(format!(
                    "seed_weights[{index}] must be finite and > 0, got {weight}"
                ));
            }
        }
    }

    if let Some(half_life) = params.recency_half_life
        && (!half_life.is_finite() || half_life <= 0.0)
    {
        return Err(format!(
            "recency_half_life must be finite and > 0, got {half_life}"
        ));
    }

    Ok(())
}

/// Pre-compute the set of detected test files to exclude, or `None` when test
/// files should be kept. Both `scan_usages` and `usage_graph` filter at the
/// source (before the regex scan and the call-site cap) rather than dropping
/// test hits after the fact: filtering post-hoc would let test hits eat into
/// the cap and turn production-only queries into `TooManyCallsites` errors.
fn excluded_test_files(
    analyzer: &dyn IAnalyzer,
    include_tests: bool,
) -> Option<Arc<HashSet<ProjectFile>>> {
    if include_tests {
        return None;
    }
    let set: HashSet<ProjectFile> = analyzer
        .analyzed_files()
        .filter(|file| analyzer.contains_tests(file))
        .cloned()
        .collect();
    Some(Arc::new(set))
}

/// Build a [`UsageFinder`] whose file filter drops the excluded test files and
/// applies the optional path filter — the workspace scoping that both
/// `scan_usages` and `usage_graph` run before querying call sites.
fn scoped_usage_finder(
    test_files: Option<&Arc<HashSet<ProjectFile>>>,
    path_filter: &Option<ScanUsagesPathFilter>,
) -> UsageFinder {
    let mut finder = UsageFinder::new();
    if let Some(test_files) = test_files {
        let test_files = Arc::clone(test_files);
        let path_filter = path_filter.clone();
        finder = finder.with_file_filter(move |file| {
            !test_files.contains(file)
                && path_filter
                    .as_ref()
                    .map(|filter| filter.matches(file))
                    .unwrap_or(true)
        });
    } else if let Some(path_filter) = path_filter.clone() {
        finder = finder.with_file_filter(move |file| path_filter.matches(file));
    }
    finder
}

/// Split a `scan_usages` symbol input into an optional file anchor and the name
/// to resolve. A plain input (`Anchor`) has no anchor; a file-anchored selector
/// (`charts/Anchor.ts#Anchor`), returned in a prior call's `candidate_targets`,
/// picks one of several same-named definitions. The `#` separator does not occur
/// in any language's symbol grammar, so a bare name is never misread as anchored.
fn split_definition_selector(input: &str) -> (Option<&str>, &str) {
    match input.split_once('#') {
        Some((anchor, name)) if !anchor.is_empty() && !name.is_empty() => (Some(anchor), name),
        _ => (None, input),
    }
}

/// The selector a caller re-queries to scan exactly this definition. Module-
/// scoped ecosystems (JS/TS) share bare fqns across files, so the selector is
/// file-anchored to stay unique; elsewhere the fqn already is.
fn definition_selector(unit: &CodeUnit) -> String {
    if Ecosystem::of(language_for_target(unit)).is_module_scoped() {
        format!("{}#{}", rel_path_string(unit.source()), unit.fq_name())
    } else {
        unit.fq_name()
    }
}

/// Partition resolved overloads into distinct selectable definitions, preserving
/// first-seen order. Overloads of one symbol share a selector and scan together;
/// module-scoped same-name definitions in different files get one selector each,
/// so the caller can choose between them rather than scan a conflation.
fn distinct_definitions(overloads: Vec<CodeUnit>) -> Vec<(String, Vec<CodeUnit>)> {
    let mut groups: Vec<(String, Vec<CodeUnit>)> = Vec::new();
    for unit in overloads {
        let selector = definition_selector(&unit);
        match groups
            .iter_mut()
            .find(|(existing, _)| *existing == selector)
        {
            Some((_, units)) => units.push(unit),
            None => groups.push((selector, vec![unit])),
        }
    }
    groups
}

fn code_unit_match_names(matches: Vec<CodeUnit>) -> Vec<String> {
    dedupe_preserving_order(matches.into_iter().map(|unit| unit.fq_name()).collect())
}

fn ambiguous_usage_symbol_from_groups(
    analyzer: &dyn IAnalyzer,
    symbol: String,
    short_name: String,
    groups: Vec<(String, Vec<CodeUnit>)>,
    note: impl Into<String>,
) -> AmbiguousUsageSymbol {
    let note = note.into();
    let total = groups.len();
    let candidate_targets: Vec<String> = groups
        .iter()
        .map(|(selector, _)| selector.clone())
        .collect();
    let candidate_details: Vec<AmbiguousUsageCandidateDetail> = groups
        .iter()
        .take(SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT)
        .filter_map(|(selector, units)| {
            let unit = units.first()?;
            let range = primary_range(analyzer, unit)?;
            let path = rel_path_string(unit.source());
            Some(AmbiguousUsageCandidateDetail {
                target: selector.clone(),
                path: path.clone(),
                start_line: range.start_line,
                end_line: range.end_line,
                scan_usages_target: ScanUsagesTargetSuggestion {
                    path,
                    line: range.start_line,
                },
            })
        })
        .collect();

    AmbiguousUsageSymbol {
        symbol,
        short_name,
        candidate_targets,
        candidate_details,
        candidate_details_total: (total > 0).then_some(total),
        candidate_details_truncated: total > SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT,
        candidates: Vec::new(),
        candidate_files_truncated: false,
        definition_sites_excluded: None,
        note: Some(if total > SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT {
            format!(
                "{} Showing first {} of {total} candidate locations.",
                note, SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT
            )
        } else {
            note
        }),
    }
}

enum ScanUsageTargetResolution {
    Resolved {
        symbol: String,
        overloads: Vec<CodeUnit>,
    },
    NotFound(String),
    Ambiguous(AmbiguousUsageSymbol),
    Failure(UsageFailureInfo),
}

fn scan_usages_target_label(target: &ScanUsagesTarget) -> String {
    if let Some(start) = target.start_byte {
        match target.end_byte {
            Some(end) => format!("{}@bytes:{start}..{end}", target.path),
            None => format!("{}@byte:{start}", target.path),
        }
    } else if let Some(line) = target.line {
        match target.column {
            Some(column) => format!("{}:{line}:{column}", target.path),
            None => format!("{}:{line}", target.path),
        }
    } else {
        target.path.clone()
    }
}

fn location_selector_failure(
    target: &ScanUsagesTarget,
    reason_kind: &str,
    reason: impl Into<String>,
) -> ScanUsageTargetResolution {
    ScanUsageTargetResolution::Failure(UsageFailureInfo {
        symbol: scan_usages_target_label(target),
        fq_name: String::new(),
        strategy: "location_selector".to_string(),
        reason_kind: reason_kind.to_string(),
        reason: reason.into(),
        candidate_files_truncated: false,
    })
}

fn resolve_scan_usages_target(
    analyzer: &dyn IAnalyzer,
    resolver: &WorkspaceFileResolver,
    target: ScanUsagesTarget,
) -> ScanUsageTargetResolution {
    let file = match resolver.resolve_literal(target.path.trim()) {
        ResolvedFileInput::File(file) => file,
        ResolvedFileInput::Ambiguous(item) => {
            return location_selector_failure(
                &target,
                "ambiguous_path",
                format!(
                    "`{}` is ambiguous; matches: {}",
                    item.input,
                    item.matches.join(", ")
                ),
            );
        }
        ResolvedFileInput::NotFound(path) => {
            return ScanUsageTargetResolution::NotFound(format!(
                "{} ({path} does not resolve to a workspace file)",
                scan_usages_target_label(&target)
            ));
        }
    };

    if target.line.is_none() && target.start_byte.is_none() {
        return location_selector_failure(
            &target,
            "invalid_location",
            "provide either start_byte or line for a scan_usages target",
        );
    }
    if target.column == Some(0) {
        return location_selector_failure(&target, "invalid_location", "column must be 1-based");
    }

    let source = match file.read_to_string() {
        Ok(source) => source,
        Err(err) => {
            return location_selector_failure(
                &target,
                "read_failed",
                format!("failed to read `{}`: {err}", rel_path_string(&file)),
            );
        }
    };

    let line_starts = compute_line_starts(&source);
    if let Some(line) = target.line {
        if line == 0 || line > line_starts.len() {
            return location_selector_failure(
                &target,
                "invalid_location",
                format!(
                    "line {line} is outside 1..={} for this file",
                    line_starts.len()
                ),
            );
        }
        if let Some(column) = target.column {
            let line_start = line_starts[line - 1];
            let line_end = line_starts.get(line).copied().unwrap_or(source.len());
            if byte_offset_for_character_column(&source, line_start, line_end, line, column)
                .is_none()
            {
                return location_selector_failure(
                    &target,
                    "invalid_location",
                    format!("column {column} is outside line {line}"),
                );
            }
        }
    }

    if let Some(start) = target.start_byte {
        if start >= source.len() {
            return location_selector_failure(
                &target,
                "invalid_location",
                format!("start_byte {start} is outside {} byte file", source.len()),
            );
        }
        if !source.is_char_boundary(start) {
            return location_selector_failure(
                &target,
                "invalid_location",
                format!("start_byte {start} does not align to a UTF-8 character boundary"),
            );
        }
        if let Some(end) = target.end_byte {
            if start >= end || end > source.len() {
                return location_selector_failure(
                    &target,
                    "invalid_location",
                    format!(
                        "invalid byte range [{start}, {end}) for {} byte file",
                        source.len()
                    ),
                );
            }
            if !source.is_char_boundary(end) {
                return location_selector_failure(
                    &target,
                    "invalid_location",
                    format!("end_byte {end} does not align to a UTF-8 character boundary"),
                );
            }
        }
    }

    let matching_units: Vec<(CodeUnit, usize)> = analyzer
        .search_definitions(".*", false)
        .into_iter()
        .filter(|unit| unit.source() == &file)
        .filter_map(|unit| {
            let best_span = analyzer
                .ranges_of(&unit)
                .into_iter()
                .filter(|range| scan_usages_target_matches_range(&target, *range))
                .map(|range| range.end_byte.saturating_sub(range.start_byte))
                .min()?;
            Some((unit, best_span))
        })
        .collect();

    if matching_units.is_empty() {
        return ScanUsageTargetResolution::NotFound(format!(
            "{} (no declaration at location)",
            scan_usages_target_label(&target)
        ));
    }

    let narrowest_span = matching_units
        .iter()
        .map(|(_, span)| *span)
        .min()
        .expect("non-empty matching units");
    let mut matches: Vec<CodeUnit> = matching_units
        .into_iter()
        .filter_map(|(unit, span)| (span == narrowest_span).then_some(unit))
        .collect();

    matches.sort_by(|left, right| {
        primary_range(analyzer, left)
            .map(|range| (range.start_line, range.start_byte))
            .cmp(&primary_range(analyzer, right).map(|range| (range.start_line, range.start_byte)))
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
    });

    let groups = distinct_definitions(matches);
    if groups.len() > 1 {
        let label = scan_usages_target_label(&target);
        return ScanUsageTargetResolution::Ambiguous(ambiguous_usage_symbol_from_groups(
            analyzer,
            label.clone(),
            label,
            groups,
            "Ambiguous location; refine line/column or byte target.",
        ));
    }

    let (_, overloads) = groups.into_iter().next().expect("non-empty target groups");
    let symbol = definition_selector(&overloads[0]);
    ScanUsageTargetResolution::Resolved { symbol, overloads }
}

fn scan_usages_target_matches_range(target: &ScanUsagesTarget, range: Range) -> bool {
    if let Some(start) = target.start_byte {
        let end = target.end_byte.unwrap_or(start.saturating_add(1));
        range.start_byte <= start && range.end_byte >= end
    } else if let Some(line) = target.line {
        range.start_line <= line && range.end_line >= line
    } else {
        false
    }
}

fn retain_hits_resolving_to_overloads(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    hits: Vec<UsageHit>,
) -> Vec<UsageHit> {
    if hits.is_empty() || overloads.is_empty() {
        return hits;
    }

    let requests: Vec<_> = hits
        .iter()
        .map(
            |hit| crate::analyzer::usages::get_definition::DefinitionLookupRequest {
                file: hit.file.clone(),
                line: None,
                column: None,
                start_byte: Some(hit.start_offset),
                end_byte: Some(hit.end_offset),
            },
        )
        .collect();
    let outcomes =
        crate::analyzer::usages::get_definition::resolve_definition_batch(analyzer, requests);

    hits.into_iter()
        .zip(outcomes)
        .filter_map(|(hit, outcome)| {
            (outcome.definitions.is_empty()
                || outcome
                    .definitions
                    .iter()
                    .any(|definition| overloads.contains(definition)))
            .then_some(hit)
        })
        .collect()
}

fn byte_offset_for_character_column(
    source: &str,
    line_start: usize,
    line_end: usize,
    _line_number: usize,
    column: usize,
) -> Option<usize> {
    let line = source.get(line_start..line_end)?;
    let character_offset = column.checked_sub(1)?;
    if character_offset == 0 {
        return Some(line_start);
    }
    if let Some((byte_offset, _)) = line.char_indices().nth(character_offset) {
        return Some(line_start + byte_offset);
    }
    (character_offset == line.chars().count()).then_some(line_end)
}

pub fn scan_usages(analyzer: &dyn IAnalyzer, params: ScanUsagesParams) -> ScanUsagesResult {
    let _scope = profiling::scope("searchtools::scan_usages");

    let symbols: Vec<String> = params
        .symbols
        .unwrap_or_default()
        .into_iter()
        .filter(|symbol| !symbol.trim().is_empty())
        .collect();
    let targets = params.targets;
    let path_filter = build_scan_usages_path_filter(analyzer, params.paths.as_deref());

    let test_files = excluded_test_files(analyzer, params.include_tests);

    let mut not_found = Vec::new();
    let mut fallbacks = Vec::new();
    let mut failures = Vec::new();
    let mut ambiguous = Vec::new();
    let mut too_many_callsites = Vec::new();
    let mut render_states = Vec::new();
    let mut resolved_targets = Vec::new();

    let resolver = WorkspaceFileResolver::new(analyzer.project());
    for target in targets {
        match resolve_scan_usages_target(analyzer, &resolver, target) {
            ScanUsageTargetResolution::Resolved { symbol, overloads } => {
                resolved_targets.push((symbol, overloads, true));
            }
            ScanUsageTargetResolution::NotFound(target) => not_found.push(target),
            ScanUsageTargetResolution::Ambiguous(entry) => ambiguous.push(entry),
            ScanUsageTargetResolution::Failure(failure) => failures.push(failure),
        }
    }

    for symbol in symbols {
        let (anchor, lookup) = split_definition_selector(&symbol);
        let overloads = match resolve_codeunit_fuzzy(analyzer, lookup) {
            CodeUnitResolution::Resolved(overloads) => overloads,
            CodeUnitResolution::Ambiguous(candidate_targets) => {
                let groups = distinct_definitions(candidate_targets);
                ambiguous.push(ambiguous_usage_symbol_from_groups(
                    analyzer,
                    symbol.clone(),
                    symbol,
                    groups,
                    "Ambiguous; re-call with one selector from candidate_targets or scan_usages_target.",
                ));
                continue;
            }
            CodeUnitResolution::NotFound => {
                not_found.push(symbol);
                continue;
            }
        };

        let overloads = match anchor {
            // A file-anchored selector picks one definition from a prior
            // ambiguous result; narrow to that file before scanning.
            Some(anchor) => {
                let narrowed: Vec<CodeUnit> = overloads
                    .into_iter()
                    .filter(|unit| rel_path_string(unit.source()) == anchor)
                    .collect();
                if narrowed.is_empty() {
                    not_found.push(symbol);
                    continue;
                }
                narrowed
            }
            // A bare name resolving to module-scoped definitions in different
            // files (two JS/TS files exporting `Anchor`) is several distinct
            // symbols, not one with overloads; surface them as selectable
            // candidates rather than scanning a conflation of all of them.
            None => {
                let groups = distinct_definitions(overloads);
                if groups.len() > 1 {
                    ambiguous.push(ambiguous_usage_symbol_from_groups(
                        analyzer,
                        symbol.clone(),
                        symbol,
                        groups,
                        "Ambiguous; re-call with one selector from candidate_targets or scan_usages_target.",
                    ));
                    continue;
                }
                groups.into_iter().flat_map(|(_, units)| units).collect()
            }
        };

        resolved_targets.push((symbol, overloads, false));
    }

    for (symbol, overloads, location_selected) in resolved_targets {
        let finder = scoped_usage_finder(test_files.as_ref(), &path_filter);
        let query = finder.query(
            analyzer,
            &overloads,
            DEFAULT_MAX_FILES,
            SCAN_USAGES_MAX_CALLSITES,
        );
        let truncated = query.candidate_files_truncated;
        if let Some(diagnostic) = query.graph_fallback.as_ref() {
            fallbacks.push(UsageFallbackInfo {
                symbol: symbol.clone(),
                fq_name: diagnostic.fq_name.clone(),
                strategy: diagnostic.strategy.clone(),
                reason_kind: diagnostic.reason_kind.clone(),
                reason: diagnostic.reason.clone(),
                fallback_policy: "regex".to_string(),
            });
        }

        match query.result {
            FuzzyResult::Success { hits_by_overload } => {
                let hits: Vec<UsageHit> = hits_by_overload
                    .into_values()
                    .flat_map(BTreeSet::into_iter)
                    .collect();
                let mut base_note = None;
                let hits = if location_selected && query.graph_fallback.is_some() {
                    retain_hits_resolving_to_overloads(analyzer, &overloads, hits)
                } else {
                    hits
                };
                let mut filtered = filter_and_dedupe_hits(analyzer, &overloads, hits);
                if filtered.hits.is_empty() && query.graph_fallback.is_none() {
                    match RegexUsageAnalyzer::new().find_usages(
                        analyzer,
                        &overloads,
                        &query.candidate_files,
                        SCAN_USAGES_MAX_CALLSITES,
                    ) {
                        FuzzyResult::Success { hits_by_overload }
                        | FuzzyResult::Ambiguous {
                            hits_by_overload, ..
                        } => {
                            let fallback_hits: Vec<UsageHit> = hits_by_overload
                                .into_values()
                                .flat_map(BTreeSet::into_iter)
                                .collect();
                            let fallback_hits = if location_selected {
                                retain_hits_resolving_to_overloads(
                                    analyzer,
                                    &overloads,
                                    fallback_hits,
                                )
                            } else {
                                fallback_hits
                            };
                            filtered = filter_and_dedupe_hits(analyzer, &overloads, fallback_hits);
                            if !filtered.hits.is_empty() {
                                fallbacks.push(UsageFallbackInfo {
                                    symbol: symbol.clone(),
                                    fq_name: overloads[0].fq_name(),
                                    strategy: "RegexUsageAnalyzer".to_string(),
                                    reason_kind: "zero_structured_hits".to_string(),
                                    reason: "Structured usage analysis found no callers; regex fallback supplied text matches."
                                        .to_string(),
                                    fallback_policy: "regex".to_string(),
                                });
                            } else {
                                base_note = Some(
                                    "No callers found by graph or text scan. Callers in excluded scopes (tests, underscore-prefixed dirs, generated code) may not be visible to this tool."
                                        .to_string(),
                                );
                            }
                        }
                        FuzzyResult::TooManyCallsites {
                            short_name,
                            total_callsites,
                            limit,
                        } => {
                            too_many_callsites.push(TooManyCallsitesInfo {
                                symbol,
                                short_name,
                                total_callsites,
                                limit,
                                note: Some(too_many_callsites_note(limit)),
                            });
                            continue;
                        }
                        FuzzyResult::Failure { .. } => {
                            base_note = Some(
                                "No callers found by graph or text scan. Callers in excluded scopes (tests, underscore-prefixed dirs, generated code) may not be visible to this tool."
                                    .to_string(),
                            );
                        }
                    }
                }

                render_states.push(SymbolUsageRenderState::new(
                    symbol,
                    truncated,
                    filtered.definition_sites_excluded,
                    filtered.hits,
                    base_note,
                ));
            }
            FuzzyResult::Ambiguous {
                short_name,
                candidate_targets,
                hits_by_overload,
            } => {
                if location_selected {
                    let hits: Vec<UsageHit> = overloads
                        .iter()
                        .flat_map(|code_unit| {
                            hits_by_overload
                                .get(code_unit)
                                .into_iter()
                                .flat_map(|hits| hits.iter().cloned())
                        })
                        .collect();
                    let hits = retain_hits_resolving_to_overloads(analyzer, &overloads, hits);
                    let filtered = filter_and_dedupe_hits(analyzer, &overloads, hits);
                    render_states.push(SymbolUsageRenderState::new(
                        symbol,
                        truncated,
                        filtered.definition_sites_excluded,
                        filtered.hits,
                        None,
                    ));
                    continue;
                }
                let groups = distinct_definitions(candidate_targets.iter().cloned().collect());
                let detail_source = ambiguous_usage_symbol_from_groups(
                    analyzer,
                    symbol.clone(),
                    short_name.clone(),
                    groups.clone(),
                    "Ambiguous; re-call with one selector from candidate_targets or scan_usages_target.",
                );
                let deduped_targets: Vec<String> = groups
                    .iter()
                    .map(|(selector, _)| selector.clone())
                    .collect();
                let mut candidates = Vec::new();
                let mut definition_sites_excluded = 0usize;
                for (target, grouped_overloads) in groups {
                    let grouped_hits: Vec<UsageHit> = grouped_overloads
                        .iter()
                        .flat_map(|code_unit| {
                            hits_by_overload
                                .get(code_unit)
                                .into_iter()
                                .flat_map(|hits| hits.iter().cloned())
                        })
                        .filter(|hit| hit.confidence >= CONFIDENCE_THRESHOLD)
                        .collect();
                    let filtered =
                        filter_and_dedupe_hits(analyzer, &grouped_overloads, grouped_hits);
                    definition_sites_excluded += filtered.definition_sites_excluded;
                    candidates.push(AmbiguousUsageCandidate {
                        target,
                        total_hits: filtered.hits.len(),
                    });
                }
                ambiguous.push(AmbiguousUsageSymbol {
                    symbol,
                    short_name,
                    candidate_targets: deduped_targets,
                    candidate_details: detail_source.candidate_details,
                    candidate_details_total: detail_source.candidate_details_total,
                    candidate_details_truncated: detail_source.candidate_details_truncated,
                    candidates,
                    candidate_files_truncated: truncated,
                    definition_sites_excluded: some_if_nonzero(definition_sites_excluded),
                    note: detail_source.note,
                });
            }
            FuzzyResult::Failure { fq_name, reason } => {
                let diagnostic = query.graph_failure.as_ref();
                failures.push(UsageFailureInfo {
                    symbol,
                    fq_name,
                    strategy: diagnostic
                        .map(|diagnostic| diagnostic.strategy.clone())
                        .unwrap_or_default(),
                    reason_kind: diagnostic
                        .map(|diagnostic| diagnostic.reason_kind.clone())
                        .unwrap_or_default(),
                    reason,
                    candidate_files_truncated: truncated,
                });
            }
            FuzzyResult::TooManyCallsites {
                short_name,
                total_callsites,
                limit,
            } => {
                too_many_callsites.push(TooManyCallsitesInfo {
                    symbol,
                    short_name,
                    total_callsites,
                    limit,
                    note: Some(too_many_callsites_note(limit)),
                });
            }
        }
    }

    let usages = render_scan_usages_with_budget(
        render_states,
        &not_found,
        &fallbacks,
        &failures,
        &ambiguous,
        &too_many_callsites,
    );
    let summary = build_scan_usages_summary(
        &usages,
        &not_found,
        &fallbacks,
        &failures,
        &ambiguous,
        &too_many_callsites,
    );

    ScanUsagesResult {
        summary,
        usages,
        not_found,
        fallbacks,
        failures,
        ambiguous,
        too_many_callsites,
    }
}

/// A definition node in the workspace usage graph.
///
/// Nodes are the classes and functions (methods included) that a consumer can
/// run PageRank or another centrality analysis over. Fields, modules, and
/// macros are intentionally excluded to keep the graph focused on the
/// call/reference structure a code map cares about. `(language, fqn)` is the
/// node identity (plus `path` for file-scoped ecosystems like JS/TS), so the
/// same fqn in two languages — or two files of one module-scoped language —
/// stays distinct nodes; `fqn` matches the names returned by [`search_symbols`].
#[derive(Debug, Clone, Serialize)]
pub struct UsageGraphNode {
    pub fqn: String,
    /// The language ecosystem the node belongs to (JS and TS share one). Part of
    /// the node identity so the same fqn in two languages stays two nodes; for
    /// file-scoped ecosystems (JavaScript/TypeScript) the `path` also
    /// participates, so two files exporting the same name stay two nodes.
    pub language: String,
    pub path: String,
    pub start_line: usize,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// One concrete reference site behind a [`UsageGraphEdge`]: the workspace-relative
/// file `path` and the 1-based `line` where the reference occurs. Lines match the
/// `line` of a [`scan_usages`] hit and a node's `start_line`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct UsageGraphCallSite {
    pub path: String,
    pub line: usize,
}

/// A directed edge from a caller to a callee, aggregated across call sites.
///
/// `from` and `to` are fully qualified names: `from` is the enclosing
/// definition of each reference, `to` is the symbol being referenced. `weight`
/// is the number of distinct `(file, line, caller)` reference sites, which
/// mirrors the reference-count weighting an aider-style repo map uses (two
/// references to the same callee on one line count once).
///
/// `sites` lists those reference locations (`{path, line}`), so a consumer can
/// build a caller→callee map *with* call sites instead of re-scraping them;
/// `sites.len() == weight`. Per-site snippets remain the domain of [`scan_usages`].
#[derive(Debug, Clone, Serialize)]
pub struct UsageGraphEdge {
    pub from: String,
    pub to: String,
    /// The language ecosystem both endpoints belong to — disambiguates `from`/`to`
    /// when the same fqn exists in more than one language.
    pub language: String,
    pub weight: usize,
    /// Reference locations for this edge, sorted by `(path, line)`. One per distinct
    /// `(file, line, caller)` site, so `sites.len() == weight`.
    pub sites: Vec<UsageGraphCallSite>,
}

/// A symbol whose call sites exceeded the analyzer's enumeration guardrail.
///
/// These symbols still appear in `nodes`; only their inbound edges are omitted,
/// because the analyzer stopped before enumerating every caller. Surfacing them
/// lets a consumer decide whether to re-query the hot symbol with a narrower
/// `paths` scope. Mirrors the `too_many_callsites` signal from [`scan_usages`].
#[derive(Debug, Clone, Serialize)]
pub struct UsageGraphTruncatedSymbol {
    pub fqn: String,
    pub language: String,
    pub total_callsites: usize,
    pub limit: usize,
}

/// The resolved definition/reference graph for the whole workspace.
#[derive(Debug, Clone, Serialize)]
pub struct UsageGraphResult {
    pub nodes: Vec<UsageGraphNode>,
    pub edges: Vec<UsageGraphEdge>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub truncated_symbols: Vec<UsageGraphTruncatedSymbol>,
}

/// Build the whole-workspace resolved usage graph: classes and functions as
/// nodes, caller -> callee references as weighted edges.
///
/// This is the bulk counterpart to [`scan_usages`]. Where `scan_usages` answers
/// "who calls this one symbol" with per-call-site detail, `usage_graph` walks
/// every class and function once and returns the aggregated graph, so a consumer
/// can run PageRank (or another ranking) to build a code map without issuing one
/// `scan_usages` call per symbol.
///
/// Edges reuse the same resolution path as `scan_usages` (the language usage
/// graph with a regex fallback) and the same definition-site exclusion, so a
/// definition's own declaration never counts as a reference to itself. Self
/// references (a recursive call whose enclosing definition *is* the callee) are
/// dropped because they do not affect centrality ranking. Every edge endpoint
/// is guaranteed to be a node: a reference whose enclosing caller is not itself
/// a class or function (a module- or field-level call site) is dropped, so the
/// nodes and edges can be loaded into a graph library without phantom nodes.
///
/// This is a full-workspace pass and is proportional to the number of
/// definitions, so consumers are expected to cache the result and rebuild it
/// only when the workspace changes.
pub fn usage_graph(analyzer: &dyn IAnalyzer, params: UsageGraphParams) -> UsageGraphResult {
    let _scope = profiling::scope("searchtools::usage_graph");

    let path_filter = build_scan_usages_path_filter(analyzer, params.paths.as_deref());
    let test_files = excluded_test_files(analyzer, params.include_tests);

    // Group the definitions that become nodes by `(ecosystem, fqn, module
    // scope)`. Only classes and functions participate; fields/modules/macros are
    // excluded to keep the graph focused on call/reference structure. The fqn
    // collapses overloads that share a name so a symbol resolves its callers once
    // (not once per signature, which would multiply its edge weights); the module
    // scope keeps two file-scoped symbols that share a bare name distinct (see
    // `Ecosystem::is_module_scoped`); and a BTreeMap gives the output a
    // deterministic order independent of the analyzer's declaration iteration.
    let mut overloads_by_node: BTreeMap<(Ecosystem, String, Option<String>), Vec<CodeUnit>> =
        BTreeMap::new();
    for unit in analyzer.all_declarations() {
        if unit.is_synthetic()
            || !matches!(unit.kind(), CodeUnitType::Class | CodeUnitType::Function)
        {
            continue;
        }
        let ecosystem = Ecosystem::of(language_for_target(unit));
        let scope = ecosystem
            .is_module_scoped()
            .then(|| rel_path_string(unit.source()));
        overloads_by_node
            .entry((ecosystem, unit.fq_name(), scope))
            .or_default()
            .push(unit.clone());
    }

    // Node metadata, built in one parallel pass over the fqn groups. (The edge
    // passes need only the set of node fqns; per-file definition ranges are
    // derived inside the inverted driver and the per-symbol path's dedupe.)
    let mut nodes: Vec<UsageGraphNode> = overloads_by_node
        .par_iter()
        .map(|((ecosystem, fqn, _scope), overloads)| {
            // Choose the representative declaration deterministically (lowest
            // location) so a multi-declaration node (overloads, or a package-scoped
            // name declared across several files) reports stable metadata across
            // rebuilds rather than whichever declaration surfaced first.
            let primary = overloads
                .iter()
                .min_by(|left, right| {
                    rel_path_string(left.source())
                        .cmp(&rel_path_string(right.source()))
                        .then_with(|| {
                            primary_range(analyzer, left)
                                .map(|range| range.start_line)
                                .cmp(&primary_range(analyzer, right).map(|range| range.start_line))
                        })
                })
                .expect("a node group always has at least one declaration");
            UsageGraphNode {
                fqn: fqn.clone(),
                language: ecosystem.as_str().to_string(),
                path: rel_path_string(primary.source()),
                start_line: primary_range(analyzer, primary)
                    .map(|range| range.start_line)
                    .unwrap_or(0),
                kind: code_unit_kind_name(primary.kind()).to_string(),
                signature: primary.signature().map(str::to_string),
            }
        })
        .collect();

    // Node-membership set per ecosystem, so each language's inverted builder only
    // matches callees that are nodes in its own ecosystem (a Go reference can't
    // resolve to a same-fqn Python node).
    let mut node_fqns_by_ecosystem: HashMap<Ecosystem, HashSet<String>> = HashMap::default();
    for (ecosystem, fqn, _scope) in overloads_by_node.keys() {
        node_fqns_by_ecosystem
            .entry(*ecosystem)
            .or_default()
            .insert(fqn.clone());
    }
    let empty_fqns: HashSet<String> = HashSet::default();
    let ecosystem_fqns = |ecosystem: Ecosystem| {
        node_fqns_by_ecosystem
            .get(&ecosystem)
            .unwrap_or(&empty_fqns)
    };

    // Edges keyed by `(ecosystem, from_fqn, to_fqn)`: both endpoints share the
    // builder's ecosystem, so the ecosystem disambiguates a fqn that exists in
    // more than one language. The value is the edge's call sites; its length is the
    // edge weight (so weight and sites can never disagree).
    let mut edge_sites: BTreeMap<(Ecosystem, String, String), Vec<UsageGraphCallSite>> =
        BTreeMap::new();
    let mut truncated_symbols: Vec<UsageGraphTruncatedSymbol> = Vec::new();

    // Go edges in a single inverted pass over the workspace: walk each file once
    // and resolve every reference to its callee, instead of scanning every
    // symbol's candidate files (quadratic on real repos). A caller file is in
    // scope only when it survives the test / path filter, matching the per-symbol
    // candidate filter.
    let keep_file = |file: &ProjectFile| {
        test_files
            .as_ref()
            .map(|excluded| !excluded.contains(file))
            .unwrap_or(true)
            && path_filter
                .as_ref()
                .map(|filter| filter.matches(file))
                .unwrap_or(true)
    };
    // Every supported language has a whole-workspace inverted builder, so all
    // edges are produced by the passes below; merge each one's result in.
    let record_inverted =
        |ecosystem: Ecosystem,
         edges: Option<crate::analyzer::usages::inverted_edges::UsageEdges>,
         edge_sites: &mut BTreeMap<(Ecosystem, String, String), Vec<UsageGraphCallSite>>,
         truncated_symbols: &mut Vec<UsageGraphTruncatedSymbol>| {
            let Some(edges) = edges else {
                return;
            };
            for ((from, to), sites) in edges.edges {
                edge_sites
                    .entry((ecosystem, from, to))
                    .or_default()
                    .extend(sites.into_iter().map(|site| UsageGraphCallSite {
                        path: site.path,
                        line: site.line,
                    }));
            }
            for (fqn, total_callsites) in edges.truncated {
                truncated_symbols.push(UsageGraphTruncatedSymbol {
                    fqn,
                    language: ecosystem.as_str().to_string(),
                    total_callsites,
                    limit: crate::analyzer::usages::inverted_edges::MAX_CALLSITES,
                });
            }
        };
    {
        let _scope = profiling::scope("usage_graph::resolve_go");
        let go_edges = crate::analyzer::usages::go_graph::build_go_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::Go),
            keep_file,
        );
        record_inverted(
            Ecosystem::Go,
            go_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_jsts");
        let jsts_edges = crate::analyzer::usages::js_ts_graph::build_jsts_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::JavaScriptTypeScript),
            keep_file,
        );
        record_inverted(
            Ecosystem::JavaScriptTypeScript,
            jsts_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_python");
        let python_edges = crate::analyzer::usages::python_graph::build_python_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::Python),
            keep_file,
        );
        record_inverted(
            Ecosystem::Python,
            python_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_rust");
        let rust_edges = crate::analyzer::usages::rust_graph::build_rust_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::Rust),
            keep_file,
        );
        record_inverted(
            Ecosystem::Rust,
            rust_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_java");
        let java_edges = crate::analyzer::usages::java_graph::build_java_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::Java),
            keep_file,
        );
        record_inverted(
            Ecosystem::Java,
            java_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_csharp");
        let csharp_edges = crate::analyzer::usages::csharp_graph::build_csharp_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::CSharp),
            keep_file,
        );
        record_inverted(
            Ecosystem::CSharp,
            csharp_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_php");
        let php_edges = crate::analyzer::usages::php_graph::build_php_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::Php),
            keep_file,
        );
        record_inverted(
            Ecosystem::Php,
            php_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_scala");
        let scala_edges = crate::analyzer::usages::scala_graph::build_scala_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::Scala),
            keep_file,
        );
        record_inverted(
            Ecosystem::Scala,
            scala_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }
    {
        let _scope = profiling::scope("usage_graph::resolve_cpp");
        let cpp_edges = crate::analyzer::usages::cpp_graph::build_cpp_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::Cpp),
            keep_file,
        );
        record_inverted(
            Ecosystem::Cpp,
            cpp_edges,
            &mut edge_sites,
            &mut truncated_symbols,
        );
    }

    // Deterministic output order, independent of ecosystem enum order: nodes and
    // the truncated list by (language, fqn), edges by (language, from, to).
    nodes.sort_by(|left, right| {
        left.language
            .cmp(&right.language)
            .then_with(|| left.fqn.cmp(&right.fqn))
    });
    truncated_symbols.sort_by(|left, right| {
        left.language
            .cmp(&right.language)
            .then_with(|| left.fqn.cmp(&right.fqn))
    });

    let mut edges: Vec<UsageGraphEdge> = edge_sites
        .into_iter()
        .map(|((ecosystem, from, to), sites)| {
            // Each `(ecosystem, from, to)` is produced by exactly one builder, whose
            // sites already arrive sorted; `weight` is the site count.
            UsageGraphEdge {
                from,
                to,
                language: ecosystem.as_str().to_string(),
                weight: sites.len(),
                sites,
            }
        })
        .collect();
    edges.sort_by(|left, right| {
        left.language
            .cmp(&right.language)
            .then_with(|| left.from.cmp(&right.from))
            .then_with(|| left.to.cmp(&right.to))
    });

    UsageGraphResult {
        nodes,
        edges,
        truncated_symbols,
    }
}

#[derive(Debug, Clone)]
struct FilteredUsageHits {
    hits: Vec<UsageHitRow>,
    definition_sites_excluded: usize,
}

#[derive(Debug, Clone)]
struct UsageHitRow {
    path: String,
    line: usize,
    enclosing: String,
    snippet: String,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct SummaryFileCount {
    path: String,
    hits: usize,
}

#[derive(Debug, Clone)]
struct SymbolUsageRenderState {
    symbol: String,
    total_hits: usize,
    candidate_files_truncated: bool,
    definition_sites_excluded: usize,
    hits: Vec<UsageHitRow>,
    summary_files: Vec<SummaryFileCount>,
    top_enclosing: Vec<UsageEnclosingCount>,
    base_note: Option<String>,
    rendering: UsageRendering,
    file_limit: Option<usize>,
    top_enclosing_limit: usize,
}

impl SymbolUsageRenderState {
    fn new(
        symbol: String,
        candidate_files_truncated: bool,
        definition_sites_excluded: usize,
        hits: Vec<UsageHitRow>,
        base_note: Option<String>,
    ) -> Self {
        let total_hits = hits.len();
        let rendering = if total_hits <= 10 {
            UsageRendering::Full
        } else if total_hits <= 100 {
            UsageRendering::Lines
        } else {
            UsageRendering::Summary
        };
        let mut file_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut enclosing_counts: BTreeMap<String, usize> = BTreeMap::new();
        for hit in &hits {
            *file_counts.entry(hit.path.clone()).or_default() += 1;
            *enclosing_counts.entry(hit.enclosing.clone()).or_default() += 1;
        }
        let mut summary_files: Vec<SummaryFileCount> = file_counts
            .into_iter()
            .map(|(path, hits)| SummaryFileCount { path, hits })
            .collect();
        summary_files.sort_by(|left, right| {
            right
                .hits
                .cmp(&left.hits)
                .then_with(|| left.path.cmp(&right.path))
        });
        let mut top_enclosing: Vec<UsageEnclosingCount> = enclosing_counts
            .into_iter()
            .map(|(enclosing, hits)| UsageEnclosingCount { enclosing, hits })
            .collect();
        top_enclosing.sort_by(|left, right| {
            right
                .hits
                .cmp(&left.hits)
                .then_with(|| left.enclosing.cmp(&right.enclosing))
        });

        let file_limit = (rendering == UsageRendering::Summary
            && summary_files.len() > SCAN_USAGES_SUMMARY_FILE_LIMIT)
            .then_some(SCAN_USAGES_SUMMARY_FILE_LIMIT);

        Self {
            symbol,
            total_hits,
            candidate_files_truncated,
            definition_sites_excluded,
            hits,
            summary_files,
            top_enclosing,
            base_note,
            rendering,
            file_limit,
            top_enclosing_limit: SCAN_USAGES_TOP_ENCLOSING_LIMIT,
        }
    }
}

fn filter_and_dedupe_hits(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    hits: Vec<UsageHit>,
) -> FilteredUsageHits {
    let mut definition_ranges: BTreeMap<ProjectFile, Vec<Range>> = BTreeMap::new();
    for overload in overloads {
        definition_ranges
            .entry(overload.source().clone())
            .or_default()
            .extend(analyzer.ranges_of(overload));
    }

    let mut rows: BTreeMap<(String, usize, String), UsageHitRow> = BTreeMap::new();
    let mut definition_sites_excluded = 0usize;
    for hit in hits {
        if definition_ranges
            .get(&hit.file)
            .is_some_and(|ranges| ranges.iter().any(|range| ranges_overlap(range, &hit)))
        {
            definition_sites_excluded += 1;
            continue;
        }

        let path = rel_path_string(&hit.file);
        let enclosing = hit.enclosing.fq_name();
        let row = UsageHitRow {
            path: path.clone(),
            line: hit.line,
            enclosing: enclosing.clone(),
            snippet: hit.snippet.trim_end().to_string(),
            confidence: hit.confidence,
        };
        let key = (path, hit.line, enclosing);
        rows.entry(key)
            .and_modify(|existing| {
                if row.confidence > existing.confidence
                    || (row.confidence == existing.confidence
                        && row.snippet.len() > existing.snippet.len())
                {
                    *existing = row.clone();
                }
            })
            .or_insert(row);
    }

    let mut hits: Vec<_> = rows.into_values().collect();
    hits.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.enclosing.cmp(&right.enclosing))
    });

    FilteredUsageHits {
        hits,
        definition_sites_excluded,
    }
}

fn ranges_overlap(range: &Range, hit: &UsageHit) -> bool {
    range.start_byte < hit.end_offset && hit.start_offset < range.end_byte
}

fn render_scan_usages_with_budget(
    states: Vec<SymbolUsageRenderState>,
    not_found: &[String],
    fallbacks: &[UsageFallbackInfo],
    failures: &[UsageFailureInfo],
    ambiguous: &[AmbiguousUsageSymbol],
    too_many_callsites: &[TooManyCallsitesInfo],
) -> Vec<SymbolUsages> {
    let mut states = states;
    loop {
        let rendered: Vec<SymbolUsages> = states.iter().map(render_symbol_usages).collect();
        let summary = build_scan_usages_summary(
            &rendered,
            not_found,
            fallbacks,
            failures,
            ambiguous,
            too_many_callsites,
        );
        let result = ScanUsagesResult {
            summary,
            usages: rendered.clone(),
            not_found: not_found.to_vec(),
            fallbacks: fallbacks.to_vec(),
            failures: failures.to_vec(),
            ambiguous: ambiguous.to_vec(),
            too_many_callsites: too_many_callsites.to_vec(),
        };
        if serde_json::to_string(&result)
            .map(|text| text.len() <= SCAN_USAGES_RESPONSE_BUDGET_BYTES)
            .unwrap_or(true)
        {
            return rendered;
        }

        if !demote_largest_symbol(&mut states) && !truncate_largest_summary_symbol(&mut states) {
            return states.iter().map(render_symbol_usages).collect();
        }
    }
}

fn build_scan_usages_summary(
    usages: &[SymbolUsages],
    not_found: &[String],
    fallbacks: &[UsageFallbackInfo],
    failures: &[UsageFailureInfo],
    ambiguous: &[AmbiguousUsageSymbol],
    too_many_callsites: &[TooManyCallsitesInfo],
) -> ScanUsagesSummary {
    let requested_symbols = usages.len()
        + not_found.len()
        + failures.len()
        + ambiguous.len()
        + too_many_callsites.len();
    let total_hits = usages.iter().map(|usage| usage.total_hits).sum();
    let partial = usages
        .iter()
        .any(|usage| usage.candidate_files_truncated || usage.files_truncated.is_some())
        || failures
            .iter()
            .any(|failure| failure.candidate_files_truncated)
        || ambiguous.iter().any(|item| item.candidate_files_truncated)
        || !too_many_callsites.is_empty();

    let symbols = usages
        .iter()
        .map(|usage| ScanUsagesSymbolSummary {
            symbol: usage.symbol.clone(),
            total_hits: usage.total_hits,
            rendering: usage.rendering,
            files_returned: usage.files.len(),
            files_truncated: usage.files_truncated,
            candidate_files_truncated: usage.candidate_files_truncated,
            top_files: usage
                .files
                .iter()
                .take(5)
                .map(|file| ScanUsagesFileSummary {
                    path: file.path.clone(),
                    hit_count: file.hit_count.unwrap_or(file.hits.len()),
                })
                .collect(),
            top_enclosing: usage.top_enclosing.iter().take(5).cloned().collect(),
            note: usage.note.clone(),
        })
        .collect::<Vec<_>>();

    let recommended_next_call = recommended_scan_usages_next_call(usages, too_many_callsites);

    let mut warnings = Vec::new();
    if !not_found.is_empty() {
        warnings.push(format!("not_found: {}", not_found.join(", ")));
    }
    if !ambiguous.is_empty() {
        warnings.push(format!(
            "ambiguous: {}",
            ambiguous
                .iter()
                .map(|item| item.symbol.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !too_many_callsites.is_empty() {
        warnings.push(format!(
            "too_many_callsites: {}",
            too_many_callsites
                .iter()
                .map(|item| item.symbol.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !fallbacks.is_empty() {
        warnings.push(format!(
            "fallbacks_used: {}",
            fallbacks
                .iter()
                .map(|item| item.symbol.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !failures.is_empty() {
        warnings.push(format!(
            "failures: {}",
            failures
                .iter()
                .map(|item| item.symbol.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    ScanUsagesSummary {
        requested_symbols,
        resolved_symbols: usages.len(),
        total_hits,
        partial,
        symbols,
        recommended_next_call,
        warnings,
    }
}

fn recommended_scan_usages_next_call(
    usages: &[SymbolUsages],
    too_many_callsites: &[TooManyCallsitesInfo],
) -> Option<ScanUsagesRecommendedNextCall> {
    if let Some(usage) = usages
        .iter()
        .find(|usage| usage.rendering == UsageRendering::Summary && !usage.files.is_empty())
    {
        let paths = usage
            .files
            .iter()
            .take(3)
            .map(|file| serde_json::Value::String(file.path.clone()))
            .collect::<Vec<_>>();
        return Some(ScanUsagesRecommendedNextCall {
            tool: "scan_usages".to_string(),
            arguments: serde_json::json!({
                "symbols": [usage.symbol.clone()],
                "paths": paths,
            }),
            reason: "Summary-mode result; narrow to top files for line-level detail.".to_string(),
        });
    }

    too_many_callsites
        .first()
        .map(|item| ScanUsagesRecommendedNextCall {
            tool: "scan_usages".to_string(),
            arguments: serde_json::json!({
                "symbols": [item.symbol.clone()],
            }),
            reason: "Callsite count exceeded the exact scan cap; use a more specific symbol or add paths."
                .to_string(),
        })
}

fn demote_largest_symbol(states: &mut [SymbolUsageRenderState]) -> bool {
    let any_full = states
        .iter()
        .any(|state| state.rendering == UsageRendering::Full);
    let mut best_index = None;
    let mut best_size = 0usize;
    for (idx, state) in states.iter().enumerate() {
        let eligible = match state.rendering {
            UsageRendering::Full => true,
            UsageRendering::Lines => !any_full,
            UsageRendering::Summary => false,
        };
        if !eligible {
            continue;
        }
        let size = serialized_char_count(&render_symbol_usages(state));
        if size > best_size {
            best_size = size;
            best_index = Some(idx);
        }
    }
    let Some(idx) = best_index else {
        return false;
    };
    states[idx].rendering = match states[idx].rendering {
        UsageRendering::Full => UsageRendering::Lines,
        UsageRendering::Lines => UsageRendering::Summary,
        UsageRendering::Summary => UsageRendering::Summary,
    };
    true
}

fn truncate_largest_summary_symbol(states: &mut [SymbolUsageRenderState]) -> bool {
    let mut best_index = None;
    let mut best_size = 0usize;
    for (idx, state) in states.iter().enumerate() {
        if state.rendering != UsageRendering::Summary {
            continue;
        }
        let can_limit_files =
            state.summary_files.len() > state.file_limit.unwrap_or(SCAN_USAGES_SUMMARY_FILE_LIMIT);
        let can_reduce_files = state.file_limit.is_some_and(|limit| limit > 1);
        let can_reduce_enclosing = state.top_enclosing_limit > 0;
        if !(can_limit_files || can_reduce_files || can_reduce_enclosing) {
            continue;
        }
        let size = serialized_char_count(&render_symbol_usages(state));
        if size > best_size {
            best_size = size;
            best_index = Some(idx);
        }
    }
    let Some(idx) = best_index else {
        return false;
    };
    let state = &mut states[idx];
    if state.file_limit.is_none() && state.summary_files.len() > SCAN_USAGES_SUMMARY_FILE_LIMIT {
        state.file_limit = Some(SCAN_USAGES_SUMMARY_FILE_LIMIT);
        return true;
    }
    if let Some(limit) = state.file_limit
        && limit > 1
    {
        state.file_limit = Some((limit / 2).max(1));
        return true;
    }
    if state.top_enclosing_limit > 0 {
        state.top_enclosing_limit /= 2;
        return true;
    }
    false
}

fn render_symbol_usages(state: &SymbolUsageRenderState) -> SymbolUsages {
    let (files, files_truncated, top_enclosing) = match state.rendering {
        UsageRendering::Full => (
            render_usage_file_groups(&state.hits, true),
            None,
            Vec::new(),
        ),
        UsageRendering::Lines => (
            render_usage_file_groups(&state.hits, false),
            None,
            Vec::new(),
        ),
        UsageRendering::Summary => {
            let limit = state.file_limit.unwrap_or(state.summary_files.len());
            let kept = state
                .summary_files
                .iter()
                .take(limit)
                .map(|item| UsageFileGroup {
                    path: item.path.clone(),
                    hits: Vec::new(),
                    hit_count: Some(item.hits),
                })
                .collect::<Vec<_>>();
            let truncated = state.summary_files.len().saturating_sub(kept.len());
            (
                kept,
                some_if_nonzero(truncated),
                state
                    .top_enclosing
                    .iter()
                    .take(state.top_enclosing_limit)
                    .cloned()
                    .collect(),
            )
        }
    };

    let mut notes = Vec::new();
    if let Some(base) = state.base_note.clone() {
        notes.push(base);
    }
    match state.rendering {
        UsageRendering::Full => {}
        UsageRendering::Lines => notes.push(format!(
            "{} hits; showing line-level callers without snippets. Re-call with a single symbol or narrower scope for snippet detail.",
            state.total_hits
        )),
        UsageRendering::Summary => notes.push(format!(
            "{} hits; showing per-file counts. Re-call with a single symbol or narrower scope for line detail.",
            state.total_hits
        )),
    }
    if files_truncated.is_some() {
        notes.push("Summary file list truncated to fit the response budget.".to_string());
    }

    SymbolUsages {
        symbol: state.symbol.clone(),
        total_hits: state.total_hits,
        rendering: state.rendering,
        candidate_files_truncated: state.candidate_files_truncated,
        definition_sites_excluded: some_if_nonzero(state.definition_sites_excluded),
        files_truncated,
        note: if notes.is_empty() {
            None
        } else {
            Some(notes.join(" "))
        },
        top_enclosing,
        files,
    }
}

fn render_usage_file_groups(hits: &[UsageHitRow], include_snippets: bool) -> Vec<UsageFileGroup> {
    let mut grouped: BTreeMap<String, Vec<UsageLocation>> = BTreeMap::new();
    for hit in hits {
        grouped
            .entry(hit.path.clone())
            .or_default()
            .push(UsageLocation {
                line: hit.line,
                enclosing: hit.enclosing.clone(),
                snippet: include_snippets.then(|| hit.snippet.clone()),
                confidence: hit.confidence,
            });
    }
    grouped
        .into_iter()
        .map(|(path, mut hits)| {
            hits.sort_by(|left, right| {
                left.line
                    .cmp(&right.line)
                    .then_with(|| left.enclosing.cmp(&right.enclosing))
            });
            UsageFileGroup {
                path,
                hits,
                hit_count: None,
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
struct ScanUsagesPathFilter {
    rules: Vec<ScanUsagesPathRule>,
}

#[derive(Debug, Clone)]
enum ScanUsagesPathRule {
    Glob(Pattern),
    Exact(String),
}

impl ScanUsagesPathFilter {
    fn matches(&self, file: &ProjectFile) -> bool {
        let rel = rel_path_string(file);
        self.rules.iter().any(|rule| match rule {
            ScanUsagesPathRule::Glob(glob) => glob.matches_with(&rel, strict_separator_options()),
            ScanUsagesPathRule::Exact(path) => rel == *path,
        })
    }
}

fn build_scan_usages_path_filter(
    analyzer: &dyn IAnalyzer,
    paths: Option<&[String]>,
) -> Option<ScanUsagesPathFilter> {
    let paths = paths?;
    let resolver = WorkspaceFileResolver::new(analyzer.project());
    let mut rules = Vec::new();
    for raw in paths {
        let normalized = normalize_pattern(raw.trim());
        if normalized.is_empty() {
            continue;
        }
        if is_glob_pattern(&normalized) {
            if let Ok(glob) = Pattern::new(&normalized) {
                rules.push(ScanUsagesPathRule::Glob(glob));
            }
            continue;
        }
        match resolver.resolve_literal(&normalized) {
            ResolvedFileInput::File(file) => {
                rules.push(ScanUsagesPathRule::Exact(rel_path_string(&file)));
            }
            ResolvedFileInput::Ambiguous(item) => {
                rules.extend(item.matches.into_iter().map(ScanUsagesPathRule::Exact));
            }
            ResolvedFileInput::NotFound(_) => {
                rules.push(ScanUsagesPathRule::Exact(normalized));
            }
        }
    }
    (!rules.is_empty()).then_some(ScanUsagesPathFilter { rules })
}

fn strict_separator_options() -> MatchOptions {
    MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    }
}

fn serialized_char_count<T: Serialize>(value: &T) -> usize {
    serde_json::to_string(value)
        .map(|text| text.chars().count())
        .unwrap_or(0)
}

fn dedupe_preserving_order(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            deduped.push(value);
        }
    }
    deduped
}

fn some_if_nonzero(value: usize) -> Option<usize> {
    (value > 0).then_some(value)
}

fn too_many_callsites_note(limit: usize) -> String {
    format!(
        "Stopped after {limit} callsites. Re-call with a single symbol or narrower paths for detail."
    )
}

fn is_full_confidence(confidence: &f64) -> bool {
    (*confidence - 1.0).abs() < f64::EPSILON
}

fn rank_search_symbol_candidates(
    analyzer: &dyn IAnalyzer,
    patterns: &[String],
    code_units: Vec<CodeUnit>,
) -> Vec<RankedSearchCandidate> {
    let mut ranked: Vec<_> = code_units
        .into_iter()
        .map(|code_unit| RankedSearchCandidate {
            line: primary_range(analyzer, &code_unit)
                .map(|range| range.start_line)
                .unwrap_or(0),
            score: score_search_symbol_candidate(analyzer, patterns, &code_unit),
            code_unit,
        })
        .collect();
    ranked.sort_by(compare_ranked_search_candidates);
    ranked
}

fn score_search_symbol_candidate(
    analyzer: &dyn IAnalyzer,
    patterns: &[String],
    code_unit: &CodeUnit,
) -> SymbolCandidateScore {
    let mut best_match = SymbolMatchScore {
        tier: 0,
        exact_patterns: 0,
    };
    for pattern in patterns {
        let match_score = score_symbol_match(pattern, code_unit);
        if match_score > best_match {
            best_match = match_score;
        }
    }

    SymbolCandidateScore {
        match_score: best_match,
        path_tier: search_symbol_path_tier(patterns, code_unit.source()),
        implementation_tier: search_symbol_implementation_tier(analyzer, code_unit),
        source_quality_tier: search_symbol_source_quality_tier(analyzer, code_unit.source()),
        synthetic_tier: u8::from(!code_unit.is_synthetic()),
    }
}

fn score_symbol_match(pattern: &str, code_unit: &CodeUnit) -> SymbolMatchScore {
    let normalized = pattern.trim();
    if normalized.is_empty() {
        return SymbolMatchScore {
            tier: 0,
            exact_patterns: 0,
        };
    }

    let pattern_kind = classify_search_pattern(normalized);
    let query = normalized.to_ascii_lowercase();
    let identifier_raw = code_unit.identifier();
    let short_name_raw = code_unit.short_name();
    let fq_name_raw = code_unit.fq_name();
    let identifier = identifier_raw.to_ascii_lowercase();
    let short_name = short_name_raw.to_ascii_lowercase();
    let fq_name = fq_name_raw.to_ascii_lowercase();
    let normalized_short = normalize_symbol_name_for_search(code_unit.short_name());
    let normalized_fq = normalize_symbol_name_for_search(&code_unit.fq_name());

    let tier = match pattern_kind {
        SearchPatternKind::LiteralIdentifier => {
            if query == identifier {
                9
            } else if query == short_name {
                8
            } else if query == fq_name {
                7
            } else if contains_exact_symbol_component(short_name_raw, &query)
                || contains_exact_symbol_component(&fq_name_raw, &query)
            {
                6
            } else if contains_prefix_symbol_component(short_name_raw, &query)
                || contains_prefix_symbol_component(&fq_name_raw, &query)
            {
                5
            } else if short_name.contains(&query) {
                3
            } else if fq_name.contains(&query) {
                2
            } else {
                1
            }
        }
        SearchPatternKind::LiteralQualified => {
            if query == normalized_short || query == normalized_fq {
                9
            } else if normalized_short.starts_with(&query) || normalized_fq.starts_with(&query) {
                7
            } else if normalized_short.contains(&query) || normalized_fq.contains(&query) {
                5
            } else if query == identifier {
                3
            } else if identifier.starts_with(&query) {
                2
            } else {
                1
            }
        }
        SearchPatternKind::RegexLike => {
            if normalized == ".*" {
                1
            } else if short_name.contains(&query)
                || fq_name.contains(&query)
                || identifier.contains(&query)
            {
                2
            } else {
                1
            }
        }
    };

    SymbolMatchScore {
        tier,
        exact_patterns: usize::from(
            (pattern_kind == SearchPatternKind::LiteralIdentifier && query == identifier)
                || (pattern_kind == SearchPatternKind::LiteralQualified
                    && (query == normalized_short || query == normalized_fq)),
        ),
    }
}

fn classify_search_pattern(pattern: &str) -> SearchPatternKind {
    if pattern.is_empty()
        || pattern.chars().any(|ch| {
            matches!(
                ch,
                '*' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '^' | ' '
            )
        })
    {
        return SearchPatternKind::RegexLike;
    }

    if pattern.contains("::")
        || pattern.contains('.')
        || pattern.contains('/')
        || pattern.contains('\\')
        || pattern.contains('$')
        || pattern.contains('+')
    {
        SearchPatternKind::LiteralQualified
    } else {
        SearchPatternKind::LiteralIdentifier
    }
}

fn normalize_symbol_name_for_search(symbol: &str) -> String {
    let mut out = String::with_capacity(symbol.len());
    let mut chars = symbol.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ':' if chars.peek() == Some(&':') => {
                chars.next();
                out.push('.');
            }
            '/' | '\\' | '$' | '+' => out.push('.'),
            _ => out.push(ch.to_ascii_lowercase()),
        }
    }
    out
}

fn contains_exact_symbol_component(haystack: &str, query: &str) -> bool {
    symbol_components(haystack).any(|component| component == query)
}

fn contains_prefix_symbol_component(haystack: &str, query: &str) -> bool {
    symbol_components(haystack).any(|component| component.starts_with(query))
}

fn symbol_components(haystack: &str) -> impl Iterator<Item = String> + '_ {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|component| !component.is_empty())
        .flat_map(split_camel_case_component)
}

fn split_camel_case_component(component: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let chars: Vec<_> = component.char_indices().collect();
    for window in chars.windows(2) {
        let (_, current) = window[0];
        let (next_index, next) = window[1];
        if current.is_ascii_lowercase() && next.is_ascii_uppercase() {
            parts.push(component[start..next_index].to_ascii_lowercase());
            start = next_index;
        }
    }
    parts.push(component[start..].to_ascii_lowercase());
    parts
}

fn search_symbol_source_quality_tier(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> u8 {
    if is_generated_like_path(file) {
        return 0;
    }
    if is_test_candidate(analyzer, file) {
        return 1;
    }
    2
}

fn search_symbol_path_tier(patterns: &[String], file: &ProjectFile) -> u8 {
    let path = rel_path_string(file).to_ascii_lowercase();
    patterns
        .iter()
        .map(|pattern| pattern.trim())
        .filter(|pattern| !pattern.is_empty())
        .filter(|pattern| classify_search_pattern(pattern) != SearchPatternKind::RegexLike)
        .map(|pattern| pattern.to_ascii_lowercase())
        .map(|query| {
            if path.contains(&query) {
                3
            } else if path
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .any(|component| !component.is_empty() && component.eq_ignore_ascii_case(&query))
            {
                2
            } else {
                0
            }
        })
        .max()
        .unwrap_or(0)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContainsTestsParams {
    pub file_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainsTestsResult {
    /// Per resolved file: whether the language analyzer detects test code in it
    /// (tree-sitter based, not a path heuristic). Keyed by workspace-relative path.
    pub contains_tests: BTreeMap<String, bool>,
    /// Inputs that did not resolve to a single existing repo file (missing or
    /// ambiguous); the caller decides how to treat these.
    pub unresolved: Vec<String>,
}

/// Classify whether each given file contains test code, via the per-language
/// analyzers' `contains_tests`. Exposed so consumers that must treat the test
/// surface specially (e.g. hermetic acceptance that resets test files to a
/// reference state) can do so without re-implementing path heuristics.
pub fn contains_tests(
    analyzer: &dyn IAnalyzer,
    params: ContainsTestsParams,
) -> ContainsTestsResult {
    let project = analyzer.project();
    let resolver = WorkspaceFileResolver::new(project);
    let mut found = BTreeMap::new();
    let mut unresolved = Vec::new();
    for input in params.file_paths.iter() {
        match resolver.resolve_literal(input.trim()) {
            ResolvedFileInput::File(file) if file.exists() => {
                found.insert(rel_path_string(&file), analyzer.contains_tests(&file));
            }
            _ => unresolved.push(input.clone()),
        }
    }
    ContainsTestsResult {
        contains_tests: found,
        unresolved,
    }
}

fn is_test_candidate(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> bool {
    analyzer.contains_tests(file) || is_test_like_path(file)
}

fn is_test_like_path(file: &ProjectFile) -> bool {
    let path = rel_path_string(file).to_ascii_lowercase();
    if path
        .split('/')
        .any(|segment| matches!(segment, "test" | "tests" | "__tests__" | "spec" | "specs"))
    {
        return true;
    }

    let stem = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(|stem| stem.to_ascii_lowercase())
        .unwrap_or_default();
    stem.ends_with("_test")
        || stem.ends_with("test")
        || stem.ends_with("_spec")
        || stem.ends_with("spec")
}

fn is_generated_like_path(file: &ProjectFile) -> bool {
    let path = rel_path_string(file).to_ascii_lowercase();
    path.split('/').any(|segment| {
        matches!(
            segment,
            "vendor"
                | "third_party"
                | "third-party"
                | "node_modules"
                | "dist"
                | "build"
                | "target"
                | "out"
                | "gen"
                | "generated"
        )
    })
}

fn search_symbol_implementation_tier(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> u8 {
    if language_for_target(code_unit) != Language::Cpp || code_unit.kind() != CodeUnitType::Function
    {
        return 1;
    }

    let signatures = display_signatures(analyzer, code_unit);
    let has_body = signatures
        .iter()
        .any(|signature| signature.ends_with("{...}"));
    let is_source_file = matches!(
        code_unit
            .source()
            .rel_path()
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
            .as_deref(),
        Some("c" | "cc" | "cpp" | "cxx" | "m" | "mm")
    );

    match (has_body, is_source_file) {
        (true, true) => 3,
        (true, false) => 2,
        (false, true) => 1,
        (false, false) => 0,
    }
}

fn compare_ranked_search_candidates(
    left: &RankedSearchCandidate,
    right: &RankedSearchCandidate,
) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then(left.line.cmp(&right.line))
        .then_with(|| {
            left.code_unit
                .identifier()
                .cmp(right.code_unit.identifier())
        })
        .then_with(|| left.code_unit.fq_name().cmp(&right.code_unit.fq_name()))
        .then_with(|| left.code_unit.source().cmp(right.code_unit.source()))
}

fn search_symbol_git_tiers(
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
) -> HashMap<ProjectFile, usize> {
    let ranked = most_important_project_files(analyzer, files, files.len());
    let max_rank = ranked.len();
    ranked
        .into_iter()
        .enumerate()
        .map(|(index, file)| (file, max_rank.saturating_sub(index)))
        .collect()
}

fn compare_search_symbol_files(
    left_file: &ProjectFile,
    left_candidates: &[RankedSearchCandidate],
    right_file: &ProjectFile,
    right_candidates: &[RankedSearchCandidate],
    git_tiers: &HashMap<ProjectFile, usize>,
) -> Ordering {
    search_symbol_file_ranking_key(left_file, left_candidates, git_tiers)
        .cmp(&search_symbol_file_ranking_key(
            right_file,
            right_candidates,
            git_tiers,
        ))
        .reverse()
        .then_with(|| left_file.cmp(right_file))
}

fn search_symbol_file_ranking_key(
    file: &ProjectFile,
    candidates: &[RankedSearchCandidate],
    git_tiers: &HashMap<ProjectFile, usize>,
) -> FileRankingKey {
    let top1 = candidates
        .first()
        .map(|candidate| candidate.score)
        .unwrap_or(SymbolCandidateScore {
            match_score: SymbolMatchScore {
                tier: 0,
                exact_patterns: 0,
            },
            path_tier: 0,
            implementation_tier: 0,
            source_quality_tier: 0,
            synthetic_tier: 0,
        });
    let top2 = candidates
        .get(1)
        .map(|candidate| candidate.score)
        .unwrap_or(top1);
    let top3 = candidates
        .get(2)
        .map(|candidate| candidate.score)
        .unwrap_or(top2);

    let cohesion_tier = if candidates.len() < 2 {
        2
    } else {
        let min_line = candidates
            .iter()
            .take(3)
            .map(|candidate| candidate.line)
            .min()
            .unwrap_or(0);
        let max_line = candidates
            .iter()
            .take(3)
            .map(|candidate| candidate.line)
            .max()
            .unwrap_or(0);
        let span = max_line.saturating_sub(min_line);
        if span <= 120 {
            2
        } else if span <= 400 {
            1
        } else {
            0
        }
    };

    let focus_tier = match candidates.len() {
        0..=4 => 2,
        5..=8 => 1,
        _ => 0,
    };

    FileRankingKey {
        top1,
        cohesion_tier,
        focus_tier,
        top2,
        top3,
        git_tier: git_tiers.get(file).copied().unwrap_or(0),
    }
}

fn collect_ranked_kind_names(
    analyzer: &dyn IAnalyzer,
    code_units: &[RankedSearchCandidate],
    kind: CodeUnitType,
) -> Vec<SearchSymbolHit> {
    let mut hits: Vec<_> = code_units
        .iter()
        .filter(|candidate| candidate.code_unit.kind() == kind)
        .flat_map(|candidate| {
            display_signatures(analyzer, &candidate.code_unit)
                .into_iter()
                .map(move |signature| SearchSymbolHit {
                    symbol: display_symbol_for_target(&candidate.code_unit),
                    signature,
                    line: candidate.line,
                })
        })
        .collect();
    hits.sort_by(|left, right| {
        left.line
            .cmp(&right.line)
            .then_with(|| left.symbol.cmp(&right.symbol))
            .then_with(|| left.signature.cmp(&right.signature))
    });
    hits.dedup_by(|left, right| {
        left.symbol == right.symbol && left.signature == right.signature && left.line == right.line
    });
    hits
}

pub(crate) fn summary_block_for_code_unit(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Option<SummaryBlock> {
    let elements = summary_elements_for_code_unit(analyzer, code_unit);
    if elements.is_empty() {
        return None;
    }

    Some(SummaryBlock {
        label: display_symbol_for_target(code_unit),
        path: rel_path_string(code_unit.source()),
        preamble: file_preamble(code_unit.source(), &elements),
        fallback_reason: None,
        elements,
    })
}

fn summary_elements_for_code_unit(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Vec<SummaryElement> {
    // getSkeleton()/getSkeletons() are opaque display strings from the analyzer layer and are not
    // suitable for ranged searchtools summaries. Searchtools needs stable per-element line ranges,
    // so it derives summary elements from signatures and source ranges instead of reverse-mapping
    // formatted skeleton text.
    let mut elements = signature_elements(analyzer, code_unit);
    if code_unit.is_class() || code_unit.is_module() {
        for child in analyzer.direct_children(code_unit) {
            if child.is_anonymous() {
                continue;
            }
            elements.extend(summary_elements_for_code_unit(analyzer, child));
        }
    }
    elements
}

fn summary_elements_for_code_unit_in_file(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    file: &ProjectFile,
) -> Vec<SummaryElement> {
    let mut elements = signature_elements(analyzer, code_unit);
    if code_unit.is_class() || code_unit.is_module() {
        for child in analyzer.direct_children(code_unit) {
            if child.is_anonymous() || child.source() != file {
                continue;
            }
            elements.extend(summary_elements_for_code_unit_in_file(
                analyzer, child, file,
            ));
        }
    }
    elements
}

fn display_signatures(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Vec<String> {
    let signatures: Vec<_> = analyzer
        .signatures(code_unit)
        .iter()
        .filter_map(|signature| {
            let normalized = normalize_display_signature(signature);
            (!normalized.is_empty()).then_some(normalized)
        })
        .collect();
    if !signatures.is_empty() {
        return signatures;
    }

    let fallback = match code_unit.kind() {
        CodeUnitType::Class => format!("class {}", display_identifier_for_target(code_unit)),
        CodeUnitType::Function => code_unit
            .signature()
            .map(|signature| format!("{}{}", display_identifier_for_target(code_unit), signature))
            .unwrap_or_else(|| format!("{}()", display_identifier_for_target(code_unit))),
        CodeUnitType::Field => display_identifier_for_target(code_unit),
        CodeUnitType::Module => {
            display_symbol_name(language_for_target(code_unit), code_unit.short_name())
        }
        CodeUnitType::Macro => code_unit
            .signature()
            .map(str::to_string)
            .unwrap_or_else(|| display_identifier_for_target(code_unit).to_string()),
    };
    vec![fallback]
}

fn normalize_display_signature(signature: &str) -> String {
    let mut normalized = signature
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    while normalized.ends_with('{') {
        normalized.pop();
        normalized = normalized.trim_end().to_string();
    }
    normalized
}

fn signature_elements(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Vec<SummaryElement> {
    let signatures = analyzer.signatures(code_unit);
    if signatures.is_empty() {
        return Vec::new();
    }

    let mut ranges = analyzer.ranges(code_unit).to_vec();
    ranges.sort_by_key(|range| (range.start_line, range.start_byte));
    let path = rel_path_string(code_unit.source());
    let fallback_start = ranges.first().map(|range| range.start_line).unwrap_or(1);

    signatures
        .iter()
        .enumerate()
        .filter_map(|(index, signature)| {
            let text = trim_summary_signature(signature);
            if text.is_empty() {
                return None;
            }

            let start_line = ranges
                .get(index)
                .map(|range| range.start_line)
                .unwrap_or(fallback_start);
            let signature_line_count = text.lines().count().max(1);
            let range_line_count = ranges
                .get(index)
                .map(|range| {
                    range
                        .end_line
                        .saturating_sub(range.start_line)
                        .saturating_add(1)
                })
                .unwrap_or(1);
            let line_count = signature_line_count.max(range_line_count);
            let end_line = start_line + line_count.saturating_sub(1);
            Some(SummaryElement {
                path: path.clone(),
                symbol: display_symbol_for_target(code_unit),
                kind: code_unit_kind_name(code_unit.kind()).to_string(),
                start_line,
                end_line,
                text,
                presentation: None,
            })
        })
        .collect()
}

fn code_unit_kind_name(kind: CodeUnitType) -> &'static str {
    match kind {
        CodeUnitType::Class => "class",
        CodeUnitType::Function => "function",
        CodeUnitType::Field => "field",
        CodeUnitType::Module => "module",
        CodeUnitType::Macro => "macro",
    }
}

fn file_preamble(file: &ProjectFile, elements: &[SummaryElement]) -> String {
    let Some(first_start_line) = elements.iter().map(|element| element.start_line).min() else {
        return String::new();
    };
    if first_start_line <= 1 {
        return String::new();
    }
    let Ok(content) = file.read_to_string() else {
        return String::new();
    };
    content
        .lines()
        .take(first_start_line.saturating_sub(1))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

fn trim_summary_signature(signature: &str) -> String {
    signature
        .lines()
        .map(str::trim_end)
        .map(|line| {
            if let Some(stripped) = line.strip_suffix('{') {
                stripped.trim_end()
            } else {
                line
            }
        })
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && trimmed != "}" && trimmed != "[...]"
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn source_blocks_for_code_unit(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    include_comments: bool,
) -> Vec<SourceBlock> {
    let Ok(content) = code_unit.source().read_to_string() else {
        return Vec::new();
    };

    let language = language_for_target(code_unit);

    let mut ranges = if code_unit.is_function() {
        let mut grouped = Vec::new();
        for candidate in analyzer.definitions(&code_unit.fq_name()) {
            if candidate.source() == code_unit.source() {
                grouped.extend(analyzer.ranges(candidate).iter().copied());
            }
        }
        grouped
    } else {
        analyzer.ranges(code_unit).to_vec()
    };
    ranges.sort_by_key(|range| range.start_byte);

    ranges
        .into_iter()
        .filter_map(|range| {
            let start_byte = if include_comments {
                expanded_comment_start(language, &content, range.start_byte)
            } else {
                range.start_byte
            };
            let text = content.get(start_byte..range.end_byte)?.to_string();
            if text.is_empty() {
                return None;
            }
            let start_line = line_number_at_offset(&content, start_byte);
            Some(SourceBlock {
                label: display_symbol_for_target(code_unit),
                path: rel_path_string(code_unit.source()),
                start_line,
                end_line: start_line + text.lines().count().saturating_sub(1),
                text,
                presentation: None,
            })
        })
        .collect()
}

fn source_blocks_for_files(analyzer: &dyn IAnalyzer, files: Vec<ProjectFile>) -> Vec<SourceBlock> {
    files
        .into_iter()
        .filter_map(|file| {
            let text = analyzer.list_top_level_symbols(&file);
            if !text.trim().is_empty() {
                let end_line = text.lines().count().max(1);
                let path = rel_path_string(&file);
                return Some(SourceBlock {
                    label: path.clone(),
                    path,
                    start_line: 1,
                    end_line,
                    text,
                    presentation: None,
                });
            }

            if let Some(block) = include_fallback_source_block(analyzer, &file) {
                return Some(block);
            }

            excerpt_fallback_source_block(&file)
        })
        .collect()
}

fn include_fallback_source_block(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<SourceBlock> {
    let elements = include_fallback_elements(analyzer, file);
    if elements.is_empty() {
        return None;
    }
    let start_line = elements
        .iter()
        .map(|element| element.start_line)
        .min()
        .unwrap_or(1);
    let end_line = elements
        .iter()
        .map(|element| element.end_line)
        .max()
        .unwrap_or(start_line);
    let text = elements
        .into_iter()
        .map(|element| element.text)
        .collect::<Vec<_>>()
        .join("\n");
    let path = rel_path_string(file);
    Some(SourceBlock {
        label: path.clone(),
        path,
        start_line,
        end_line,
        text,
        presentation: None,
    })
}

fn excerpt_fallback_source_block(file: &ProjectFile) -> Option<SourceBlock> {
    let sampled = excerpt_fallback_elements(file)?.into_iter().next()?;
    Some(SourceBlock {
        label: sampled.path.clone(),
        path: sampled.path,
        start_line: sampled.start_line,
        end_line: sampled.end_line,
        text: sampled.text,
        presentation: sampled.presentation,
    })
}

fn module_file_listing_blocks(code_unit: &CodeUnit) -> Vec<SourceBlock> {
    vec![SourceBlock {
        label: display_symbol_for_target(code_unit),
        path: rel_path_string(code_unit.source()),
        start_line: 0,
        end_line: 0,
        text: "Module/object lookup returns defining files instead of the full source body."
            .to_string(),
        presentation: Some("file_listing".to_string()),
    }]
}

fn dedup_source_blocks(blocks: Vec<SourceBlock>) -> Vec<SourceBlock> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for block in blocks {
        let key = (
            block.label.clone(),
            block.path.clone(),
            block.start_line,
            block.end_line,
            block.text.clone(),
            block.presentation.clone(),
        );
        if seen.insert(key) {
            deduped.push(block);
        }
    }
    deduped
}

fn is_file_listing_target(code_unit: &CodeUnit) -> bool {
    code_unit.is_module() || is_scala_object_like(code_unit)
}

fn is_ancestor_target(code_unit: &CodeUnit) -> bool {
    code_unit.is_class() || code_unit.is_module()
}

fn primary_range(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Option<Range> {
    analyzer
        .ranges(code_unit)
        .iter()
        .copied()
        .min_by_key(|range| (range.start_line, range.start_byte))
}

fn resolve_file_patterns(analyzer: &dyn IAnalyzer, patterns: &[String]) -> ResolvedFilePatterns {
    let mut matched = BTreeSet::new();
    let mut globs = Vec::new();
    let resolver = WorkspaceFileResolver::new(analyzer.project());
    let mut ambiguous_paths = Vec::new();

    for pattern in patterns {
        let normalized = normalize_pattern(pattern.trim());
        if normalized.is_empty() {
            continue;
        }

        if is_glob_pattern(&normalized) {
            if let Ok(glob) = Pattern::new(&normalized) {
                globs.push(glob);
            }
            continue;
        }

        match resolver.resolve_literal(&normalized) {
            ResolvedFileInput::File(file) => {
                matched.insert(file);
                continue;
            }
            ResolvedFileInput::Ambiguous(item) => {
                ambiguous_paths.push(item);
                continue;
            }
            ResolvedFileInput::NotFound(_) => {}
        }

        let directory_matches = resolve_directory_target(analyzer, &normalized);
        if !directory_matches.is_empty() {
            matched.extend(directory_matches);
        }
    }

    if !globs.is_empty() {
        let glob_matches: BTreeSet<_> = analyzer
            .analyzed_files()
            .cloned()
            .collect::<Vec<_>>()
            .into_par_iter()
            .filter(|file| {
                let path = rel_path_string(file);
                globs.iter().any(|glob| glob.matches(&path))
            })
            .collect();
        matched.extend(glob_matches);
    }

    ResolvedFilePatterns {
        files: matched.into_iter().collect(),
        ambiguous_paths,
    }
}

fn resolve_directory_target(analyzer: &dyn IAnalyzer, target: &str) -> Vec<ProjectFile> {
    if target == "." {
        return analyzer.analyzed_files().cloned().collect();
    }
    let prefix = format!("{}/", target.trim_end_matches('/'));
    analyzer
        .analyzed_files()
        .filter(|file| rel_path_string(file).starts_with(&prefix))
        .cloned()
        .collect()
}

fn select_files_for_display(
    analyzer: &dyn IAnalyzer,
    mut files: Vec<ProjectFile>,
    limit: usize,
) -> Vec<ProjectFile> {
    files.sort();
    files.dedup();
    if files.len() <= limit {
        return files;
    }

    let mut selected = most_important_project_files(analyzer, &files, limit);
    let mut seen: BTreeSet<_> = selected.iter().cloned().collect();
    if selected.len() < limit {
        for file in &files {
            if selected.len() >= limit {
                break;
            }
            if seen.insert(file.clone()) {
                selected.push(file.clone());
            }
        }
    }
    selected.sort();
    selected.truncate(limit);
    selected
}

fn looks_like_file_target(target: &str) -> bool {
    if target == "."
        || target.starts_with("./")
        || target.starts_with("../")
        || target.starts_with('/')
        || target.starts_with('\\')
        || target.contains('*')
        || target.contains('?')
    {
        return true;
    }

    let normalized = target.replace('\\', "/");
    let leaf = normalized.rsplit('/').next().unwrap_or(target);
    let Some((_, extension)) = leaf.rsplit_once('.') else {
        return false;
    };
    !extension.is_empty() && likely_file_target_extension(extension)
}

fn likely_file_target_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "c" | "cc"
            | "cpp"
            | "cs"
            | "css"
            | "cxx"
            | "dart"
            | "go"
            | "gradle"
            | "groovy"
            | "h"
            | "hpp"
            | "htm"
            | "html"
            | "java"
            | "js"
            | "json"
            | "jsx"
            | "kt"
            | "kts"
            | "less"
            | "m"
            | "md"
            | "mm"
            | "php"
            | "properties"
            | "py"
            | "rb"
            | "rs"
            | "sass"
            | "scala"
            | "scss"
            | "sh"
            | "sql"
            | "svelte"
            | "swift"
            | "toml"
            | "ts"
            | "tsx"
            | "txt"
            | "vue"
            | "xml"
            | "yaml"
            | "yml"
    )
}

fn is_glob_pattern(pattern: &str) -> bool {
    pattern.contains(['*', '?', '['])
}

fn line_count(content: &str) -> usize {
    model_context::count_lines(content)
}

fn line_number_at_offset(content: &str, offset: usize) -> usize {
    let bounded = offset.min(content.len());
    find_line_index_for_offset(&compute_line_starts(content), bounded) + 1
}

fn expanded_comment_start(language: Language, source: &str, start_byte: usize) -> usize {
    if language == Language::Python {
        return python_expanded_comment_start(source, start_byte);
    }

    let line_starts = line_starts(source);
    let line_index = find_line_index_for_offset(&line_starts, start_byte);

    let mut comment_start = start_byte;
    for line_idx in (0..line_index).rev() {
        let line_start = line_starts[line_idx];
        let line_end = line_starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];
        let trimmed = line.trim_start();

        if trimmed.trim().is_empty() {
            continue;
        }

        if is_comment_like(trimmed) {
            comment_start = line_start;
            continue;
        }

        if let Some(offset) = first_comment_offset(line) {
            comment_start = line_start + offset;
        }

        break;
    }

    comment_start
}

fn python_expanded_comment_start(source: &str, start_byte: usize) -> usize {
    let line_starts = line_starts(source);
    let line_index = find_line_index_for_offset(&line_starts, start_byte);

    let mut comment_start = start_byte;
    for line_idx in (0..line_index).rev() {
        let line_start = line_starts[line_idx];
        let line_end = line_starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];
        let trimmed = line.trim_start();

        if trimmed.trim().is_empty() {
            continue;
        }

        if trimmed.starts_with('#') {
            comment_start = line_start;
            continue;
        }

        break;
    }

    comment_start
}

fn line_starts(source: &str) -> Vec<usize> {
    compute_line_starts(source)
}

fn is_comment_like(trimmed_line: &str) -> bool {
    trimmed_line.starts_with("//")
        || trimmed_line.starts_with("/*")
        || trimmed_line.starts_with('*')
        || trimmed_line.starts_with("*/")
}

fn first_comment_offset(line: &str) -> Option<usize> {
    static COMMENT_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    COMMENT_RE
        .get_or_init(|| Regex::new(r"(?://|/\*|\*)").expect("valid comment regex"))
        .find(line)
        .map(|capture| capture.start())
}

#[cfg(test)]
fn split_logical_lines(content: &str) -> Vec<&str> {
    model_context::logical_lines(content)
}

fn strip_params(symbols: Vec<String>) -> Vec<String> {
    symbols
        .into_iter()
        .map(|symbol| strip_trailing_call_suffix(&symbol))
        .collect()
}

fn default_limit() -> usize {
    20
}

/// The usage-graph ecosystem a node belongs to — the identity component that
/// keeps same-fqn symbols in different languages from merging into one node.
/// JavaScript and TypeScript share one ecosystem because they share an fqn
/// namespace and interop (a `.ts` file can import a `.js` symbol).
///
/// A `Copy` enum rather than a string so the `usage_graph` builders carry one
/// value for both the node-membership lookup and the edge tag — the compiler,
/// not a matched string literal, guarantees the two stay in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Ecosystem {
    JavaScriptTypeScript,
    Python,
    Go,
    Rust,
    Java,
    CSharp,
    Cpp,
    Php,
    Scala,
    Unknown,
}

impl Ecosystem {
    fn of(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self::JavaScriptTypeScript,
            Language::Python => Self::Python,
            Language::Go => Self::Go,
            Language::Rust => Self::Rust,
            Language::Java => Self::Java,
            Language::CSharp => Self::CSharp,
            Language::Cpp => Self::Cpp,
            Language::Php => Self::Php,
            Language::Scala => Self::Scala,
            Language::None => Self::Unknown,
        }
    }

    /// Whether a bare symbol name is scoped to its defining file rather than a
    /// package. JavaScript/TypeScript modules are file-scoped, so two files
    /// exporting the same name are distinct symbols and the file is part of node
    /// identity; every other ecosystem qualifies its fqn by package and merges
    /// declarations that share an fqn across files (Go package symbols, C#
    /// partial classes).
    fn is_module_scoped(self) -> bool {
        matches!(self, Self::JavaScriptTypeScript)
    }

    /// The wire label carried in `UsageGraphNode`/`UsageGraphEdge.language`.
    fn as_str(self) -> &'static str {
        match self {
            Self::JavaScriptTypeScript => "js_ts",
            Self::Python => "python",
            Self::Go => "go",
            Self::Rust => "rust",
            Self::Java => "java",
            Self::CSharp => "csharp",
            Self::Cpp => "cpp",
            Self::Php => "php",
            Self::Scala => "scala",
            Self::Unknown => "unknown",
        }
    }
}

fn language_name(language: Language) -> String {
    match language {
        Language::None => "none",
        Language::Java => "java",
        Language::Go => "go",
        Language::Cpp => "cpp",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::Php => "php",
        Language::Scala => "scala",
        Language::CSharp => "csharp",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        SourceBlock, SummaryElement, list_symbols, resolve_file_patterns, trim_summary_signature,
    };
    use crate::analyzer::{
        CodeUnit, DeclarationInfo, IAnalyzer, Language, Project, ProjectFile, Range,
    };
    use std::collections::BTreeSet;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct CountingProject {
        root: PathBuf,
        files: BTreeSet<ProjectFile>,
    }

    impl CountingProject {
        fn new(root: PathBuf, files: BTreeSet<ProjectFile>) -> Self {
            Self { root, files }
        }
    }

    impl Project for CountingProject {
        fn root(&self) -> &Path {
            &self.root
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([Language::Java])
        }

        fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
            Ok(self.files.clone())
        }

        fn analyzable_files(&self, _language: Language) -> io::Result<BTreeSet<ProjectFile>> {
            Ok(self.files.clone())
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
            self.files.contains(&file).then_some(file)
        }
    }

    struct CountingAnalyzer {
        project: CountingProject,
        analyzed_files_calls: AtomicUsize,
    }

    impl CountingAnalyzer {
        fn new(root: PathBuf, rel_paths: &[&str]) -> Self {
            let files = rel_paths
                .iter()
                .map(|rel_path| ProjectFile::new(root.clone(), *rel_path))
                .collect();
            Self {
                project: CountingProject::new(root, files),
                analyzed_files_calls: AtomicUsize::new(0),
            }
        }

        fn analyzed_files_calls(&self) -> usize {
            self.analyzed_files_calls.load(Ordering::Relaxed)
        }
    }

    impl IAnalyzer for CountingAnalyzer {
        fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a> {
            self.analyzed_files_calls.fetch_add(1, Ordering::Relaxed);
            Box::new(self.project.files.iter())
        }

        fn languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([Language::Java])
        }

        fn update(&self, _changed_files: &BTreeSet<ProjectFile>) -> Self {
            Self {
                project: CountingProject::new(
                    self.project.root.clone(),
                    self.project.files.clone(),
                ),
                analyzed_files_calls: AtomicUsize::new(self.analyzed_files_calls()),
            }
        }

        fn update_all(&self) -> Self {
            Self {
                project: CountingProject::new(
                    self.project.root.clone(),
                    self.project.files.clone(),
                ),
                analyzed_files_calls: AtomicUsize::new(self.analyzed_files_calls()),
            }
        }

        fn project(&self) -> &dyn Project {
            &self.project
        }

        fn all_declarations<'a>(&'a self) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
            Box::new(std::iter::empty())
        }

        fn get_declarations(&self, _file: &ProjectFile) -> BTreeSet<CodeUnit> {
            BTreeSet::new()
        }

        fn get_definitions(&self, _fq_name: &str) -> Vec<CodeUnit> {
            Vec::new()
        }

        fn get_direct_children(&self, _code_unit: &CodeUnit) -> Vec<CodeUnit> {
            Vec::new()
        }

        fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
            None
        }

        fn import_statements_of(&self, _file: &ProjectFile) -> Vec<String> {
            Vec::new()
        }

        fn enclosing_code_unit(&self, _file: &ProjectFile, _range: &Range) -> Option<CodeUnit> {
            None
        }

        fn enclosing_code_unit_for_lines(
            &self,
            _file: &ProjectFile,
            _start_line: usize,
            _end_line: usize,
        ) -> Option<CodeUnit> {
            None
        }

        fn is_access_expression(
            &self,
            _file: &ProjectFile,
            _start_byte: usize,
            _end_byte: usize,
        ) -> bool {
            false
        }

        fn find_nearest_declaration(
            &self,
            _file: &ProjectFile,
            _start_byte: usize,
            _end_byte: usize,
            _ident: &str,
        ) -> Option<DeclarationInfo> {
            None
        }

        fn ranges_of(&self, _code_unit: &CodeUnit) -> Vec<Range> {
            Vec::new()
        }

        fn get_skeleton(&self, _code_unit: &CodeUnit) -> Option<String> {
            None
        }

        fn get_skeleton_header(&self, _code_unit: &CodeUnit) -> Option<String> {
            None
        }

        fn get_source(&self, _code_unit: &CodeUnit, _include_comments: bool) -> Option<String> {
            None
        }

        fn get_sources(&self, _code_unit: &CodeUnit, _include_comments: bool) -> BTreeSet<String> {
            BTreeSet::new()
        }

        fn search_definitions(&self, _pattern: &str, _auto_quote: bool) -> BTreeSet<CodeUnit> {
            BTreeSet::new()
        }

        fn list_symbols(&self, file: &ProjectFile) -> String {
            format!("- {}", super::rel_path_string(file).replace('/', "_"))
        }
    }

    #[test]
    fn trims_synthetic_summary_lines() {
        assert_eq!(trim_summary_signature("class A {\n}\n"), "class A");
        assert_eq!(trim_summary_signature("[...]\n"), "");
    }

    #[test]
    fn split_logical_lines_handles_crlf_lf_and_lone_cr() {
        assert_eq!(
            super::split_logical_lines("a\r\nb\r\nc"),
            vec!["a", "b", "c"]
        );
        assert_eq!(super::split_logical_lines("a\nb\nc"), vec!["a", "b", "c"]);
        assert_eq!(super::split_logical_lines("a\rb\rc"), vec!["a", "b", "c"]);
        assert_eq!(super::split_logical_lines("a\r\n"), vec!["a"]);
        assert_eq!(super::split_logical_lines(""), Vec::<&str>::new());
    }

    #[test]
    fn source_block_fields_are_publicly_constructible() {
        let _block = SourceBlock {
            label: "A".to_string(),
            path: "A.java".to_string(),
            start_line: 10,
            end_line: 12,
            text: "class A {}".to_string(),
            presentation: None,
        };
        let _element = SummaryElement {
            path: "A.java".to_string(),
            symbol: "A".to_string(),
            kind: "class".to_string(),
            start_line: 10,
            end_line: 10,
            text: "class A {".to_string(),
            presentation: None,
        };
    }

    #[test]
    fn literal_file_pattern_uses_project_lookup_without_scanning_analyzed_files() {
        let root = std::env::current_dir().unwrap();
        let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java"]);
        let files = resolve_file_patterns(&analyzer, &["nested/B.java".to_string()]);

        assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
        assert!(files.ambiguous_paths.is_empty());
        assert_eq!(0, analyzer.analyzed_files_calls());
    }

    #[test]
    fn glob_file_pattern_scans_analyzed_files() {
        let root = std::env::current_dir().unwrap();
        let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java", "notes.txt"]);
        let files = resolve_file_patterns(&analyzer, &["nested/*.java".to_string()]);

        assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
        assert!(files.ambiguous_paths.is_empty());
        assert_eq!(1, analyzer.analyzed_files_calls());
    }

    #[test]
    fn file_pattern_resolution_deduplicates_literal_and_glob_matches() {
        let root = std::env::current_dir().unwrap();
        let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java"]);
        let files = resolve_file_patterns(
            &analyzer,
            &[
                "nested/B.java".to_string(),
                "nested/*.java".to_string(),
                "nested/B.java".to_string(),
            ],
        );

        assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
        assert!(files.ambiguous_paths.is_empty());
        assert_eq!(1, analyzer.analyzed_files_calls());
    }

    #[test]
    fn bare_filename_repairs_uniquely_without_scanning_analyzed_files() {
        let root = std::env::current_dir().unwrap();
        let analyzer = CountingAnalyzer::new(root, &["nested/B.java", "other/C.java"]);
        let files = resolve_file_patterns(&analyzer, &["B.java".to_string()]);

        assert_eq!(vec!["nested/B.java"], rel_paths(&files.files));
        assert!(files.ambiguous_paths.is_empty());
        assert_eq!(0, analyzer.analyzed_files_calls());
    }

    #[test]
    fn bare_filename_reports_ambiguity_without_guessing() {
        let root = std::env::current_dir().unwrap();
        let analyzer = CountingAnalyzer::new(root, &["src/B.java", "nested/B.java"]);
        let files = resolve_file_patterns(&analyzer, &["B.java".to_string()]);

        assert!(files.files.is_empty());
        assert_eq!(1, files.ambiguous_paths.len());
        assert_eq!("B.java", files.ambiguous_paths[0].input);
        assert_eq!(
            vec!["nested/B.java".to_string(), "src/B.java".to_string()],
            files.ambiguous_paths[0].matches
        );
        assert_eq!(0, analyzer.analyzed_files_calls());
    }

    #[test]
    fn list_symbols_uses_fast_literal_resolution() {
        let root = std::env::current_dir().unwrap();
        let analyzer = CountingAnalyzer::new(root, &["A.java"]);

        let _ = list_symbols(
            &analyzer,
            super::FilePatternsParams {
                file_patterns: vec!["A.java".to_string()],
            },
        );

        assert_eq!(0, analyzer.analyzed_files_calls());
    }

    #[test]
    fn directory_targets_are_reported_as_not_found() {
        let root = std::env::current_dir().unwrap();
        let rel_paths: Vec<_> = (0..25)
            .map(|index| format!("src/File{index}.java"))
            .collect();
        let rel_path_refs: Vec<_> = rel_paths.iter().map(String::as_str).collect();
        let analyzer = CountingAnalyzer::new(root, &rel_path_refs);

        let result = super::get_summaries(
            &analyzer,
            super::SummariesParams {
                targets: vec!["src".to_string()],
            },
        );

        assert!(result.summaries.is_empty());
        assert_eq!(vec!["src"], result.not_found);
    }

    fn rel_paths(files: &[ProjectFile]) -> Vec<String> {
        files
            .iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect()
    }
}
