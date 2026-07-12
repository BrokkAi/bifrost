use crate::analyzer::common::{
    display_identifier_for_target, display_parent_symbol_for_target, display_symbol_for_target,
    display_symbol_name, is_scala_object_like, language_for_file, language_for_target,
};
use crate::analyzer::declaration_range::{
    DeclarationNameRangeContext, code_unit_declaration_name_range,
};
use crate::analyzer::lexical_definitions::LexicalDefinition;
use crate::analyzer::symbol_lookup::{
    CodeUnitResolution, resolve_codeunit_exact, resolve_codeunit_fuzzy,
    resolve_enclosing_codeunits, strip_trailing_call_suffix, symbol_selector_leaf,
};
use crate::analyzer::test_paths;
use crate::analyzer::usages::get_definition::{
    SCALA_UNSUPPORTED_CALL_TARGET_SHAPE, SCALA_UNSUPPORTED_RECEIVER,
    java_lombok_accessor_field_candidates,
};
use crate::analyzer::usages::reference_site::reference_target_match_offsets;
use crate::analyzer::usages::{
    CONFIDENCE_THRESHOLD, CandidateFileProvider, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES,
    ExplicitCandidateProvider, FuzzyResult, UsageFinder, UsageHit, UsageHitKind, UsageHitSurface,
};
use crate::analyzer::{
    CodeUnit, CodeUnitType, DeclarationKind, GO_MODULE_SCOPE_SEGMENT, GoModuleRoot, IAnalyzer,
    Language, ProjectFile, Range, SummaryFileProjection, go_module_roots,
};
use crate::hash::{HashMap, HashSet};
use crate::lsp::conversion::percent_decode;
use crate::model_context;
use crate::path_utils::{
    AmbiguousPathInput, ResolvedFileInput, WorkspaceFileResolver, has_drive_letter_prefix,
    normalize_pattern, rel_path_string, workspace_rel_path,
};
use crate::profiling;
use crate::relevance::{
    DEFAULT_RECENCY_HALF_LIFE, most_important_project_files, most_relevant_project_files,
    most_relevant_project_files_with_half_life,
};
use crate::text_utils::{
    compute_line_starts, find_line_index_for_offset, render_location_diagnostic,
};
use glob::MatchOptions;
use glob::Pattern;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

const FILE_SEARCH_LIMIT: usize = 100;
const FILE_SKIM_LIMIT: usize = 20;
// Keep MCP structured JSON below Codex's default 10 KB function-output
// truncation limit after JSON escaping and tool wrapper overhead.
pub const SCAN_USAGES_RESPONSE_BUDGET_BYTES: usize = 8_192;
const SCAN_USAGES_MAX_CALLSITES: usize = DEFAULT_MAX_USAGES;
const SCAN_USAGES_PATH_SCOPED_MAX_FILES: usize = 10_000;
const SCAN_USAGES_SUMMARY_FILE_LIMIT: usize = 20;
const SCAN_USAGES_TOP_ENCLOSING_LIMIT: usize = 10;
const SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT: usize = 3;
const SCAN_USAGES_PATH_SELECTOR_MATCH_LIMIT: usize = 5;
const SCAN_USAGES_SCOPE_PATH_LIMIT: usize = 5;
const SCAN_USAGES_SCOPE_PATH_MAX_BYTES: usize = 256;
pub const TYPE_LOOKUP_MAX_REFERENCES: usize = 100;
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
pub struct ScanUsagesByReferenceParams {
    pub symbols: Vec<String>,
    #[serde(default)]
    pub include_tests: bool,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUsagesByLocationParams {
    pub targets: Vec<ScanUsagesTarget>,
    #[serde(default)]
    pub include_tests: bool,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUsagesTarget {
    pub path: String,
    pub line: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    /// Optional exact declaration selector used to disambiguate overlapping
    /// declaration ranges at this location. The selector must name a declaration
    /// in `path` that contains the requested location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

/// Parameters for [`usage_graph`].
///
/// These fields mirror the scope controls on the scan-usage APIs.
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
pub struct GetTypeParams {
    pub references: Vec<TypeReferenceQuery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameSymbolParams {
    pub path: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
    pub new_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionReferenceQuery {
    pub path: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeReferenceQuery {
    pub path: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
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
pub struct RenameSymbolResult {
    pub query: RenameSymbolParams,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<RenameSymbolTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_name: Option<String>,
    pub edits: Vec<RenameFileEdits>,
    pub diagnostics: Vec<DefinitionDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameSymbolTarget {
    pub symbol: String,
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameFileEdits {
    pub path: String,
    pub edits: Vec<RenameTextEdit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameTextEdit {
    pub old_text: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub new_text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSymbolsResult {
    pub patterns: Vec<String>,
    pub truncated: bool,
    pub total_files: usize,
    pub files: Vec<SearchSymbolsFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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
    primary_range: Range,
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
    pub not_found: Vec<NotFoundInput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolAncestorsResult {
    pub ancestors: Vec<SymbolAncestors>,
    pub not_found: Vec<NotFoundInput>,
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
pub struct GetTypeResult {
    pub results: Vec<TypeLookupResult>,
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
pub struct TypeLookupResult {
    pub query: TypeReferenceQuery,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<DefinitionReferenceSite>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub types: Vec<TypeLookupCandidate>,
    #[serde(default)]
    pub diagnostics: Vec<DefinitionDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeLookupCandidate {
    pub fqn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub definitions: Vec<DefinitionCandidate>,
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

type DefinitionCandidateKey = (
    String,
    Option<String>,
    String,
    usize,
    usize,
    String,
    Option<String>,
    String,
);
type DefinitionOutcomeKey = (String, Vec<DefinitionCandidateKey>);

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionCandidate {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqn: Option<String>,
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
    pub not_found: Vec<NotFoundInput>,
    pub ambiguous: Vec<AmbiguousSymbol>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotFoundInput {
    pub input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

const SYMBOL_NOT_FOUND_NOTE: &str =
    "no symbol matched; try search_symbols with a substring or regex pattern";
const FILE_NOT_FOUND_NOTE: &str =
    "no workspace file matched this path; check the relative path or pass a glob pattern";

#[derive(Debug, Clone, Copy)]
enum PathLikeSymbolGuidanceContext {
    DefinitionByReference,
    ScanUsages,
    SymbolLookup,
}

fn not_found_input(input: impl Into<String>, note: Option<String>) -> NotFoundInput {
    NotFoundInput {
        input: input.into(),
        note,
    }
}

fn symbol_not_found_input(input: impl Into<String>) -> NotFoundInput {
    not_found_input(input, Some(SYMBOL_NOT_FOUND_NOTE.to_string()))
}

fn unsupported_selector_shape_not_found_input(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> Option<NotFoundInput> {
    unsupported_selector_shape_guidance(analyzer, input)
        .map(|note| not_found_input(input.to_string(), Some(note)))
}

fn path_like_symbol_not_found_input(
    input: impl Into<String>,
    context: PathLikeSymbolGuidanceContext,
) -> NotFoundInput {
    let input = input.into();
    let note = path_like_symbol_guidance(&input, context)
        .unwrap_or_else(|| SYMBOL_NOT_FOUND_NOTE.to_string());
    not_found_input(input, Some(note))
}

fn path_like_symbol_guidance(
    input: &str,
    context: PathLikeSymbolGuidanceContext,
) -> Option<String> {
    if !looks_like_file_target(input) {
        return None;
    }
    Some(match context {
        PathLikeSymbolGuidanceContext::DefinitionByReference => {
            "`symbol` must be an enclosing workspace symbol, not a file path. `context` must be exact source text copied from inside that symbol. If you already have exact context, use get_summaries on the file to identify the enclosing symbol, then retry with the same context and a single-token target. If you do not have exact context, identify the enclosing symbol first, then call get_symbol_sources for that symbol and copy context from the returned source."
                .to_string()
        }
        PathLikeSymbolGuidanceContext::ScanUsages => {
            "`symbols` expects workspace symbols, not file paths. Use list_symbols or search_symbols to identify the declaration, then call scan_usages_by_reference with that symbol; use `paths` only to narrow where usages are searched."
                .to_string()
        }
        PathLikeSymbolGuidanceContext::SymbolLookup => {
            "this field expects a workspace symbol, not a file path; use list_symbols on the file to discover symbols, then retry with the symbol"
                .to_string()
        }
    })
}

fn file_not_found_input(input: impl Into<String>) -> NotFoundInput {
    not_found_input(input, Some(FILE_NOT_FOUND_NOTE.to_string()))
}

fn anchor_not_found_input(input: impl Into<String>, anchor: &str, name: &str) -> NotFoundInput {
    not_found_input(
        input,
        Some(format!(
            "`{name}` resolved, but no definition is in `{anchor}`; re-call with the bare name to list valid selectors"
        )),
    )
}

fn symbol_source_anchor_not_found_input(
    input: impl Into<String>,
    anchor: &str,
    name: &str,
    candidate_names: &[String],
) -> NotFoundInput {
    if looks_like_extensionless_path_anchor(anchor)
        && let [canonical] = candidate_names
    {
        return not_found_input(
            input,
            Some(format!(
                "`{anchor}` looks like a source path missing its extension; retry with the canonical workspace symbol `{canonical}`"
            )),
        );
    }
    anchor_not_found_input(input, anchor, name)
}

fn renderable_not_found_input(input: impl Into<String>) -> NotFoundInput {
    not_found_input(input, None)
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousSymbol {
    pub target: String,
    pub matches: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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
    /// Display symbol of the enclosing scope (declaring/receiver type) for a method, else
    /// None for a top-level declaration. Lets consumers resolve a method's parent without
    /// the brittle line-span/string heuristics that break on Go/Rust/C++ method layouts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolSourcesResult {
    pub sources: Vec<SourceBlock>,
    pub not_found: Vec<NotFoundInput>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFilesResult {
    pub truncated: bool,
    pub total_files: usize,
    pub files: Vec<SkimFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MostRelevantFilesResult {
    pub files: Vec<String>,
    pub not_found: Vec<NotFoundInput>,
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
    #[serde(skip)]
    pub(crate) surface: ScanUsagesSurface,
    pub scope: ScanUsagesScope,
    pub summary: ScanUsagesSummary,
    pub results: Vec<ScanUsagesEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanUsagesSurface {
    Reference,
    Location,
}

impl ScanUsagesSurface {
    pub(crate) fn tool_name(self) -> &'static str {
        match self {
            Self::Reference => "scan_usages_by_reference",
            Self::Location => "scan_usages_by_location",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesScope {
    pub include_tests: bool,
    pub whole_workspace: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths_omitted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignored_paths: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesSummary {
    pub requested: usize,
    pub resolved: usize,
    pub total_hits: usize,
    pub partial: bool,
    pub found: usize,
    pub verified_absent: usize,
    pub unverified_absent: usize,
    pub not_found: usize,
    pub ambiguous: usize,
    pub failure: usize,
    pub too_many_callsites: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ScanUsagesInput {
    Symbol(String),
    Target(ScanUsagesTarget),
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanUsagesInputKind {
    Symbol,
    Target,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanUsagesStatus {
    Found,
    VerifiedAbsent,
    UnverifiedAbsent,
    NotFound,
    Ambiguous,
    Failure,
    TooManyCallsites,
}

impl ScanUsagesStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::VerifiedAbsent => "verified_absent",
            Self::UnverifiedAbsent => "unverified_absent",
            Self::NotFound => "not_found",
            Self::Ambiguous => "ambiguous",
            Self::Failure => "failure",
            Self::TooManyCallsites => "too_many_callsites",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanUsagesAbsenceCaveat {
    UnprovenMatches,
    CandidateFilesTruncated,
    ReferenceOnlySiblings,
}

impl ScanUsagesAbsenceCaveat {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnprovenMatches => "unproven_matches",
            Self::CandidateFilesTruncated => "candidate_files_truncated",
            Self::ReferenceOnlySiblings => "reference_only_siblings",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesEntry {
    pub input: ScanUsagesInput,
    pub input_kind: ScanUsagesInputKind,
    pub status: ScanUsagesStatus,
    #[serde(skip_serializing_if = "is_true")]
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_hits: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unproven_hits: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendering: Option<UsageRendering>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub files: Vec<UsageFileGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub unproven_files: Vec<UsageFileGroup>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub top_enclosing: Vec<UsageEnclosingCount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_sites_excluded: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_truncated: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub absence_caveats: Vec<ScanUsagesAbsenceCaveat>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidate_targets: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidate_details: Vec<AmbiguousUsageCandidateDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_details_total: Option<usize>,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_details_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidates: Vec<AmbiguousUsageCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fq_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_files_sample: Option<ScanUsagesCandidateFilesSample>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_callsites: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fq_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_line: Option<usize>,
    pub total_hits: usize,
    pub unproven_hits: usize,
    pub rendering: UsageRendering,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned. Results are partial when set.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub candidate_files_truncated: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub reference_only_siblings: bool,
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub unproven_files: Vec<UsageFileGroup>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_range: Option<String>,
    pub enclosing: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_count: Option<usize>,
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
    pub scan_usages_by_location_target: ScanUsagesTargetSuggestion,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesTargetSuggestion {
    pub path: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
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
    /// Stable machine-readable failure category, when available.
    pub reason_kind: String,
    /// Analyzer-provided reason. This is separate from `not_found` because the symbol
    /// resolved, but usage analysis could not produce a trustworthy answer.
    pub reason: String,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned before the failure was produced.
    pub candidate_files_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_files_sample: Option<ScanUsagesCandidateFilesSample>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesCandidateFilesSample {
    pub scanned: Vec<String>,
    pub omitted: Vec<String>,
    pub omitted_count: usize,
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
    let _scope = profiling::scope("searchtools::search_symbols");
    let patterns: Vec<String> = strip_params(params.patterns)
        .into_iter()
        .filter(|pattern| !pattern.trim().is_empty())
        .collect();

    let definitions = {
        let _scope = profiling::scope("searchtools::search_symbols.resolve");
        patterns
            .par_iter()
            .map(|pattern| analyzer.search_symbol_candidates(pattern, false))
            .reduce(Vec::new, |mut acc, definitions| {
                acc.extend(definitions);
                acc
            })
    };

    let filtered: Vec<_> = {
        let _scope = profiling::scope("searchtools::search_symbols.filter_ranged");
        let mut seen = HashSet::default();
        definitions
            .into_iter()
            .filter_map(|candidate| {
                // A search result is an implicit selector offer for source/location tools. Internal
                // graph identities without a unique range (for example replicated Go inline-struct
                // members) must not be advertised even when they intentionally remain resolvable.
                if !seen.insert(candidate.code_unit.clone()) {
                    return None;
                }
                let range = candidate
                    .primary_range
                    .or_else(|| primary_range(analyzer, &candidate.code_unit))?;
                let is_test = candidate.contains_tests
                    || test_paths::is_test_like_path(
                        &rel_path_string(candidate.code_unit.source()),
                        language_for_file(candidate.code_unit.source()),
                    );
                (params.include_tests || !is_test).then_some((candidate.code_unit, range, is_test))
            })
            .collect()
    };

    let ranked = {
        let _scope = profiling::scope("searchtools::search_symbols.rank");
        rank_search_symbol_candidates(analyzer, &patterns, filtered)
    };

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

    let files: Vec<SearchSymbolsFile> = {
        let _scope = profiling::scope("searchtools::search_symbols.render");
        file_entries
            .into_iter()
            .map(|(file, code_units)| {
                let render_context = load_declaration_name_context(analyzer, &file);
                let render_context = render_context.as_ref();
                SearchSymbolsFile {
                    path: rel_path_string(&file),
                    loc: render_context
                        .map(|context| line_count(context.content()))
                        .unwrap_or(0),
                    classes: collect_ranked_kind_names(
                        analyzer,
                        &code_units,
                        CodeUnitType::Class,
                        render_context,
                    ),
                    functions: collect_callable_kind_names(analyzer, &code_units, render_context),
                    fields: collect_ranked_kind_names(
                        analyzer,
                        &code_units,
                        CodeUnitType::Field,
                        render_context,
                    ),
                    modules: collect_ranked_kind_names(
                        analyzer,
                        &code_units,
                        CodeUnitType::Module,
                        render_context,
                    ),
                    macros: collect_ranked_kind_names(
                        analyzer,
                        &code_units,
                        CodeUnitType::Macro,
                        render_context,
                    ),
                }
            })
            .collect()
    };
    let note = search_symbols_note(truncated, files.len(), total_files);

    SearchSymbolsResult {
        patterns,
        truncated,
        total_files,
        files,
        note,
    }
}

fn search_symbols_note(truncated: bool, shown: usize, total: usize) -> Option<String> {
    if truncated {
        Some(format!(
            "Showing {shown} of {total} matching files. Raise `limit` or use a more specific identifier, qualified, or regex-like pattern to see the rest."
        ))
    } else if total == 0 {
        Some(
            "No files matched. Try a broader identifier, qualified, or regex-like pattern; if matches may be in test files, set `include_tests` to true."
                .to_string(),
        )
    } else {
        None
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

            let code_units =
                match resolve_selectable_definitions(analyzer, &symbol, resolve_codeunit_fuzzy) {
                    SelectableDefinitionResolution::Resolved(code_units) => Some(code_units),
                    SelectableDefinitionResolution::Ambiguous(_)
                    | SelectableDefinitionResolution::NotFound(_) => None,
                };
            let Some(code_units) = code_units else {
                return Some((
                    index,
                    Err(path_like_symbol_not_found_input(
                        symbol,
                        PathLikeSymbolGuidanceContext::SymbolLookup,
                    )),
                ));
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
                Some((index, Err(renderable_not_found_input(symbol))))
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

pub fn get_definitions_by_location(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionParams,
) -> GetDefinitionResult {
    let _scope = profiling::scope("searchtools::get_definitions_by_location");

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
                        start_byte: None,
                        end_byte: None,
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

    let mut render_cache = DefinitionCandidateRenderCache::default();
    for ((index, query, request), outcome) in pending.into_iter().zip(outcomes) {
        results[index] = Some(render_definition_lookup(
            analyzer,
            query,
            &request.file,
            outcome,
            &mut render_cache,
        ));
    }

    GetDefinitionResult {
        results: results.into_iter().flatten().collect(),
    }
}

pub fn get_type_by_location(analyzer: &dyn IAnalyzer, params: GetTypeParams) -> GetTypeResult {
    let _scope = profiling::scope("searchtools::get_type_by_location");

    if params.references.len() > TYPE_LOOKUP_MAX_REFERENCES {
        return GetTypeResult {
            results: vec![TypeLookupResult {
                query: TypeReferenceQuery {
                    path: String::new(),
                    line: None,
                    column: None,
                },
                status: "invalid_location".to_string(),
                reference: None,
                types: Vec::new(),
                diagnostics: vec![DefinitionDiagnostic {
                    kind: "too_many_references".to_string(),
                    message: format!(
                        "get_type_by_location accepts at most {TYPE_LOOKUP_MAX_REFERENCES} references per call"
                    ),
                }],
            }],
        };
    }

    let resolver = WorkspaceFileResolver::new(analyzer.project());
    let mut pending = Vec::new();
    let mut results: Vec<Option<TypeLookupResult>> = vec![None; params.references.len()];

    for (index, query) in params.references.into_iter().enumerate() {
        match resolver.resolve_literal(&query.path) {
            ResolvedFileInput::File(file) => {
                pending.push((
                    index,
                    query.clone(),
                    crate::analyzer::usages::get_type::TypeLookupRequest {
                        file,
                        source: None,
                        line: query.line,
                        column: query.column,
                        start_byte: None,
                        end_byte: None,
                    },
                ));
            }
            ResolvedFileInput::Ambiguous(item) => {
                results[index] = Some(TypeLookupResult {
                    query,
                    status: "not_found".to_string(),
                    reference: None,
                    types: Vec::new(),
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
                results[index] = Some(TypeLookupResult {
                    query,
                    status: "not_found".to_string(),
                    reference: None,
                    types: Vec::new(),
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
    let outcomes = crate::analyzer::usages::get_type::resolve_type_batch(analyzer, requests);

    for ((index, query, request), outcome) in pending.into_iter().zip(outcomes) {
        results[index] = Some(render_type_lookup(analyzer, query, &request.file, outcome));
    }

    GetTypeResult {
        results: results.into_iter().flatten().collect(),
    }
}

pub fn rename_symbol(analyzer: &dyn IAnalyzer, params: RenameSymbolParams) -> RenameSymbolResult {
    let _scope = profiling::scope("searchtools::rename_symbol");

    let resolver = WorkspaceFileResolver::new(analyzer.project());
    let file = match resolver.resolve_literal(params.path.trim()) {
        ResolvedFileInput::File(file) => file,
        ResolvedFileInput::Ambiguous(item) => {
            return rename_symbol_failure(
                params,
                "ambiguous_path",
                format!(
                    "`{}` is ambiguous; matches: {}",
                    item.input,
                    item.matches.join(", ")
                ),
            );
        }
        ResolvedFileInput::NotFound(path) => {
            return rename_symbol_failure(
                params,
                "path_not_found",
                format!("`{path}` does not resolve to a workspace file"),
            );
        }
    };

    let selection = match rename_selection_from_params(&params) {
        Ok(selection) => selection,
        Err(message) => return rename_symbol_failure(params, "invalid_location", message),
    };

    match crate::symbol_rename::rename_symbol(
        analyzer,
        analyzer.project(),
        file.clone(),
        selection,
        &params.new_name,
    ) {
        Ok(result) => render_rename_symbol_result(analyzer, params, result),
        Err(err) => {
            let message = if matches!(err.kind, "invalid_location" | "not_found") {
                location_failure_message(
                    analyzer,
                    &file,
                    &params.path,
                    params.line,
                    params.column,
                    &err.message,
                    "move the location to an identifier token and retry rename_symbol; use get_definitions_by_location first if the target is uncertain.",
                )
                .unwrap_or(err.message)
            } else {
                err.message
            };
            rename_symbol_failure(params, err.kind, message)
        }
    }
}

fn rename_selection_from_params(
    params: &RenameSymbolParams,
) -> Result<crate::symbol_rename::RenameSelection, String> {
    match (params.line, params.column) {
        (Some(line), Some(column)) => {
            Ok(crate::symbol_rename::RenameSelection::LineColumn { line, column })
        }
        (Some(_), None) => Err("rename_symbol requires column when line is provided".to_string()),
        (None, Some(_)) => Err("rename_symbol requires line when column is provided".to_string()),
        _ => Err("rename_symbol requires line and column".to_string()),
    }
}

fn render_rename_symbol_result(
    analyzer: &dyn IAnalyzer,
    query: RenameSymbolParams,
    result: crate::symbol_rename::RenameResult,
) -> RenameSymbolResult {
    let mut file_edits = Vec::new();
    for file_result in result.files {
        let source = match analyzer.project().read_source(&file_result.file) {
            Ok(source) => source,
            Err(err) => {
                return rename_symbol_failure(
                    query,
                    "read_failed",
                    format!(
                        "failed to read `{}` while rendering rename edits: {err}",
                        rel_path_string(&file_result.file)
                    ),
                );
            }
        };
        let line_starts = compute_line_starts(&source);
        let edits = file_result
            .edits
            .into_iter()
            .map(|edit| {
                let old_text = source
                    .get(edit.start_byte..edit.end_byte)
                    .unwrap_or_default()
                    .to_string();
                let (start_line, start_column) = crate::symbol_rename::line_column_for_byte_offset(
                    &source,
                    &line_starts,
                    edit.start_byte,
                );
                let (end_line, end_column) = crate::symbol_rename::line_column_for_byte_offset(
                    &source,
                    &line_starts,
                    edit.end_byte,
                );
                RenameTextEdit {
                    old_text,
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                    new_text: edit.new_text,
                }
            })
            .collect();
        file_edits.push(RenameFileEdits {
            path: rel_path_string(&file_result.file),
            edits,
        });
    }

    RenameSymbolResult {
        query,
        status: "ok".to_string(),
        target: Some(RenameSymbolTarget {
            symbol: result.target.fq_name().to_string(),
            kind: result.target.kind().display_lowercase().to_string(),
            path: rel_path_string(result.target.source()),
        }),
        old_name: Some(result.old_name),
        edits: file_edits,
        diagnostics: Vec::new(),
    }
}

fn rename_symbol_failure(
    query: RenameSymbolParams,
    kind: &'static str,
    message: String,
) -> RenameSymbolResult {
    RenameSymbolResult {
        query,
        status: kind.to_string(),
        target: None,
        old_name: None,
        edits: Vec::new(),
        diagnostics: vec![DefinitionDiagnostic {
            kind: kind.to_string(),
            message,
        }],
    }
}

pub fn get_definitions_by_reference(
    analyzer: &dyn IAnalyzer,
    params: GetDefinitionByReferenceParams,
) -> GetDefinitionByReferenceResult {
    let _scope = profiling::scope("searchtools::get_definitions_by_reference");

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
        let language = language_for_file(unit.source());
        for (context_offset, context) in symbol_source.match_indices(&query.context) {
            for target_offset in reference_target_match_offsets(context, &query.target, language) {
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

    let anchored = match split_definition_selector(symbol) {
        DefinitionSelector::FileAnchored { anchor, lookup } => Some((anchor, lookup)),
        DefinitionSelector::Name(_) => {
            match split_path_qualified_definition_selector(analyzer, symbol) {
                Some(PathQualifiedSelector::Resolved { anchor, lookup }) => Some((anchor, lookup)),
                Some(PathQualifiedSelector::AmbiguousPath(item)) => {
                    return Err(vec![DefinitionDiagnostic {
                        kind: "ambiguous_path".to_string(),
                        message: format!(
                            "`{}` is ambiguous; matches: {}",
                            item.input,
                            item.matches.join(", ")
                        ),
                    }]);
                }
                None => None,
            }
        }
    };
    if let Some((anchor, lookup)) = anchored {
        let candidates = match exact_then_fuzzy_codeunit_resolution(analyzer, lookup) {
            CodeUnitResolution::Resolved(units) | CodeUnitResolution::Ambiguous(units) => units,
            CodeUnitResolution::NotFound => Vec::new(),
        };
        let narrowed: Vec<_> = candidates
            .into_iter()
            .filter(|unit| rel_path_string(unit.source()) == anchor)
            .collect();
        let groups = distinct_definitions(narrowed);
        return match groups.as_slice() {
            [(_, _)] => Ok(groups.into_iter().flat_map(|(_, units)| units).collect()),
            [] => Err(vec![DefinitionDiagnostic {
                kind: "symbol_not_found".to_string(),
                message: format!("`{symbol}` does not resolve to a workspace symbol"),
            }]),
            _ => Err(vec![DefinitionDiagnostic {
                kind: "ambiguous_symbol".to_string(),
                message: format!(
                    "`{symbol}` is ambiguous; matches: {}",
                    groups
                        .into_iter()
                        .map(|(selector, _)| selector)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }]),
        };
    }

    match resolve_codeunit_fuzzy(analyzer, symbol) {
        CodeUnitResolution::Resolved(units) => Ok(units),
        CodeUnitResolution::Ambiguous(matches) => Err(vec![DefinitionDiagnostic {
            kind: "ambiguous_symbol".to_string(),
            message: format!(
                "`{symbol}` is ambiguous; matches: {}",
                code_unit_match_names(&matches).join(", ")
            ),
        }]),
        CodeUnitResolution::NotFound => Err(vec![DefinitionDiagnostic {
            kind: "symbol_not_found".to_string(),
            message: path_like_symbol_guidance(
                symbol,
                PathLikeSymbolGuidanceContext::DefinitionByReference,
            )
            .unwrap_or_else(|| format!("`{symbol}` does not resolve to a workspace symbol")),
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
    if outcome.lexical_definition.is_some() {
        return DefinitionByReferenceLookupResult {
            query,
            status: "no_definition".to_string(),
            definitions: Vec::new(),
            diagnostics: vec![DefinitionDiagnostic {
                kind: "local_binding_requires_location".to_string(),
                message: "the target resolves to a lexical binding; use get_definitions_by_location with its source position"
                    .to_string(),
            }],
        };
    }
    let diagnostics = outcome
        .diagnostics
        .into_iter()
        .map(|diagnostic| definition_by_reference_diagnostic(&query, diagnostic))
        .collect();
    DefinitionByReferenceLookupResult {
        query,
        status: outcome.status.as_str().to_string(),
        definitions: definition_candidates(analyzer, &outcome.definitions),
        diagnostics,
    }
}

fn definition_by_reference_diagnostic(
    query: &DefinitionContextReferenceQuery,
    diagnostic: crate::analyzer::usages::get_definition::DefinitionLookupDiagnostic,
) -> DefinitionDiagnostic {
    let message = match diagnostic.kind.as_str() {
        "invalid_location"
            if diagnostic.message
                == "byte range must identify a single reference token; use start_byte inside the token for qualified expressions" =>
        {
            "target must identify a single reference token; for qualified expressions, set target to the member or name token inside the expression rather than the whole qualified expression"
                .to_string()
        }
        "invalid_location" if diagnostic.message == "provide either start_byte or line/column" => {
            "provide a positive line and, when needed, a positive character column".to_string()
        }
        SCALA_UNSUPPORTED_CALL_TARGET_SHAPE => {
            format!(
                "{}. The reference tool cannot follow this Scala call target shape yet. Try search_symbols for the callable/member name or owner/member selector when known, then use get_symbol_sources on the owner or resolved member symbol.",
                diagnostic.message
            )
        }
        SCALA_UNSUPPORTED_RECEIVER => {
            let target = query.target.trim();
            format!(
                "{}. The reference tool cannot follow this Scala receiver/member shape yet. Try search_symbols for `{target}` or an owner/member selector when known, then use get_symbol_sources on the owner or resolved member symbol.",
                diagnostic.message
            )
        }
        _ => external_location_diagnostic_message(&diagnostic.kind, diagnostic.message),
    };
    DefinitionDiagnostic {
        kind: diagnostic.kind,
        message,
    }
}

fn external_location_diagnostic_message(kind: &str, message: String) -> String {
    if kind == "invalid_location" && (message.contains("byte") || message.contains("offset")) {
        "provide a positive line and, when needed, a positive character column".to_string()
    } else {
        message
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
        candidate.name.clone(),
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
    file: &ProjectFile,
    outcome: crate::analyzer::usages::get_definition::DefinitionLookupOutcome,
    render_cache: &mut DefinitionCandidateRenderCache,
) -> DefinitionLookupResult {
    let status = outcome.status.as_str().to_string();
    let mut definitions =
        definition_candidates_with_cache(analyzer, &outcome.definitions, render_cache);
    if let Some(definition) = outcome.lexical_definition.as_ref()
        && let Some(candidate) = lexical_definition_candidate(analyzer, file, definition)
    {
        definitions.push(candidate);
    }
    let mut diagnostics: Vec<DefinitionDiagnostic> = outcome
        .diagnostics
        .into_iter()
        .map(|diagnostic| DefinitionDiagnostic {
            message: external_location_diagnostic_message(&diagnostic.kind, diagnostic.message),
            kind: diagnostic.kind,
        })
        .collect();
    if matches!(
        status.as_str(),
        "invalid_location" | "not_found" | "no_definition"
    ) {
        enrich_location_diagnostics(
            analyzer,
            file,
            &query.path,
            query.line,
            query.column,
            &mut diagnostics,
            "the requested location did not resolve to a definition",
            "move the location to the intended reference token and retry get_definitions_by_location; use get_summaries on the file or search_symbols if the target is uncertain.",
        );
    }
    DefinitionLookupResult {
        query,
        status,
        reference: outcome.reference.map(|site| DefinitionReferenceSite {
            path: site.path,
            target: site.text,
        }),
        definitions,
        diagnostics,
    }
}

fn lexical_definition_candidate(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    definition: &LexicalDefinition,
) -> Option<DefinitionCandidate> {
    let source = analyzer.project().read_source(file).ok()?;
    let signature = source
        .get(definition.declaration_range.start_byte..definition.declaration_range.end_byte)?
        .trim()
        .to_string();
    Some(DefinitionCandidate {
        name: definition.identifier.clone(),
        fqn: None,
        path: rel_path_string(file),
        start_line: definition.name_range.start_line,
        end_line: definition.name_range.end_line,
        kind: declaration_kind_name(definition.kind).to_string(),
        signature: (!signature.is_empty()).then_some(signature),
        language: language_name(language_for_file(file)),
    })
}

fn declaration_kind_name(kind: DeclarationKind) -> &'static str {
    match kind {
        DeclarationKind::Parameter => "parameter",
        DeclarationKind::ReceiverParameter => "receiver_parameter",
        DeclarationKind::LambdaParameter => "lambda_parameter",
        DeclarationKind::LocalVariable
        | DeclarationKind::CatchParameter
        | DeclarationKind::EnhancedForVariable
        | DeclarationKind::PatternVariable
        | DeclarationKind::ResourceVariable => "local_variable",
    }
}

#[derive(Default)]
struct DefinitionCandidateRenderCache {
    contexts: HashMap<ProjectFile, Option<DeclarationNameRangeContext>>,
}

impl DefinitionCandidateRenderCache {
    fn display_range(&mut self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<Range> {
        let context = self
            .contexts
            .entry(unit.source().clone())
            .or_insert_with(|| load_declaration_name_context(analyzer, unit.source()));
        let name_range = context
            .as_ref()
            .and_then(|context| context.name_range(analyzer, unit));
        display_range_with_declaration_name(analyzer, unit, name_range)
    }
}

fn render_type_lookup(
    analyzer: &dyn IAnalyzer,
    query: TypeReferenceQuery,
    file: &ProjectFile,
    outcome: crate::analyzer::usages::get_type::TypeLookupOutcome,
) -> TypeLookupResult {
    let status = outcome.status.as_str().to_string();
    let mut diagnostics: Vec<DefinitionDiagnostic> = outcome
        .diagnostics
        .into_iter()
        .map(|diagnostic| DefinitionDiagnostic {
            message: external_location_diagnostic_message(&diagnostic.kind, diagnostic.message),
            kind: diagnostic.kind,
        })
        .collect();
    if matches!(
        status.as_str(),
        "invalid_location" | "not_found" | "no_type"
    ) {
        enrich_location_diagnostics(
            analyzer,
            file,
            &query.path,
            query.line,
            query.column,
            &mut diagnostics,
            "the requested location did not resolve to a type",
            "move the location to the intended reference token and retry get_type_by_location; use get_definitions_by_location or get_summaries if the target is uncertain.",
        );
    }
    TypeLookupResult {
        query,
        status,
        reference: outcome.reference.map(|site| DefinitionReferenceSite {
            path: site.path,
            target: site.text,
        }),
        types: outcome
            .types
            .iter()
            .map(|item| type_lookup_candidate(analyzer, item))
            .collect(),
        diagnostics,
    }
}

#[allow(clippy::too_many_arguments)]
fn enrich_location_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    path: &str,
    line: Option<usize>,
    column: Option<usize>,
    diagnostics: &mut Vec<DefinitionDiagnostic>,
    fallback_reason: &str,
    recovery: &str,
) {
    let reason = diagnostics
        .first()
        .map(|diagnostic| diagnostic.message.as_str())
        .unwrap_or(fallback_reason);
    let Some(message) =
        location_failure_message(analyzer, file, path, line, column, reason, recovery)
    else {
        return;
    };
    if let Some(diagnostic) = diagnostics.first_mut() {
        diagnostic.message = message;
    } else {
        diagnostics.push(DefinitionDiagnostic {
            kind: "location_context".to_string(),
            message,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn location_failure_message(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    path: &str,
    line: Option<usize>,
    column: Option<usize>,
    reason: &str,
    recovery: &str,
) -> Option<String> {
    let line = line?;
    let source = analyzer.project().read_source(file).ok()?;
    Some(render_location_diagnostic(
        &source, path, line, column, reason, recovery,
    ))
}

fn type_lookup_candidate(
    analyzer: &dyn IAnalyzer,
    item: &crate::analyzer::usages::get_type::TypeLookupType,
) -> TypeLookupCandidate {
    let definitions = definition_candidates(analyzer, &item.definitions);
    let primary = definitions.first();
    TypeLookupCandidate {
        fqn: item.fqn.clone(),
        kind: primary.map(|candidate| candidate.kind.clone()),
        language: primary.map(|candidate| candidate.language.clone()),
        definitions,
    }
}

fn definition_candidates(analyzer: &dyn IAnalyzer, units: &[CodeUnit]) -> Vec<DefinitionCandidate> {
    units
        .iter()
        .filter_map(|unit| definition_candidate(analyzer, unit))
        .collect()
}

fn definition_candidates_with_cache(
    analyzer: &dyn IAnalyzer,
    units: &[CodeUnit],
    render_cache: &mut DefinitionCandidateRenderCache,
) -> Vec<DefinitionCandidate> {
    units
        .iter()
        .filter_map(|unit| definition_candidate_with_cache(analyzer, unit, render_cache))
        .collect()
}

fn definition_candidate_with_cache(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    render_cache: &mut DefinitionCandidateRenderCache,
) -> Option<DefinitionCandidate> {
    let range = render_cache.display_range(analyzer, unit)?;
    Some(definition_candidate_from_range(analyzer, unit, range))
}

fn definition_candidate(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<DefinitionCandidate> {
    let range = definition_display_range(analyzer, unit)?;
    Some(definition_candidate_from_range(analyzer, unit, range))
}

fn definition_candidate_from_range(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    range: Range,
) -> DefinitionCandidate {
    DefinitionCandidate {
        name: unit.identifier().to_string(),
        fqn: Some(unit.fq_name()),
        path: rel_path_string(unit.source()),
        start_line: range.start_line,
        end_line: range.end_line,
        kind: code_unit_kind_name(unit.kind()).to_string(),
        signature: unit
            .signature()
            .map(str::to_string)
            .or_else(|| analyzer.signatures(unit).first().cloned()),
        language: language_name(language_for_target(unit)),
    }
}

fn definition_display_range(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<Range> {
    let name_range = analyzer
        .project()
        .read_source(unit.source())
        .ok()
        .and_then(|content| {
            code_unit_declaration_name_range(analyzer, unit.source(), &content, unit)
        });
    display_range_with_declaration_name(analyzer, unit, name_range)
}

pub fn get_symbol_ancestors(
    analyzer: &dyn IAnalyzer,
    params: SymbolLookupParams,
) -> SymbolAncestorsResult {
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        return SymbolAncestorsResult {
            ancestors: Vec::new(),
            not_found: params
                .symbols
                .into_iter()
                .filter(|symbol| !symbol.trim().is_empty())
                .map(renderable_not_found_input)
                .collect(),
            ambiguous: Vec::new(),
        };
    };

    let mut ancestors = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();

    for symbol in params
        .symbols
        .into_iter()
        .filter(|symbol| !symbol.trim().is_empty())
    {
        match resolve_selectable_definitions(analyzer, &symbol, resolve_codeunit_fuzzy) {
            SelectableDefinitionResolution::Resolved(code_units) => {
                let mut resolved = Vec::new();
                let mut rejected_kind = None;
                for code_unit in code_units {
                    if !is_ancestor_target(&code_unit) {
                        rejected_kind.get_or_insert(code_unit_kind_name(code_unit.kind()));
                        continue;
                    }
                    resolved.push(SymbolAncestors {
                        symbol: display_symbol_for_target(&code_unit),
                        ancestors: provider
                            .get_ancestors(&code_unit)
                            .into_iter()
                            .map(|ancestor| display_symbol_for_target(&ancestor))
                            .collect(),
                    });
                }
                if resolved.is_empty() {
                    let note = rejected_kind.map(|kind| {
                        format!(
                            "resolves to a {kind}; get_symbol_ancestors only accepts class/module/type symbols"
                        )
                    });
                    not_found.push(not_found_input(symbol, note));
                } else {
                    ancestors.extend(resolved);
                }
            }
            SelectableDefinitionResolution::Ambiguous(item) => ambiguous.push(item),
            SelectableDefinitionResolution::NotFound(target) => {
                if path_like_symbol_guidance(
                    &target.input,
                    PathLikeSymbolGuidanceContext::SymbolLookup,
                )
                .is_some()
                {
                    not_found.push(path_like_symbol_not_found_input(
                        target.input,
                        PathLikeSymbolGuidanceContext::SymbolLookup,
                    ));
                } else {
                    not_found.push(target);
                }
            }
        }
    }

    SymbolAncestorsResult {
        ancestors,
        not_found,
        ambiguous,
    }
}

#[derive(Debug)]
enum SelectableDefinitionResolution {
    Resolved(Vec<CodeUnit>),
    Ambiguous(AmbiguousSymbol),
    NotFound(NotFoundInput),
}

enum DefinitionSelector<'a> {
    Name(&'a str),
    FileAnchored { anchor: String, lookup: &'a str },
}

enum PathQualifiedSelector<'a> {
    Resolved { anchor: String, lookup: &'a str },
    AmbiguousPath(AmbiguousPathInput),
}

fn exact_codeunit_resolution(analyzer: &dyn IAnalyzer, input: &str) -> CodeUnitResolution {
    let units = resolve_codeunit_exact(analyzer, input);
    if units.is_empty() {
        CodeUnitResolution::NotFound
    } else {
        CodeUnitResolution::Resolved(units)
    }
}

fn exact_then_fuzzy_codeunit_resolution(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> CodeUnitResolution {
    let exact = resolve_codeunit_exact(analyzer, input);
    if exact.is_empty() {
        resolve_codeunit_fuzzy(analyzer, input)
    } else {
        CodeUnitResolution::Resolved(exact)
    }
}

/// Resolve a symbol input into one selectable definition group. A file anchor
/// (`src/plugin/relativeTime/index.js#default`) narrows same-name module-scoped
/// definitions to the exact relative path before grouping; a bare name that
/// spans multiple selectors is ambiguous and returns requestable selectors.
fn resolve_selectable_definitions(
    analyzer: &dyn IAnalyzer,
    input: &str,
    resolve: impl Fn(&dyn IAnalyzer, &str) -> CodeUnitResolution,
) -> SelectableDefinitionResolution {
    let selector = split_definition_selector(input);
    let (mut anchor, mut lookup) = match selector {
        DefinitionSelector::Name(name) => (None, name),
        DefinitionSelector::FileAnchored { anchor, lookup } => (Some(anchor), lookup),
    };
    let mut resolution = resolve(analyzer, lookup);
    if matches!(resolution, CodeUnitResolution::NotFound)
        && anchor.is_none()
        && let Some(path_selector) = split_path_qualified_definition_selector(analyzer, input)
    {
        match path_selector {
            PathQualifiedSelector::Resolved {
                anchor: path_anchor,
                lookup: path_lookup,
            } => {
                anchor = Some(path_anchor);
                lookup = path_lookup;
                resolution = resolve(analyzer, lookup);
            }
            PathQualifiedSelector::AmbiguousPath(item) => {
                return SelectableDefinitionResolution::NotFound(not_found_input(
                    input,
                    Some(format!(
                        "path is ambiguous; retry with one of: {}",
                        item.matches.join(", ")
                    )),
                ));
            }
        }
    }
    let code_units = match resolution {
        CodeUnitResolution::Resolved(code_units) => code_units,
        CodeUnitResolution::Ambiguous(matches) => matches,
        CodeUnitResolution::NotFound => {
            return SelectableDefinitionResolution::NotFound(symbol_not_found_input(input));
        }
    };

    let code_units = match anchor {
        Some(anchor) => {
            let candidate_names = if looks_like_extensionless_path_anchor(&anchor) {
                code_unit_match_names(&code_units)
            } else {
                Vec::new()
            };
            let narrowed: Vec<CodeUnit> = code_units
                .into_iter()
                .filter(|unit| rel_path_string(unit.source()) == anchor)
                .collect();
            if narrowed.is_empty() {
                return SelectableDefinitionResolution::NotFound(
                    symbol_source_anchor_not_found_input(input, &anchor, lookup, &candidate_names),
                );
            }
            narrowed
        }
        None => code_units,
    };

    let groups = distinct_definitions(code_units);
    match groups.as_slice() {
        [] => SelectableDefinitionResolution::NotFound(symbol_not_found_input(input)),
        [(_, _)] => SelectableDefinitionResolution::Resolved(
            groups.into_iter().flat_map(|(_, units)| units).collect(),
        ),
        _ => {
            let matches: Vec<String> = groups.into_iter().map(|(selector, _)| selector).collect();
            SelectableDefinitionResolution::Ambiguous(AmbiguousSymbol {
                target: input.to_string(),
                note: ambiguous_symbol_selector_note(&matches),
                matches,
            })
        }
    }
}

fn ambiguous_symbol_selector_note(matches: &[String]) -> Option<String> {
    matches.first().map(|example| {
        format!("Ambiguous; re-call with one selector from `matches` (e.g. {example}).")
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
    NotFound(NotFoundInput),
    Ambiguous(AmbiguousSymbol),
    AmbiguousPath(AmbiguousPathInput),
}

fn route_summary_targets(analyzer: &dyn IAnalyzer, targets: &[String]) -> SummaryTargets {
    let _scope = profiling::scope("searchtools::route_summary_targets");
    let resolver = WorkspaceFileResolver::new(analyzer.project());
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
        if matches!(
            split_definition_selector(target),
            DefinitionSelector::FileAnchored { .. }
        ) {
            symbol_targets.push(target.to_string());
            continue;
        }

        match resolver.resolve_literal(target) {
            ResolvedFileInput::File(file) => {
                file_targets.insert(file);
                continue;
            }
            ResolvedFileInput::Ambiguous(item) => {
                ambiguous_paths.push(item);
                continue;
            }
            ResolvedFileInput::NotFound(_) => {}
        }

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
        match resolve_selectable_definitions(analyzer, &target, resolve_codeunit_fuzzy) {
            SelectableDefinitionResolution::Resolved(code_units) => {
                let start_len = summaries.len();
                for code_unit in code_units {
                    if let Some(block) = summary_block_for_code_unit(analyzer, &code_unit) {
                        summaries.push(block);
                    }
                }
                if summaries.len() == start_len {
                    not_found.push(renderable_not_found_input(target));
                }
            }
            SelectableDefinitionResolution::Ambiguous(item) => ambiguous.push(item),
            SelectableDefinitionResolution::NotFound(target) => not_found.push(target),
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
    let mut blocks = Vec::new();
    let mut module_units = Vec::new();

    for code_unit in code_units {
        if is_file_listing_target(code_unit) {
            module_units.push(code_unit.clone());
            continue;
        }

        let source_blocks = source_blocks_for_code_unit(analyzer, code_unit, true);
        if source_blocks.is_empty() && is_scala_object_like(code_unit) {
            module_units.push(code_unit.clone());
        } else {
            blocks.extend(source_blocks);
        }
    }

    blocks.extend(module_file_listing_blocks(analyzer, &module_units));
    blocks
}

fn java_generated_accessor_source_blocks(
    analyzer: &dyn IAnalyzer,
    input: &str,
    anchor: Option<&str>,
) -> Vec<SourceBlock> {
    let lookup = strip_trailing_call_suffix(input.trim());
    let Some(member) = symbol_selector_leaf(Language::Java, &lookup) else {
        return Vec::new();
    };

    let owners: Vec<_> = resolve_enclosing_codeunits(analyzer, &lookup)
        .into_iter()
        .filter(|owner| language_for_target(owner) == Language::Java && owner.is_class())
        .collect();
    let owner_names: BTreeSet<_> = owners.iter().map(CodeUnit::fq_name).collect();
    if owner_names.len() != 1 {
        return Vec::new();
    }

    let mut fields: Vec<_> = owners
        .iter()
        .flat_map(|owner| {
            java_lombok_accessor_field_candidates(
                analyzer,
                analyzer.definition_lookup_index(),
                owner,
                &member,
            )
        })
        .filter(|field| anchor.is_none_or(|anchor| rel_path_string(field.source()) == anchor))
        .collect();
    fields.sort();
    fields.dedup();
    source_blocks_for_resolved_units(analyzer, &fields)
}

pub(crate) fn symbol_source_candidate_files(
    analyzer: &dyn IAnalyzer,
    result: &SymbolSourcesResult,
) -> BTreeSet<ProjectFile> {
    let resolver = WorkspaceFileResolver::new(analyzer.project());
    let mut files = BTreeSet::new();

    for source in &result.sources {
        if let Some(rel_path) = workspace_rel_path(&source.path) {
            files.insert(ProjectFile::new(
                analyzer.project().root().to_path_buf(),
                rel_path,
            ));
        }
    }

    for selector in result.ambiguous.iter().flat_map(|item| item.matches.iter()) {
        if let SelectableDefinitionResolution::Resolved(units) =
            resolve_selectable_definitions(analyzer, selector, exact_then_fuzzy_codeunit_resolution)
        {
            extend_candidate_unit_files(&mut files, units, None);
        }
    }

    for symbol in result
        .not_found
        .iter()
        .map(|item| item.input.trim())
        .filter(|symbol| !symbol.is_empty())
    {
        let (mut anchor, mut lookup) = match split_definition_selector(symbol) {
            DefinitionSelector::Name(name) => (None, name),
            DefinitionSelector::FileAnchored { anchor, lookup } => {
                if let ResolvedFileInput::File(file) = resolver.resolve_literal(&anchor) {
                    files.insert(file);
                }
                (Some(anchor), lookup)
            }
        };

        if anchor.is_none()
            && let Some(PathQualifiedSelector::Resolved {
                anchor: path_anchor,
                lookup: path_lookup,
            }) = split_path_qualified_definition_selector(analyzer, symbol)
        {
            if let ResolvedFileInput::File(file) = resolver.resolve_literal(&path_anchor) {
                files.insert(file);
            }
            anchor = Some(path_anchor);
            lookup = path_lookup;
        }

        let resolved = resolve_enclosing_codeunits(analyzer, lookup);
        extend_candidate_unit_files(&mut files, resolved, anchor.as_deref());
    }

    files
}

fn extend_candidate_unit_files(
    files: &mut BTreeSet<ProjectFile>,
    units: Vec<CodeUnit>,
    anchor: Option<&str>,
) {
    files.extend(units.into_iter().filter_map(|unit| {
        anchor
            .is_none_or(|anchor| rel_path_string(unit.source()) == anchor)
            .then(|| unit.source().clone())
    }));
}

fn resolve_file_anchored_symbol_sources(
    analyzer: &dyn IAnalyzer,
    input: &str,
    anchor: String,
    lookup: &str,
) -> SourceLookupOutcome {
    let code_units = match exact_then_fuzzy_codeunit_resolution(analyzer, lookup) {
        CodeUnitResolution::Resolved(code_units) | CodeUnitResolution::Ambiguous(code_units) => {
            code_units
        }
        CodeUnitResolution::NotFound => {
            let generated = java_generated_accessor_source_blocks(analyzer, lookup, Some(&anchor));
            if !generated.is_empty() {
                return SourceLookupOutcome::Found(generated);
            }
            if let Some(item) = unsupported_selector_shape_not_found_input(analyzer, input) {
                return SourceLookupOutcome::NotFound(item);
            }
            return SourceLookupOutcome::NotFound(symbol_not_found_input(input));
        }
    };
    let narrowed: Vec<_> = code_units
        .into_iter()
        .filter(|unit| rel_path_string(unit.source()) == anchor)
        .collect();
    if narrowed.is_empty() {
        return SourceLookupOutcome::NotFound(anchor_not_found_input(input, &anchor, lookup));
    }

    let groups = distinct_definitions(narrowed);
    match groups.as_slice() {
        [] => SourceLookupOutcome::NotFound(symbol_not_found_input(input)),
        [(_, _)] => {
            let code_units: Vec<_> = groups.into_iter().flat_map(|(_, units)| units).collect();
            let sources = source_blocks_for_resolved_units(analyzer, &code_units);
            if sources.is_empty() {
                SourceLookupOutcome::NotFound(renderable_not_found_input(input))
            } else {
                SourceLookupOutcome::Found(sources)
            }
        }
        _ => {
            let matches: Vec<_> = groups.into_iter().map(|(selector, _)| selector).collect();
            SourceLookupOutcome::Ambiguous(AmbiguousSymbol {
                target: input.to_string(),
                note: ambiguous_symbol_selector_note(&matches),
                matches,
            })
        }
    }
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
            // misrouted as a filesystem path, and real namespace symbols like
            // `fmt::formatter` are never stolen by path-selector parsing.
            match resolve_selectable_definitions(analyzer, &symbol, exact_codeunit_resolution) {
                SelectableDefinitionResolution::Resolved(code_units) => {
                    let sources = source_blocks_for_resolved_units(analyzer, &code_units);
                    return if sources.is_empty() {
                        (
                            index,
                            SourceLookupOutcome::NotFound(renderable_not_found_input(symbol)),
                        )
                    } else {
                        (index, SourceLookupOutcome::Found(sources))
                    };
                }
                SelectableDefinitionResolution::Ambiguous(item) => {
                    return (index, SourceLookupOutcome::Ambiguous(item));
                }
                SelectableDefinitionResolution::NotFound(_) => {
                    if let DefinitionSelector::FileAnchored { anchor, lookup } =
                        split_definition_selector(&symbol)
                    {
                        let generated =
                            java_generated_accessor_source_blocks(analyzer, lookup, Some(&anchor));
                        if !generated.is_empty() {
                            return (index, SourceLookupOutcome::Found(generated));
                        }
                    }
                }
            }

            match split_path_qualified_definition_selector(analyzer, &symbol) {
                Some(PathQualifiedSelector::Resolved { anchor, lookup }) => {
                    return match resolve_file_anchored_symbol_sources(
                        analyzer, &symbol, anchor, lookup,
                    ) {
                        SourceLookupOutcome::Found(blocks) => {
                            (index, SourceLookupOutcome::Found(blocks))
                        }
                        SourceLookupOutcome::NotFound(item) => {
                            (index, SourceLookupOutcome::NotFound(item))
                        }
                        SourceLookupOutcome::Ambiguous(item) => {
                            (index, SourceLookupOutcome::Ambiguous(item))
                        }
                        SourceLookupOutcome::AmbiguousPath(item) => {
                            (index, SourceLookupOutcome::AmbiguousPath(item))
                        }
                    };
                }
                Some(PathQualifiedSelector::AmbiguousPath(item)) => {
                    return (index, SourceLookupOutcome::AmbiguousPath(item));
                }
                None => {}
            }

            if analyzer.languages().contains(&Language::Go)
                && looks_like_go_receiver_selector(&symbol)
            {
                match resolve_selectable_definitions(
                    analyzer,
                    &symbol,
                    exact_then_fuzzy_codeunit_resolution,
                ) {
                    SelectableDefinitionResolution::Resolved(code_units) => {
                        let sources = source_blocks_for_resolved_units(analyzer, &code_units);
                        return if sources.is_empty() {
                            (
                                index,
                                SourceLookupOutcome::NotFound(renderable_not_found_input(symbol)),
                            )
                        } else {
                            (index, SourceLookupOutcome::Found(sources))
                        };
                    }
                    SelectableDefinitionResolution::Ambiguous(item) => {
                        return (index, SourceLookupOutcome::Ambiguous(item));
                    }
                    SelectableDefinitionResolution::NotFound(_) => {}
                }
            }

            let file_matches = resolve_file_patterns(analyzer, std::slice::from_ref(&symbol));
            if let Some(item) = file_matches.ambiguous_paths.first() {
                return (index, SourceLookupOutcome::AmbiguousPath(item.clone()));
            }
            if !file_matches.files.is_empty() {
                let sources = source_blocks_for_files(analyzer, file_matches.files);
                return if sources.is_empty() {
                    (
                        index,
                        SourceLookupOutcome::NotFound(renderable_not_found_input(symbol)),
                    )
                } else {
                    (index, SourceLookupOutcome::Found(sources))
                };
            }

            if looks_like_file_target(&symbol) {
                if let Some(item) = unsupported_selector_shape_not_found_input(analyzer, &symbol) {
                    return (index, SourceLookupOutcome::NotFound(item));
                }
                return (
                    index,
                    SourceLookupOutcome::NotFound(file_not_found_input(symbol)),
                );
            }

            match resolve_selectable_definitions(analyzer, &symbol, resolve_codeunit_fuzzy) {
                SelectableDefinitionResolution::Resolved(code_units) => {
                    let sources = source_blocks_for_resolved_units(analyzer, &code_units);
                    if sources.is_empty() {
                        (
                            index,
                            SourceLookupOutcome::NotFound(renderable_not_found_input(symbol)),
                        )
                    } else {
                        (index, SourceLookupOutcome::Found(sources))
                    }
                }
                SelectableDefinitionResolution::Ambiguous(item) => {
                    (index, SourceLookupOutcome::Ambiguous(item))
                }
                SelectableDefinitionResolution::NotFound(target) => {
                    let generated = java_generated_accessor_source_blocks(analyzer, &symbol, None);
                    if !generated.is_empty() {
                        return (index, SourceLookupOutcome::Found(generated));
                    }
                    let target = unsupported_selector_shape_not_found_input(analyzer, &symbol)
                        .unwrap_or(target);
                    (index, SourceLookupOutcome::NotFound(target))
                }
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
    let _scope = profiling::scope("searchtools::get_summaries");
    let (mut summaries, _directory_symbols, directory_target_inputs) =
        summarize_targets_with_directory_inventory(analyzer, &params.targets);
    summaries.not_found.extend(
        directory_target_inputs
            .into_iter()
            .map(renderable_not_found_input),
    );
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
    let note = skim_files_note(truncated, files.len(), total_files);

    SkimFilesResult {
        truncated,
        total_files,
        files,
        note,
        ambiguous_paths: Vec::new(),
    }
}

fn skim_files_note(truncated: bool, shown: usize, total: usize) -> Option<String> {
    truncated.then(|| {
        format!(
            "Showing {shown} of {total} selected files. Narrow `file_patterns` on list_symbols or `targets` on get_summaries to see the rest."
        )
    })
}

pub(crate) fn summarize_files(analyzer: &dyn IAnalyzer, files: Vec<ProjectFile>) -> SummaryResult {
    let _scope = profiling::scope("searchtools::summarize_files");
    let mut summaries: Vec<_> = files
        .into_par_iter()
        .filter_map(|file| {
            let mut elements = analyzer
                .summary_file_projection(&file)
                .map(|projection| summary_elements_from_file_projection(&projection, &file))
                .unwrap_or_else(|| {
                    let mut elements = Vec::new();
                    for code_unit in analyzer.top_level_declarations(&file) {
                        elements.extend(summary_elements_for_code_unit_in_file(
                            analyzer, &code_unit, &file,
                        ));
                    }
                    elements
                });

            // A module-level declaration can appear both as its own entry in
            // top_level_declarations and as a child of the synthetic module unit
            // (which is itself top-level), so the recursion above emits it twice --
            // for Python this doubles every module-level `def`. Collapse to one
            // element per (symbol, line span) so each declaration is summarized
            // exactly once; this feeds both the structured `elements` and the
            // derived render_text.
            let mut seen = HashSet::default();
            elements.retain(|element| {
                seen.insert((element.symbol.clone(), element.start_line, element.end_line))
            });

            let (elements, fallback_reason) = if elements.is_empty() {
                summary_fallback_for_file(analyzer, &file)?
            } else {
                (elements, None)
            };

            Some(SummaryBlock {
                label: rel_path_string(&file),
                path: rel_path_string(&file),
                preamble: file_preamble(analyzer, &file, &elements),
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

    excerpt_fallback_elements(analyzer, file).map(|(elements, note)| (elements, Some(note)))
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

    let Ok(content) = analyzer.project().read_source(file) else {
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
            parent_symbol: None,
            presentation: None,
        });
    }
    elements
}

fn excerpt_fallback_elements(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<(Vec<SummaryElement>, String)> {
    let content = analyzer.project().read_source(file).ok()?;
    let sampled = model_context::sample(&content);
    if sampled.text.is_empty() {
        return None;
    }
    let note = sampled_excerpt_note(&sampled);
    let elements = vec![SummaryElement {
        path: rel_path_string(file),
        symbol: rel_path_string(file),
        kind: "excerpt".to_string(),
        start_line: 1,
        end_line: sampled.total_lines,
        text: sampled.text,
        parent_symbol: None,
        presentation: Some("sampled_excerpt".to_string()),
    }];
    Some((elements, note))
}

fn sampled_excerpt_note(sampled: &model_context::HeadTail) -> String {
    if sampled.truncated {
        format!(
            "no indexed declarations or top-level includes found in this file; showing a head/tail sample with the first {} and last {} of its {} lines (the middle is omitted)",
            sampled.head_shown, sampled.tail_shown, sampled.total_lines
        )
    } else {
        format!(
            "no indexed declarations or top-level includes found in this file; showing its full text ({} lines)",
            sampled.total_lines
        )
    }
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
    file_output.not_found.extend(
        summary_targets
            .unmatched_file_targets
            .iter()
            .cloned()
            .map(file_not_found_input),
    );
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
                ResolvedFileInput::NotFound(item) => not_found.push(file_not_found_input(item)),
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
        .into_iter()
        .filter(|file| {
            matches!(
                classify_resolved_test_file(analyzer, file).kind,
                TestFileKind::Test | TestFileKind::TestSupport
            )
        })
        .collect();
    Some(Arc::new(set))
}

/// Build a [`UsageFinder`] whose file filter drops the excluded test files and
/// applies the optional path filter — the workspace scoping that both
/// `scan_usages` and `usage_graph` run before querying call sites.
fn scoped_usage_finder(
    test_files: Option<&Arc<HashSet<ProjectFile>>>,
    path_filter: Option<&Arc<ScanUsagesPathFilter>>,
) -> UsageFinder {
    let mut finder = UsageFinder::new();
    if let Some(test_files) = test_files {
        let test_files = Arc::clone(test_files);
        let path_filter = path_filter.map(Arc::clone);
        finder = finder.with_file_filter(move |file| {
            !test_files.contains(file)
                && path_filter
                    .as_ref()
                    .map(|filter| filter.matches(file))
                    .unwrap_or(true)
        });
    } else if let Some(path_filter) = path_filter.map(Arc::clone) {
        finder = finder.with_file_filter(move |file| path_filter.matches(file));
    }
    finder.with_authoritative_scope(path_filter.is_some())
}

/// Split a definition selector into an optional file anchor and the name to
/// resolve. A plain input (`Anchor`) has no anchor; a file-anchored selector
/// (`charts/Anchor.ts#Anchor`), returned in a prior ambiguity result, picks one
/// of several same-named definitions.
fn split_definition_selector(input: &str) -> DefinitionSelector<'_> {
    match input.split_once('#') {
        Some((anchor, name))
            if !anchor.is_empty()
                && !name.is_empty()
                && looks_like_path_selector_anchor(anchor) =>
        {
            DefinitionSelector::FileAnchored {
                anchor: anchor.to_string(),
                lookup: name,
            }
        }
        _ => DefinitionSelector::Name(input),
    }
}

fn split_path_qualified_definition_selector<'a>(
    analyzer: &dyn IAnalyzer,
    input: &'a str,
) -> Option<PathQualifiedSelector<'a>> {
    let resolver = WorkspaceFileResolver::new(analyzer.project());
    for separator in ["::", ":"] {
        let Some((path, name)) = input.split_once(separator) else {
            continue;
        };
        let path = path.trim();
        let name = name.trim();
        if path.is_empty() || name.is_empty() {
            continue;
        }
        if !looks_like_path_selector_anchor(path) {
            continue;
        }
        return Some(match resolver.resolve_literal(path) {
            ResolvedFileInput::File(file) => PathQualifiedSelector::Resolved {
                anchor: rel_path_string(&file),
                lookup: name,
            },
            ResolvedFileInput::Ambiguous(item) => PathQualifiedSelector::AmbiguousPath(item),
            ResolvedFileInput::NotFound(_) => continue,
        });
    }

    if let Some(selector) = dotted_file_symbol_selector(analyzer, input) {
        return Some(selector);
    }

    None
}

fn looks_like_path_selector_anchor(path: &str) -> bool {
    if path.contains('/') || path.contains('\\') {
        return true;
    }
    let Some(rel) = workspace_rel_path(path) else {
        return false;
    };
    rel.file_name()
        .and_then(|name| std::path::Path::new(name).extension())
        .is_some_and(|extension| !extension.is_empty())
}

fn unsupported_path_qualified_scan_symbol(
    resolver: &WorkspaceFileResolver,
    input: &str,
) -> Option<NotFoundInput> {
    let (path, symbol) = input.trim().split_once("::")?;
    let path = path.trim();
    let symbol = symbol.trim();
    if path.is_empty() || symbol.is_empty() {
        return None;
    }

    match resolver.resolve_literal(path) {
        ResolvedFileInput::File(file) => {
            let path = rel_path_string(&file);
            Some(not_found_input(
                input,
                Some(format!(
                    "unsupported path::symbol selector; re-call scan_usages_by_reference with symbols:[\"{symbol}\"] and paths:[\"{path}\"]"
                )),
            ))
        }
        ResolvedFileInput::Ambiguous(item) => Some(not_found_input(
            input,
            Some(format!(
                "unsupported path::symbol selector; `{}` is ambiguous; choose one path from {} and re-call scan_usages_by_reference with symbols:[\"{symbol}\"] and paths:[\"chosen/path\"]",
                item.input,
                path_match_sample(&item.matches)
            )),
        )),
        ResolvedFileInput::NotFound(_) => None,
    }
}

fn path_match_sample(matches: &[String]) -> String {
    let sample = matches
        .iter()
        .take(SCAN_USAGES_PATH_SELECTOR_MATCH_LIMIT)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if matches.len() > SCAN_USAGES_PATH_SELECTOR_MATCH_LIMIT {
        format!(
            "{sample} (showing first {SCAN_USAGES_PATH_SELECTOR_MATCH_LIMIT} of {})",
            matches.len()
        )
    } else {
        sample
    }
}

/// The preferred selector for one definition. Module-scoped ecosystems (JS/TS)
/// are always file-anchored. [`distinct_definitions`] also anchors other
/// ecosystems when the same FQN spans multiple language/file domains.
fn definition_selector(unit: &CodeUnit) -> String {
    if Ecosystem::of(language_for_target(unit)).is_module_scoped() {
        file_anchored_definition_selector(unit)
    } else {
        unit.fq_name()
    }
}

fn file_anchored_definition_selector(unit: &CodeUnit) -> String {
    format!("{}#{}", rel_path_string(unit.source()), unit.fq_name())
}

/// Partition resolved overloads into distinct selectable definitions, preserving
/// first-seen order. Overloads of one symbol share a selector and scan together.
/// An FQN present in multiple language/file domains is file-anchored in every
/// domain so each ambiguity candidate can be re-queried without looping.
fn distinct_definitions(overloads: Vec<CodeUnit>) -> Vec<(String, Vec<CodeUnit>)> {
    let mut domains_by_fqn: HashMap<String, HashSet<(Language, Option<String>)>> =
        HashMap::default();
    for unit in &overloads {
        let language = language_for_target(unit);
        let module_path = Ecosystem::of(language)
            .is_module_scoped()
            .then(|| rel_path_string(unit.source()));
        domains_by_fqn
            .entry(unit.fq_name())
            .or_default()
            .insert((language, module_path));
    }

    let mut groups: Vec<(String, Vec<CodeUnit>)> = Vec::new();
    for unit in overloads {
        let selector = if domains_by_fqn
            .get(&unit.fq_name())
            .is_some_and(|domains| domains.len() > 1)
        {
            file_anchored_definition_selector(&unit)
        } else {
            definition_selector(&unit)
        };
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

fn prefer_exact_lookup_matches(overloads: Vec<CodeUnit>, lookup: &str) -> Vec<CodeUnit> {
    if overloads.iter().any(|unit| unit.fq_name() == lookup) {
        overloads
            .into_iter()
            .filter(|unit| unit.fq_name() == lookup)
            .collect()
    } else {
        overloads
    }
}

fn code_unit_match_names(matches: &[CodeUnit]) -> Vec<String> {
    distinct_definitions(matches.to_vec())
        .into_iter()
        .map(|(selector, _)| selector)
        .collect()
}

fn ambiguous_usage_symbol_from_groups(
    analyzer: &dyn IAnalyzer,
    surface: ScanUsagesSurface,
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
    let candidate_details: Vec<AmbiguousUsageCandidateDetail> =
        if surface == ScanUsagesSurface::Location {
            groups
                .iter()
                .take(SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT)
                .filter_map(|(selector, units)| {
                    let unit = units.first()?;
                    let source = unit.source().read_to_string().ok()?;
                    let range =
                        code_unit_declaration_name_range(analyzer, unit.source(), &source, unit)?;
                    let path = rel_path_string(unit.source());
                    let line = range.start_line + 1;
                    let column = character_column_for_byte(&source, line, range.start_byte);
                    Some(AmbiguousUsageCandidateDetail {
                        target: selector.clone(),
                        path: path.clone(),
                        start_line: line,
                        end_line: range.end_line + 1,
                        scan_usages_by_location_target: ScanUsagesTargetSuggestion {
                            path,
                            line,
                            column,
                        },
                    })
                })
                .collect()
        } else {
            Vec::new()
        };

    let has_candidate_details = !candidate_details.is_empty();
    AmbiguousUsageSymbol {
        symbol,
        short_name,
        candidate_targets,
        candidate_details,
        candidate_details_total: has_candidate_details.then_some(total),
        candidate_details_truncated: has_candidate_details
            && total > SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT,
        candidates: Vec::new(),
        candidate_files_truncated: false,
        definition_sites_excluded: None,
        note: Some(
            if surface == ScanUsagesSurface::Location && total > SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT
            {
                format!(
                    "{} Showing first {} of {total} candidate locations.",
                    note, SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT
                )
            } else {
                note
            },
        ),
    }
}

fn scan_usages_ambiguity_note(surface: ScanUsagesSurface) -> &'static str {
    match surface {
        ScanUsagesSurface::Reference => {
            "Ambiguous; re-call scan_usages_by_reference with one symbol from candidate_targets."
        }
        ScanUsagesSurface::Location => {
            "Ambiguous location; refine the line/column target and re-call scan_usages_by_location."
        }
    }
}

enum ScanUsageTargetResolution {
    Resolved {
        symbol: String,
        overloads: Vec<CodeUnit>,
    },
    NotFound(NotFoundInput),
    Ambiguous(AmbiguousUsageSymbol),
    Failure(UsageFailureInfo),
}

#[derive(Debug, Clone, Copy)]
enum ScanUsagesLocationSelection {
    Point(usize),
    Line(usize),
}

#[derive(Debug, Clone)]
struct ScanUsageRequest {
    index: usize,
    input: ScanUsagesInput,
    input_kind: ScanUsagesInputKind,
    label: String,
    surface: ScanUsagesSurface,
}

impl ScanUsageRequest {
    fn symbol(index: usize, symbol: String) -> Self {
        Self {
            index,
            input: ScanUsagesInput::Symbol(symbol.clone()),
            input_kind: ScanUsagesInputKind::Symbol,
            label: symbol,
            surface: ScanUsagesSurface::Reference,
        }
    }

    fn target(index: usize, target: ScanUsagesTarget) -> Self {
        let label = scan_usages_target_label(&target);
        Self {
            index,
            input: ScanUsagesInput::Target(target),
            input_kind: ScanUsagesInputKind::Target,
            label,
            surface: ScanUsagesSurface::Location,
        }
    }
}

#[derive(Debug)]
struct ScanUsagesQueryScope {
    path_filter: Option<Arc<ScanUsagesPathFilter>>,
    include_tests: bool,
    ignored_paths: usize,
}

impl ScanUsagesQueryScope {
    fn new(analyzer: &dyn IAnalyzer, paths: Option<&[String]>, include_tests: bool) -> Self {
        let built = build_scan_usages_path_filter(analyzer, paths);
        Self {
            path_filter: built.filter,
            include_tests,
            ignored_paths: built.ignored_paths,
        }
    }

    fn whole_workspace(&self) -> bool {
        self.path_filter.is_none()
    }

    fn result_scope(&self) -> ScanUsagesScope {
        let (paths, paths_omitted) = self
            .path_filter
            .as_deref()
            .map(ScanUsagesPathFilter::summarized_paths)
            .unwrap_or_default();
        ScanUsagesScope {
            include_tests: self.include_tests,
            whole_workspace: self.whole_workspace(),
            paths,
            paths_omitted,
            ignored_paths: some_if_nonzero(self.ignored_paths),
        }
    }
}

#[derive(Debug, Clone)]
struct IndexedResolvedScanTarget {
    request: ScanUsageRequest,
    symbol: String,
    overloads: Vec<CodeUnit>,
    location_selected: bool,
}

#[derive(Debug, Clone)]
enum ScanUsagesWorkEntry {
    Usage {
        request: ScanUsageRequest,
        state: SymbolUsageRenderState,
        candidate_files_sample: Option<ScanUsagesCandidateFilesSample>,
        target_is_method: bool,
    },
    NotFound {
        request: ScanUsageRequest,
        item: NotFoundInput,
    },
    Ambiguous {
        request: ScanUsageRequest,
        item: AmbiguousUsageSymbol,
    },
    Failure {
        request: ScanUsageRequest,
        failure: UsageFailureInfo,
    },
    TooManyCallsites {
        request: ScanUsageRequest,
        state: SymbolUsageRenderState,
        short_name: String,
        total_callsites: usize,
        limit: usize,
        target_is_method: bool,
    },
}

impl ScanUsagesWorkEntry {
    fn index(&self) -> usize {
        match self {
            ScanUsagesWorkEntry::Usage { request, .. }
            | ScanUsagesWorkEntry::NotFound { request, .. }
            | ScanUsagesWorkEntry::Ambiguous { request, .. }
            | ScanUsagesWorkEntry::Failure { request, .. }
            | ScanUsagesWorkEntry::TooManyCallsites { request, .. } => request.index,
        }
    }
}

pub(crate) fn scan_usages_target_label(target: &ScanUsagesTarget) -> String {
    match target.column {
        Some(column) => format!("{}:{}:{column}", target.path, target.line),
        None => format!("{}:{}", target.path, target.line),
    }
}

fn location_selector_failure(
    target: &ScanUsagesTarget,
    reason_kind: &str,
    reason: impl Into<String>,
) -> ScanUsageTargetResolution {
    let hint = usage_failure_hint(ScanUsagesSurface::Location, reason_kind, None, true, false);
    ScanUsageTargetResolution::Failure(UsageFailureInfo {
        symbol: scan_usages_target_label(target),
        fq_name: String::new(),
        reason_kind: reason_kind.to_string(),
        reason: reason.into(),
        candidate_files_truncated: false,
        candidate_files_sample: None,
        hint,
    })
}

fn usage_failure_hint(
    surface: ScanUsagesSurface,
    reason_kind: &str,
    target: Option<&CodeUnit>,
    location_selected: bool,
    candidate_files_truncated: bool,
) -> Option<String> {
    if reason_kind == "unsupported_target_shape" {
        return Some(unsupported_target_shape_guidance(target));
    }

    if candidate_files_truncated {
        return Some(format!(
            "The candidate file set exceeded the per-query cap; re-call {} with narrower `paths` to reduce the scan scope.",
            surface.tool_name()
        ));
    }

    match (reason_kind, location_selected) {
        ("no_graph_seed", true) => Some(
            "No export seed was resolved for this selected definition. Use search_symbols or get_symbol_sources to choose an exported declaration, or narrow `paths` to likely callers."
                .to_string(),
        ),
        ("no_graph_seed", false) => Some(
            "No export seed was resolved for this symbol. Use search_symbols or get_symbol_sources to choose an exported declaration, then re-call scan_usages_by_reference with that symbol."
                .to_string(),
        ),
        ("unsupported_target_language", _)
        | ("missing_analyzer_capability", _)
        | ("unsupported_target_shape", _) => None,
        _ => None,
    }
}

fn unsupported_target_shape_message(target: Option<&CodeUnit>) -> String {
    let Some(target) = target else {
        return "`scan_usages` cannot resolve this declaration kind yet".to_string();
    };
    format!(
        "`scan_usages` cannot resolve {} {} declarations yet",
        scan_usages_language_name(language_for_target(target)),
        target.kind().display_lowercase(),
    )
}

const UNSUPPORTED_TARGET_SHAPE_GUIDANCE: &str = "Use `get_symbol_sources` to inspect the declaration, then `query_code` to find syntactic candidates; `query_code` does not resolve references.";

fn unsupported_target_shape_guidance(target: Option<&CodeUnit>) -> String {
    let Some(target) = target else {
        return UNSUPPORTED_TARGET_SHAPE_GUIDANCE.to_string();
    };

    if target.is_macro() {
        return function_like_macro_query_guidance(
            language_for_target(target),
            target.identifier(),
        );
    }

    UNSUPPORTED_TARGET_SHAPE_GUIDANCE.to_string()
}

fn function_like_macro_query_guidance(language: Language, identifier: &str) -> String {
    let query = function_like_macro_query(language, identifier);
    format!(
        "Use `get_symbol_sources` to inspect the macro. For a function-like macro, call `query_code` with `{query}` to find syntactic invocation candidates; `query_code` does not resolve references."
    )
}

fn function_like_macro_query(language: Language, identifier: &str) -> String {
    serde_json::json!({
        "languages": [language.config_label()],
        "match": { "kind": "call", "callee": { "name": identifier } }
    })
    .to_string()
}

fn scan_usages_language_name(language: Language) -> &'static str {
    match language {
        Language::None => "this language",
        Language::Java => "Java",
        Language::Go => "Go",
        Language::Cpp => "C/C++",
        Language::JavaScript => "JavaScript",
        Language::TypeScript => "TypeScript",
        Language::Python => "Python",
        Language::Rust => "Rust",
        Language::Php => "PHP",
        Language::Scala => "Scala",
        Language::CSharp => "C#",
        Language::Ruby => "Ruby",
    }
}

fn scan_usages_anchor_not_found_input(
    input: impl Into<String>,
    anchor: &str,
    name: &str,
    resolved_targets: &[CodeUnit],
) -> NotFoundInput {
    if resolved_targets
        .iter()
        .all(|target| language_for_target(target) == Language::Cpp && target.is_macro())
        && !resolved_targets.is_empty()
    {
        let target = &resolved_targets[0];
        return not_found_input(
            input,
            Some(format!(
                "`{name}` has no definition in `{anchor}`. It resolves elsewhere as a C/C++ macro, which `scan_usages` cannot resolve. {}",
                unsupported_target_shape_guidance(Some(target)),
            )),
        );
    }

    anchor_not_found_input(input, anchor, name)
}

fn character_column_for_byte(source: &str, line: usize, byte: usize) -> Option<usize> {
    if line == 0 || byte > source.len() || !source.is_char_boundary(byte) {
        return None;
    }
    let line_starts = compute_line_starts(source);
    let line_start = *line_starts.get(line - 1)?;
    let line_end = line_starts.get(line).copied().unwrap_or(source.len());
    let slice = source.get(line_start..byte.min(line_end))?;
    Some(slice.chars().count() + 1)
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
            return ScanUsageTargetResolution::NotFound(file_not_found_input(format!(
                "{} ({path} does not resolve to a workspace file)",
                scan_usages_target_label(&target)
            )));
        }
    };

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

    if target.column == Some(0) {
        return location_selector_failure(
            &target,
            "invalid_location",
            scan_usages_location_diagnostic(&target, &source, "column must be 1-based"),
        );
    }

    let line_starts = compute_line_starts(&source);
    let line = target.line;
    if line == 0 || line > line_starts.len() {
        return location_selector_failure(
            &target,
            "invalid_location",
            scan_usages_location_diagnostic(
                &target,
                &source,
                &format!(
                    "line {line} is outside 1..={} for this file",
                    line_starts.len()
                ),
            ),
        );
    }
    let selection = if let Some(column) = target.column {
        let line_start = line_starts[line - 1];
        let line_end = line_starts.get(line).copied().unwrap_or(source.len());
        match crate::analyzer::usages::get_definition::byte_offset_for_character_column(
            &source, line_start, line_end, line, column,
        ) {
            Ok(point) => ScanUsagesLocationSelection::Point(point),
            Err(reason) => {
                return location_selector_failure(
                    &target,
                    "invalid_location",
                    scan_usages_location_diagnostic(&target, &source, &reason),
                );
            }
        }
    } else {
        ScanUsagesLocationSelection::Line(line)
    };

    let selector = match target.symbol.as_deref() {
        None => None,
        Some(symbol) => match split_definition_selector(symbol) {
            DefinitionSelector::Name(name) => Some(name),
            DefinitionSelector::FileAnchored { anchor, lookup } => {
                let anchor_file = match resolver.resolve_literal(&anchor) {
                    ResolvedFileInput::File(file) => file,
                    ResolvedFileInput::Ambiguous(item) => {
                        return location_selector_failure(
                            &target,
                            "ambiguous_path",
                            format!(
                                "selector anchor `{}` is ambiguous; matches: {}",
                                item.input,
                                item.matches.join(", ")
                            ),
                        );
                    }
                    ResolvedFileInput::NotFound(path) => {
                        return ScanUsageTargetResolution::NotFound(not_found_input(
                            scan_usages_target_label(&target),
                            Some(format!(
                                "selector anchor `{path}` does not resolve to a workspace file"
                            )),
                        ));
                    }
                };
                if anchor_file != file {
                    return ScanUsageTargetResolution::NotFound(not_found_input(
                        scan_usages_target_label(&target),
                        Some(format!(
                            "selector anchor `{anchor}` does not match target path `{}`",
                            rel_path_string(&file)
                        )),
                    ));
                }
                Some(lookup)
            }
        },
    };

    let range_context = DeclarationNameRangeContext::new(&file, source);

    let matching_units: Vec<(CodeUnit, usize)> = declarations_in_file(analyzer, &file)
        .into_iter()
        .filter_map(|unit| {
            let selector_matches = selector.is_some_and(|symbol| {
                unit.fq_name() == symbol
                    || definition_selector(&unit) == symbol
                    || display_symbol_for_target(&unit) == symbol
            });
            let ranges = if selector_matches && unit.is_module() {
                analyzer.ranges_of(&unit)
            } else if selector_matches || selector.is_none() {
                range_context.name_ranges(analyzer, &unit)
            } else {
                return None;
            };
            let best_span = ranges
                .into_iter()
                .filter(|range| scan_usages_target_matches_range(selection, *range))
                .map(|range| range.end_byte.saturating_sub(range.start_byte))
                .min()?;
            Some((unit, best_span))
        })
        .collect();

    if matching_units.is_empty() && selector.is_none() {
        return ScanUsageTargetResolution::NotFound(not_found_input(
            scan_usages_target_label(&target),
            Some(scan_usages_location_diagnostic(
                &target,
                range_context.content(),
                "no declaration at location",
            )),
        ));
    }

    if matching_units.is_empty()
        && let Some(symbol) = target.symbol.as_deref()
    {
        return ScanUsageTargetResolution::NotFound(not_found_input(
            scan_usages_target_label(&target),
            Some(scan_usages_location_diagnostic(
                &target,
                range_context.content(),
                &format!("no declaration matching selector `{symbol}` at location"),
            )),
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

    // A source-backed synthetic identity may intentionally share its declaration
    // name range with the source declaration that owns it. Scala primary
    // constructors are the current example: `class Service(value: String)`
    // defines both the `Service` type and a synthetic `Service.Service`
    // constructor at the `Service` token. A plain location target selects the
    // source declaration, while an explicit `symbol` selector can still request
    // the synthetic identity.
    if selector.is_none() && matches.iter().any(|unit| !unit.is_synthetic()) {
        matches.retain(|unit| !unit.is_synthetic());
    }

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
            ScanUsagesSurface::Location,
            label.clone(),
            label,
            groups,
            "Ambiguous location; refine the line/column target.",
        ));
    }

    let (_, overloads) = groups.into_iter().next().expect("non-empty target groups");
    let symbol = definition_selector(&overloads[0]);
    ScanUsageTargetResolution::Resolved { symbol, overloads }
}

fn scan_usages_location_diagnostic(
    target: &ScanUsagesTarget,
    source: &str,
    reason: &str,
) -> String {
    render_location_diagnostic(
        source,
        &target.path,
        target.line,
        target.column,
        reason,
        "move the target to a declaration name token and retry scan_usages_by_location; use get_summaries on the file or search_symbols if the declaration location is unknown.",
    )
}

fn declarations_in_file(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Vec<CodeUnit> {
    let mut declarations: Vec<CodeUnit> = analyzer
        .get_declarations(file)
        .into_iter()
        .filter(|unit| unit.source() == file)
        .collect();
    let mut stack = declarations.clone();
    while let Some(unit) = stack.pop() {
        for child in analyzer.get_members_in_class(&unit) {
            if child.source() != file {
                continue;
            }
            stack.push(child.clone());
            declarations.push(child);
        }
    }
    declarations
}

fn scan_usages_target_matches_range(selection: ScanUsagesLocationSelection, range: Range) -> bool {
    match selection {
        ScanUsagesLocationSelection::Point(point) => {
            range.start_byte <= point && range.end_byte > point
        }
        ScanUsagesLocationSelection::Line(line) => {
            let zero_based_line = line - 1;
            range.start_line <= zero_based_line && range.end_line >= zero_based_line
        }
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
            (!outcome.definitions.is_empty()
                && outcome
                    .definitions
                    .iter()
                    .any(|definition| overloads.contains(definition))
                || (outcome.definitions.is_empty()
                    && unresolved_hit_matches_target_shape(analyzer, overloads, &hit)))
            .then_some(hit)
        })
        .collect()
}

fn resolved_usage_definition(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
) -> Option<ResolvedUsageDefinition> {
    overloads
        .iter()
        .filter_map(|unit| {
            let range = primary_range(analyzer, unit)?;
            Some((unit, range))
        })
        .min_by(|(left, left_range), (right, right_range)| {
            rel_path_string(left.source())
                .cmp(&rel_path_string(right.source()))
                .then_with(|| left_range.start_line.cmp(&right_range.start_line))
                .then_with(|| left_range.start_byte.cmp(&right_range.start_byte))
                .then_with(|| left.fq_name().cmp(&right.fq_name()))
        })
        .map(|(unit, range)| ResolvedUsageDefinition {
            fq_name: unit.fq_name(),
            path: rel_path_string(unit.source()),
            line: range.start_line,
        })
}

fn unresolved_hit_matches_target_shape(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    hit: &UsageHit,
) -> bool {
    let hit_is_member_access = usage_hit_is_member_access(hit);
    overloads.iter().any(|unit| {
        declaration_is_member_access(analyzer, unit)
            .map(|is_member| is_member == hit_is_member_access)
            .unwrap_or(true)
    })
}

fn usage_hit_is_member_access(hit: &UsageHit) -> bool {
    source_has_dot_before(hit.file.read_to_string().ok().as_deref(), hit.start_offset)
}

fn declaration_is_member_access(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<bool> {
    let range = primary_range(analyzer, unit)?;
    let source = unit.source().read_to_string().ok()?;
    let identifier_offset = source
        .get(range.start_byte..range.end_byte)?
        .find(unit.identifier())
        .map(|offset| range.start_byte + offset)?;
    Some(source_has_dot_before(Some(&source), identifier_offset))
}

fn source_has_dot_before(source: Option<&str>, byte: usize) -> bool {
    let Some(source) = source else {
        return false;
    };
    source
        .get(..byte.min(source.len()))
        .and_then(|prefix| prefix.chars().rev().find(|ch| !ch.is_whitespace()))
        == Some('.')
}

fn present_reference_only_sibling_extensions_by_language(
    analyzer: &dyn IAnalyzer,
) -> BTreeMap<Language, Vec<&'static str>> {
    let mut present = BTreeMap::new();
    let Ok(files) = analyzer.project().all_files() else {
        return present;
    };

    let mut workspace_extensions = HashSet::default();
    for file in files {
        if let Some(extension) = file
            .rel_path()
            .extension()
            .and_then(|extension| extension.to_str())
        {
            workspace_extensions.insert(extension.to_ascii_lowercase());
        }
    }

    for language in Language::ANALYZABLE {
        let language_present = language
            .reference_only_sibling_extensions()
            .iter()
            .copied()
            .filter(|extension| workspace_extensions.contains(*extension))
            .collect::<Vec<_>>();
        if !language_present.is_empty() {
            present.insert(language, language_present);
        }
    }

    present
}

fn reference_only_absence_note(
    overloads: &[CodeUnit],
    present_by_language: &BTreeMap<Language, Vec<&'static str>>,
) -> Option<String> {
    let language = overloads.first().map(language_for_target)?;
    let extensions = present_by_language.get(&language)?;
    let extension_list = extensions
        .iter()
        .map(|extension| format!(".{extension}"))
        .collect::<Vec<_>>()
        .join("/");
    Some(format!(
        "workspace contains {extension_list} files that may reference this symbol but are not analyzed; inspect or analyze those files separately before concluding absence"
    ))
}

pub fn scan_usages_by_reference(
    analyzer: &dyn IAnalyzer,
    params: ScanUsagesByReferenceParams,
) -> ScanUsagesResult {
    let symbols = params
        .symbols
        .into_iter()
        .enumerate()
        .map(|(index, symbol)| ScanUsageRequest::symbol(index, symbol))
        .collect();
    scan_usages_backend(
        analyzer,
        ScanUsagesSurface::Reference,
        params.include_tests,
        params.paths.as_deref(),
        symbols,
        Vec::new(),
    )
}

pub fn scan_usages_by_location(
    analyzer: &dyn IAnalyzer,
    params: ScanUsagesByLocationParams,
) -> ScanUsagesResult {
    let targets = params
        .targets
        .into_iter()
        .enumerate()
        .map(|(index, target)| ScanUsageRequest::target(index, target))
        .collect();
    scan_usages_backend(
        analyzer,
        ScanUsagesSurface::Location,
        params.include_tests,
        params.paths.as_deref(),
        Vec::new(),
        targets,
    )
}

fn scan_usages_backend(
    analyzer: &dyn IAnalyzer,
    surface: ScanUsagesSurface,
    include_tests: bool,
    paths: Option<&[String]>,
    symbols: Vec<ScanUsageRequest>,
    targets: Vec<ScanUsageRequest>,
) -> ScanUsagesResult {
    let _scope = profiling::scope("searchtools::scan_usages_backend");

    let query_scope = ScanUsagesQueryScope::new(analyzer, paths, include_tests);
    let reference_only_sibling_extensions =
        present_reference_only_sibling_extensions_by_language(analyzer);

    // When the caller scopes the query to `paths`, the answer can only live in those files, so
    // resolve the candidate set straight from them instead of enumerating references across the
    // whole workspace and filtering after the fact. This bounds the search by the number of
    // `paths`, not by how common the symbols are — a single high-fan-in name (`Context`, `func`)
    // no longer drags an O(workspace) reference scan behind it. The set is built once and reused
    // for every symbol; the finder's file filter still drops excluded test files on top.
    let path_scoped_candidates = query_scope.path_filter.as_ref().map(|filter| {
        let files: HashSet<ProjectFile> = analyzer
            .analyzed_files()
            .into_iter()
            .filter(|file| filter.matches(file))
            .collect();
        ExplicitCandidateProvider::new(Arc::new(files))
    });

    let test_files = excluded_test_files(analyzer, include_tests);

    let mut work_entries = Vec::new();
    let mut resolved_targets = Vec::new();

    let resolver = WorkspaceFileResolver::new(analyzer.project());
    for request in targets {
        let target = match &request.input {
            ScanUsagesInput::Target(target) => target.clone(),
            ScanUsagesInput::Symbol(_) => unreachable!("target request has target input"),
        };
        match resolve_scan_usages_target(analyzer, &resolver, target) {
            ScanUsageTargetResolution::Resolved { symbol, overloads } => {
                resolved_targets.push(IndexedResolvedScanTarget {
                    request,
                    symbol,
                    overloads,
                    location_selected: true,
                });
            }
            ScanUsageTargetResolution::NotFound(item) => {
                work_entries.push(ScanUsagesWorkEntry::NotFound { request, item });
            }
            ScanUsageTargetResolution::Ambiguous(item) => {
                work_entries.push(ScanUsagesWorkEntry::Ambiguous { request, item });
            }
            ScanUsageTargetResolution::Failure(failure) => {
                work_entries.push(ScanUsagesWorkEntry::Failure { request, failure });
            }
        }
    }

    for request in symbols {
        let symbol = request.label.clone();
        if symbol.trim().is_empty() {
            work_entries.push(ScanUsagesWorkEntry::NotFound {
                request,
                item: NotFoundInput {
                    input: symbol,
                    note: Some("symbol must not be empty".to_string()),
                },
            });
            continue;
        }
        let (anchor, lookup) = match split_definition_selector(&symbol) {
            DefinitionSelector::Name(name) => (None, name),
            DefinitionSelector::FileAnchored { anchor, lookup } => (Some(anchor), lookup),
        };
        let overloads = match resolve_codeunit_fuzzy(analyzer, lookup) {
            CodeUnitResolution::Resolved(overloads) => overloads,
            CodeUnitResolution::Ambiguous(candidate_targets) => {
                let groups = distinct_definitions(candidate_targets);
                let item = ambiguous_usage_symbol_from_groups(
                    analyzer,
                    ScanUsagesSurface::Reference,
                    symbol.clone(),
                    symbol,
                    groups,
                    "Ambiguous; re-call scan_usages_by_reference with one symbol from candidate_targets.",
                );
                work_entries.push(ScanUsagesWorkEntry::Ambiguous { request, item });
                continue;
            }
            CodeUnitResolution::NotFound => {
                let item = unsupported_path_qualified_scan_symbol(&resolver, &symbol)
                    .unwrap_or_else(|| {
                        path_like_symbol_not_found_input(
                            symbol.clone(),
                            PathLikeSymbolGuidanceContext::ScanUsages,
                        )
                    });
                work_entries.push(ScanUsagesWorkEntry::NotFound { request, item });
                continue;
            }
        };

        let overloads = match anchor {
            // A file-anchored selector picks one definition from a prior
            // ambiguous result; narrow to that file before scanning.
            Some(anchor) => {
                let not_found =
                    scan_usages_anchor_not_found_input(symbol.clone(), &anchor, lookup, &overloads);
                let narrowed: Vec<CodeUnit> = overloads
                    .into_iter()
                    .filter(|unit| rel_path_string(unit.source()) == anchor)
                    .collect();
                let narrowed = prefer_exact_lookup_matches(narrowed, lookup);
                if narrowed.is_empty() {
                    work_entries.push(ScanUsagesWorkEntry::NotFound {
                        request,
                        item: not_found,
                    });
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
                    let item = ambiguous_usage_symbol_from_groups(
                        analyzer,
                        ScanUsagesSurface::Reference,
                        symbol.clone(),
                        symbol,
                        groups,
                        "Ambiguous; re-call scan_usages_by_reference with one symbol from candidate_targets.",
                    );
                    work_entries.push(ScanUsagesWorkEntry::Ambiguous { request, item });
                    continue;
                }
                groups.into_iter().flat_map(|(_, units)| units).collect()
            }
        };

        resolved_targets.push(IndexedResolvedScanTarget {
            request,
            symbol,
            overloads,
            location_selected: false,
        });
    }

    for resolved in resolved_targets {
        let IndexedResolvedScanTarget {
            request,
            symbol,
            overloads,
            location_selected,
        } = resolved;
        let resolved_definition = resolved_usage_definition(analyzer, &overloads);
        let target_is_method = overloads
            .iter()
            .any(|unit| unit.is_function() && display_parent_symbol_for_target(unit).is_some());
        let finder = scoped_usage_finder(test_files.as_ref(), query_scope.path_filter.as_ref());
        let max_candidate_files = if path_scoped_candidates.is_some() {
            SCAN_USAGES_PATH_SCOPED_MAX_FILES
        } else {
            DEFAULT_MAX_FILES
        };
        let query = finder.query_with_provider(
            analyzer,
            &overloads,
            path_scoped_candidates
                .as_ref()
                .map(|provider| provider as &dyn CandidateFileProvider),
            max_candidate_files,
            SCAN_USAGES_MAX_CALLSITES,
        );
        let truncated = query.candidate_files_truncated;
        let candidate_files_sample =
            query
                .candidate_files_sample
                .as_ref()
                .map(|sample| ScanUsagesCandidateFilesSample {
                    scanned: sample.scanned.iter().map(rel_path_string).collect(),
                    omitted: sample.omitted.iter().map(rel_path_string).collect(),
                    omitted_count: sample.omitted_count,
                });

        match query.result {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
            } => {
                let hits: Vec<UsageHit> = hits_by_overload
                    .into_values()
                    .flat_map(BTreeSet::into_iter)
                    .collect();
                let filtered = filter_and_dedupe_hits(analyzer, &overloads, hits);
                let unproven_total = unproven_total_by_overload.values().sum();
                let unproven_hits: Vec<UsageHit> = unproven_by_overload
                    .into_values()
                    .flat_map(BTreeSet::into_iter)
                    .collect();
                let filtered_unproven = filter_and_dedupe_hits(analyzer, &overloads, unproven_hits);

                let state = SymbolUsageRenderState::new(
                    symbol,
                    resolved_definition.clone(),
                    truncated,
                    filtered.definition_sites_excluded,
                    filtered.hits,
                    unproven_total,
                    filtered_unproven.hits,
                    None,
                    reference_only_absence_note(&overloads, &reference_only_sibling_extensions),
                );
                work_entries.push(ScanUsagesWorkEntry::Usage {
                    request,
                    state,
                    candidate_files_sample,
                    target_is_method,
                });
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
                    let state = SymbolUsageRenderState::new(
                        symbol,
                        resolved_definition.clone(),
                        truncated,
                        filtered.definition_sites_excluded,
                        filtered.hits,
                        0,
                        Vec::new(),
                        None,
                        reference_only_absence_note(&overloads, &reference_only_sibling_extensions),
                    );
                    work_entries.push(ScanUsagesWorkEntry::Usage {
                        request,
                        state,
                        candidate_files_sample,
                        target_is_method,
                    });
                    continue;
                }
                let groups = distinct_definitions(candidate_targets.iter().cloned().collect());
                let surface = request.surface;
                let detail_source = ambiguous_usage_symbol_from_groups(
                    analyzer,
                    surface,
                    symbol.clone(),
                    short_name.clone(),
                    groups.clone(),
                    scan_usages_ambiguity_note(surface),
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
                let item = AmbiguousUsageSymbol {
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
                };
                work_entries.push(ScanUsagesWorkEntry::Ambiguous { request, item });
            }
            FuzzyResult::Failure { fq_name, reason } => {
                let diagnostic = query.graph_failure.as_ref();
                let reason_kind = diagnostic
                    .map(|diagnostic| diagnostic.reason_kind.clone())
                    .unwrap_or_default();
                let reason = if reason_kind == "unsupported_target_shape" {
                    unsupported_target_shape_message(overloads.first())
                } else {
                    reason
                };
                let failure = UsageFailureInfo {
                    symbol,
                    fq_name,
                    hint: usage_failure_hint(
                        request.surface,
                        &reason_kind,
                        overloads.first(),
                        location_selected,
                        truncated,
                    ),
                    reason_kind,
                    reason,
                    candidate_files_truncated: truncated,
                    candidate_files_sample,
                };
                work_entries.push(ScanUsagesWorkEntry::Failure { request, failure });
            }
            FuzzyResult::TooManyCallsites {
                short_name,
                total_callsites,
                limit,
                sample_hits,
            } => {
                let filtered =
                    filter_and_dedupe_hits(analyzer, &overloads, sample_hits.into_iter().collect());
                let state = SymbolUsageRenderState::partial_summary(
                    symbol.clone(),
                    resolved_definition.clone(),
                    total_callsites,
                    truncated,
                    filtered.definition_sites_excluded,
                    filtered.hits,
                    0,
                    Vec::new(),
                    Some(too_many_callsites_summary_note(limit)),
                    reference_only_absence_note(&overloads, &reference_only_sibling_extensions),
                );
                work_entries.push(ScanUsagesWorkEntry::TooManyCallsites {
                    request,
                    state,
                    short_name,
                    total_callsites,
                    limit,
                    target_is_method,
                });
            }
        }
    }

    work_entries.sort_by_key(ScanUsagesWorkEntry::index);
    render_scan_usages_with_budget(work_entries, query_scope.result_scope(), surface)
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
/// Edges reuse the same graph-backed resolution path as `scan_usages` and the
/// same definition-site exclusion, so a
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

    let path_filter = build_scan_usages_path_filter(analyzer, params.paths.as_deref()).filter;
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
        if unit.is_synthetic() || !(unit.is_class() || unit.is_callable()) {
            continue;
        }
        let ecosystem = Ecosystem::of(language_for_target(&unit));
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
        let _scope = profiling::scope("usage_graph::resolve_ruby");
        let ruby_edges = crate::analyzer::usages::ruby_graph::build_ruby_usage_edges(
            analyzer,
            ecosystem_fqns(Ecosystem::Ruby),
            keep_file,
        );
        record_inverted(
            Ecosystem::Ruby,
            ruby_edges,
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
    kind: UsageHitKind,
    snippet: String,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct ResolvedUsageDefinition {
    fq_name: String,
    path: String,
    line: usize,
}

#[derive(Debug, Clone)]
struct SummaryFileCount {
    path: String,
    hits: usize,
}

#[derive(Debug, Clone)]
struct SymbolUsageRenderState {
    symbol: String,
    fq_name: Option<String>,
    definition_path: Option<String>,
    definition_line: Option<usize>,
    total_hits: usize,
    unproven_hits: usize,
    candidate_files_truncated: bool,
    definition_sites_excluded: usize,
    hits: Vec<UsageHitRow>,
    unproven_rows: Vec<UsageHitRow>,
    summary_files: Vec<SummaryFileCount>,
    top_enclosing: Vec<UsageEnclosingCount>,
    base_note: Option<String>,
    reference_only_absence_note: Option<String>,
    rendering: UsageRendering,
    file_limit: Option<usize>,
    top_enclosing_limit: usize,
}

impl SymbolUsageRenderState {
    #[allow(clippy::too_many_arguments)]
    fn new(
        symbol: String,
        resolved_definition: Option<ResolvedUsageDefinition>,
        candidate_files_truncated: bool,
        definition_sites_excluded: usize,
        hits: Vec<UsageHitRow>,
        unproven_hits: usize,
        unproven_rows: Vec<UsageHitRow>,
        base_note: Option<String>,
        reference_only_absence_note: Option<String>,
    ) -> Self {
        let total_hits = hits.len();
        let clustered_line_rows = clustered_usage_line_row_count(&hits);
        let rendering = if total_hits <= 10 {
            UsageRendering::Full
        } else if clustered_line_rows <= 100 {
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
            fq_name: resolved_definition
                .as_ref()
                .map(|definition| definition.fq_name.clone()),
            definition_path: resolved_definition
                .as_ref()
                .map(|definition| definition.path.clone()),
            definition_line: resolved_definition.map(|definition| definition.line),
            total_hits,
            unproven_hits,
            candidate_files_truncated,
            definition_sites_excluded,
            hits,
            unproven_rows,
            summary_files,
            top_enclosing,
            base_note,
            reference_only_absence_note,
            rendering,
            file_limit,
            top_enclosing_limit: SCAN_USAGES_TOP_ENCLOSING_LIMIT,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn partial_summary(
        symbol: String,
        resolved_definition: Option<ResolvedUsageDefinition>,
        total_hits: usize,
        candidate_files_truncated: bool,
        definition_sites_excluded: usize,
        hits: Vec<UsageHitRow>,
        unproven_hits: usize,
        unproven_rows: Vec<UsageHitRow>,
        base_note: Option<String>,
        reference_only_absence_note: Option<String>,
    ) -> Self {
        let mut state = Self::new(
            symbol,
            resolved_definition,
            candidate_files_truncated,
            definition_sites_excluded,
            hits,
            unproven_hits,
            unproven_rows,
            base_note,
            reference_only_absence_note,
        );
        state.total_hits = total_hits;
        state.rendering = UsageRendering::Summary;
        state.file_limit = (state.summary_files.len() > SCAN_USAGES_SUMMARY_FILE_LIMIT)
            .then_some(SCAN_USAGES_SUMMARY_FILE_LIMIT);
        state
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

    let mut rows: BTreeMap<(String, usize, String, UsageHitKind), UsageHitRow> = BTreeMap::new();
    let mut definition_sites_excluded = 0usize;
    for hit in hits {
        // Import and self-receiver hits are for editor references, not the
        // call-graph/relevance rendering here.
        if !hit.kind.included_in(UsageHitSurface::ExternalUsages) {
            continue;
        }
        if hit.kind == UsageHitKind::Reference
            && definition_ranges
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
            kind: hit.kind,
            snippet: hit.snippet.trim_end().to_string(),
            confidence: hit.confidence,
        };
        let key = (path, hit.line, enclosing, hit.kind);
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
    entries: Vec<ScanUsagesWorkEntry>,
    scope: ScanUsagesScope,
    surface: ScanUsagesSurface,
) -> ScanUsagesResult {
    let mut entries = entries;
    loop {
        let results: Vec<ScanUsagesEntry> =
            entries.iter().map(classify_scan_usages_entry).collect();
        let summary = build_scan_usages_summary(&results);
        let result = ScanUsagesResult {
            surface,
            scope: scope.clone(),
            summary,
            results,
        };
        if serde_json::to_string(&result)
            .map(|text| text.len() <= SCAN_USAGES_RESPONSE_BUDGET_BYTES)
            .unwrap_or(true)
        {
            return result;
        }

        if !demote_largest_scan_usage_entry(&mut entries)
            && !truncate_largest_summary_scan_usage_entry(&mut entries)
        {
            return result;
        }
    }
}

fn build_scan_usages_summary(results: &[ScanUsagesEntry]) -> ScanUsagesSummary {
    let requested = results.len();
    let found = scan_usages_status_count(results, ScanUsagesStatus::Found);
    let verified_absent = scan_usages_status_count(results, ScanUsagesStatus::VerifiedAbsent);
    let unverified_absent = scan_usages_status_count(results, ScanUsagesStatus::UnverifiedAbsent);
    let not_found = scan_usages_status_count(results, ScanUsagesStatus::NotFound);
    let ambiguous = scan_usages_status_count(results, ScanUsagesStatus::Ambiguous);
    let failure = scan_usages_status_count(results, ScanUsagesStatus::Failure);
    let too_many_callsites = scan_usages_status_count(results, ScanUsagesStatus::TooManyCallsites);
    let resolved = results
        .iter()
        .filter(|entry| {
            matches!(
                entry.status,
                ScanUsagesStatus::Found
                    | ScanUsagesStatus::VerifiedAbsent
                    | ScanUsagesStatus::UnverifiedAbsent
                    | ScanUsagesStatus::TooManyCallsites
            )
        })
        .count();
    let total_hits = results
        .iter()
        .filter_map(|entry| match entry.status {
            ScanUsagesStatus::Found => entry.total_hits,
            ScanUsagesStatus::TooManyCallsites => entry.total_callsites,
            _ => None,
        })
        .sum();
    let partial = results.iter().any(|entry| !entry.complete);
    ScanUsagesSummary {
        requested,
        resolved,
        total_hits,
        partial,
        found,
        verified_absent,
        unverified_absent,
        not_found,
        ambiguous,
        failure,
        too_many_callsites,
    }
}

fn scan_usages_status_count(results: &[ScanUsagesEntry], status: ScanUsagesStatus) -> usize {
    results
        .iter()
        .filter(|entry| entry.status == status)
        .count()
}

fn classify_scan_usages_entry(entry: &ScanUsagesWorkEntry) -> ScanUsagesEntry {
    match entry {
        ScanUsagesWorkEntry::Usage {
            request,
            state,
            candidate_files_sample,
            target_is_method,
        } => {
            let usage = render_symbol_usages(state);
            classify_usage_entry(
                request,
                usage,
                candidate_files_sample.clone(),
                false,
                None,
                *target_is_method,
            )
        }
        ScanUsagesWorkEntry::TooManyCallsites {
            request,
            state,
            short_name,
            total_callsites,
            limit,
            target_is_method,
        } => {
            let usage = render_symbol_usages(state);
            classify_usage_entry(
                request,
                usage,
                None,
                true,
                Some((short_name.clone(), *total_callsites, *limit)),
                *target_is_method,
            )
        }
        ScanUsagesWorkEntry::NotFound { request, item } => {
            let mut result = scan_usages_entry_base(request, ScanUsagesStatus::NotFound, true);
            result.message = Some(match item.note.as_deref() {
                Some(note) => format!("{}: {note}", item.input),
                None => item.input.clone(),
            });
            result
        }
        ScanUsagesWorkEntry::Ambiguous { request, item } => {
            let mut result = scan_usages_entry_base(request, ScanUsagesStatus::Ambiguous, true);
            result.symbol = Some(item.symbol.clone());
            result.short_name = Some(item.short_name.clone());
            result.candidate_targets = item.candidate_targets.clone();
            result.candidate_details = item.candidate_details.clone();
            result.candidate_details_total = item.candidate_details_total;
            result.candidate_details_truncated = item.candidate_details_truncated;
            result.candidates = item.candidates.clone();
            result.definition_sites_excluded = item.definition_sites_excluded;
            result.complete = !item.candidate_files_truncated;
            result.message = Some(item.note.clone().unwrap_or_else(|| {
                match request.surface {
                    ScanUsagesSurface::Reference => "Ambiguous; re-call scan_usages_by_reference with one symbol from candidate_targets.".to_string(),
                    ScanUsagesSurface::Location => "Ambiguous location; refine the line/column target and re-call scan_usages_by_location.".to_string(),
                }
            }));
            result
        }
        ScanUsagesWorkEntry::Failure { request, failure } => {
            let mut result = scan_usages_entry_base(
                request,
                ScanUsagesStatus::Failure,
                !failure.candidate_files_truncated,
            );
            result.symbol = Some(failure.symbol.clone());
            result.fq_name = Some(failure.fq_name.clone());
            result.reason_kind = Some(failure.reason_kind.clone());
            result.candidate_files_sample = failure.candidate_files_sample.clone();
            result.message = Some(match failure.hint.as_deref() {
                Some(hint) => format!("{}; {hint}", failure.reason),
                None => failure.reason.clone(),
            });
            result
        }
    }
}

fn classify_usage_entry(
    request: &ScanUsageRequest,
    usage: SymbolUsages,
    candidate_files_sample: Option<ScanUsagesCandidateFilesSample>,
    too_many_callsites: bool,
    callsite_cap: Option<(String, usize, usize)>,
    target_is_method: bool,
) -> ScanUsagesEntry {
    let complete =
        !too_many_callsites && !usage.candidate_files_truncated && usage.files_truncated.is_none();

    if too_many_callsites {
        let (short_name, total_callsites, limit) =
            callsite_cap.expect("too_many_callsites entry includes cap details");
        let mut result = scan_usages_entry_base(request, ScanUsagesStatus::TooManyCallsites, false);
        populate_usage_payload(&mut result, usage, target_is_method, &[], request.surface);
        result.short_name = Some(short_name);
        result.total_callsites = Some(total_callsites);
        result.limit = Some(limit);
        result.message = Some(too_many_callsites_note(limit));
        return result;
    }

    let mut caveats = Vec::new();
    if usage.unproven_hits > 0 {
        caveats.push(ScanUsagesAbsenceCaveat::UnprovenMatches);
    }
    if usage.candidate_files_truncated {
        caveats.push(ScanUsagesAbsenceCaveat::CandidateFilesTruncated);
    }
    if usage.reference_only_siblings {
        caveats.push(ScanUsagesAbsenceCaveat::ReferenceOnlySiblings);
    }

    let status = if usage.total_hits > 0 {
        ScanUsagesStatus::Found
    } else if caveats.is_empty() {
        ScanUsagesStatus::VerifiedAbsent
    } else {
        ScanUsagesStatus::UnverifiedAbsent
    };

    let mut result = scan_usages_entry_base(request, status, complete);
    if usage.candidate_files_truncated {
        result.candidate_files_sample = candidate_files_sample;
    }
    populate_usage_payload(
        &mut result,
        usage,
        target_is_method,
        &caveats,
        request.surface,
    );
    if status == ScanUsagesStatus::UnverifiedAbsent {
        result.absence_caveats = caveats;
    }
    result
}

fn populate_usage_payload(
    entry: &mut ScanUsagesEntry,
    usage: SymbolUsages,
    target_is_method: bool,
    absence_caveats: &[ScanUsagesAbsenceCaveat],
    surface: ScanUsagesSurface,
) {
    let guidance = scan_usages_absence_guidance(
        entry.status,
        target_is_method,
        &usage,
        absence_caveats,
        surface,
    );
    entry.symbol = Some(usage.symbol);
    entry.fq_name = usage.fq_name;
    entry.definition_path = usage.definition_path;
    entry.definition_line = usage.definition_line;
    entry.total_hits = Some(usage.total_hits);
    entry.unproven_hits = Some(usage.unproven_hits);
    entry.rendering = Some(usage.rendering);
    entry.files = usage.files;
    entry.unproven_files = usage.unproven_files;
    entry.top_enclosing = usage.top_enclosing;
    entry.definition_sites_excluded = usage.definition_sites_excluded;
    entry.files_truncated = usage.files_truncated;
    if let Some(note) = usage.note {
        entry.notes.push(note);
    }
    if usage.candidate_files_truncated && entry.status == ScanUsagesStatus::Found {
        entry.notes.push(format!(
            "Candidate file set was truncated; additional usage sites may exist. Re-call {} with narrower `paths` for exhaustive coverage.",
            surface.tool_name()
        ));
    }
    if entry.message.is_none() {
        entry.message = guidance.message;
    }
    entry.notes.extend(guidance.notes);
}

struct ScanUsagesAbsenceGuidance {
    message: Option<String>,
    notes: Vec<String>,
}

fn scan_usages_absence_guidance(
    status: ScanUsagesStatus,
    target_is_method: bool,
    usage: &SymbolUsages,
    caveats: &[ScanUsagesAbsenceCaveat],
    surface: ScanUsagesSurface,
) -> ScanUsagesAbsenceGuidance {
    let notes = if matches!(
        status,
        ScanUsagesStatus::VerifiedAbsent | ScanUsagesStatus::UnverifiedAbsent
    ) && target_is_method
    {
        vec!["if this is a framework-invoked entrypoint (e.g. servlet filters, DI callbacks), direct callers may not exist: scan the enclosing type or search for its registration.".to_string()]
    } else {
        Vec::new()
    };
    let message = match status {
        ScanUsagesStatus::VerifiedAbsent => {
            Some("resolved symbol; no external usage sites found.".to_string())
        }
        ScanUsagesStatus::UnverifiedAbsent => {
            scan_usages_unverified_absence_message(usage, caveats, surface)
        }
        _ => None,
    };
    ScanUsagesAbsenceGuidance { message, notes }
}

fn scan_usages_unverified_absence_message(
    usage: &SymbolUsages,
    caveats: &[ScanUsagesAbsenceCaveat],
    surface: ScanUsagesSurface,
) -> Option<String> {
    if usage.unproven_hits > 0 {
        let file_count = usage.unproven_files.len();
        let recovery = match surface {
            ScanUsagesSurface::Reference => {
                "narrow `paths` to a relevant candidate file or choose a more specific exported symbol"
            }
            ScanUsagesSurface::Location => {
                "narrow `paths` to a relevant candidate file or refine the declaration line/column"
            }
        };
        return Some(format!(
            "no PROVEN usage sites, but {} unproven candidate usage(s) found across {} file(s); inspect these before concluding absence. Next step: {recovery} and re-call {}.",
            usage.unproven_hits,
            file_count,
            surface.tool_name()
        ));
    }
    if caveats.contains(&ScanUsagesAbsenceCaveat::CandidateFilesTruncated) {
        return Some(
            "no PROVEN usage sites in the scanned candidate sample; candidate files were truncated, so narrow paths and retry before concluding absence."
                .to_string(),
        );
    }
    None
}

fn scan_usages_entry_base(
    request: &ScanUsageRequest,
    status: ScanUsagesStatus,
    complete: bool,
) -> ScanUsagesEntry {
    ScanUsagesEntry {
        input: request.input.clone(),
        input_kind: request.input_kind,
        status,
        complete,
        symbol: None,
        short_name: None,
        total_hits: None,
        unproven_hits: None,
        rendering: None,
        files: Vec::new(),
        unproven_files: Vec::new(),
        top_enclosing: Vec::new(),
        definition_sites_excluded: None,
        files_truncated: None,
        absence_caveats: Vec::new(),
        notes: Vec::new(),
        message: None,
        candidate_targets: Vec::new(),
        candidate_details: Vec::new(),
        candidate_details_total: None,
        candidate_details_truncated: false,
        candidates: Vec::new(),
        fq_name: None,
        definition_path: None,
        definition_line: None,
        reason_kind: None,
        candidate_files_sample: None,
        total_callsites: None,
        limit: None,
    }
}

fn entry_render_state(entry: &ScanUsagesWorkEntry) -> Option<&SymbolUsageRenderState> {
    match entry {
        ScanUsagesWorkEntry::Usage { state, .. }
        | ScanUsagesWorkEntry::TooManyCallsites { state, .. } => Some(state),
        _ => None,
    }
}

fn entry_render_state_mut(entry: &mut ScanUsagesWorkEntry) -> Option<&mut SymbolUsageRenderState> {
    match entry {
        ScanUsagesWorkEntry::Usage { state, .. }
        | ScanUsagesWorkEntry::TooManyCallsites { state, .. } => Some(state),
        _ => None,
    }
}

fn demote_largest_scan_usage_entry(entries: &mut [ScanUsagesWorkEntry]) -> bool {
    let any_full = entries.iter().any(|entry| {
        entry_render_state(entry).is_some_and(|state| state.rendering == UsageRendering::Full)
    });
    let mut best_index = None;
    let mut best_size = 0usize;
    for (idx, entry) in entries.iter().enumerate() {
        let Some(state) = entry_render_state(entry) else {
            continue;
        };
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
    let state = entry_render_state_mut(&mut entries[idx]).expect("selected render state");
    state.rendering = match state.rendering {
        UsageRendering::Full => UsageRendering::Lines,
        UsageRendering::Lines => UsageRendering::Summary,
        UsageRendering::Summary => UsageRendering::Summary,
    };
    true
}

fn truncate_largest_summary_scan_usage_entry(entries: &mut [ScanUsagesWorkEntry]) -> bool {
    let mut best_index = None;
    let mut best_size = 0usize;
    for (idx, entry) in entries.iter().enumerate() {
        let Some(state) = entry_render_state(entry) else {
            continue;
        };
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
    let state = entry_render_state_mut(&mut entries[idx]).expect("selected render state");
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
            render_clustered_usage_file_groups(&state.hits),
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
            "{} hits; showing line-level callers clustered by enclosing symbol. Snippets are included for low-repeat callers.",
            state.total_hits
        )),
        UsageRendering::Summary => notes.push(format!(
            "{} hits; showing bounded per-file counts instead of line-level callers. Re-call with narrower `paths` or a more specific symbol for line detail.",
            state.total_hits
        )),
    }
    if files_truncated.is_some() {
        notes.push("Summary file list truncated to fit the response budget.".to_string());
    }
    let reference_only_siblings = state.reference_only_absence_note.is_some();
    let absence_would_be_verified =
        !state.candidate_files_truncated && state.total_hits == 0 && state.unproven_hits == 0;
    if absence_would_be_verified && let Some(note) = &state.reference_only_absence_note {
        notes.push(note.clone());
    }

    SymbolUsages {
        symbol: state.symbol.clone(),
        fq_name: state.fq_name.clone(),
        definition_path: state.definition_path.clone(),
        definition_line: state.definition_line,
        total_hits: state.total_hits,
        unproven_hits: state.unproven_hits,
        rendering: state.rendering,
        candidate_files_truncated: state.candidate_files_truncated,
        reference_only_siblings,
        definition_sites_excluded: some_if_nonzero(state.definition_sites_excluded),
        files_truncated,
        note: if notes.is_empty() {
            None
        } else {
            Some(notes.join(" "))
        },
        top_enclosing,
        files,
        unproven_files: render_usage_file_groups(&state.unproven_rows, true),
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
                line_range: None,
                enclosing: hit.enclosing.clone(),
                kind: hit.kind.external_label().map(str::to_string),
                snippet: include_snippets.then(|| hit.snippet.clone()),
                hit_count: None,
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

fn clustered_usage_line_row_count(hits: &[UsageHitRow]) -> usize {
    let mut counts: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for hit in hits {
        *counts
            .entry((hit.path.as_str(), hit.enclosing.as_str()))
            .or_default() += 1;
    }
    counts
        .into_values()
        .map(|count| if count > 2 { 1 } else { count })
        .sum()
}

fn render_clustered_usage_file_groups(hits: &[UsageHitRow]) -> Vec<UsageFileGroup> {
    let mut by_file: BTreeMap<String, BTreeMap<String, Vec<&UsageHitRow>>> = BTreeMap::new();
    for hit in hits {
        by_file
            .entry(hit.path.clone())
            .or_default()
            .entry(hit.enclosing.clone())
            .or_default()
            .push(hit);
    }

    by_file
        .into_iter()
        .map(|(path, enclosing_groups)| {
            let mut rendered_hits = Vec::new();
            for (enclosing, mut group) in enclosing_groups {
                group.sort_by_key(|hit| hit.line);
                if group.len() > 2 {
                    let first = group.first().expect("non-empty group");
                    let last = group.last().expect("non-empty group");
                    let max_confidence = group
                        .iter()
                        .map(|hit| hit.confidence)
                        .fold(0.0_f64, f64::max);
                    rendered_hits.push(UsageLocation {
                        line: first.line,
                        line_range: Some(if first.line == last.line {
                            first.line.to_string()
                        } else {
                            format!("{}-{}", first.line, last.line)
                        }),
                        enclosing,
                        kind: group
                            .iter()
                            .find_map(|hit| hit.kind.external_label())
                            .map(str::to_string),
                        snippet: None,
                        hit_count: Some(group.len()),
                        confidence: max_confidence,
                    });
                } else {
                    rendered_hits.extend(group.into_iter().map(|hit| UsageLocation {
                        line: hit.line,
                        line_range: None,
                        enclosing: hit.enclosing.clone(),
                        kind: hit.kind.external_label().map(str::to_string),
                        snippet: Some(hit.snippet.clone()),
                        hit_count: None,
                        confidence: hit.confidence,
                    }));
                }
            }
            rendered_hits.sort_by(|left, right| {
                left.line
                    .cmp(&right.line)
                    .then_with(|| left.enclosing.cmp(&right.enclosing))
            });
            UsageFileGroup {
                path,
                hits: rendered_hits,
                hit_count: None,
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
struct ScanUsagesPathFilter {
    rules: Vec<ScanUsagesPathRule>,
}

struct BuiltScanUsagesPathFilter {
    filter: Option<Arc<ScanUsagesPathFilter>>,
    ignored_paths: usize,
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

    fn summarized_paths(&self) -> (Vec<String>, Option<usize>) {
        let mut seen = HashSet::default();
        let mut paths = Vec::new();
        let mut unique_count = 0usize;
        for rule in &self.rules {
            let path = match rule {
                ScanUsagesPathRule::Glob(glob) => glob.as_str(),
                ScanUsagesPathRule::Exact(path) => path.as_str(),
            };
            if !seen.insert(path) {
                continue;
            }
            unique_count += 1;
            if paths.len() < SCAN_USAGES_SCOPE_PATH_LIMIT {
                paths.push(truncate_scan_usages_scope_path(path));
            }
        }
        let paths_omitted = unique_count
            .checked_sub(paths.len())
            .and_then(some_if_nonzero);
        (paths, paths_omitted)
    }
}

fn truncate_scan_usages_scope_path(path: &str) -> String {
    if path.len() <= SCAN_USAGES_SCOPE_PATH_MAX_BYTES {
        return path.to_string();
    }
    let mut cut = SCAN_USAGES_SCOPE_PATH_MAX_BYTES;
    while !path.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &path[..cut])
}

fn build_scan_usages_path_filter(
    analyzer: &dyn IAnalyzer,
    paths: Option<&[String]>,
) -> BuiltScanUsagesPathFilter {
    let Some(paths) = paths else {
        return BuiltScanUsagesPathFilter {
            filter: None,
            ignored_paths: 0,
        };
    };
    let resolver = WorkspaceFileResolver::new(analyzer.project());
    let mut rules = Vec::new();
    let mut ignored_paths = 0;
    for raw in paths {
        let normalized = normalize_pattern(raw.trim());
        if normalized.is_empty() {
            ignored_paths += 1;
            continue;
        }
        if is_glob_pattern(&normalized) {
            if let Ok(glob) = Pattern::new(&normalized) {
                rules.push(ScanUsagesPathRule::Glob(glob));
            } else {
                ignored_paths += 1;
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
    BuiltScanUsagesPathFilter {
        filter: (!rules.is_empty()).then(|| Arc::new(ScanUsagesPathFilter { rules })),
        ignored_paths,
    }
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

fn some_if_nonzero(value: usize) -> Option<usize> {
    (value > 0).then_some(value)
}

fn is_true(value: &bool) -> bool {
    *value
}

fn too_many_callsites_note(limit: usize) -> String {
    format!(
        "Stopped after the {limit}-callsite cap for this high-fanout symbol. Re-call with narrower `paths` or a more specific declaration; exhaustive output is intentionally suppressed for this query."
    )
}

fn too_many_callsites_summary_note(limit: usize) -> String {
    format!(
        "Callsite cap exceeded for this high-fanout symbol (limit {limit}); this is an incomplete summary of observed hits before stopping. Re-call with `paths` from the files list for line-level detail."
    )
}

fn is_full_confidence(confidence: &f64) -> bool {
    (*confidence - 1.0).abs() < f64::EPSILON
}

fn rank_search_symbol_candidates(
    analyzer: &dyn IAnalyzer,
    patterns: &[String],
    code_units: Vec<(CodeUnit, Range, bool)>,
) -> Vec<RankedSearchCandidate> {
    let mut ranked: Vec<_> = code_units
        .into_iter()
        .map(
            |(code_unit, primary_range, is_test)| RankedSearchCandidate {
                line: primary_range.start_line,
                score: score_search_symbol_candidate(analyzer, patterns, &code_unit, is_test),
                code_unit,
                primary_range,
            },
        )
        .collect();
    ranked.sort_by(compare_ranked_search_candidates);
    ranked
}

fn score_search_symbol_candidate(
    analyzer: &dyn IAnalyzer,
    patterns: &[String],
    code_unit: &CodeUnit,
    is_test: bool,
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
        source_quality_tier: search_symbol_source_quality_tier(code_unit.source(), is_test),
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

fn search_symbol_source_quality_tier(file: &ProjectFile, is_test: bool) -> u8 {
    if is_generated_like_path(file) {
        return 0;
    }
    if is_test {
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
pub struct ClassifyTestFilesParams {
    pub file_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestFileKind {
    Test,
    TestSupport,
    Production,
    Ambiguous,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestFileClassification {
    pub kind: TestFileKind,
    /// Semantic runnable-test detection for the same file, reported so callers
    /// can separate file-level test surface from files that contain test code.
    pub contains_test_code: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClassifyTestFilesResult {
    pub classifications: BTreeMap<String, TestFileClassification>,
    pub unresolved: Vec<String>,
}

pub fn classify_test_files(
    analyzer: &dyn IAnalyzer,
    params: ClassifyTestFilesParams,
) -> ClassifyTestFilesResult {
    let project = analyzer.project();
    let resolver = WorkspaceFileResolver::new(project);
    let mut classifications = BTreeMap::new();
    let mut unresolved = Vec::new();
    for input in params.file_paths.iter() {
        match resolver.resolve_literal(input.trim()) {
            ResolvedFileInput::File(file) if file.exists() => {
                classifications.insert(
                    rel_path_string(&file),
                    classify_resolved_test_file(analyzer, &file),
                );
            }
            _ => unresolved.push(input.clone()),
        }
    }
    ClassifyTestFilesResult {
        classifications,
        unresolved,
    }
}

fn classify_resolved_test_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> TestFileClassification {
    let path = rel_path_string(file);
    let language = language_for_file(file);
    let path_verdict = test_paths::path_test_verdict(&path);
    let contains_test_code = analyzer.contains_tests(file);
    let test_like = path_verdict == test_paths::PathTestVerdict::TestRoot
        || test_paths::has_test_filename_convention(&path, language);
    let kind = if test_like && contains_test_code {
        TestFileKind::Test
    } else if test_like {
        TestFileKind::TestSupport
    } else if path_verdict == test_paths::PathTestVerdict::ProductionRoot {
        TestFileKind::Production
    } else {
        TestFileKind::Ambiguous
    };
    TestFileClassification {
        kind,
        contains_test_code,
    }
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
    render_context: Option<&DeclarationNameRangeContext>,
) -> Vec<SearchSymbolHit> {
    collect_ranked_names_by(analyzer, code_units, render_context, |unit| {
        unit.kind() == kind
    })
}

fn collect_callable_kind_names(
    analyzer: &dyn IAnalyzer,
    code_units: &[RankedSearchCandidate],
    render_context: Option<&DeclarationNameRangeContext>,
) -> Vec<SearchSymbolHit> {
    collect_ranked_names_by(analyzer, code_units, render_context, CodeUnit::is_callable)
}

fn collect_ranked_names_by(
    analyzer: &dyn IAnalyzer,
    code_units: &[RankedSearchCandidate],
    render_context: Option<&DeclarationNameRangeContext>,
    matches_kind: impl Fn(&CodeUnit) -> bool,
) -> Vec<SearchSymbolHit> {
    let mut hits: Vec<_> = code_units
        .iter()
        .filter(|candidate| matches_kind(&candidate.code_unit))
        .flat_map(|candidate| {
            display_signatures(analyzer, &candidate.code_unit)
                .into_iter()
                .map(move |signature| SearchSymbolHit {
                    symbol: display_symbol_for_target(&candidate.code_unit),
                    signature,
                    line: search_symbol_display_range(analyzer, candidate, render_context)
                        .start_line,
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

fn load_declaration_name_context(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<DeclarationNameRangeContext> {
    let content = analyzer.project().read_source(file).ok()?;
    Some(DeclarationNameRangeContext::new(file, content))
}

fn search_symbol_display_range(
    analyzer: &dyn IAnalyzer,
    candidate: &RankedSearchCandidate,
    render_context: Option<&DeclarationNameRangeContext>,
) -> Range {
    let name_range =
        render_context.and_then(|context| context.name_range(analyzer, &candidate.code_unit));
    if let Some(mut name_range) = name_range {
        name_range.start_line += 1;
        name_range.end_line += 1;
        return name_range;
    }
    candidate.primary_range
}

fn display_range_with_declaration_name(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    name_range: Option<Range>,
) -> Option<Range> {
    let primary = primary_range(analyzer, code_unit)?;
    if let Some(mut name_range) = name_range {
        name_range.start_line += 1;
        name_range.end_line += 1;
        return Some(name_range);
    }
    Some(primary)
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
        preamble: file_preamble(analyzer, code_unit.source(), &elements),
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
            elements.extend(summary_elements_for_code_unit(analyzer, &child));
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
                analyzer, &child, file,
            ));
        }
    }
    elements
}

fn summary_elements_from_file_projection(
    projection: &SummaryFileProjection,
    file: &ProjectFile,
) -> Vec<SummaryElement> {
    let _scope = profiling::scope("searchtools::summary_elements_from_file_projection");
    let mut elements = Vec::new();
    let mut stack: Vec<_> = projection
        .top_level_declarations
        .iter()
        .rev()
        .cloned()
        .collect();
    let mut visited = HashSet::default();

    while let Some(code_unit) = stack.pop() {
        if !visited.insert(code_unit.clone()) {
            continue;
        }
        let signatures = projection
            .signatures
            .get(&code_unit)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let ranges = projection
            .ranges
            .get(&code_unit)
            .map(Vec::as_slice)
            .unwrap_or_default();
        elements.extend(summary_elements_from_signature_data(
            &code_unit, signatures, ranges,
        ));

        if !code_unit.is_class() && !code_unit.is_module() {
            continue;
        }
        if let Some(children) = projection.children.get(&code_unit) {
            stack.extend(
                children
                    .iter()
                    .rev()
                    .filter(|child| !child.is_anonymous() && child.source() == file)
                    .cloned(),
            );
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
        CodeUnitType::FileScope => display_identifier_for_target(code_unit).to_string(),
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
    let ranges = analyzer.ranges(code_unit);
    summary_elements_from_signature_data(code_unit, &signatures, &ranges)
}

fn summary_elements_from_signature_data(
    code_unit: &CodeUnit,
    signatures: &[String],
    ranges: &[Range],
) -> Vec<SummaryElement> {
    if signatures.is_empty() {
        return Vec::new();
    }

    let mut ranges = ranges.to_vec();
    ranges.sort_by_key(|range| (range.start_line, range.start_byte));
    let path = rel_path_string(code_unit.source());
    let fallback_start = ranges.first().map(|range| range.start_line).unwrap_or(1);

    let element_count = if signatures.len() == 1 {
        ranges.len().max(1)
    } else {
        signatures.len()
    };

    (0..element_count)
        .filter_map(|index| {
            let signature = signatures
                .get(index)
                .or_else(|| signatures.first())
                .expect("signatures is not empty");
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
                parent_symbol: display_parent_symbol_for_target(code_unit),
                presentation: None,
            })
        })
        .collect()
}

fn code_unit_kind_name(kind: CodeUnitType) -> &'static str {
    kind.display_lowercase()
}

fn file_preamble(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    elements: &[SummaryElement],
) -> String {
    let Some(first_start_line) = elements.iter().map(|element| element.start_line).min() else {
        return String::new();
    };
    if first_start_line <= 1 {
        return String::new();
    }
    let Ok(content) = analyzer.project().read_source(file) else {
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
    let Some(content) = analyzer.indexed_source(code_unit.source()) else {
        return Vec::new();
    };

    let language = language_for_target(code_unit);

    let mut ranges = if code_unit.is_function() {
        let mut grouped = Vec::new();
        for candidate in analyzer.definitions(&code_unit.fq_name()) {
            if candidate.source() == code_unit.source() {
                grouped.extend(analyzer.ranges(&candidate));
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
            let text = analyzer.render_source_fragment(
                code_unit,
                text,
                range.start_byte.saturating_sub(start_byte),
            );
            let start_line = line_number_at_offset(&content, start_byte);
            Some(SourceBlock {
                label: display_symbol_for_target(code_unit),
                path: rel_path_string(code_unit.source()),
                start_line,
                end_line: start_line + text.lines().count().saturating_sub(1),
                text,
                presentation: None,
                note: None,
            })
        })
        .collect()
}

fn source_blocks_for_files(analyzer: &dyn IAnalyzer, files: Vec<ProjectFile>) -> Vec<SourceBlock> {
    files
        .into_iter()
        .filter_map(|file| {
            if let Some(block) = file_outline_source_block(
                analyzer,
                &file,
                file_outline_source_note(&file),
                None,
                None,
            ) {
                return Some(block);
            }

            if let Some(block) = include_fallback_source_block(analyzer, &file) {
                return Some(block);
            }

            excerpt_fallback_source_block(analyzer, &file)
        })
        .collect()
}

fn file_outline_source_block(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    note: String,
    label: Option<String>,
    presentation: Option<String>,
) -> Option<SourceBlock> {
    let text = analyzer.list_top_level_symbols(file);
    if text.trim().is_empty() {
        return None;
    }
    let end_line = text.lines().count().max(1);
    let path = rel_path_string(file);
    Some(SourceBlock {
        label: label.unwrap_or_else(|| path.clone()),
        path,
        start_line: 1,
        end_line,
        text,
        presentation,
        note: Some(note),
    })
}

fn file_outline_source_note(file: &ProjectFile) -> String {
    if Ecosystem::of(language_for_file(file)).is_module_scoped() {
        "file target: showing a flat outline of top-level symbols, not the full source; pass a symbol name for its full body (for JS/TS module-scoped symbols, use the full relative path selector such as src/plugin/relativeTime/index.js#default), or use get_summaries for structured summaries"
            .to_string()
    } else {
        "file target: showing a flat outline of top-level symbols, not the full source; pass a symbol name for its full body, or use get_summaries for structured summaries"
            .to_string()
    }
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
        note: Some(
            "no indexed declarations found in this file; showing its top-level #include lines, not the full source"
                .to_string(),
        ),
    })
}

fn excerpt_fallback_source_block(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<SourceBlock> {
    let (elements, note) = excerpt_fallback_elements(analyzer, file)?;
    let sampled = elements.into_iter().next()?;
    Some(SourceBlock {
        label: sampled.path.clone(),
        path: sampled.path,
        start_line: sampled.start_line,
        end_line: sampled.end_line,
        text: sampled.text,
        presentation: sampled.presentation,
        note: Some(note),
    })
}

const MAX_MODULE_OUTLINE_FILES: usize = 10;

fn module_file_listing_blocks(
    analyzer: &dyn IAnalyzer,
    code_units: &[CodeUnit],
) -> Vec<SourceBlock> {
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    for code_unit in code_units {
        let mut definitions = analyzer
            .all_declarations()
            .filter(|definition| {
                (definition.is_module() || is_scala_object_like(definition))
                    && definition.fq_name() == code_unit.fq_name()
            })
            .collect::<Vec<_>>();
        if definitions.is_empty() {
            definitions.push(code_unit.clone());
        }
        for definition in definitions {
            let file = definition.source().clone();
            if seen.insert(file.clone()) {
                files.push((file, display_symbol_for_target(code_unit)));
            }
        }
    }

    let omitted = files.len().saturating_sub(MAX_MODULE_OUTLINE_FILES);
    files
        .into_iter()
        .take(MAX_MODULE_OUTLINE_FILES)
        .map(|(file, label)| {
            let note = module_outline_source_note(&file, omitted);
            file_outline_source_block(
                analyzer,
                &file,
                note.clone(),
                Some(label.clone()),
                Some("file_listing".to_string()),
            )
            .unwrap_or_else(|| {
                let path = rel_path_string(&file);
                SourceBlock {
                    label,
                    path,
                    start_line: 1,
                    end_line: 1,
                    text: String::new(),
                    presentation: Some("file_listing".to_string()),
                    note: Some(note),
                }
            })
        })
        .collect()
}

fn module_outline_source_note(file: &ProjectFile, omitted_defining_files: usize) -> String {
    let mut note = if Ecosystem::of(language_for_file(file)).is_module_scoped() {
        "module target: showing an outline of top-level symbols, not a full source body; pass a member symbol using path#symbol for module-scoped JS/TS, or use get_summaries for structured summaries"
            .to_string()
    } else {
        "module target: showing an outline of top-level symbols, not a full source body; pass a member symbol for its full body, or use get_summaries for structured summaries"
            .to_string()
    };
    if omitted_defining_files > 0 {
        note.push_str(&format!(
            "; omitted {omitted_defining_files} additional defining files, so pass a more specific member symbol or file path to target them"
        ));
    }
    note
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
    code_unit.is_module()
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
    let go_modules = OnceLock::new();
    let has_go = analyzer.languages().contains(&Language::Go);
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
            ResolvedFileInput::NotFound(_) => {
                let module_resolution = has_go
                    .then(|| {
                        let modules =
                            go_modules.get_or_init(|| go_module_roots(analyzer.project()));
                        resolve_go_module_prefixed_file(analyzer, modules, &normalized)
                    })
                    .flatten();
                match module_resolution {
                    Some(ResolvedFileInput::File(file)) => {
                        matched.insert(file);
                        continue;
                    }
                    Some(ResolvedFileInput::Ambiguous(item)) => {
                        ambiguous_paths.push(item);
                        continue;
                    }
                    Some(ResolvedFileInput::NotFound(_)) | None => {}
                }
            }
        }

        let directory_matches = resolve_directory_target(analyzer, &normalized);
        if !directory_matches.is_empty() {
            matched.extend(directory_matches);
        }
    }

    if !globs.is_empty() {
        let glob_matches: BTreeSet<_> = analyzer
            .analyzed_files()
            .into_iter()
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

fn resolve_go_module_prefixed_file(
    analyzer: &dyn IAnalyzer,
    modules: &[GoModuleRoot],
    input: &str,
) -> Option<ResolvedFileInput> {
    let longest_prefix = modules
        .iter()
        .filter(|module| {
            input
                .strip_prefix(&module.import_path)
                .is_some_and(|suffix| suffix.starts_with('/'))
        })
        .map(|module| module.import_path.len())
        .max()?;
    let mut matches = modules
        .iter()
        .filter(|module| module.import_path.len() == longest_prefix)
        .filter_map(|module| {
            let suffix = input.strip_prefix(&module.import_path)?.strip_prefix('/')?;
            let suffix = workspace_rel_path(suffix)?;
            analyzer
                .project()
                .file_by_rel_path(&module.workspace_dir.join(&suffix))
        })
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();

    match matches.as_slice() {
        [] => None,
        [file] => Some(ResolvedFileInput::File(file.clone())),
        _ => Some(ResolvedFileInput::Ambiguous(AmbiguousPathInput {
            input: input.to_string(),
            matches: matches.iter().map(rel_path_string).collect(),
        })),
    }
}

fn resolve_directory_target(analyzer: &dyn IAnalyzer, target: &str) -> Vec<ProjectFile> {
    if target == "." {
        return analyzer.analyzed_files().into_iter().collect();
    }
    let normalized = target.trim_end_matches('/');
    let prefix = format!("{normalized}/");
    let fs_matches: Vec<_> = analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| rel_path_string(file).starts_with(&prefix))
        .collect();
    if !fs_matches.is_empty() {
        return fs_matches;
    }

    // No filesystem directory matched: treat the target as a language import/package
    // path (e.g. `github.com/cli/cli/v2/internal/skills/discovery`) and resolve it to
    // the package's files so it rides the same compact "directory inventory" rail as a
    // filesystem directory. Filesystem matches win first, so workspace-relative paths
    // never collide with import paths.
    analyzer
        .definition_lookup_index()
        .package_files_with_prefix(normalized)
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

fn unsupported_selector_shape_guidance(analyzer: &dyn IAnalyzer, input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(anchor) = line_range_anchor_selector(trimmed) {
        return Some(format!(
            "`{}` is a line/range anchor, not a symbol selector. Use get_summaries or `{}` as a file target for an outline, or retry as path#symbol with a real symbol name.",
            anchor.anchor, anchor.file_path
        ));
    }
    let decoded = percent_decode(trimmed);
    if decoded != trimmed
        && let Some(anchor) = line_range_anchor_selector(&decoded)
    {
        return Some(format!(
            "`{trimmed}` contains a URL-encoded line/range anchor; decode it to `{decoded}`. Line/range anchors are not symbol selectors; use get_summaries or `{}` as a file target for an outline, or retry as path#symbol with a real symbol name.",
            anchor.file_path
        ));
    }
    if let Some(note) = invalid_file_anchored_selector_guidance(analyzer, trimmed) {
        return Some(note);
    }
    if selector_ends_with_go_module_scope_segment(trimmed) {
        return Some(format!(
            "`{GO_MODULE_SCOPE_SEGMENT}` is an outline grouping for Go module-scope declarations, not a selectable symbol. Use a file path as a file target for an outline, or select a member as `pkg.{GO_MODULE_SCOPE_SEGMENT}.<name>` or `pkg.<name>`."
        ));
    }
    if let Some(name) = signature_string_selector_name(trimmed) {
        return Some(format!(
            "signature strings are not supported as symbol selectors; retry with the bare function name `{name}`"
        ));
    }
    if let Some((symbol, path)) = malformed_at_joined_selector(trimmed) {
        return Some(format!(
            "`symbol@path` selectors are not supported; retry with the bare symbol `{symbol}` plus the `paths` parameter `{path}`, or use `{path}#{symbol}`"
        ));
    }
    if let Some(PathQualifiedSelector::Resolved {
        anchor: path,
        lookup: symbol,
    }) = dotted_file_symbol_selector(analyzer, trimmed)
    {
        return Some(format!(
            "`{symbol}` is not a symbol in `{path}`; use `{path}` as a file target for an outline, or call get_summaries on `{path}`"
        ));
    }
    if looks_like_absolute_path(trimmed) {
        return Some(absolute_path_selector_guidance(analyzer, trimmed));
    }
    None
}

fn selector_ends_with_go_module_scope_segment(input: &str) -> bool {
    input
        .rsplit_once('.')
        .is_some_and(|(_, segment)| segment == GO_MODULE_SCOPE_SEGMENT)
}

struct LineRangeAnchorSelector<'a> {
    file_path: &'a str,
    anchor: &'a str,
}

fn line_range_anchor_selector(input: &str) -> Option<LineRangeAnchorSelector<'_>> {
    let (file_path, anchor) = input
        .rsplit_once("::")
        .or_else(|| input.rsplit_once('#'))
        .or_else(|| input.rsplit_once(':'))?;
    if file_path.is_empty() || anchor.is_empty() {
        return None;
    }
    is_line_range_anchor(anchor).then_some(LineRangeAnchorSelector { file_path, anchor })
}

fn is_line_range_anchor(anchor: &str) -> bool {
    if let Some(line) = anchor
        .strip_prefix("line ")
        .or_else(|| anchor.strip_prefix("Line "))
    {
        return !line.is_empty() && line.chars().all(|ch| ch.is_ascii_digit());
    }
    let Some((start, end)) = anchor.split_once('-') else {
        return is_line_anchor_part(anchor);
    };
    is_line_anchor_part(start) && is_line_anchor_part(end)
}

fn invalid_file_anchored_selector_guidance(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> Option<String> {
    let (path, selector) = input.split_once('#')?;
    if path.is_empty() || selector.is_empty() {
        return None;
    }
    let file = match WorkspaceFileResolver::new(analyzer.project()).resolve_literal(path) {
        ResolvedFileInput::File(file) => file,
        ResolvedFileInput::Ambiguous(_) | ResolvedFileInput::NotFound(_) => return None,
    };
    let path = rel_path_string(&file);
    if let Some(shorter) = redundant_filename_selector(&file, selector) {
        return Some(format!(
            "`{selector}` redundantly repeats the file name; retry `{path}#{shorter}`"
        ));
    }
    Some(format!(
        "`{selector}` is not a symbol selector for existing file `{path}`; use `{path}` as a file target for an outline, or retry `{path}#<symbol>` with a real symbol name"
    ))
}

fn redundant_filename_selector<'a>(file: &ProjectFile, selector: &'a str) -> Option<&'a str> {
    let filename = file.rel_path().file_name()?.to_str()?;
    selector
        .strip_prefix(filename)?
        .strip_prefix('.')
        .filter(|shorter| !shorter.is_empty())
}

fn looks_like_extensionless_path_anchor(anchor: &str) -> bool {
    let Some(path) = workspace_rel_path(anchor) else {
        return false;
    };
    (anchor.contains('/') || anchor.contains('\\'))
        && path
            .file_name()
            .is_some_and(|name| std::path::Path::new(name).extension().is_none())
}

fn is_line_anchor_part(part: &str) -> bool {
    let digits = part
        .strip_prefix('L')
        .or_else(|| part.strip_prefix('l'))
        .unwrap_or(part);
    !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())
}

fn signature_string_selector_name(input: &str) -> Option<&str> {
    if !input.contains('(') || !input.contains(')') || !input.chars().any(char::is_whitespace) {
        return None;
    }
    let before_paren = input.split_once('(')?.0.trim_end();
    let name_start = before_paren
        .char_indices()
        .rev()
        .find_map(|(index, ch)| (!is_symbol_identifier_char(ch)).then_some(index + ch.len_utf8()))
        .unwrap_or(0);
    let name = before_paren[name_start..].trim();
    (!name.is_empty()).then_some(name)
}

fn is_symbol_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'
}

fn malformed_at_joined_selector(input: &str) -> Option<(&str, &str)> {
    let (symbol, path) = input.split_once('@')?;
    if symbol.is_empty() || path.is_empty() || path.contains('@') {
        return None;
    }
    (looks_like_file_target(path) || path.contains('/') || path.contains('\\'))
        .then_some((symbol, path))
}

fn dotted_file_symbol_selector<'a>(
    analyzer: &dyn IAnalyzer,
    input: &'a str,
) -> Option<PathQualifiedSelector<'a>> {
    let resolver = WorkspaceFileResolver::new(analyzer.project());
    for (separator, _) in input.rmatch_indices('.') {
        let path_candidate = &input[..separator];
        let symbol = &input[separator + 1..];
        if path_candidate.is_empty() || symbol.is_empty() || likely_file_target_extension(symbol) {
            continue;
        }
        match resolver.resolve_literal(path_candidate) {
            ResolvedFileInput::File(file) => {
                return Some(PathQualifiedSelector::Resolved {
                    anchor: rel_path_string(&file),
                    lookup: symbol,
                });
            }
            ResolvedFileInput::Ambiguous(item) => {
                return Some(PathQualifiedSelector::AmbiguousPath(item));
            }
            ResolvedFileInput::NotFound(_) => {}
        }
    }
    None
}

fn looks_like_absolute_path(input: &str) -> bool {
    input.starts_with('/') || input.starts_with('\\') || has_drive_letter_prefix(input)
}

fn absolute_path_selector_guidance(analyzer: &dyn IAnalyzer, input: &str) -> String {
    if let Some(relative_path) = unique_absolute_suffix_match(analyzer, input) {
        return format!(
            "this looks like an absolute path; strip the workspace-root prefix and retry `{relative_path}`"
        );
    }
    "this looks like an absolute path; strip the workspace-root prefix and retry the workspace-relative path".to_string()
}

fn unique_absolute_suffix_match(analyzer: &dyn IAnalyzer, input: &str) -> Option<String> {
    let normalized = normalize_pattern(input);
    let matches: Vec<_> = analyzer
        .analyzed_files()
        .into_iter()
        .map(|file| rel_path_string(&file))
        .filter(|relative| normalized.ends_with(relative))
        .collect();
    match matches.as_slice() {
        [relative] => Some(relative.clone()),
        _ => None,
    }
}

fn looks_like_go_receiver_selector(target: &str) -> bool {
    let trimmed = target.trim();
    trimmed.starts_with('(') || trimmed.contains(".(")
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
    // Share the analyzer's comment-walk so both source-rendering paths agree on
    // what counts as a declaration's attached comment block (and inherit fixes
    // like the blank-line terminator that excludes file-level license headers).
    crate::analyzer::tree_sitter_analyzer::expanded_comment_start(source, start_byte)
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
    Ruby,
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
            Language::Ruby => Self::Ruby,
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
            Self::Ruby => "ruby",
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
        Language::Ruby => "ruby",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        ScanUsageRequest, ScanUsagesAbsenceCaveat, ScanUsagesCandidateFilesSample,
        ScanUsagesStatus, ScanUsagesSurface, ScanUsagesWorkEntry, SourceBlock, SummaryElement,
        SymbolUsageRenderState, UsageFailureInfo, UsageHitKind, UsageHitRow, UsageRendering,
        classify_scan_usages_entry, list_symbols, resolve_file_patterns, trim_summary_signature,
    };
    use super::{function_like_macro_query, route_summary_targets, usage_failure_hint};
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
        fn indexed_source(&self, _file: &ProjectFile) -> Option<String> {
            None
        }

        fn analyzed_files(&self) -> Vec<ProjectFile> {
            self.analyzed_files_calls.fetch_add(1, Ordering::Relaxed);
            self.project.files.iter().cloned().collect()
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

        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
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
    fn python_module_functions_are_not_duplicated_in_file_summary() {
        use crate::analyzer::{Language, PythonAnalyzer, TestProject};

        // Module-level Python defs are registered both as their own top-level
        // declarations and as children of the synthetic module unit (which is
        // itself top-level), so the file-summary recursion previously emitted each
        // one twice. The file summary must list each declaration exactly once.
        let source = "\
def alpha(x):
    return x

def beta(y):
    return y + 1

def gamma():
    return 0
";
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), std::path::PathBuf::from("mod.py"));
        file.write(source).unwrap();
        let analyzer = PythonAnalyzer::from_project(TestProject::new(root, Language::Python));

        let result = super::summarize_files(&analyzer, vec![file]);
        let block = result.summaries.first().expect("one file summary");
        let names: Vec<&str> = block.elements.iter().map(|e| e.symbol.as_str()).collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            names.len(),
            unique.len(),
            "each module-level function must appear once, got {names:?}"
        );
        assert_eq!(
            unique.len(),
            3,
            "expected alpha/beta/gamma once each, got {names:?}"
        );
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
            note: None,
        };
        let _element = SummaryElement {
            path: "A.java".to_string(),
            symbol: "A".to_string(),
            kind: "class".to_string(),
            start_line: 10,
            end_line: 10,
            text: "class A {".to_string(),
            parent_symbol: None,
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
    fn summary_literal_file_target_avoids_directory_scan() {
        let root = std::env::current_dir().unwrap();
        let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java"]);

        let targets = route_summary_targets(&analyzer, &["nested/B.java".to_string()]);

        assert_eq!(vec!["nested/B.java"], rel_paths(&targets.file_targets));
        assert!(targets.directory_targets.is_empty());
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
        assert_eq!(
            vec!["src"],
            result
                .not_found
                .iter()
                .map(|item| item.input.as_str())
                .collect::<Vec<_>>()
        );
    }

    fn rel_paths(files: &[ProjectFile]) -> Vec<String> {
        files
            .iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect()
    }

    #[test]
    fn no_graph_seed_hint_uses_reference_arguments_for_symbol_queries() {
        let anchored = usage_failure_hint(
            ScanUsagesSurface::Reference,
            "no_graph_seed",
            None,
            true,
            false,
        )
        .unwrap();
        assert!(
            !anchored.contains("`targets`") && !anchored.contains("`symbols`"),
            "anchored query must not suggest another selector re-call: {anchored}"
        );

        let unanchored = usage_failure_hint(
            ScanUsagesSurface::Reference,
            "no_graph_seed",
            None,
            false,
            false,
        )
        .unwrap();
        assert!(
            unanchored.contains("scan_usages_by_reference")
                && unanchored.contains("symbol")
                && !unanchored.contains("`targets`"),
            "unanchored reference query should suggest a symbolic retry: {unanchored}"
        );
    }

    #[test]
    fn function_like_macro_guidance_escapes_identifier_for_query_code() {
        let query = function_like_macro_query(Language::Cpp, r"\U000003B1");
        let value: serde_json::Value = serde_json::from_str(&query).expect("valid query_code JSON");
        assert_eq!(r"\U000003B1", value["match"]["callee"]["name"]);
    }

    fn scan_usage_request(symbol: &str) -> ScanUsageRequest {
        ScanUsageRequest::symbol(0, symbol.to_string())
    }

    fn usage_row(path: &str, line: usize) -> UsageHitRow {
        UsageHitRow {
            path: path.to_string(),
            line,
            enclosing: "Caller.run".to_string(),
            kind: UsageHitKind::Reference,
            snippet: "target();".to_string(),
            confidence: 1.0,
        }
    }

    fn usage_work_entry(
        symbol: &str,
        proven: Vec<UsageHitRow>,
        unproven_hits: usize,
        unproven_rows: Vec<UsageHitRow>,
        candidate_files_truncated: bool,
        reference_only_absence_note: Option<String>,
    ) -> ScanUsagesWorkEntry {
        ScanUsagesWorkEntry::Usage {
            request: scan_usage_request(symbol),
            state: SymbolUsageRenderState::new(
                symbol.to_string(),
                None,
                candidate_files_truncated,
                0,
                proven,
                unproven_hits,
                unproven_rows,
                None,
                reference_only_absence_note,
            ),
            candidate_files_sample: Some(ScanUsagesCandidateFilesSample {
                scanned: vec!["scanned.rs".to_string()],
                omitted: vec!["omitted.rs".to_string()],
                omitted_count: 1,
            }),
            target_is_method: false,
        }
    }

    #[test]
    fn scan_usages_classification_matrix_keeps_status_and_completeness_separate() {
        let found_full = classify_scan_usages_entry(&usage_work_entry(
            "target",
            vec![usage_row("caller.rs", 1)],
            0,
            Vec::new(),
            false,
            None,
        ));
        assert_eq!(ScanUsagesStatus::Found, found_full.status);
        assert!(found_full.complete);

        let found_truncated = classify_scan_usages_entry(&usage_work_entry(
            "target",
            vec![usage_row("caller.rs", 1)],
            0,
            Vec::new(),
            true,
            None,
        ));
        assert_eq!(ScanUsagesStatus::Found, found_truncated.status);
        assert!(!found_truncated.complete);
        assert!(found_truncated.absence_caveats.is_empty());
        assert!(found_truncated.candidate_files_sample.is_some());

        let found_with_unproven = classify_scan_usages_entry(&usage_work_entry(
            "target",
            vec![usage_row("caller.rs", 1)],
            1,
            vec![usage_row("maybe.rs", 2)],
            false,
            None,
        ));
        assert_eq!(ScanUsagesStatus::Found, found_with_unproven.status);
        assert!(found_with_unproven.complete);
        assert!(found_with_unproven.absence_caveats.is_empty());

        let found_lines = classify_scan_usages_entry(&usage_work_entry(
            "target",
            (0..11)
                .map(|line| usage_row("caller.rs", line + 1))
                .collect(),
            0,
            Vec::new(),
            false,
            None,
        ));
        assert_eq!(ScanUsagesStatus::Found, found_lines.status);
        assert_eq!(Some(UsageRendering::Lines), found_lines.rendering);
        assert!(found_lines.complete);
        assert!(!super::build_scan_usages_summary(std::slice::from_ref(&found_lines)).partial);

        let verified_absent = classify_scan_usages_entry(&usage_work_entry(
            "target",
            Vec::new(),
            0,
            Vec::new(),
            false,
            None,
        ));
        assert_eq!(ScanUsagesStatus::VerifiedAbsent, verified_absent.status);
        assert!(verified_absent.complete);

        let unproven_absent = classify_scan_usages_entry(&usage_work_entry(
            "target",
            Vec::new(),
            1,
            vec![usage_row("caller.rs", 2)],
            false,
            None,
        ));
        assert_eq!(ScanUsagesStatus::UnverifiedAbsent, unproven_absent.status);
        assert!(unproven_absent.complete);
        assert!(
            unproven_absent
                .absence_caveats
                .contains(&ScanUsagesAbsenceCaveat::UnprovenMatches)
        );

        let truncated_absent = classify_scan_usages_entry(&usage_work_entry(
            "target",
            Vec::new(),
            0,
            Vec::new(),
            true,
            None,
        ));
        assert_eq!(ScanUsagesStatus::UnverifiedAbsent, truncated_absent.status);
        assert!(!truncated_absent.complete);
        assert!(
            truncated_absent
                .absence_caveats
                .contains(&ScanUsagesAbsenceCaveat::CandidateFilesTruncated)
        );
        assert!(truncated_absent.candidate_files_sample.is_some());

        let sibling_absent = classify_scan_usages_entry(&usage_work_entry(
            "target",
            Vec::new(),
            0,
            Vec::new(),
            false,
            Some("workspace contains .razor files; absence not verified".to_string()),
        ));
        assert_eq!(ScanUsagesStatus::UnverifiedAbsent, sibling_absent.status);
        assert!(sibling_absent.complete);
        assert!(
            sibling_absent
                .absence_caveats
                .contains(&ScanUsagesAbsenceCaveat::ReferenceOnlySiblings)
        );

        let unproven_sibling_absent = classify_scan_usages_entry(&usage_work_entry(
            "target",
            Vec::new(),
            1,
            vec![usage_row("maybe.rs", 2)],
            false,
            Some("workspace contains .razor files; absence not verified".to_string()),
        ));
        assert_eq!(
            ScanUsagesStatus::UnverifiedAbsent,
            unproven_sibling_absent.status
        );
        assert!(unproven_sibling_absent.complete);
        assert!(
            unproven_sibling_absent
                .absence_caveats
                .contains(&ScanUsagesAbsenceCaveat::UnprovenMatches)
        );
        assert!(
            unproven_sibling_absent
                .absence_caveats
                .contains(&ScanUsagesAbsenceCaveat::ReferenceOnlySiblings)
        );

        let truncated_sibling_absent = classify_scan_usages_entry(&usage_work_entry(
            "target",
            Vec::new(),
            0,
            Vec::new(),
            true,
            Some("workspace contains .razor files; absence not verified".to_string()),
        ));
        assert_eq!(
            ScanUsagesStatus::UnverifiedAbsent,
            truncated_sibling_absent.status
        );
        assert!(!truncated_sibling_absent.complete);
        assert!(
            truncated_sibling_absent
                .absence_caveats
                .contains(&ScanUsagesAbsenceCaveat::CandidateFilesTruncated)
        );
        assert!(
            truncated_sibling_absent
                .absence_caveats
                .contains(&ScanUsagesAbsenceCaveat::ReferenceOnlySiblings)
        );
    }

    #[test]
    fn scan_usages_classifies_callsite_cap_and_graph_failure_rows() {
        let too_many = classify_scan_usages_entry(&ScanUsagesWorkEntry::TooManyCallsites {
            request: scan_usage_request("target"),
            state: SymbolUsageRenderState::partial_summary(
                "target".to_string(),
                None,
                1001,
                false,
                0,
                vec![usage_row("caller.rs", 1)],
                0,
                Vec::new(),
                None,
                None,
            ),
            short_name: "target".to_string(),
            total_callsites: 1001,
            limit: 1000,
            target_is_method: false,
        });
        assert_eq!(ScanUsagesStatus::TooManyCallsites, too_many.status);
        assert!(!too_many.complete);
        assert_eq!(Some(1001), too_many.total_callsites);

        let failure = classify_scan_usages_entry(&ScanUsagesWorkEntry::Failure {
            request: scan_usage_request("target"),
            failure: UsageFailureInfo {
                symbol: "target".to_string(),
                fq_name: "target".to_string(),
                reason_kind: "no_graph_seed".to_string(),
                reason: "no graph seed".to_string(),
                candidate_files_truncated: true,
                candidate_files_sample: None,
                hint: None,
            },
        });
        assert_eq!(ScanUsagesStatus::Failure, failure.status);
        assert!(!failure.complete);
        assert_eq!(Some("no_graph_seed"), failure.reason_kind.as_deref());
    }
}
