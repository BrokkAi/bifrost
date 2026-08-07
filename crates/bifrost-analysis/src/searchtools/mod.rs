use crate::analyzer::common::{
    display_identifier_for_target, display_parent_symbol_for_target, display_symbol_for_target,
    display_symbol_name, is_scala_object_like, language_for_file, language_for_target,
};
use crate::analyzer::declaration_range::{
    DeclarationNameRangeContext, code_unit_declaration_name_range,
};
use crate::analyzer::lexical_definitions::LexicalDefinition;
use crate::analyzer::symbol_lookup::{
    CodeUnitResolution, is_bare_symbol_query, resolve_codeunit_exact, resolve_codeunit_fuzzy,
    resolve_codeunit_fuzzy_with, resolve_enclosing_codeunits, strip_trailing_call_suffix,
    symbol_selector_leaf,
};
use crate::analyzer::test_paths;
use crate::analyzer::usages::get_definition::{
    SCALA_UNSUPPORTED_CALL_TARGET_SHAPE, SCALA_UNSUPPORTED_RECEIVER,
};
use crate::analyzer::usages::reference_site::reference_target_match_offsets;
use crate::analyzer::usages::workspace_graph::{UsageEcosystem, WorkspaceUsageCatalog};
use crate::analyzer::usages::{
    CONFIDENCE_THRESHOLD, CandidateFileProvider, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES,
    ExplicitCandidateProvider, FuzzyResult, UsageFinder, UsageHit, UsageHitKind, UsageHitSurface,
    UsageQueryCompletion,
};
use crate::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, BoundedDefinitionLookup, CodeUnit, CodeUnitType,
    DeclarationKind, GO_MODULE_SCOPE_SEGMENT, GoModuleRoot, IAnalyzer, Language, ProjectFile,
    Range, SearchSymbolPatternBatch, SummaryFileProjection, go_module_roots,
};
use crate::hash::{HashMap, HashSet};
use crate::model_context;
pub use crate::navigation::NavigationOperation;
use crate::path_utils::{
    AmbiguousPathInput, ResolvedFileInput, WorkspaceFileResolver, has_drive_letter_prefix,
    normalize_pattern, percent_decode, rel_path_string, workspace_rel_path,
};
use crate::profiling;
pub use crate::relevance::MostRelevantFilesRankingMode;
use crate::relevance::{
    DEFAULT_RECENCY_HALF_LIFE, MostRelevantProjectFilesOutcome, most_important_project_files,
    most_important_project_files_with_cancellation, most_relevant_project_files_history_only,
    most_relevant_project_files_with_half_life,
    most_relevant_project_files_with_ranking_mode_and_cancellation,
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
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

mod definitions;
mod navigation;
mod scan_usages;
mod selectors;
mod sources;
mod summaries;
#[cfg(test)]
mod tests;

// `refresh_result` and `looks_like_file_target` below (this file's own
// cross-family helpers) reach into `selectors` for these two.
use selectors::{language_name, likely_file_target_extension};

// Internal wiring: hoist the handful of child-module items the moved test
// module (tests.rs) still reaches via a bare `super::name` path, exactly as
// it did when this was one flat file. This is private (not part of the
// external crate/pub surface below) and only referenced under `#[cfg(test)]`.
#[cfg(test)]
use scan_usages::{
    ScanUsageRequest, ScanUsagesExecutionContext, ScanUsagesWorkEntry, SymbolUsageRenderState,
    UsageHitRow, build_scan_usages_summary, classify_scan_usages_entry, function_like_macro_query,
    scan_usages_by_location_with_context, usage_failure_hint,
};
#[cfg(test)]
use selectors::{DefinitionCandidateRenderCache, definition_candidate_from_range};
#[cfg(test)]
use summaries::{route_summary_targets, trim_summary_signature};

// Re-export the exact previous public/pub(crate) surface of `searchtools.rs`
// so that `crate::searchtools::X` keeps resolving for every existing
// consumer path unchanged.

pub use definitions::DefinitionByReferenceLookupResult;
pub use definitions::DefinitionContextReferenceQuery;
pub use definitions::DefinitionReferenceSite;
pub use definitions::GetDefinitionByReferenceParams;
pub use definitions::GetDefinitionByReferenceResult;
pub use definitions::get_definitions_by_reference;
pub use navigation::DeclarationLookupResult;
pub use navigation::DefinitionLookupResult;
pub use navigation::DefinitionReferenceQuery;
pub use navigation::GetDeclarationResult;
pub use navigation::GetDefinitionParams;
pub use navigation::GetDefinitionResult;
pub use navigation::GetTypeParams;
pub use navigation::GetTypeResult;
pub use navigation::RenameFileEdits;
pub use navigation::RenameSymbolParams;
pub use navigation::RenameSymbolResult;
pub use navigation::RenameSymbolTarget;
pub use navigation::RenameTextEdit;
pub use navigation::SearchSymbolHit;
pub use navigation::SearchSymbolsFile;
pub use navigation::SearchSymbolsParams;
pub use navigation::SearchSymbolsResult;
pub use navigation::SymbolAncestors;
pub use navigation::SymbolAncestorsResult;
pub use navigation::SymbolLocation;
pub use navigation::SymbolLocationsResult;
pub use navigation::SymbolLookupParams;
pub use navigation::TooManySymbolMatches;
pub use navigation::TypeLookupCandidate;
pub use navigation::TypeLookupResult;
pub use navigation::TypeReferenceQuery;
pub use navigation::get_declarations_by_location;
pub use navigation::get_definitions_by_location;
pub use navigation::get_symbol_ancestors;
pub use navigation::get_symbol_locations;
pub use navigation::get_type_by_location;
pub use navigation::rename_symbol;
pub use navigation::search_symbols;
pub use navigation::search_symbols_with_cancellation;
pub use navigation::{
    get_declarations_by_location_with_cancellation, get_definitions_by_location_with_cancellation,
    get_symbol_locations_with_cancellation,
};
pub use scan_usages::AmbiguousUsageCandidate;
pub use scan_usages::AmbiguousUsageCandidateDetail;
pub use scan_usages::AmbiguousUsageSymbol;
pub use scan_usages::ClassifyTestFilesParams;
pub use scan_usages::ClassifyTestFilesResult;
pub use scan_usages::ScanUsagesAbsenceCaveat;
pub use scan_usages::ScanUsagesByLocationParams;
pub use scan_usages::ScanUsagesByReferenceParams;
pub use scan_usages::ScanUsagesCandidateFilesSample;
pub use scan_usages::ScanUsagesEntry;
pub use scan_usages::ScanUsagesIncompleteReason;
pub use scan_usages::ScanUsagesInput;
pub use scan_usages::ScanUsagesInputKind;
pub use scan_usages::ScanUsagesResult;
pub use scan_usages::ScanUsagesScope;
pub use scan_usages::ScanUsagesStatus;
pub use scan_usages::ScanUsagesSummary;
pub use scan_usages::ScanUsagesTarget;
pub use scan_usages::ScanUsagesTargetSuggestion;
pub use scan_usages::SymbolUsages;
pub use scan_usages::TestFileClassification;
pub use scan_usages::TestFileKind;
pub use scan_usages::TooManyCallsitesInfo;
pub use scan_usages::UsageEnclosingCount;
pub use scan_usages::UsageFailureInfo;
pub use scan_usages::UsageFileGroup;
pub use scan_usages::UsageGraphCallSite;
pub use scan_usages::UsageGraphEdge;
pub use scan_usages::UsageGraphNode;
pub use scan_usages::UsageGraphParams;
pub use scan_usages::UsageGraphResult;
pub use scan_usages::UsageGraphTruncatedSymbol;
pub use scan_usages::UsageLocation;
pub use scan_usages::UsageRendering;
pub use scan_usages::classify_test_files;
pub use scan_usages::scan_usages_by_location;
pub use scan_usages::scan_usages_by_reference;
pub use scan_usages::usage_graph;
#[cfg(any(test, feature = "test-support"))]
pub use scan_usages::{ScanUsagesTimeBudgetGuard, disable_time_budget_for_test};
pub use scan_usages::{
    scan_usages_by_location_with_cancellation, scan_usages_by_reference_with_cancellation,
};
pub use selectors::AmbiguousSymbol;
pub use selectors::DefinitionCandidate;
pub use selectors::DefinitionDiagnostic;
pub use selectors::NotFoundInput;
pub use sources::SourceBlock;
pub use sources::SymbolSourcesResult;
pub use sources::get_symbol_sources;
pub use summaries::ContainerKind;
pub use summaries::ContainerListing;
pub use summaries::ContainerListingEntry;
pub use summaries::FilePatternsParams;
pub use summaries::MostRelevantFile;
pub use summaries::MostRelevantFilesIncompleteReason;
pub use summaries::MostRelevantFilesParams;
pub use summaries::MostRelevantFilesResult;
pub use summaries::SkimFile;
pub use summaries::SkimFilesResult;
pub use summaries::SummariesParams;
pub use summaries::SummaryBlock;
pub use summaries::SummaryElement;
pub use summaries::SummaryResult;
pub use summaries::get_summaries;
pub use summaries::get_summaries_with_cancellation;
pub use summaries::list_symbols;
pub use summaries::most_relevant_files;
pub use summaries::most_relevant_files_history_only;
pub use summaries::most_relevant_files_with_cancellation;

// Only the moved `#[cfg(test)]` test module reaches this name through the
// `crate::searchtools::` path today; without a non-test crate consumer, a
// lib-only compilation (no `cfg(test)`) sees the re-export as unused. The
// original flat file never tripped this because a directly declared
// `pub(crate)` item is exempt from `dead_code`, unlike a `use` re-export
// under `unused_imports`. Keep the re-export (it preserves the previous
// `crate::searchtools::ScanUsagesSurface` path) and suppress the lint here.
#[allow(unused_imports)]
pub(crate) use scan_usages::ScanUsagesSurface;
pub use scan_usages::scan_usages_target_label;
pub use sources::symbol_source_candidate_files;
// The semantic chunker's entry points into summarization; the chunker lives in
// brokk-bifrost-nlp, so they are part of this crate's public surface
// (summary_block_for_file joined for the extraction profiler).
pub use summaries::{summarize_files, summary_block_for_code_unit, summary_block_for_file};

const FILE_SEARCH_LIMIT: usize = 100;

pub const SEARCH_SYMBOL_MAX_PATTERNS: usize = 64;
pub const SEARCH_SYMBOL_MAX_PATTERN_BYTES: usize = 4_096;
pub const SEARCH_SYMBOL_MAX_TOTAL_PATTERN_BYTES: usize = 65_536;
pub const SYMBOL_LOOKUP_MAX_SYMBOLS: usize = 64;
pub const SYMBOL_LOOKUP_MAX_SYMBOL_BYTES: usize = 4_096;
pub const SYMBOL_LOOKUP_MAX_TOTAL_BYTES: usize = 65_536;

const FILE_SKIM_LIMIT: usize = 20;

// Keep MCP structured JSON below Codex's default 10 KB function-output
// truncation limit after JSON escaping and tool wrapper overhead.
pub const SCAN_USAGES_RESPONSE_BUDGET_BYTES: usize = 8_192;

const SCAN_USAGES_MAX_CALLSITES: usize = DEFAULT_MAX_USAGES;

const SCAN_USAGES_PATH_SCOPED_MAX_FILES: usize = 10_000;

const SCAN_USAGES_MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;

const SCAN_USAGES_SUMMARY_FILE_LIMIT: usize = 20;

const SCAN_USAGES_TOP_ENCLOSING_LIMIT: usize = 10;

const SCAN_USAGES_AMBIGUOUS_DETAILS_LIMIT: usize = 3;

const SCAN_USAGES_PATH_SELECTOR_MATCH_LIMIT: usize = 5;

const SCAN_USAGES_SCOPE_PATH_LIMIT: usize = 5;

const SCAN_USAGES_SCOPE_PATH_MAX_BYTES: usize = 256;

/// How many matched paths a too-broad reply shows so the caller can narrow.
pub const FILE_PATTERN_FANOUT_SAMPLE: usize = 10;

/// Files a single `get_summaries` glob target may expand to before the tool
/// skips it. Mirrors `FILE_SKIM_LIMIT`, the bound `list_symbols` already puts
/// on the same expansion; a summary block is strictly larger than a skim
/// listing, so a larger cap needs new evidence first.
pub const GET_SUMMARIES_MAX_FILES_PER_TARGET: usize = 20;

/// Files a single `get_symbol_sources` glob target may expand to before the
/// tool skips it. Half the `get_summaries` cap because this tool answers with
/// full source text, the heaviest payload per file the searchtools produce.
pub const GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET: usize = 10;

/// Deduplicated `search_symbols` candidates that may be ranked before the tool
/// gives up and answers with counts instead. Broad multi-pattern search with
/// ranking is this tool's normal, intended use, so the cap only has to catch
/// pathological explosions.
///
/// The value is provisional. It comes from the Firefox measurement in
/// `.agents/docs/codescale-grep-hard-checkpoint-2026-08-06.md` -- about 34 s of
/// ranking for a broad six-pattern search -- without a candidate count for that
/// workload. Record the measured count here and retune once one exists.
pub const SEARCH_SYMBOLS_MAX_RANKED_CANDIDATES: usize = 10_000;

/// A single request target that matched more of the workspace than the
/// tool will process. The work was skipped, not truncated: `sample`
/// holds the first `FILE_PATTERN_FANOUT_SAMPLE` matched paths so the
/// caller can narrow, and `matched` is the true total.
#[derive(Debug, Clone, Serialize)]
pub struct TooBroadScope {
    pub target: String,
    pub matched: usize,
    pub cap: usize,
    pub sample: Vec<String>,
}

/// `matched` is already ordered (it comes out of a `BTreeSet<ProjectFile>`), so
/// the sample is the first `FILE_PATTERN_FANOUT_SAMPLE` paths; sorting those
/// few strings makes the rendered order path-lexicographic on every platform.
fn too_broad_scope(target: &str, matched: &[ProjectFile], cap: usize) -> TooBroadScope {
    let mut sample: Vec<_> = matched
        .iter()
        .take(FILE_PATTERN_FANOUT_SAMPLE)
        .map(rel_path_string)
        .collect();
    sample.sort();
    TooBroadScope {
        target: target.to_string(),
        matched: matched.len(),
        cap,
        sample,
    }
}

pub const TYPE_LOOKUP_MAX_REFERENCES: usize = 100;

pub const DEFINITION_LOOKUP_MAX_REFERENCES: usize = 100;

/// Bare-name symbol resolution can legitimately surface far more candidates
/// than a caller can act on (e.g. dayjs's ~130 per-locale `formats` object
/// literals, #1088). Cap the rendered `AmbiguousSymbol.matches` list so the
/// response stays a manageable size; the note always carries the true total
/// so nothing is silently dropped.
pub const AMBIGUOUS_SYMBOL_MATCH_LIMIT: usize = 25;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshParams {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivateWorkspaceParams {
    pub workspace_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetActiveWorkspaceParams {}

#[derive(Debug, Clone, Serialize)]
pub struct RefreshResult {
    pub languages: Vec<String>,
    pub analyzed_files: usize,
    pub declarations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveWorkspaceResult {
    pub workspace_path: String,
    /// Whether a usage query would wait for background usage-analysis work.
    /// Under the per-file fact design this is false only while an
    /// above-threshold catch-up batch is being persisted; a tool that needs
    /// those facts blocks until it drains, which is the right default, and a
    /// caller that must not block asks this first (#1757). The field name is
    /// the tool contract and did not change when the implementation moved off
    /// the v1 usage index (ExecPlan Milestone 3).
    pub usage_index_ready: bool,
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

struct ResolvedFilePatterns {
    files: Vec<ProjectFile>,
    ambiguous_paths: Vec<AmbiguousPathInput>,
}

fn code_unit_kind_name(kind: CodeUnitType) -> &'static str {
    kind.display_lowercase()
}

fn primary_range(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Option<Range> {
    let source = (language_for_target(code_unit) == Language::Cpp && code_unit.is_callable())
        .then(|| analyzer.indexed_source(code_unit.source()))
        .flatten();
    let classifier = source
        .as_deref()
        .and_then(crate::analyzer::CppOccurrenceClassifier::new);
    primary_range_with_cpp_classifier(analyzer, code_unit, classifier.as_ref())
}

fn primary_range_with_cpp_classifier(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    classifier: Option<&crate::analyzer::CppOccurrenceClassifier>,
) -> Option<Range> {
    let ranges = analyzer.ranges(code_unit);
    if language_for_target(code_unit) == Language::Cpp
        && code_unit.is_callable()
        && let Some(classifier) = classifier
        && let Some(definition) = ranges
            .iter()
            .filter(|range| {
                classifier.classify(code_unit, range)
                    == crate::analyzer::CppOccurrenceRole::Definition
            })
            .min_by_key(|range| (range.start_line, range.start_byte))
    {
        return Some(*definition);
    }
    ranges
        .into_iter()
        .min_by_key(|range| (range.start_line, range.start_byte))
}

fn resolve_file_patterns(analyzer: &dyn IAnalyzer, patterns: &[String]) -> ResolvedFilePatterns {
    let mut matched = BTreeSet::new();
    let mut globs = Vec::new();
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
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

        let directory_matches = summaries::directory_listing_root(&normalized)
            .filter(|directory| analyzer.project().has_directory(directory))
            .map(|_| resolve_directory_target(analyzer, &normalized))
            .unwrap_or_default();
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
    analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| rel_path_string(file).starts_with(&prefix))
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

fn looks_like_explicit_source_file_target(target: &str) -> bool {
    let normalized = target.replace('\\', "/");
    if !normalized.contains('/') {
        return false;
    }
    let Some(extension) = Path::new(&normalized)
        .extension()
        .and_then(|value| value.to_str())
    else {
        return false;
    };
    Language::is_source_extension(extension)
}

fn is_glob_pattern(pattern: &str) -> bool {
    pattern.contains(['*', '?', '['])
}

fn line_count(content: &str) -> usize {
    model_context::count_lines(content)
}

fn default_limit() -> usize {
    20
}
