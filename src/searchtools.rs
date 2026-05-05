use crate::analyzer::{CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile, Range};
use crate::profiling;
use crate::relevance::{most_important_project_files, most_relevant_project_files};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::{
    CONFIDENCE_THRESHOLD, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, UsageFinder, UsageHit,
};
use glob::Pattern;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const FILE_SEARCH_LIMIT: usize = 100;
const FILE_SKIM_LIMIT: usize = 20;
const CLASS_COUNT_LIMIT: usize = 10;

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
pub struct SymbolNamesParams {
    pub symbols: Vec<String>,
    #[serde(default)]
    pub kind_filter: SymbolKindFilter,
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
    pub seed_files: Vec<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUsagesParams {
    pub symbols: Vec<String>,
    #[serde(default)]
    pub include_tests: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKindFilter {
    #[default]
    Any,
    Class,
    Function,
    Field,
    Module,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSymbolHit {
    pub symbol: String,
    pub signature: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolLocationsResult {
    pub locations: Vec<SymbolLocation>,
    pub not_found: Vec<String>,
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
pub struct SummaryResult {
    pub summaries: Vec<SummaryBlock>,
    pub not_found: Vec<String>,
    pub ambiguous: Vec<AmbiguousSymbol>,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolSourcesResult {
    pub sources: Vec<SourceBlock>,
    pub not_found: Vec<String>,
    pub ambiguous: Vec<AmbiguousSymbol>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceBlock {
    pub label: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFilesResult {
    pub truncated: bool,
    pub total_files: usize,
    pub files: Vec<SkimFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MostRelevantFilesResult {
    pub files: Vec<String>,
    pub not_found: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFile {
    pub path: String,
    pub loc: usize,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanUsagesResult {
    pub usages: Vec<SymbolUsages>,
    pub not_found: Vec<String>,
    pub ambiguous: Vec<AmbiguousUsageSymbol>,
    pub too_many_callsites: Vec<TooManyCallsitesInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolUsages {
    pub symbol: String,
    pub total_hits: usize,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned. Results are partial when set.
    pub candidate_files_truncated: bool,
    pub files: Vec<UsageFileGroup>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageFileGroup {
    pub path: String,
    pub hits: Vec<UsageLocation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageLocation {
    pub line: usize,
    pub enclosing: String,
    pub snippet: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousUsageSymbol {
    pub symbol: String,
    pub short_name: String,
    pub candidate_targets: Vec<String>,
    /// True when the candidate file set exceeded the analyzer's per-query cap
    /// and an arbitrary subset was scanned. Results are partial when set.
    pub candidate_files_truncated: bool,
    pub files: Vec<UsageFileGroup>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TooManyCallsitesInfo {
    pub symbol: String,
    pub short_name: String,
    pub total_callsites: usize,
    pub limit: usize,
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
        .filter(|code_unit| params.include_tests || !analyzer.contains_tests(code_unit.source()))
        .collect::<Vec<_>>()
        .into_iter()
        .collect();

    let mut grouped: BTreeMap<ProjectFile, Vec<CodeUnit>> = BTreeMap::new();
    for code_unit in filtered {
        grouped
            .entry(code_unit.source().clone())
            .or_default()
            .push(code_unit);
    }

    let effective_limit = params.limit.clamp(1, FILE_SEARCH_LIMIT);
    let total_files = grouped.len();
    let truncated = total_files > effective_limit;
    let selected_files =
        select_files_for_display(analyzer, grouped.keys().cloned().collect(), effective_limit);
    let files = selected_files
        .into_iter()
        .filter_map(|file| grouped.remove(&file).map(|code_units| (file, code_units)))
        .map(|(file, code_units)| SearchSymbolsFile {
            path: rel_path_string(&file),
            loc: file
                .read_to_string()
                .map(|content| line_count(&content))
                .unwrap_or(0),
            classes: collect_kind_names(analyzer, &code_units, CodeUnitType::Class),
            functions: collect_kind_names(analyzer, &code_units, CodeUnitType::Function),
            fields: collect_kind_names(analyzer, &code_units, CodeUnitType::Field),
            modules: collect_kind_names(analyzer, &code_units, CodeUnitType::Module),
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
    params: SymbolNamesParams,
) -> SymbolLocationsResult {
    let mut outcomes: Vec<_> = strip_params(params.symbols)
        .into_par_iter()
        .enumerate()
        .filter_map(|(index, symbol)| {
            if symbol.trim().is_empty() {
                return None;
            }

            let Some(code_unit) = first_matching_definition(analyzer, &symbol, params.kind_filter)
            else {
                return Some((index, Err(symbol)));
            };

            let Some(primary_range) = primary_range(analyzer, &code_unit) else {
                return Some((index, Err(symbol)));
            };

            let loc = code_unit
                .source()
                .read_to_string()
                .map(|content| line_count(&content))
                .unwrap_or(0);

            Some((
                index,
                Ok(SymbolLocation {
                    symbol,
                    path: rel_path_string(code_unit.source()),
                    loc,
                    start_line: primary_range.start_line,
                    end_line: primary_range.end_line,
                }),
            ))
        })
        .collect();
    outcomes.sort_by_key(|(index, _)| *index);

    let mut locations = Vec::new();
    let mut not_found = Vec::new();
    for (_, outcome) in outcomes {
        match outcome {
            Ok(location) => locations.push(location),
            Err(symbol) => not_found.push(symbol),
        }
    }

    SymbolLocationsResult {
        locations,
        not_found,
    }
}

pub fn get_symbol_summaries(analyzer: &dyn IAnalyzer, params: SymbolNamesParams) -> SummaryResult {
    let mut outcomes: Vec<_> = strip_params(params.symbols)
        .into_par_iter()
        .enumerate()
        .filter_map(|(index, symbol)| {
            if symbol.trim().is_empty() {
                return None;
            }

            let definitions = matching_definitions(analyzer, &symbol, params.kind_filter);
            if definitions.is_empty() {
                return Some((index, Err(symbol)));
            }

            let blocks = definitions
                .into_iter()
                .filter_map(|code_unit| {
                    let elements = summary_elements_for_code_unit(analyzer, &code_unit);
                    if elements.is_empty() {
                        return None;
                    }

                    Some(SummaryBlock {
                        label: code_unit.fq_name(),
                        path: rel_path_string(code_unit.source()),
                        preamble: file_preamble(code_unit.source(), &elements),
                        elements,
                    })
                })
                .collect::<Vec<_>>();

            if blocks.is_empty() {
                Some((index, Err(symbol)))
            } else {
                Some((index, Ok(blocks)))
            }
        })
        .collect();
    outcomes.sort_by_key(|(index, _)| *index);

    let mut summaries = Vec::new();
    let mut not_found = Vec::new();
    for (_, outcome) in outcomes {
        match outcome {
            Ok(blocks) => summaries.extend(blocks),
            Err(symbol) => not_found.push(symbol),
        }
    }

    SummaryResult {
        summaries,
        not_found,
        ambiguous: Vec::new(),
    }
}

#[derive(Debug)]
struct SummaryTargets {
    file_targets: Vec<ProjectFile>,
    unmatched_file_targets: Vec<String>,
    symbol_targets: Vec<String>,
}

enum SourceLookupOutcome {
    Found(Vec<SourceBlock>),
    NotFound(String),
    Ambiguous(AmbiguousSymbol),
}

fn route_summary_targets(analyzer: &dyn IAnalyzer, targets: &[String]) -> SummaryTargets {
    let mut file_targets = BTreeSet::new();
    let mut unmatched_file_targets = Vec::new();
    let mut symbol_targets = Vec::new();

    for target in targets
        .iter()
        .map(|target| target.trim())
        .filter(|target| !target.is_empty())
    {
        let matches = resolve_file_patterns(analyzer, &[target.to_string()]);
        if !matches.is_empty() {
            file_targets.extend(matches);
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
        unmatched_file_targets,
        symbol_targets,
    }
}

fn summarize_symbol_targets(analyzer: &dyn IAnalyzer, targets: Vec<String>) -> SummaryResult {
    let lookups = resolve_relaxed_lookups(analyzer, &targets, SymbolKindFilter::Class);
    let mut summaries = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();

    for target in targets {
        match lookups.get(&target) {
            Some(RelaxedLookup::Resolved(code_units)) => {
                let start_len = summaries.len();
                for code_unit in code_units {
                    if let Some(block) = summary_block_for_code_unit(analyzer, code_unit) {
                        summaries.push(block);
                    }
                }
                if summaries.len() == start_len {
                    not_found.push(target);
                }
            }
            Some(RelaxedLookup::Ambiguous(matches)) => ambiguous.push(AmbiguousSymbol {
                target,
                matches: matches.clone(),
            }),
            Some(RelaxedLookup::NotFound) | None => not_found.push(target),
        }
    }

    SummaryResult {
        summaries,
        not_found,
        ambiguous,
    }
}

pub fn get_symbol_sources(
    analyzer: &dyn IAnalyzer,
    params: SymbolNamesParams,
) -> SymbolSourcesResult {
    let max_symbols = if params.kind_filter == SymbolKindFilter::Class {
        CLASS_COUNT_LIMIT
    } else {
        usize::MAX
    };

    let selected_symbols: Vec<_> = strip_params(params.symbols)
        .into_iter()
        .filter(|symbol| !symbol.trim().is_empty())
        .take(max_symbols)
        .collect();

    let lookups = resolve_relaxed_lookups(analyzer, &selected_symbols, params.kind_filter);
    let mut outcomes: Vec<_> = selected_symbols
        .into_par_iter()
        .enumerate()
        .map(|(index, symbol)| match lookups.get(&symbol) {
            Some(RelaxedLookup::Resolved(code_units)) => {
                let sources = code_units
                    .iter()
                    .flat_map(|code_unit| source_blocks_for_code_unit(analyzer, code_unit, true))
                    .collect::<Vec<_>>();
                if sources.is_empty() {
                    (index, SourceLookupOutcome::NotFound(symbol))
                } else {
                    (index, SourceLookupOutcome::Found(sources))
                }
            }
            Some(RelaxedLookup::Ambiguous(matches)) => (
                index,
                SourceLookupOutcome::Ambiguous(AmbiguousSymbol {
                    target: symbol,
                    matches: matches.clone(),
                }),
            ),
            Some(RelaxedLookup::NotFound) | None => (index, SourceLookupOutcome::NotFound(symbol)),
        })
        .collect();
    outcomes.sort_by_key(|(index, _)| *index);

    let mut sources = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();
    for (_, outcome) in outcomes {
        match outcome {
            SourceLookupOutcome::Found(blocks) => sources.extend(dedup_source_blocks(blocks)),
            SourceLookupOutcome::NotFound(symbol) => not_found.push(symbol),
            SourceLookupOutcome::Ambiguous(item) => ambiguous.push(item),
        }
    }

    SymbolSourcesResult {
        sources,
        not_found,
        ambiguous,
    }
}

pub fn get_summaries(analyzer: &dyn IAnalyzer, params: SummariesParams) -> SummaryResult {
    let targets = strip_params(params.targets);
    let summary_targets = route_summary_targets(analyzer, &targets);
    let mut file_output = summarize_files(analyzer, summary_targets.file_targets);
    let symbol_output = summarize_symbol_targets(analyzer, summary_targets.symbol_targets);

    file_output.summaries.extend(symbol_output.summaries);
    file_output
        .not_found
        .extend(summary_targets.unmatched_file_targets);
    file_output.not_found.extend(symbol_output.not_found);
    file_output.ambiguous.extend(symbol_output.ambiguous);
    file_output.summaries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.label.cmp(&right.label))
    });
    file_output
}

fn summarize_files(analyzer: &dyn IAnalyzer, files: Vec<ProjectFile>) -> SummaryResult {
    let mut summaries: Vec<_> = files
        .into_par_iter()
        .filter_map(|file| {
            let mut elements = Vec::new();
            for code_unit in analyzer.top_level_declarations(&file) {
                elements.extend(summary_elements_for_code_unit(analyzer, code_unit));
            }

            if elements.is_empty() {
                return None;
            }

            Some(SummaryBlock {
                label: rel_path_string(&file),
                path: rel_path_string(&file),
                preamble: file_preamble(&file, &elements),
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
    }
}

pub fn list_symbols(analyzer: &dyn IAnalyzer, params: FilePatternsParams) -> SkimFilesResult {
    let expanded = resolve_file_patterns(analyzer, &params.file_patterns);
    let total_files = expanded.len();
    let truncated = total_files > FILE_SKIM_LIMIT;
    let selected = select_files_for_display(analyzer, expanded, FILE_SKIM_LIMIT);
    let files: Vec<_> = selected
        .into_par_iter()
        .map(|file| {
            let loc = file
                .read_to_string()
                .map(|content| line_count(&content))
                .unwrap_or(0);
            let lines = analyzer
                .list_symbols(&file)
                .lines()
                .map(str::to_string)
                .collect();
            SkimFile {
                path: rel_path_string(&file),
                loc,
                lines,
            }
        })
        .collect();

    SkimFilesResult {
        truncated,
        total_files,
        files,
    }
}

pub fn most_relevant_files(
    analyzer: &dyn IAnalyzer,
    params: MostRelevantFilesParams,
) -> MostRelevantFilesResult {
    let _scope = profiling::scope("searchtools::most_relevant_files");
    let mut seeds = Vec::new();
    let mut not_found = Vec::new();

    {
        let _scope = profiling::scope("searchtools::most_relevant_files.resolve_seeds");
        for input in params.seed_files {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                continue;
            }

            let rel_path = PathBuf::from(normalize_pattern(trimmed));
            match analyzer.project().file_by_rel_path(&rel_path) {
                Some(file) => seeds.push(file),
                None => not_found.push(trimmed.to_string()),
            }
        }
    }

    let files = {
        let _scope = profiling::scope("searchtools::most_relevant_files.rank");
        most_relevant_project_files(analyzer, &seeds, params.limit)
            .into_iter()
            .map(|file| rel_path_string(&file))
            .collect()
    };

    MostRelevantFilesResult { files, not_found }
}

pub fn scan_usages(analyzer: &dyn IAnalyzer, params: ScanUsagesParams) -> ScanUsagesResult {
    let _scope = profiling::scope("searchtools::scan_usages");

    let symbols: Vec<String> = strip_params(params.symbols)
        .into_iter()
        .filter(|symbol| !symbol.trim().is_empty())
        .collect();

    // Pre-compute the test-file set once when filtering tests so each per-symbol
    // UsageFinder can drop test files *before* the regex scan and the
    // DEFAULT_MAX_USAGES cap. Filtering post-hoc would let test hits eat into
    // the cap and turn production-only queries into TooManyCallsites errors.
    let test_files: Option<Arc<std::collections::HashSet<ProjectFile>>> = if params.include_tests {
        None
    } else {
        let set: std::collections::HashSet<ProjectFile> = analyzer
            .analyzed_files()
            .filter(|file| analyzer.contains_tests(file))
            .cloned()
            .collect();
        Some(Arc::new(set))
    };

    let mut usages = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();
    let mut too_many_callsites = Vec::new();

    for symbol in symbols {
        let overloads = analyzer.get_definitions(&symbol);
        if overloads.is_empty() {
            not_found.push(symbol);
            continue;
        }

        let mut finder = UsageFinder::new();
        if let Some(test_files) = test_files.as_ref() {
            let test_files = Arc::clone(test_files);
            finder = finder.with_file_filter(move |file| !test_files.contains(file));
        }
        let query = finder.query(analyzer, &overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES);
        let truncated = query.candidate_files_truncated;

        match query.result {
            FuzzyResult::Success { hits_by_overload } => {
                let hits: BTreeSet<UsageHit> = hits_by_overload
                    .into_values()
                    .flat_map(BTreeSet::into_iter)
                    .collect();
                // A resolved symbol with no call sites is still emitted with
                // zero hits, so callers can distinguish "unknown symbol" (not_found)
                // from "symbol exists but has no callers" (usages with total_hits = 0).
                usages.push(SymbolUsages {
                    symbol,
                    total_hits: hits.len(),
                    candidate_files_truncated: truncated,
                    files: group_hits_by_file(hits),
                });
            }
            FuzzyResult::Ambiguous {
                short_name,
                candidate_targets,
                hits_by_overload,
            } => {
                let high_confidence: BTreeSet<UsageHit> = hits_by_overload
                    .into_values()
                    .flat_map(BTreeSet::into_iter)
                    .filter(|hit| hit.confidence >= CONFIDENCE_THRESHOLD)
                    .collect();
                ambiguous.push(AmbiguousUsageSymbol {
                    symbol,
                    short_name,
                    candidate_targets: candidate_targets
                        .into_iter()
                        .map(|code_unit| code_unit.fq_name())
                        .collect(),
                    candidate_files_truncated: truncated,
                    files: group_hits_by_file(high_confidence),
                });
            }
            FuzzyResult::Failure { .. } => {
                not_found.push(symbol);
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
                });
            }
        }
    }

    ScanUsagesResult {
        usages,
        not_found,
        ambiguous,
        too_many_callsites,
    }
}

fn group_hits_by_file(hits: BTreeSet<UsageHit>) -> Vec<UsageFileGroup> {
    let mut grouped: BTreeMap<ProjectFile, Vec<UsageLocation>> = BTreeMap::new();
    for hit in hits {
        grouped
            .entry(hit.file.clone())
            .or_default()
            .push(UsageLocation {
                line: hit.line,
                enclosing: hit.enclosing.fq_name(),
                snippet: hit.snippet.trim_end().to_string(),
                confidence: hit.confidence,
            });
    }
    grouped
        .into_iter()
        .map(|(file, mut hits)| {
            hits.sort_by(|left, right| {
                left.line
                    .cmp(&right.line)
                    .then_with(|| left.enclosing.cmp(&right.enclosing))
            });
            UsageFileGroup {
                path: rel_path_string(&file),
                hits,
            }
        })
        .collect()
}

fn collect_kind_names(
    analyzer: &dyn IAnalyzer,
    code_units: &[CodeUnit],
    kind: CodeUnitType,
) -> Vec<SearchSymbolHit> {
    let mut hits: Vec<_> = code_units
        .iter()
        .filter(|code_unit| code_unit.kind() == kind)
        .flat_map(|code_unit| {
            let line = primary_range(analyzer, code_unit)
                .map(|range| range.start_line)
                .unwrap_or(0);
            display_signatures(analyzer, code_unit)
                .into_iter()
                .map(move |signature| SearchSymbolHit {
                    symbol: code_unit.fq_name(),
                    signature,
                    line,
                })
        })
        .collect();
    hits.sort_by(|left, right| {
        left.signature
            .to_ascii_lowercase()
            .cmp(&right.signature.to_ascii_lowercase())
            .then(left.line.cmp(&right.line))
            .then(left.symbol.cmp(&right.symbol))
    });
    hits.dedup_by(|left, right| {
        left.symbol == right.symbol && left.signature == right.signature && left.line == right.line
    });
    hits
}

fn matching_definitions(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    kind_filter: SymbolKindFilter,
) -> Vec<CodeUnit> {
    analyzer
        .definitions(symbol)
        .filter(|code_unit| matches_kind_filter(code_unit, kind_filter))
        .cloned()
        .collect()
}

fn first_matching_definition(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    kind_filter: SymbolKindFilter,
) -> Option<CodeUnit> {
    matching_definitions(analyzer, symbol, kind_filter)
        .into_iter()
        .next()
}

#[derive(Debug, Clone)]
enum RelaxedLookup {
    Resolved(Vec<CodeUnit>),
    Ambiguous(Vec<String>),
    NotFound,
}

fn resolve_relaxed_lookups(
    analyzer: &dyn IAnalyzer,
    symbols: &[String],
    kind_filter: SymbolKindFilter,
) -> BTreeMap<String, RelaxedLookup> {
    let mut results = BTreeMap::new();
    let mut unresolved = Vec::new();

    for symbol in symbols {
        if results.contains_key(symbol) {
            continue;
        }
        let trimmed = symbol.trim();
        if trimmed.is_empty() {
            continue;
        }

        let definitions = matching_definitions(analyzer, trimmed, kind_filter);
        if !definitions.is_empty() {
            results.insert(symbol.clone(), RelaxedLookup::Resolved(definitions));
            continue;
        }

        unresolved.push(symbol.clone());
    }

    if unresolved.is_empty() {
        return results;
    }

    let declarations = analyzer.get_all_declarations();
    for requested in unresolved {
        let normalized = normalize_lookup_name(requested.trim());
        if normalized.is_empty() {
            results.insert(requested, RelaxedLookup::NotFound);
            continue;
        }

        let mut matches = BTreeMap::new();
        for candidate in &declarations {
            collect_relaxed_match(&normalized, candidate, kind_filter, &mut matches);
            if candidate.is_class() || candidate.is_module() {
                for member in analyzer.get_members_in_class(candidate) {
                    collect_relaxed_match(&normalized, &member, kind_filter, &mut matches);
                }
            }
        }

        let lookup = match matches.len() {
            0 => RelaxedLookup::NotFound,
            1 => RelaxedLookup::Resolved(vec![matches.into_values().next().expect("one match")]),
            _ => RelaxedLookup::Ambiguous(matches.into_keys().collect()),
        };
        results.insert(requested, lookup);
    }

    results
}

fn collect_relaxed_match(
    normalized_requested: &str,
    candidate: &CodeUnit,
    kind_filter: SymbolKindFilter,
    matches: &mut BTreeMap<String, CodeUnit>,
) {
    if !matches_kind_filter(candidate, kind_filter) {
        return;
    }
    if lookup_keys_for(candidate)
        .iter()
        .any(|key| key == normalized_requested)
    {
        matches
            .entry(candidate.fq_name())
            .or_insert_with(|| candidate.clone());
    }
}

fn lookup_keys_for(code_unit: &CodeUnit) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let normalized_fq_name = normalize_lookup_name(&code_unit.fq_name());
    if !normalized_fq_name.is_empty() {
        keys.insert(normalized_fq_name.clone());
        for (index, _) in normalized_fq_name.match_indices('.') {
            if index + 1 < normalized_fq_name.len() {
                keys.insert(normalized_fq_name[index + 1..].to_string());
            }
        }
    }

    let normalized_short_name = normalize_lookup_name(code_unit.short_name());
    if !normalized_short_name.is_empty() {
        keys.insert(normalized_short_name);
    }
    let normalized_identifier = normalize_lookup_name(code_unit.identifier());
    if !normalized_identifier.is_empty() {
        keys.insert(normalized_identifier);
    }

    keys
}

fn normalize_lookup_name(name: &str) -> String {
    name.replace('$', ".")
}

fn matches_kind_filter(code_unit: &CodeUnit, filter: SymbolKindFilter) -> bool {
    match filter {
        SymbolKindFilter::Any => true,
        SymbolKindFilter::Class => code_unit.is_class(),
        SymbolKindFilter::Function => code_unit.is_function(),
        SymbolKindFilter::Field => code_unit.is_field(),
        SymbolKindFilter::Module => code_unit.is_module(),
    }
}

fn summary_block_for_code_unit(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Option<SummaryBlock> {
    let elements = summary_elements_for_code_unit(analyzer, code_unit);
    if elements.is_empty() {
        return None;
    }

    Some(SummaryBlock {
        label: code_unit.fq_name(),
        path: rel_path_string(code_unit.source()),
        preamble: file_preamble(code_unit.source(), &elements),
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
        CodeUnitType::Class => format!("class {}", code_unit.identifier()),
        CodeUnitType::Function => code_unit
            .signature()
            .map(|signature| format!("{}{}", code_unit.identifier(), signature))
            .unwrap_or_else(|| format!("{}()", code_unit.identifier())),
        CodeUnitType::Field => code_unit.identifier().to_string(),
        CodeUnitType::Module => code_unit.short_name().to_string(),
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
                symbol: code_unit.fq_name(),
                kind: code_unit_kind_name(code_unit.kind()).to_string(),
                start_line,
                end_line,
                text,
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

    let language = code_unit
        .source()
        .rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None);

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
                label: code_unit.fq_name(),
                path: rel_path_string(code_unit.source()),
                start_line,
                end_line: start_line + text.lines().count().saturating_sub(1),
                text,
            })
        })
        .collect()
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
        );
        if seen.insert(key) {
            deduped.push(block);
        }
    }
    deduped
}

fn primary_range(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Option<Range> {
    analyzer
        .ranges(code_unit)
        .iter()
        .copied()
        .min_by_key(|range| (range.start_line, range.start_byte))
}

fn resolve_file_patterns(analyzer: &dyn IAnalyzer, patterns: &[String]) -> Vec<ProjectFile> {
    let mut matched = BTreeSet::new();
    let mut globs = Vec::new();

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

        let rel_path = Path::new(&normalized);
        if !rel_path.is_absolute()
            && let Some(file) = analyzer.project().file_by_rel_path(rel_path)
        {
            matched.insert(file);
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

    matched.into_iter().collect()
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
        || target.starts_with('.')
        || target.contains('/')
        || target.contains('\\')
        || target.contains('*')
        || target.contains('?')
    {
        return true;
    }

    let Some((_, extension)) = target.rsplit_once('.') else {
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

fn normalize_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/")
}

fn is_glob_pattern(pattern: &str) -> bool {
    pattern.contains(['*', '?', '['])
}

fn rel_path_string(file: &ProjectFile) -> String {
    file.rel_path().to_string_lossy().replace('\\', "/")
}

fn line_count(content: &str) -> usize {
    if content.is_empty() {
        0
    } else {
        split_logical_lines(content).len()
    }
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

fn split_logical_lines(content: &str) -> Vec<&str> {
    if content.is_empty() {
        return Vec::new();
    }

    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut iter = content.char_indices().peekable();
    while let Some((index, ch)) = iter.next() {
        if ch == '\n' || ch == '\r' {
            lines.push(&content[start..index]);
            if ch == '\r' && matches!(iter.peek(), Some((_, '\n'))) {
                let (next_index, _) = iter.next().unwrap();
                start = next_index + 1;
            } else {
                start = index + 1;
            }
        }
    }
    if start < content.len() {
        lines.push(&content[start..]);
    }
    lines
}

fn strip_params(symbols: Vec<String>) -> Vec<String> {
    symbols
        .into_iter()
        .map(|symbol| strip_trailing_call_suffix(&symbol))
        .collect()
}

fn strip_trailing_call_suffix(symbol: &str) -> String {
    if !symbol.ends_with(')') {
        return symbol.to_string();
    }

    let Some(open_paren) = symbol.rfind('(') else {
        return symbol.to_string();
    };
    if !symbol[open_paren + 1..symbol.len() - 1].contains(')') {
        let prefix = &symbol[..open_paren];
        if prefix
            .chars()
            .last()
            .map(|ch| ch.is_alphanumeric() || ch == '_')
            .unwrap_or(false)
        {
            return prefix.to_string();
        }
    }

    symbol.to_string()
}

fn default_limit() -> usize {
    20
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
        };
        let _element = SummaryElement {
            path: "A.java".to_string(),
            symbol: "A".to_string(),
            kind: "class".to_string(),
            start_line: 10,
            end_line: 10,
            text: "class A {".to_string(),
        };
    }

    #[test]
    fn literal_file_pattern_uses_project_lookup_without_scanning_analyzed_files() {
        let root = std::env::current_dir().unwrap();
        let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java"]);
        let files = resolve_file_patterns(&analyzer, &["nested/B.java".to_string()]);

        assert_eq!(vec!["nested/B.java"], rel_paths(&files));
        assert_eq!(0, analyzer.analyzed_files_calls());
    }

    #[test]
    fn glob_file_pattern_scans_analyzed_files() {
        let root = std::env::current_dir().unwrap();
        let analyzer = CountingAnalyzer::new(root, &["A.java", "nested/B.java", "notes.txt"]);
        let files = resolve_file_patterns(&analyzer, &["nested/*.java".to_string()]);

        assert_eq!(vec!["nested/B.java"], rel_paths(&files));
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

        assert_eq!(vec!["nested/B.java"], rel_paths(&files));
        assert_eq!(1, analyzer.analyzed_files_calls());
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

    fn rel_paths(files: &[ProjectFile]) -> Vec<String> {
        files
            .iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect()
    }
}
