use crate::analyzer::{CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile, Range};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use glob::Pattern;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const FILE_SEARCH_LIMIT: usize = 100;
const FILE_SKIM_LIMIT: usize = 20;
const CLASS_COUNT_LIMIT: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshParams {}

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
pub struct SearchSymbolsResult {
    pub patterns: Vec<String>,
    pub truncated: bool,
    pub files: Vec<SearchSymbolsFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchSymbolsFile {
    pub path: String,
    pub loc: usize,
    pub classes: Vec<String>,
    pub functions: Vec<String>,
    pub fields: Vec<String>,
    pub modules: Vec<String>,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryBlock {
    pub label: String,
    pub path: String,
    pub elements: Vec<SummaryElement>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryElement {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolSourcesResult {
    pub sources: Vec<SourceBlock>,
    pub not_found: Vec<String>,
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
    pub files: Vec<SkimFile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkimFile {
    pub path: String,
    pub loc: usize,
    pub lines: Vec<String>,
}

pub fn refresh_result(analyzer: &dyn IAnalyzer) -> RefreshResult {
    let mut languages: Vec<_> = analyzer
        .languages()
        .into_iter()
        .map(language_name)
        .collect();
    languages.sort();

    RefreshResult {
        languages,
        analyzed_files: analyzer.get_analyzed_files().len(),
        declarations: analyzer.get_all_declarations().len(),
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
    let truncated = grouped.len() > effective_limit;
    let files = grouped
        .into_iter()
        .take(effective_limit)
        .map(|(file, code_units)| SearchSymbolsFile {
            path: rel_path_string(&file),
            loc: file
                .read_to_string()
                .map(|content| line_count(&content))
                .unwrap_or(0),
            classes: collect_kind_names(&code_units, CodeUnitType::Class),
            functions: collect_kind_names(&code_units, CodeUnitType::Function),
            fields: collect_kind_names(&code_units, CodeUnitType::Field),
            modules: collect_kind_names(&code_units, CodeUnitType::Module),
        })
        .collect();

    SearchSymbolsResult {
        patterns,
        truncated,
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

    let mut outcomes: Vec<_> = selected_symbols
        .into_par_iter()
        .enumerate()
        .map(|(index, symbol)| {
            let definitions = matching_definitions(analyzer, &symbol, params.kind_filter);
            if definitions.is_empty() {
                return (index, Err(symbol));
            }

            let sources = definitions
                .into_iter()
                .flat_map(|code_unit| source_blocks_for_code_unit(analyzer, &code_unit, true))
                .collect::<Vec<_>>();

            if sources.is_empty() {
                (index, Err(symbol))
            } else {
                (index, Ok(sources))
            }
        })
        .collect();
    outcomes.sort_by_key(|(index, _)| *index);

    let mut sources = Vec::new();
    let mut not_found = Vec::new();
    for (_, outcome) in outcomes {
        match outcome {
            Ok(blocks) => sources.extend(dedup_source_blocks(blocks)),
            Err(symbol) => not_found.push(symbol),
        }
    }

    SymbolSourcesResult { sources, not_found }
}

pub fn get_file_summaries(analyzer: &dyn IAnalyzer, params: FilePatternsParams) -> SummaryResult {
    let files = expand_file_patterns(analyzer, &params.file_patterns);
    let mut summaries: Vec<_> = files
        .into_par_iter()
        .filter_map(|file| {
            let mut elements = Vec::new();
            for code_unit in analyzer.get_top_level_declarations(&file) {
                elements.extend(summary_elements_for_code_unit(analyzer, &code_unit));
            }

            if elements.is_empty() {
                return None;
            }

            Some(SummaryBlock {
                label: rel_path_string(&file),
                path: rel_path_string(&file),
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
    }
}

pub fn skim_files(analyzer: &dyn IAnalyzer, params: FilePatternsParams) -> SkimFilesResult {
    summarize_symbols(analyzer, params)
}

pub fn summarize_symbols(analyzer: &dyn IAnalyzer, params: FilePatternsParams) -> SkimFilesResult {
    let expanded = expand_file_patterns(analyzer, &params.file_patterns);
    let truncated = expanded.len() > FILE_SKIM_LIMIT;
    let files: Vec<_> = expanded
        .into_iter()
        .take(FILE_SKIM_LIMIT)
        .collect::<Vec<_>>()
        .into_par_iter()
        .map(|file| {
            let loc = file
                .read_to_string()
                .map(|content| line_count(&content))
                .unwrap_or(0);
            let lines = analyzer
                .summarize_symbols(&file)
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

    SkimFilesResult { truncated, files }
}

fn collect_kind_names(code_units: &[CodeUnit], kind: CodeUnitType) -> Vec<String> {
    let mut names: Vec<_> = code_units
        .iter()
        .filter(|code_unit| code_unit.kind() == kind)
        .map(CodeUnit::fq_name)
        .collect();
    names.sort();
    names.dedup();
    names
}

fn matching_definitions(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    kind_filter: SymbolKindFilter,
) -> Vec<CodeUnit> {
    analyzer
        .get_definitions(symbol)
        .into_iter()
        .filter(|code_unit| matches_kind_filter(code_unit, kind_filter))
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

fn matches_kind_filter(code_unit: &CodeUnit, filter: SymbolKindFilter) -> bool {
    match filter {
        SymbolKindFilter::Any => true,
        SymbolKindFilter::Class => code_unit.is_class(),
        SymbolKindFilter::Function => code_unit.is_function(),
        SymbolKindFilter::Field => code_unit.is_field(),
        SymbolKindFilter::Module => code_unit.is_module(),
    }
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
        for child in analyzer.get_direct_children(code_unit) {
            if child.is_anonymous() {
                continue;
            }
            elements.extend(summary_elements_for_code_unit(analyzer, &child));
        }
    }
    elements
}

fn signature_elements(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Vec<SummaryElement> {
    let signatures = analyzer.signatures_of(code_unit);
    if signatures.is_empty() {
        return Vec::new();
    }

    let mut ranges = analyzer.ranges_of(code_unit);
    ranges.sort_by_key(|range| (range.start_line, range.start_byte));
    let path = rel_path_string(code_unit.source());
    let fallback_start = ranges.first().map(|range| range.start_line).unwrap_or(1);

    signatures
        .into_iter()
        .enumerate()
        .filter_map(|(index, signature)| {
            let text = trim_summary_signature(&signature);
            if text.is_empty() {
                return None;
            }

            let line_count = text.lines().count().max(1);
            let start_line = ranges
                .get(index)
                .map(|range| range.start_line)
                .unwrap_or(fallback_start);
            let end_line = start_line + line_count.saturating_sub(1);
            Some(SummaryElement {
                path: path.clone(),
                start_line,
                end_line,
                text,
            })
        })
        .collect()
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
        for candidate in analyzer.get_definitions(&code_unit.fq_name()) {
            if candidate.source() == code_unit.source() {
                grouped.extend(analyzer.ranges_of(&candidate));
            }
        }
        grouped
    } else {
        analyzer.ranges_of(code_unit)
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
        .ranges_of(code_unit)
        .into_iter()
        .min_by_key(|range| (range.start_line, range.start_byte))
}

fn expand_file_patterns(analyzer: &dyn IAnalyzer, patterns: &[String]) -> Vec<ProjectFile> {
    let globs: Vec<_> = patterns
        .iter()
        .filter_map(|pattern| Pattern::new(&normalize_pattern(pattern)).ok())
        .collect();
    if globs.is_empty() {
        return Vec::new();
    }

    let mut matched: Vec<_> = analyzer
        .get_analyzed_files()
        .into_iter()
        .collect::<Vec<_>>()
        .into_par_iter()
        .filter(|file| {
            let path = rel_path_string(file);
            globs.iter().any(|glob| glob.matches(&path))
        })
        .collect();
    matched.sort();
    matched
}

fn normalize_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/")
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
    for (index, ch) in content.char_indices() {
        if ch == '\n' || ch == '\r' {
            lines.push(&content[start..index]);
            if ch == '\r' && content[index + 1..].starts_with('\n') {
                start = index + 2;
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
    use super::{SourceBlock, SummaryElement, trim_summary_signature};

    #[test]
    fn trims_synthetic_summary_lines() {
        assert_eq!(trim_summary_signature("class A {\n}\n"), "class A");
        assert_eq!(trim_summary_signature("[...]\n"), "");
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
            start_line: 10,
            end_line: 10,
            text: "class A {".to_string(),
        };
    }
}
