//! MCP `report_dead_code_and_unused_abstraction_smells` handler. Composes
//! declaration discovery with bounded graph-backed usage queries to report
//! likely dead code and one-call abstractions while skipping inconclusive
//! cases.

use super::{ReportLines, append_ambiguous_path_notes, resolve_project_files, sanitize_table_cell};
use crate::analyzer::common::language_for_target;
use crate::analyzer::usages::ImportGraphCandidateProvider;
use crate::analyzer::usages::{
    CandidateFileProvider, FallbackCandidateProvider, FuzzyResult, JsTsExportUsageGraphStrategy,
    PythonExportUsageGraphStrategy, RustExportUsageGraphStrategy, TextSearchCandidateProvider,
    UsageAnalyzer, UsageHit,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::path_utils::{AmbiguousPathInput, rel_path_string};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;

const DEFAULT_MIN_SCORE: i32 = 8;
const DEFAULT_MAX_FINDINGS: usize = 40;
const DEFAULT_MAX_INPUT_FILES: usize = 25;
const DEFAULT_MAX_CANDIDATE_SYMBOLS: usize = 200;
const DEFAULT_MAX_USAGE_CANDIDATE_FILES: usize = 1000;
const DEFAULT_MAX_USAGES_PER_SYMBOL: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReportDeadCodeAndUnusedAbstractionSmellsParams {
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub fq_names: Vec<String>,
    #[serde(default)]
    pub min_score: i32,
    #[serde(default)]
    pub max_findings: i32,
    #[serde(default)]
    pub max_input_files: i32,
    #[serde(default)]
    pub max_candidate_symbols: i32,
    #[serde(default)]
    pub max_usage_candidate_files: i32,
    #[serde(default)]
    pub max_usages_per_symbol: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportDeadCodeAndUnusedAbstractionSmellsResult {
    pub report: String,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
}

#[derive(Debug, Clone)]
struct CandidateSelection {
    candidates: Vec<CodeUnit>,
    truncated: bool,
}

#[derive(Debug, Clone)]
struct DeadCodeFinding {
    language: Language,
    score: i32,
    confidence: f64,
    kind: String,
    symbol: String,
    file: ProjectFile,
    start_line: usize,
    end_line: usize,
    total_usage_count: usize,
    external_usage_count: usize,
    evidence: String,
    rationale: String,
}

pub fn report_dead_code_and_unused_abstraction_smells(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> ReportDeadCodeAndUnusedAbstractionSmellsResult {
    let threshold = positive_or(params.min_score, DEFAULT_MIN_SCORE);
    let findings_cap = positive_or(params.max_findings, DEFAULT_MAX_FINDINGS as i32) as usize;
    let input_file_cap =
        positive_or(params.max_input_files, DEFAULT_MAX_INPUT_FILES as i32) as usize;
    let candidate_cap = positive_or(
        params.max_candidate_symbols,
        DEFAULT_MAX_CANDIDATE_SYMBOLS as i32,
    ) as usize;
    let usage_candidate_file_cap = positive_or(
        params.max_usage_candidate_files,
        DEFAULT_MAX_USAGE_CANDIDATE_FILES as i32,
    ) as usize;
    let usage_cap = positive_or(
        params.max_usages_per_symbol,
        DEFAULT_MAX_USAGES_PER_SYMBOL as i32,
    ) as usize;

    let resolved = resolve_project_files(analyzer.project(), params.file_paths);
    let ambiguous_paths = resolved.ambiguous_paths.clone();
    let resolved_file_count = resolved.files.len();
    let input_files: Vec<ProjectFile> = resolved.files.into_iter().take(input_file_cap).collect();
    let mut truncated = resolved.input_truncated || resolved_file_count > input_file_cap;
    let selected_files: BTreeSet<ProjectFile> = input_files.iter().cloned().collect();
    let mut skipped: Vec<String> = Vec::new();

    let candidate_selection = dead_code_candidates(
        analyzer,
        &input_files,
        &params.fq_names,
        &selected_files,
        candidate_cap,
        &mut skipped,
    );
    truncated |= candidate_selection.truncated;
    let mut findings: Vec<DeadCodeFinding> = Vec::new();

    for candidate in &candidate_selection.candidates {
        if let Some(finding) = analyze_candidate(
            analyzer,
            candidate,
            usage_candidate_file_cap,
            usage_cap,
            &mut skipped,
        ) && finding.score >= threshold
        {
            findings.push(finding);
        }
    }

    findings.sort_by(dead_code_finding_cmp);
    let shown = findings.len().min(findings_cap);
    let rows_truncated = findings.len() > shown;
    truncated |= rows_truncated;

    let mut lines = ReportLines::with_capacity(shown + skipped.len().min(10) + 16);
    lines.line("## Dead code and unused abstraction smells");
    lines.blank();
    lines.line(format!("- Min score: {threshold}"));
    lines.line(format!(
        "- Input files analyzed cap: {input_file_cap}{}",
        if resolved.input_truncated || resolved_file_count > input_file_cap {
            " (truncated)"
        } else {
            ""
        }
    ));
    lines.line(format!(
        "- Candidate symbol cap: {candidate_cap}{}",
        if candidate_selection.truncated {
            " (truncated)"
        } else {
            ""
        }
    ));
    lines.line(format!(
        "- Usage candidate file cap: {usage_candidate_file_cap}"
    ));
    lines.line(format!("- Usage cap per symbol: {usage_cap}"));
    lines.line("- Analysis mode: graph-backed tree-sitter usage analysis (best-effort).");
    lines.line(format!(
        "- Candidate symbols analyzed: {}",
        candidate_selection.candidates.len()
    ));
    lines.line(format!("- Findings shown: {shown} of {}", findings.len()));
    if !skipped.is_empty() {
        lines.line(format!("- Skipped symbols: {}", skipped.len()));
    }
    append_ambiguous_path_notes(&mut lines, &ambiguous_paths);
    lines.blank();

    if findings.is_empty() {
        lines.line(format!(
            "No dead code or unused abstraction smells met minScore {threshold}."
        ));
        append_skipped(&mut lines, &skipped);
        return ReportDeadCodeAndUnusedAbstractionSmellsResult {
            report: lines.build(),
            truncated,
            ambiguous_paths,
        };
    }

    lines.line(
        "| Score | Confidence | Kind | Symbol | File | Total Usages | External Usages | Evidence | Rationale |",
    );
    lines.line(
        "|------:|-----------:|------|--------|------|-------------:|----------------:|----------|-----------|",
    );
    for finding in findings.iter().take(shown) {
        let location = format!(
            "{}:{}-{}",
            rel_path_string(&finding.file),
            finding.start_line,
            finding.end_line
        );
        lines.line(format!(
            "| {} | {:.2} | `{}` | `{}` | `{}` | {} | {} | `{}` | `{}` |",
            finding.score,
            finding.confidence,
            sanitize_table_cell(&finding.kind),
            sanitize_table_cell(&finding.symbol),
            sanitize_table_cell(&location),
            finding.total_usage_count,
            finding.external_usage_count,
            sanitize_table_cell(&finding.evidence),
            sanitize_table_cell(&finding.rationale),
        ));
    }
    if rows_truncated {
        lines.blank();
        lines.line("- Note: output truncated; increase maxFindings to see more.");
    }
    append_skipped(&mut lines, &skipped);

    ReportDeadCodeAndUnusedAbstractionSmellsResult {
        report: lines.build(),
        truncated,
        ambiguous_paths,
    }
}

fn positive_or(value: i32, fallback: i32) -> i32 {
    if value > 0 { value } else { fallback }
}

fn append_skipped(lines: &mut ReportLines, skipped: &[String]) {
    if skipped.is_empty() {
        return;
    }
    lines.blank();
    lines.line("Skipped evidence:");
    for skip in skipped.iter().take(10) {
        lines.line(format!("- {skip}"));
    }
    if skipped.len() > 10 {
        lines.line(format!("- ... {} more skipped symbols", skipped.len() - 10));
    }
}

fn dead_code_candidates(
    analyzer: &dyn IAnalyzer,
    files: &[ProjectFile],
    fq_names: &[String],
    selected_files: &BTreeSet<ProjectFile>,
    candidate_cap: usize,
    skipped: &mut Vec<String>,
) -> CandidateSelection {
    let mut candidates: Vec<CodeUnit> = Vec::new();
    let mut seen: BTreeSet<CodeUnit> = BTreeSet::new();
    let targets: Vec<&str> = fq_names
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();

    if !targets.is_empty() {
        for fq_name in targets {
            let definitions = analyzer.get_definitions(fq_name);
            if definitions.is_empty() {
                skipped.push(format!("`{fq_name}`: no definition found"));
                continue;
            }
            let mut matched_any = false;
            for definition in definitions {
                if !selected_files.is_empty() && !selected_files.contains(definition.source()) {
                    continue;
                }
                if !is_dead_code_candidate(&definition) {
                    continue;
                }
                matched_any = true;
                if seen.insert(definition.clone()) {
                    candidates.push(definition);
                }
            }
            if !matched_any {
                skipped.push(format!(
                    "`{fq_name}`: language/declaration shape is not yet supported for smell analysis in selected files"
                ));
            }
        }
    } else {
        for file in files {
            for declaration in analyzer.get_declarations(file) {
                if !is_dead_code_candidate(&declaration) {
                    continue;
                }
                if seen.insert(declaration.clone()) {
                    candidates.push(declaration);
                }
            }
        }
    }

    candidates.sort_by(|left, right| {
        rel_path_string(left.source())
            .cmp(&rel_path_string(right.source()))
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
            .then_with(|| left.kind().cmp(&right.kind()))
    });
    let truncated = candidates.len() > candidate_cap;
    if truncated {
        skipped.push(format!(
            "candidate symbol cap reached: analyzed first {candidate_cap} of {} candidates",
            candidates.len()
        ));
        candidates.truncate(candidate_cap);
    }
    CandidateSelection {
        candidates,
        truncated,
    }
}

fn is_dead_code_candidate(code_unit: &CodeUnit) -> bool {
    if code_unit.is_synthetic() || code_unit.is_anonymous() {
        return false;
    }
    let language = code_unit_language(code_unit);
    matches!(
        language,
        Language::Rust | Language::Python | Language::JavaScript | Language::TypeScript
    ) && (code_unit.is_function() || code_unit.is_class() || code_unit.is_field())
}

fn analyze_candidate(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Option<DeadCodeFinding> {
    let language = code_unit_language(candidate);
    let range = analyzer
        .ranges_of(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)?;

    let query = query_graph_usages(analyzer, candidate, usage_candidate_file_cap, usage_cap)?;

    if query.candidate_files_truncated {
        skipped.push(format!(
            "`{}`: usage candidate files exceeded cap {usage_candidate_file_cap}; evidence is inconclusive",
            candidate.fq_name()
        ));
        return None;
    }

    let hits = match query.result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect::<Vec<_>>(),
        FuzzyResult::Ambiguous { .. } => {
            skipped.push(format!(
                "`{}`: usage analysis was ambiguous; evidence is inconclusive",
                candidate.fq_name()
            ));
            return None;
        }
        FuzzyResult::Failure { reason, .. } => {
            skipped.push(format!("`{}`: {reason}", candidate.fq_name()));
            return None;
        }
        FuzzyResult::TooManyCallsites {
            total_callsites,
            limit,
            ..
        } => {
            skipped.push(format!(
                "`{}`: too many call sites ({total_callsites}, limit {limit}); evidence is inconclusive",
                candidate.fq_name()
            ));
            return None;
        }
    };

    let non_self_hits: Vec<UsageHit> = hits
        .into_iter()
        .filter(|hit| hit.enclosing != *candidate)
        .collect();
    if non_self_hits.len() > 1 {
        return None;
    }

    let defining_owner = analyzer
        .parent_of(candidate)
        .unwrap_or_else(|| candidate.clone());
    let external_hits: Vec<&UsageHit> = non_self_hits
        .iter()
        .filter(|hit| is_external_usage(analyzer, &defining_owner, hit))
        .collect();

    let declaration_lines = span_lines(&range);
    let score = if non_self_hits.is_empty() {
        30 + (declaration_lines / 4).min(20) as i32
    } else {
        12 + (declaration_lines / 8).min(12) as i32
    };
    let confidence = if non_self_hits.is_empty() { 0.95 } else { 0.75 };
    let evidence = if let Some(hit) = non_self_hits.first() {
        format!(
            "only usage: {}:{} in {}{}",
            rel_path_string(&hit.file),
            hit.line,
            hit.enclosing.fq_name(),
            if external_hits.is_empty() {
                " (same owner)"
            } else {
                ""
            }
        )
    } else {
        "no non-self usages found".to_string()
    };
    let rationale = if non_self_hits.is_empty() {
        format!(
            "symbol has no usage evidence in {} tree-sitter analysis and may be generated residue",
            language_label(language)
        )
    } else {
        format!(
            "symbol has only one non-self caller in {} tree-sitter analysis and may be a low-value abstraction",
            language_label(language)
        )
    };

    Some(DeadCodeFinding {
        language,
        score,
        confidence,
        kind: candidate.kind().display_lowercase().to_string(),
        symbol: candidate.fq_name(),
        file: candidate.source().clone(),
        start_line: range.start_line + 1,
        end_line: range.end_line + 1,
        total_usage_count: non_self_hits.len(),
        external_usage_count: external_hits.len(),
        evidence,
        rationale,
    })
}

struct GraphQueryResult {
    candidate_files_truncated: bool,
    result: FuzzyResult,
}

fn query_graph_usages(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    usage_candidate_file_cap: usize,
    usage_cap: usize,
) -> Option<GraphQueryResult> {
    let strategy = graph_strategy_for(candidate)?;
    let provider: FallbackCandidateProvider<
        ImportGraphCandidateProvider,
        TextSearchCandidateProvider,
    > = crate::analyzer::usages::default_provider();
    let mut candidates = provider.find_candidates(candidate, analyzer);
    let candidate_files_truncated = candidates.len() > usage_candidate_file_cap;
    if candidate_files_truncated {
        candidates = candidates
            .into_iter()
            .take(usage_candidate_file_cap)
            .collect();
    }
    let result = strategy.find_usages(
        analyzer,
        std::slice::from_ref(candidate),
        &candidates,
        usage_cap,
    );
    Some(GraphQueryResult {
        candidate_files_truncated,
        result,
    })
}

fn graph_strategy_for(candidate: &CodeUnit) -> Option<Box<dyn UsageAnalyzer>> {
    if RustExportUsageGraphStrategy::can_handle(candidate) {
        return Some(Box::new(RustExportUsageGraphStrategy::new()));
    }
    if PythonExportUsageGraphStrategy::can_handle(candidate) {
        return Some(Box::new(PythonExportUsageGraphStrategy::new()));
    }
    if JsTsExportUsageGraphStrategy::can_handle(candidate) {
        return Some(Box::new(JsTsExportUsageGraphStrategy::new()));
    }
    None
}

fn code_unit_language(code_unit: &CodeUnit) -> Language {
    language_for_target(code_unit)
}

fn language_label(language: Language) -> &'static str {
    match language {
        Language::Rust => "Rust",
        Language::Python => "Python",
        Language::JavaScript => "JavaScript",
        Language::TypeScript => "TypeScript",
        _ => "graph-backed",
    }
}

fn is_external_usage(analyzer: &dyn IAnalyzer, defining_owner: &CodeUnit, hit: &UsageHit) -> bool {
    let hit_owner = analyzer
        .parent_of(&hit.enclosing)
        .unwrap_or_else(|| hit.enclosing.clone());
    hit_owner != *defining_owner
}

fn span_lines(range: &Range) -> usize {
    range.end_line.saturating_sub(range.start_line) + 1
}

fn dead_code_finding_cmp(left: &DeadCodeFinding, right: &DeadCodeFinding) -> Ordering {
    left.total_usage_count
        .cmp(&right.total_usage_count)
        .then_with(|| right.score.cmp(&left.score))
        .then_with(|| left.language.cmp(&right.language))
        .then_with(|| rel_path_string(&left.file).cmp(&rel_path_string(&right.file)))
        .then_with(|| left.symbol.cmp(&right.symbol))
}
