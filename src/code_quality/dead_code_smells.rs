//! MCP `report_dead_code_and_unused_abstraction_smells` handler. Composes
//! declaration discovery with bounded graph-backed usage queries to report
//! likely dead code and one-call abstractions while skipping inconclusive
//! cases.

use super::{ReportLines, append_ambiguous_path_notes, resolve_project_files, sanitize_table_cell};
use crate::analyzer::common::language_for_target;
use crate::analyzer::usages::ImportGraphCandidateProvider;
use crate::analyzer::usages::inverted_edges::{UsageEdges, UsageNodeKey};
use crate::analyzer::usages::js_ts_graph::JsTsScopedNodeStatus;
use crate::analyzer::usages::{
    CandidateFileProvider, FallbackCandidateProvider, FuzzyResult, JavaUsageGraphStrategy,
    JsTsExportUsageGraphStrategy, RustExportUsageGraphStrategy, TextSearchCandidateProvider,
    UsageAnalyzer, UsageHit,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range, RustAnalyzer};
use crate::hash::HashSet;
use crate::path_utils::{AmbiguousPathInput, rel_path_string};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

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
    let requested_usage_cap = positive_or(
        params.max_usages_per_symbol,
        DEFAULT_MAX_USAGES_PER_SYMBOL as i32,
    ) as usize;
    let usage_cap = requested_usage_cap.min(crate::analyzer::usages::inverted_edges::MAX_CALLSITES);

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
    let mut rust_candidates: Vec<CodeUnit> = Vec::new();
    let mut python_candidates: Vec<CodeUnit> = Vec::new();
    let mut jsts_candidates: Vec<CodeUnit> = Vec::new();
    let mut java_candidates: Vec<CodeUnit> = Vec::new();
    let mut java_overloaded_fqns: Option<HashSet<String>> = None;
    let mut java_static_imports_present: Option<bool> = None;
    let mut scala_files_present: Option<bool> = None;

    for candidate in &candidate_selection.candidates {
        match code_unit_language(candidate) {
            Language::Rust => {
                if !rust_candidate_needs_precise_member_scan(analyzer, candidate) {
                    rust_candidates.push(candidate.clone());
                    continue;
                }
            }
            Language::Python => {
                python_candidates.push(candidate.clone());
                continue;
            }
            Language::JavaScript | Language::TypeScript => {
                jsts_candidates.push(candidate.clone());
                continue;
            }
            Language::Java
                if !java_candidate_needs_precise_scan(
                    analyzer,
                    candidate,
                    &mut java_overloaded_fqns,
                    &mut java_static_imports_present,
                    &mut scala_files_present,
                ) =>
            {
                java_candidates.push(candidate.clone());
                continue;
            }
            _ => {}
        }
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
    findings.extend(
        analyze_rust_candidates_with_usage_graph(
            analyzer,
            &rust_candidates,
            usage_candidate_file_cap,
            usage_cap,
            &mut skipped,
        )
        .into_iter()
        .filter(|finding| finding.score >= threshold),
    );
    findings.extend(
        analyze_python_candidates_with_usage_graph(
            analyzer,
            &python_candidates,
            usage_candidate_file_cap,
            usage_cap,
            &mut skipped,
        )
        .into_iter()
        .filter(|finding| finding.score >= threshold),
    );
    findings.extend(
        analyze_jsts_candidates_with_scoped_usage_graph(
            analyzer,
            &jsts_candidates,
            usage_candidate_file_cap,
            usage_cap,
            &mut skipped,
        )
        .into_iter()
        .filter(|finding| finding.score >= threshold),
    );
    findings.extend(
        analyze_java_candidates_with_usage_graph(
            analyzer,
            &java_candidates,
            usage_candidate_file_cap,
            usage_cap,
            &mut skipped,
        )
        .into_iter()
        .filter(|finding| finding.score >= threshold),
    );

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
    if usage_cap == requested_usage_cap {
        lines.line(format!("- Usage cap per symbol: {usage_cap}"));
    } else {
        lines.line(format!(
            "- Usage cap per symbol: {usage_cap} (clamped from {requested_usage_cap} by graph call-site cap)"
        ));
    }
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
        Language::Rust
            | Language::Python
            | Language::JavaScript
            | Language::TypeScript
            | Language::Java
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

fn rust_candidate_needs_precise_member_scan(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
) -> bool {
    if !(candidate.is_function() || candidate.is_field()) {
        return false;
    }
    let Some(rust) = crate::analyzer::usages::rust_graph::resolve_rust_analyzer(analyzer) else {
        return false;
    };
    rust.parent_of(candidate).is_some()
}

fn analyze_rust_candidates_with_usage_graph(
    analyzer: &dyn IAnalyzer,
    candidates: &[CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let Some(rust) = crate::analyzer::usages::rust_graph::resolve_rust_analyzer(analyzer) else {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: Rust analyzer capability was unavailable; evidence is inconclusive",
                candidate.fq_name()
            ));
        }
        return Vec::new();
    };

    let rust_file_count = rust.get_analyzed_files().len();
    if rust_file_count > usage_candidate_file_cap {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: Rust usage graph candidate files exceeded cap {usage_candidate_file_cap} ({rust_file_count} Rust files); evidence is inconclusive",
                candidate.fq_name()
            ));
        }
        return Vec::new();
    }

    let mut nodes: HashSet<String> = analyzer
        .all_declarations()
        .filter(|unit| {
            code_unit_language(unit) == Language::Rust
                && !unit.is_synthetic()
                && (unit.is_function() || unit.is_class())
        })
        .map(CodeUnit::fq_name)
        .collect();
    nodes.extend(candidates.iter().map(CodeUnit::fq_name));

    let Some(edges) =
        crate::analyzer::usages::rust_graph::build_rust_usage_edges(analyzer, &nodes, |_| true)
    else {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: Rust usage graph could not be built; evidence is inconclusive",
                candidate.fq_name()
            ));
        }
        return Vec::new();
    };

    let declarations_by_fqn = rust_declarations_by_fqn(analyzer);
    let mut incoming: BTreeMap<String, GraphIncomingUsage> = BTreeMap::new();
    for ((caller, callee), weight) in edges.edges {
        let usage = incoming.entry(callee).or_default();
        usage.total += weight;
        usage.callers.entry(caller.clone()).or_insert(weight);
    }

    candidates
        .iter()
        .filter_map(|candidate| {
            let candidate_fqn = candidate.fq_name();
            if let Some(total_callsites) = edges.truncated.get(&candidate_fqn) {
                skipped.push(format!(
                    "`{candidate_fqn}`: too many workspace inbound call sites ({total_callsites}, limit {}); evidence is inconclusive",
                    crate::analyzer::usages::inverted_edges::MAX_CALLSITES
                ));
                return None;
            }
            let usage = incoming.get(&candidate_fqn).cloned().unwrap_or_default();
            if usage.total > usage_cap {
                skipped.push(format!(
                    "`{candidate_fqn}`: too many workspace inbound call sites ({}, limit {usage_cap}); evidence is inconclusive",
                    usage.total
                ));
                return None;
            }
            rust_graph_finding(
                analyzer,
                rust,
                &declarations_by_fqn,
                candidate,
                usage,
            )
        })
        .collect()
}

#[derive(Clone, Debug, Default)]
struct GraphIncomingUsage {
    total: usize,
    callers: BTreeMap<String, usize>,
}

fn analyze_python_candidates_with_usage_graph(
    analyzer: &dyn IAnalyzer,
    candidates: &[CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    analyze_fqn_candidates_with_usage_graph(
        FqnBulkGraphRequest {
            analyzer,
            language: Language::Python,
            candidates,
            usage_candidate_file_cap,
            usage_cap,
            skipped,
        },
        |unit| unit.is_function() || unit.is_class(),
        |nodes| {
            crate::analyzer::usages::python_graph::build_python_usage_edges(analyzer, nodes, |_| {
                true
            })
        },
        |analyzer, declarations_by_fqn, candidate, usage| {
            graph_finding_for_language(
                analyzer,
                Language::Python,
                declarations_by_fqn,
                candidate,
                usage,
            )
        },
    )
}

fn analyze_java_candidates_with_usage_graph(
    analyzer: &dyn IAnalyzer,
    candidates: &[CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    analyze_fqn_candidates_with_usage_graph(
        FqnBulkGraphRequest {
            analyzer,
            language: Language::Java,
            candidates,
            usage_candidate_file_cap,
            usage_cap,
            skipped,
        },
        |unit| unit.is_function() || unit.is_class(),
        |nodes| {
            crate::analyzer::usages::java_graph::build_java_usage_edges(analyzer, nodes, |_| true)
        },
        java_graph_finding,
    )
}

struct FqnBulkGraphRequest<'a, 's> {
    analyzer: &'a dyn IAnalyzer,
    language: Language,
    candidates: &'a [CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &'s mut Vec<String>,
}

fn analyze_fqn_candidates_with_usage_graph<BuildEdges, NodePredicate, BuildFinding>(
    request: FqnBulkGraphRequest<'_, '_>,
    node_predicate: NodePredicate,
    build_edges: BuildEdges,
    build_finding: BuildFinding,
) -> Vec<DeadCodeFinding>
where
    BuildEdges: FnOnce(&HashSet<String>) -> Option<UsageEdges>,
    NodePredicate: Fn(&CodeUnit) -> bool,
    BuildFinding: Fn(
        &dyn IAnalyzer,
        &BTreeMap<String, Vec<CodeUnit>>,
        &CodeUnit,
        GraphIncomingUsage,
    ) -> Option<DeadCodeFinding>,
{
    let FqnBulkGraphRequest {
        analyzer,
        language,
        candidates,
        usage_candidate_file_cap,
        usage_cap,
        skipped,
    } = request;

    if candidates.is_empty() {
        return Vec::new();
    }

    let file_count = analyzer
        .project()
        .analyzable_files(language)
        .map_or(0, |files| files.len());
    let label = language_label(language);
    if file_count > usage_candidate_file_cap {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: {label} usage graph candidate files exceeded cap {usage_candidate_file_cap} ({file_count} {label} files); evidence is inconclusive",
                candidate.fq_name()
            ));
        }
        return Vec::new();
    }

    let mut nodes: HashSet<String> = analyzer
        .all_declarations()
        .filter(|unit| {
            code_unit_language(unit) == language && !unit.is_synthetic() && node_predicate(unit)
        })
        .map(CodeUnit::fq_name)
        .collect();
    nodes.extend(candidates.iter().map(CodeUnit::fq_name));

    let Some(edges) = build_edges(&nodes) else {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: {label} usage graph could not be built; evidence is inconclusive",
                candidate.fq_name()
            ));
        }
        return Vec::new();
    };

    let declarations_by_fqn = declarations_by_fqn_for_language(analyzer, language);
    let mut incoming: BTreeMap<String, GraphIncomingUsage> = BTreeMap::new();
    for ((caller, callee), weight) in edges.edges {
        let usage = incoming.entry(callee).or_default();
        usage.total += weight;
        usage.callers.entry(caller.clone()).or_insert(weight);
    }

    candidates
        .iter()
        .filter_map(|candidate| {
            let candidate_fqn = candidate.fq_name();
            if let Some(total_callsites) = edges.truncated.get(&candidate_fqn) {
                skipped.push(format!(
                    "`{candidate_fqn}`: too many workspace inbound call sites ({total_callsites}, limit {}); evidence is inconclusive",
                    crate::analyzer::usages::inverted_edges::MAX_CALLSITES
                ));
                return None;
            }
            let usage = incoming.get(&candidate_fqn).cloned().unwrap_or_default();
            if usage.total > usage_cap {
                skipped.push(format!(
                    "`{candidate_fqn}`: too many workspace inbound call sites ({}, limit {usage_cap}); evidence is inconclusive",
                    usage.total
                ));
                return None;
            }
            build_finding(analyzer, &declarations_by_fqn, candidate, usage)
        })
        .collect()
}

fn analyze_jsts_candidates_with_scoped_usage_graph(
    analyzer: &dyn IAnalyzer,
    candidates: &[CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let jsts_file_count = [Language::JavaScript, Language::TypeScript]
        .into_iter()
        .map(|language| {
            analyzer
                .project()
                .analyzable_files(language)
                .map_or(0, |files| files.len())
        })
        .sum::<usize>();
    if jsts_file_count > usage_candidate_file_cap {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: JS/TS usage graph candidate files exceeded cap {usage_candidate_file_cap} ({jsts_file_count} JS/TS files); evidence is inconclusive",
                candidate.fq_name()
            ));
        }
        return Vec::new();
    }

    let mut nodes: HashSet<UsageNodeKey> = analyzer
        .all_declarations()
        .filter(|unit| {
            matches!(
                code_unit_language(unit),
                Language::JavaScript | Language::TypeScript
            ) && !unit.is_synthetic()
                && (unit.is_function() || unit.is_class() || unit.is_field())
        })
        .map(scoped_key_for)
        .collect();
    nodes.extend(candidates.iter().map(scoped_key_for));

    let Some(result) = crate::analyzer::usages::js_ts_graph::build_jsts_scoped_usage_edges(
        analyzer,
        &nodes,
        |_| true,
    ) else {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: JS/TS usage graph could not be built; evidence is inconclusive",
                candidate.fq_name()
            ));
        }
        return Vec::new();
    };

    let declarations_by_key = scoped_declarations_by_key_for_languages(
        analyzer,
        &[Language::JavaScript, Language::TypeScript],
    );
    let mut incoming: BTreeMap<UsageNodeKey, ScopedGraphIncomingUsage> = BTreeMap::new();
    for ((caller, callee), weight) in result.edges.edges {
        let usage = incoming.entry(callee).or_default();
        usage.total += weight;
        usage.callers.entry(caller).or_insert(weight);
    }

    candidates
        .iter()
        .filter_map(|candidate| {
            let candidate_key = scoped_key_for(candidate);
            match result.node_status.get(&candidate_key) {
                Some(JsTsScopedNodeStatus::Resolved) => {}
                Some(JsTsScopedNodeStatus::Ambiguous) => {
                    skipped.push(format!(
                        "`{}`: JS/TS export identity was ambiguous; evidence is inconclusive",
                        candidate.fq_name()
                    ));
                    return None;
                }
                Some(JsTsScopedNodeStatus::Unseedable) | None => {
                    skipped.push(format!(
                        "`{}`: JS/TS export seed could not be resolved; evidence is inconclusive",
                        candidate.fq_name()
                    ));
                    return None;
                }
            }
            if let Some(total_callsites) = result.edges.truncated.get(&candidate_key) {
                skipped.push(format!(
                    "`{}`: too many workspace inbound call sites ({total_callsites}, limit {}); evidence is inconclusive",
                    candidate.fq_name(),
                    crate::analyzer::usages::inverted_edges::MAX_CALLSITES
                ));
                return None;
            }
            let usage = incoming.get(&candidate_key).cloned().unwrap_or_default();
            if usage.total > usage_cap {
                skipped.push(format!(
                    "`{}`: too many workspace inbound call sites ({}, limit {usage_cap}); evidence is inconclusive",
                    candidate.fq_name(),
                    usage.total
                ));
                return None;
            }
            scoped_graph_finding_for_language(
                analyzer,
                code_unit_language(candidate),
                &declarations_by_key,
                candidate,
                usage,
            )
        })
        .collect()
}

fn rust_graph_finding(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    if usage.total > 1 {
        return None;
    }

    let range = analyzer
        .ranges_of(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)?;
    let declaration_lines = span_lines(&range);
    let is_public = rust.is_rust_public_like_declaration(candidate);
    let score = rust_graph_score(usage.total, declaration_lines, is_public);
    let confidence = rust_graph_confidence(usage.total, is_public);
    let evidence = graph_inbound_evidence(&usage);
    let rationale = rust_graph_rationale(usage.total, is_public);

    Some(DeadCodeFinding {
        language: Language::Rust,
        score,
        confidence,
        kind: candidate.kind().display_lowercase().to_string(),
        symbol: candidate.fq_name(),
        file: candidate.source().clone(),
        start_line: range.start_line + 1,
        end_line: range.end_line + 1,
        total_usage_count: usage.total,
        external_usage_count: external_usage_count(
            analyzer,
            declarations_by_fqn,
            candidate,
            &usage,
        ),
        evidence,
        rationale,
    })
}

fn graph_finding_for_language(
    analyzer: &dyn IAnalyzer,
    language: Language,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    if usage.total > 1 {
        return None;
    }

    let range = analyzer
        .ranges_of(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)?;
    let declaration_lines = span_lines(&range);
    let score = graph_score(usage.total, declaration_lines);
    let confidence = if usage.total == 0 { 0.90 } else { 0.70 };
    let evidence = graph_inbound_evidence(&usage);
    let label = language_label(language);
    let rationale = if usage.total == 0 {
        format!(
            "symbol has no workspace inbound usage evidence in {label} tree-sitter analysis and may be generated residue"
        )
    } else {
        format!(
            "symbol has only one workspace inbound caller in {label} tree-sitter analysis and may be a low-value abstraction"
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
        total_usage_count: usage.total,
        external_usage_count: external_usage_count(
            analyzer,
            declarations_by_fqn,
            candidate,
            &usage,
        ),
        evidence,
        rationale,
    })
}

fn java_graph_finding(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    if usage.total > 1 {
        return None;
    }

    let range = analyzer
        .ranges_of(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)?;
    let declaration_lines = span_lines(&range);
    let is_public = java_public_like_declaration(analyzer, candidate);
    let score = java_graph_score(usage.total, declaration_lines, is_public);
    let confidence = java_graph_confidence(usage.total, is_public);
    let evidence = graph_inbound_evidence(&usage);
    let rationale = java_graph_rationale(usage.total, is_public);

    Some(DeadCodeFinding {
        language: Language::Java,
        score,
        confidence,
        kind: candidate.kind().display_lowercase().to_string(),
        symbol: candidate.fq_name(),
        file: candidate.source().clone(),
        start_line: range.start_line + 1,
        end_line: range.end_line + 1,
        total_usage_count: usage.total,
        external_usage_count: external_usage_count(
            analyzer,
            declarations_by_fqn,
            candidate,
            &usage,
        ),
        evidence,
        rationale,
    })
}

#[derive(Clone, Debug, Default)]
struct ScopedGraphIncomingUsage {
    total: usize,
    callers: BTreeMap<UsageNodeKey, usize>,
}

fn scoped_graph_finding_for_language(
    analyzer: &dyn IAnalyzer,
    language: Language,
    declarations_by_key: &BTreeMap<UsageNodeKey, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: ScopedGraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    if usage.total > 1 {
        return None;
    }

    let range = analyzer
        .ranges_of(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)?;
    let declaration_lines = span_lines(&range);
    let score = graph_score(usage.total, declaration_lines);
    let confidence = if usage.total == 0 { 0.90 } else { 0.70 };
    let evidence = scoped_graph_inbound_evidence(&usage);
    let label = language_label(language);
    let rationale = if usage.total == 0 {
        format!(
            "symbol has no workspace inbound usage evidence in {label} tree-sitter analysis and may be generated residue"
        )
    } else {
        format!(
            "symbol has only one workspace inbound caller in {label} tree-sitter analysis and may be a low-value abstraction"
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
        total_usage_count: usage.total,
        external_usage_count: scoped_external_usage_count(
            analyzer,
            declarations_by_key,
            candidate,
            &usage,
        ),
        evidence,
        rationale,
    })
}

fn graph_score(total_usage_count: usize, declaration_lines: usize) -> i32 {
    if total_usage_count == 0 {
        30 + (declaration_lines / 4).min(20) as i32
    } else {
        12 + (declaration_lines / 8).min(12) as i32
    }
}

fn rust_graph_score(total_usage_count: usize, declaration_lines: usize, is_public: bool) -> i32 {
    match (total_usage_count, is_public) {
        (0, true) => 10 + (declaration_lines / 8).min(8) as i32,
        (0, false) => 30 + (declaration_lines / 4).min(20) as i32,
        (_, true) => 8 + (declaration_lines / 16).min(6) as i32,
        (_, false) => 12 + (declaration_lines / 8).min(12) as i32,
    }
}

fn java_graph_score(total_usage_count: usize, declaration_lines: usize, is_public: bool) -> i32 {
    match (total_usage_count, is_public) {
        (0, true) => 10 + (declaration_lines / 8).min(8) as i32,
        (0, false) => graph_score(total_usage_count, declaration_lines),
        (_, true) => 8 + (declaration_lines / 16).min(6) as i32,
        (_, false) => graph_score(total_usage_count, declaration_lines),
    }
}

fn rust_graph_confidence(total_usage_count: usize, is_public: bool) -> f64 {
    match (total_usage_count, is_public) {
        (0, true) => 0.55,
        (0, false) => 0.90,
        (_, true) => 0.45,
        (_, false) => 0.70,
    }
}

fn java_graph_confidence(total_usage_count: usize, is_public: bool) -> f64 {
    match (total_usage_count, is_public) {
        (0, true) => 0.55,
        (0, false) => 0.90,
        (_, true) => 0.45,
        (_, false) => 0.70,
    }
}

fn graph_inbound_evidence(usage: &GraphIncomingUsage) -> String {
    if usage.total == 0 {
        return "no non-self usages found".to_string();
    }
    if let Some((caller, weight)) = usage.callers.iter().next() {
        if *weight == 1 {
            format!("one workspace inbound edge from {caller}")
        } else {
            format!("one workspace inbound caller: {caller} ({weight} references)")
        }
    } else {
        "one workspace inbound edge".to_string()
    }
}

fn scoped_graph_inbound_evidence(usage: &ScopedGraphIncomingUsage) -> String {
    if usage.total == 0 {
        return "no non-self usages found".to_string();
    }
    if let Some((caller, weight)) = usage.callers.iter().next() {
        if *weight == 1 {
            format!("one workspace inbound edge from {}", caller.fqn)
        } else {
            format!(
                "one workspace inbound caller: {} ({weight} references)",
                caller.fqn
            )
        }
    } else {
        "one workspace inbound edge".to_string()
    }
}

fn rust_graph_rationale(total_usage_count: usize, is_public: bool) -> String {
    match (total_usage_count, is_public) {
        (0, true) => {
            "public Rust symbol is unreferenced in workspace; it may be untested public surface or consumed externally".to_string()
        }
        (0, false) => {
            "symbol has no workspace inbound usage evidence in Rust tree-sitter analysis and may be generated residue".to_string()
        }
        (_, true) => {
            "public Rust symbol has only one workspace inbound reference; it may be lightly tested public surface or consumed externally".to_string()
        }
        (_, false) => {
            "symbol has only one workspace inbound caller in Rust tree-sitter analysis and may be a low-value abstraction".to_string()
        }
    }
}

fn java_graph_rationale(total_usage_count: usize, is_public: bool) -> String {
    match (total_usage_count, is_public) {
        (0, true) => {
            "public Java symbol is unreferenced in workspace; it may be untested public surface or consumed externally".to_string()
        }
        (0, false) => {
            "symbol has no workspace inbound usage evidence in Java tree-sitter analysis and may be generated residue".to_string()
        }
        (_, true) => {
            "public Java symbol has only one workspace inbound reference; it may be lightly tested public surface or consumed externally".to_string()
        }
        (_, false) => {
            "symbol has only one workspace inbound caller in Java tree-sitter analysis and may be a low-value abstraction".to_string()
        }
    }
}

fn scoped_declarations_by_key_for_languages(
    analyzer: &dyn IAnalyzer,
    languages: &[Language],
) -> BTreeMap<UsageNodeKey, Vec<CodeUnit>> {
    let mut declarations: BTreeMap<UsageNodeKey, Vec<CodeUnit>> = BTreeMap::new();
    for declaration in analyzer
        .all_declarations()
        .filter(|unit| languages.contains(&code_unit_language(unit)))
    {
        declarations
            .entry(scoped_key_for(declaration))
            .or_default()
            .push(declaration.clone());
    }
    declarations
}

fn scoped_external_usage_count(
    analyzer: &dyn IAnalyzer,
    declarations_by_key: &BTreeMap<UsageNodeKey, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: &ScopedGraphIncomingUsage,
) -> usize {
    usage
        .callers
        .iter()
        .filter(|(caller, _)| {
            let Some(caller) = declarations_by_key
                .get(caller)
                .and_then(|declarations| declarations.first())
            else {
                return true;
            };
            let defining_owner = analyzer
                .parent_of(candidate)
                .unwrap_or_else(|| candidate.clone());
            let caller_owner = analyzer.parent_of(caller).unwrap_or_else(|| caller.clone());
            caller_owner != defining_owner
        })
        .map(|(_, weight)| *weight)
        .sum()
}

fn scoped_key_for(unit: &CodeUnit) -> UsageNodeKey {
    UsageNodeKey::new(unit.source().clone(), unit.fq_name())
}

fn java_candidate_needs_precise_scan(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    overloaded_fqns: &mut Option<HashSet<String>>,
    static_imports_present: &mut Option<bool>,
    scala_files_present: &mut Option<bool>,
) -> bool {
    let empty_overloads = HashSet::default();
    let overloads = if candidate.is_function() {
        overloaded_fqns.get_or_insert_with(|| java_overloaded_function_fqns(analyzer))
    } else {
        &empty_overloads
    };
    let has_static_imports = candidate.is_function()
        && *static_imports_present.get_or_insert_with(|| java_static_imports_present(analyzer));
    let has_scala_files =
        *scala_files_present.get_or_insert_with(|| has_analyzable_files(analyzer, Language::Scala));

    matches!(
        crate::analyzer::usages::java_graph::dead_code_bulk_eligibility(
            analyzer,
            candidate,
            overloads,
            has_static_imports,
            has_scala_files,
        ),
        crate::analyzer::usages::java_graph::JavaDeadCodeBulkEligibility::NeedsPrecise
    )
}

fn java_overloaded_function_fqns(analyzer: &dyn IAnalyzer) -> HashSet<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for declaration in analyzer.all_declarations().filter(|unit| {
        code_unit_language(unit) == Language::Java && !unit.is_synthetic() && unit.is_function()
    }) {
        *counts.entry(declaration.fq_name()).or_default() += 1;
    }
    counts
        .into_iter()
        .filter_map(|(fqn, count)| (count > 1).then_some(fqn))
        .collect()
}

fn has_analyzable_files(analyzer: &dyn IAnalyzer, language: Language) -> bool {
    analyzer
        .project()
        .analyzable_files(language)
        .is_ok_and(|files| !files.is_empty())
}

fn java_static_imports_present(analyzer: &dyn IAnalyzer) -> bool {
    analyzer
        .project()
        .analyzable_files(Language::Java)
        .is_ok_and(|files| {
            files.into_iter().any(|file| {
                file.read_to_string()
                    .is_ok_and(|source| source.contains("import static "))
            })
        })
}

fn java_public_like_declaration(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    analyzer
        .get_source(candidate, true)
        .is_some_and(|source| contains_java_visibility_modifier(&source, "public"))
}

fn contains_java_visibility_modifier(source: &str, modifier: &str) -> bool {
    source
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|token| token == modifier)
}

fn rust_declarations_by_fqn(analyzer: &dyn IAnalyzer) -> BTreeMap<String, Vec<CodeUnit>> {
    declarations_by_fqn_for_language(analyzer, Language::Rust)
}

fn declarations_by_fqn_for_language(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> BTreeMap<String, Vec<CodeUnit>> {
    let mut declarations: BTreeMap<String, Vec<CodeUnit>> = BTreeMap::new();
    for declaration in analyzer
        .all_declarations()
        .filter(|unit| code_unit_language(unit) == language)
    {
        declarations
            .entry(declaration.fq_name())
            .or_default()
            .push(declaration.clone());
    }
    declarations
}

fn external_usage_count(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: &GraphIncomingUsage,
) -> usize {
    usage
        .callers
        .iter()
        .filter(|(caller, _)| edge_is_external(analyzer, declarations_by_fqn, caller, candidate))
        .map(|(_, weight)| *weight)
        .sum()
}

fn edge_is_external(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    caller_fqn: &str,
    candidate: &CodeUnit,
) -> bool {
    let Some(caller) = declarations_by_fqn
        .get(caller_fqn)
        .and_then(|declarations| declarations.first())
    else {
        return true;
    };
    let defining_owner = analyzer
        .parent_of(candidate)
        .unwrap_or_else(|| candidate.clone());
    let caller_owner = analyzer.parent_of(caller).unwrap_or_else(|| caller.clone());
    caller_owner != defining_owner
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
    if JsTsExportUsageGraphStrategy::can_handle(candidate) {
        return Some(Box::new(JsTsExportUsageGraphStrategy::new()));
    }
    if JavaUsageGraphStrategy::can_handle(candidate) {
        return Some(Box::new(JavaUsageGraphStrategy::new()));
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
        Language::Java => "Java",
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
