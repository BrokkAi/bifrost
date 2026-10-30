//! MCP `report_dead_code_and_unused_abstraction_smells` handler. Composes
//! declaration discovery with bounded graph-backed usage queries to report
//! likely dead code and one-call abstractions while skipping inconclusive
//! cases.

use crate::code_quality::ReportLines;

use crate::code_quality::append_ambiguous_path_notes;

use crate::code_quality::resolve_project_files;

use crate::code_quality::resolve_project_files_or_all_analyzed;

use crate::code_quality::sanitize_table_cell;

use brokk_bifrost_core::analyzer::common::language_for_target;

pub(crate) use brokk_bifrost_analysis::analyzer::common::declaration_header;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeBulkEdges;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeBulkPreflight;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeBulkProof;

use brokk_bifrost_analysis::analyzer::languages::DeadCodeRouting;

use brokk_bifrost_analysis::analyzer::languages::EdgePassId;

use brokk_bifrost_analysis::analyzer::languages::LanguageGraphBackend;

use brokk_bifrost_analysis::analyzer::languages::NativeWorkspaceGraphProvider;

use brokk_bifrost_analysis::analyzer::languages::edge_passes;

use brokk_bifrost_analysis::analyzer::languages::language_support_for_hook;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;

use brokk_bifrost_analysis::analyzer::usages::candidates::ImportGraphCandidateProvider;

use brokk_bifrost_core::analyzer::usages::inverted_edges::JsTsScopedNodeStatus;

use brokk_bifrost_core::analyzer::usages::inverted_edges::JsTsScopedUsageEdges;

use brokk_bifrost_core::analyzer::usages::inverted_edges::NodeKey;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageNodeKey;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;

use brokk_bifrost_analysis::analyzer::usages::workspace_graph::is_graph_declaration;

use brokk_bifrost_analysis::analyzer::usages::traits::CandidateFileProvider;

use brokk_bifrost_analysis::analyzer::usages::candidates::FallbackCandidateProvider;

use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use brokk_bifrost_analysis::analyzer::usages::candidates::TextSearchCandidateProvider;

use brokk_bifrost_analysis::analyzer::usages::traits::{GraphUsageBatchQuery, UsageAnalyzer};
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::usages::model::UsageHit;

use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;

use brokk_bifrost_core::analyzer::usages::model::UsageHitSurface;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_analysis::path_utils::AmbiguousPathInput;

use brokk_bifrost_core::path_utils::rel_path_string;

use brokk_bifrost_core::analyzer::structural::edges::EdgeAxis;

use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const DEFAULT_MIN_SCORE: i32 = 8;
const DEFAULT_MAX_FINDINGS: usize = 40;
const DEFAULT_MAX_INPUT_FILES: usize = 25;
const DEFAULT_MAX_CANDIDATE_SYMBOLS: usize = 200;
const DEFAULT_MAX_USAGE_CANDIDATE_FILES: usize = 1000;
/// Findings are emitted only for symbols with zero or one inbound usage. Stop
/// precise usage scans as soon as a second site proves that the symbol cannot be
/// a dead-code or one-call-abstraction smell.
const MAX_USAGES_FOR_SMELL: usize = 1;

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

struct GraphFindingDetails {
    score: i32,
    confidence: f64,
    external_usage_count: usize,
    evidence: String,
    rationale: String,
}

fn build_graph_dead_code_finding(
    language: Language,
    candidate: &CodeUnit,
    range: Range,
    total_usage_count: usize,
    details: GraphFindingDetails,
) -> DeadCodeFinding {
    DeadCodeFinding {
        language,
        score: details.score,
        confidence: details.confidence,
        kind: candidate.kind().display_lowercase().to_string(),
        symbol: candidate.fq_name(),
        file: candidate.source().clone(),
        start_line: range.start_line + 1,
        end_line: range.end_line + 1,
        total_usage_count,
        external_usage_count: details.external_usage_count,
        evidence: details.evidence,
        rationale: details.rationale,
    }
}

pub fn report_dead_code_and_unused_abstraction_smells(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> ReportDeadCodeAndUnusedAbstractionSmellsResult {
    let query_scope =
        brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(analyzer);
    let generation = analyzer.project().analysis_generation();
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
    let requested_usage_cap =
        positive_or(params.max_usages_per_symbol, MAX_USAGES_FOR_SMELL as i32) as usize;
    let usage_cap = requested_usage_cap.min(MAX_USAGES_FOR_SMELL);

    let has_explicit_file_scope = !params.file_paths.is_empty();
    let resolved = if params.fq_names.is_empty() {
        resolve_project_files_or_all_analyzed(analyzer, params.file_paths)
    } else {
        // FQ-name-only selection already discovers its definitions through the
        // analyzer index. Keep an empty path list unbounded instead of first
        // truncating the workspace to `max_input_files`.
        resolve_project_files(analyzer, params.file_paths)
    };
    let ambiguous_paths = resolved.ambiguous_paths.clone();
    let resolved_file_count = resolved.files.len();
    let input_files: Vec<ProjectFile> = resolved.files.into_iter().take(input_file_cap).collect();
    let mut truncated = resolved.input_truncated || resolved_file_count > input_file_cap;
    let selected_file_ids: HashSet<PathBuf> =
        input_files.iter().map(canonical_file_identity).collect();
    let mut skipped: Vec<String> = Vec::new();

    let mut declaration_syntax = DeclarationSyntaxCache::new(analyzer);
    let candidate_selection = dead_code_candidates(
        &mut declaration_syntax,
        &input_files,
        &params.fq_names,
        &selected_file_ids,
        has_explicit_file_scope,
        candidate_cap,
        &mut skipped,
    );
    truncated |= candidate_selection.truncated;
    // Resolve excluded-file names once for the whole report, before either
    // native projection or precise inverse search can declare a candidate dead.
    let outside_build_names = (|| -> brokk_bifrost_analysis::analyzer::store::Result<_> {
        let languages: HashSet<_> = candidate_selection
            .candidates
            .iter()
            .map(code_unit_language)
            .collect();
        let mut files = HashSet::default();
        for language in languages {
            if let Some(support) =
                language_support_for_hook(language, "dead_code_outside_build_files")
            {
                files.extend(support.dead_code_outside_build_files(analyzer)?);
            }
        }
        let mut files: Vec<_> = files.into_iter().collect();
        files.sort();
        let names: HashSet<_> = candidate_selection
            .candidates
            .iter()
            .map(|candidate| strip_raw_identifier_prefix(candidate.terminal_name()).to_string())
            .collect();
        let names: Vec<_> = names.into_iter().collect();
        analyzer.reference_names_in_files(
            brokk_bifrost_analysis::analyzer::i_analyzer::ReferenceNamesInFilesRequest {
                files: &files,
                names: &names,
            },
        )
    })();
    let graph_passes = edge_passes();
    let mut scope_notes = Vec::new();
    let mut coverage_vetoes = HashMap::default();
    for language in candidate_selection
        .candidates
        .iter()
        .map(code_unit_language)
        .collect::<HashSet<_>>()
    {
        let Some(support) = language_support_for_hook(language, "dead_code_coverage") else {
            continue;
        };
        let candidates = candidate_selection
            .candidates
            .iter()
            .filter(|candidate| code_unit_language(candidate) == language)
            .cloned()
            .collect::<Vec<_>>();
        // Precise native candidates need the same input authority as graph
        // candidates. An unpublished caller must not disappear from admission.
        if support.dead_code().bulk.is_none()
            && let Some(provider) = graph_passes.iter().find_map(|entry| {
                let LanguageGraphBackend::Native(provider) = entry.backend else {
                    return None;
                };
                entry.languages.contains(&language).then_some(provider)
            })
        {
            let inventory = analyzer
                .source_file_inventory()
                .rows
                .into_iter()
                .filter(|file| {
                    brokk_bifrost_core::analyzer::common::language_for_file(file) == language
                })
                .collect::<Vec<_>>();
            if let Some(failure) = provider.input_failure(analyzer, &inventory) {
                for candidate in &candidates {
                    coverage_vetoes.insert(
                        candidate.declaration_id(),
                        format!("{}; files: {:?}", failure.reason, failure.files),
                    );
                }
                continue;
            }
            match provider.excluded_sources(analyzer) {
                Ok(files) if files.is_empty() => {}
                outcome => {
                    for candidate in &candidates {
                        coverage_vetoes.insert(
                            candidate.declaration_id(),
                            format!("source admission coverage unavailable: {outcome:?}"),
                        );
                    }
                    continue;
                }
            }
        }
        match support.dead_code_coverage(analyzer, &candidates) {
            Ok(coverage) => {
                scope_notes.extend(coverage.note);
                coverage_vetoes.extend(coverage.vetoes);
            }
            Err(error) => {
                analyzer.record_query_failure(error.clone());
                for candidate in candidates {
                    coverage_vetoes.insert(
                        candidate.declaration_id(),
                        format!("dead-code coverage unavailable: {error}"),
                    );
                }
            }
        }
    }
    scope_notes.sort();
    scope_notes.dedup();
    let mut findings: Vec<DeadCodeFinding> = Vec::new();
    // One bucket per bulk proof, not per language: JavaScript and TypeScript candidates
    // share a proof while Java, Scala and Kotlin do not. A bucket is created on first
    // sight of a language that has a proof, because its routing memo is what makes the
    // whole-workspace facts a per-report cost rather than a per-candidate one.
    let mut buckets: HashMap<EdgePassId, DeadCodeBulkBucket> = HashMap::default();
    struct NativeDeadCodeBucket {
        provider: &'static dyn NativeWorkspaceGraphProvider,
        languages: Vec<Language>,
        candidates: Vec<CodeUnit>,
    }
    let mut native_buckets: HashMap<EdgePassId, NativeDeadCodeBucket> = HashMap::default();
    // Deferred queries retain their original skip positions; grouping must not
    // change which ten explanations the report presents first.
    let mut precise_go = Vec::new();
    for candidate in &candidate_selection.candidates {
        if let Some(reason) = coverage_vetoes.get(&candidate.declaration_id()) {
            skipped.push(format!(
                "`{}`: {reason}; evidence is inconclusive",
                candidate.fq_name()
            ));
            continue;
        }
        match &outside_build_names {
            Err(error) => {
                skipped.push(format!("`{}`: outside-build reference inventory unavailable ({error}); evidence is inconclusive", candidate.fq_name()));
                continue;
            }
            Ok(names) => {
                if let Some(file) = names
                    .by_name
                    .get(strip_raw_identifier_prefix(candidate.terminal_name()))
                {
                    skipped.push(format!("`{}`: referenced from file outside the selected build (`{}`); evidence is inconclusive", candidate.fq_name(), rel_path_string(file)));
                    continue;
                }
            }
        }
        let support = language_support_for_hook(code_unit_language(candidate), "dead_code");
        let dead_code = support
            .map(|support| support.dead_code())
            .unwrap_or_default();
        if support.is_some_and(|support| support.dead_code_needs_precise_scan(analyzer, candidate))
        {
            if code_unit_language(candidate) == Language::Go
                && graph_strategy_for(candidate).is_some()
            {
                if let Some(range) = candidate_range(analyzer, candidate) {
                    precise_go.push((candidate, range, skipped.len()));
                }
                continue;
            }
            if let Some(finding) = analyze_candidate(
                &mut declaration_syntax,
                candidate,
                usage_candidate_file_cap,
                usage_cap,
                &mut skipped,
            ) && finding.score >= threshold
            {
                findings.push(finding);
            }
            continue;
        }
        // A language's specialized dead-code proof can retain caller evidence
        // that the general workspace graph does not project, such as Go package
        // variable initializer edges. Keep that proof authoritative when present.
        if is_graph_declaration(candidate)
            && dead_code.bulk.is_none()
            && let Some((entry, provider)) = graph_passes.iter().find_map(|entry| {
                let LanguageGraphBackend::Native(provider) = entry.backend else {
                    return None;
                };
                entry
                    .languages
                    .contains(&code_unit_language(candidate))
                    .then_some((entry, provider))
            })
        {
            native_buckets
                .entry(entry.id)
                .or_insert_with(|| NativeDeadCodeBucket {
                    provider,
                    languages: entry.languages.clone(),
                    candidates: Vec::new(),
                })
                .candidates
                .push(candidate.clone());
            continue;
        }
        if let Some(proof) = dead_code.bulk {
            let bucket = buckets
                .entry(proof.id())
                .or_insert_with(|| DeadCodeBulkBucket {
                    proof,
                    memo: proof.new_memo(),
                    candidates: Vec::new(),
                    precise_candidates: Vec::new(),
                });
            let routing = DeadCodeRouting {
                analyzer,
                candidate,
                file_cap: usage_candidate_file_cap,
                memo: bucket.memo.as_mut(),
            };
            if !proof.needs_precise_scan(routing) {
                bucket.candidates.push(candidate.clone());
                continue;
            }
            if proof.supports_precise_inbound_preflight(DeadCodeRouting {
                analyzer,
                candidate,
                file_cap: usage_candidate_file_cap,
                memo: bucket.memo.as_mut(),
            }) {
                bucket.precise_candidates.push(candidate.clone());
                continue;
            }
        }
        if let Some(finding) = analyze_candidate(
            &mut declaration_syntax,
            candidate,
            usage_candidate_file_cap,
            usage_cap,
            &mut skipped,
        ) && finding.score >= threshold
        {
            findings.push(finding);
        }
    }
    let precise_queries = query_graph_usage_batches(
        analyzer,
        &precise_go
            .iter()
            .map(|(candidate, _, _)| *candidate)
            .collect::<Vec<_>>(),
        usage_candidate_file_cap,
        usage_cap,
    );
    let mut deferred_skip_count = 0;
    for ((candidate, range, skip_position), query) in precise_go.into_iter().zip(precise_queries) {
        let mut candidate_skips = Vec::new();
        if let Some(finding) = analyze_candidate_query(
            &mut declaration_syntax,
            candidate,
            range,
            query,
            usage_candidate_file_cap,
            &mut candidate_skips,
        ) && finding.score >= threshold
        {
            findings.push(finding);
        }
        let position = skip_position + deferred_skip_count;
        deferred_skip_count += candidate_skips.len();
        skipped.splice(position..position, candidate_skips);
    }
    for id in EdgePassId::ALL {
        if let Some(bucket) = native_buckets.remove(&id) {
            findings.extend(
                prove_native_candidates(
                    &mut declaration_syntax,
                    bucket.provider,
                    &bucket.languages,
                    &bucket.candidates,
                    usage_candidate_file_cap,
                    usage_cap,
                    &mut skipped,
                )
                .into_iter()
                .filter(|finding| finding.score >= threshold),
            );
        }
        let Some(bucket) = buckets.remove(&id) else {
            continue;
        };
        findings.extend(
            preflight_precise_candidates(
                &mut declaration_syntax,
                bucket.proof,
                &bucket.precise_candidates,
                usage_candidate_file_cap,
                usage_cap,
                &mut skipped,
            )
            .into_iter()
            .filter(|finding| finding.score >= threshold),
        );
        findings.extend(
            prove_bulk_candidates(
                &mut declaration_syntax,
                bucket.proof,
                &bucket.candidates,
                usage_candidate_file_cap,
                usage_cap,
                &mut skipped,
            )
            .into_iter()
            .filter(|finding| finding.score >= threshold),
        );
    }

    if let Some(error) = query_scope.store_error() {
        findings.clear();
        skipped.push(format!(
            "dead-code analysis input authority failed: {error}; no findings published"
        ));
    } else if analyzer.project().analysis_generation() != generation {
        findings.clear();
        skipped.push(
            "workspace generation changed during dead-code analysis; no findings published".into(),
        );
    }
    // Test-support census records the full request before display caps. It is
    // opt-in, bounded by candidate admission, and retains nothing across calls.
    #[cfg(any(test, feature = "test-support"))]
    if std::env::var_os("BIFROST_DEAD_CODE_TRACE").is_some() {
        let census = serde_json::json!({
            "candidates": candidate_selection.candidates.iter().map(|candidate| serde_json::json!({
                "symbol": candidate.fq_name(), "file": rel_path_string(candidate.source()),
                "kind": candidate.kind().display_lowercase().to_string(),
            })).collect::<Vec<_>>(),
            "findings": findings.iter().map(|finding| serde_json::json!({
                "symbol": finding.symbol, "file": rel_path_string(&finding.file),
                "total_usages": finding.total_usage_count,
            })).collect::<Vec<_>>(),
            "skipped": skipped,
        });
        eprintln!("BIFROST_DEAD_CODE_TRACE {census}");
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
    if usage_cap == requested_usage_cap {
        lines.line(format!("- Usage cap per symbol: {usage_cap}"));
    } else {
        lines.line(format!(
            "- Usage cap per symbol: {usage_cap} (clamped from {requested_usage_cap} by smell relevance threshold)"
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
    for note in &scope_notes {
        lines.line(format!("- Note: {note}"));
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
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    files: &[ProjectFile],
    fq_names: &[String],
    selected_file_ids: &HashSet<PathBuf>,
    restrict_to_selected_files: bool,
    candidate_cap: usize,
    skipped: &mut Vec<String>,
) -> CandidateSelection {
    let analyzer = declaration_syntax.analyzer;
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
                if restrict_to_selected_files
                    && !selected_file_ids.contains(&canonical_file_identity(definition.source()))
                {
                    continue;
                }
                if !is_dead_code_candidate(analyzer, &definition, skipped) {
                    continue;
                }
                if code_unit_language(&definition) == Language::CSharp
                    && csharp_implicit_entry_point(declaration_syntax, &definition)
                {
                    continue;
                }
                if code_unit_language(&definition) == Language::Cpp
                    && brokk_bifrost_cpp_analysis::analyzer::usages::cpp_graph::is_cpp_global_main(
                        analyzer,
                        &definition,
                    )
                {
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
            for declaration in analyzer.declarations(file) {
                if !is_dead_code_candidate(analyzer, &declaration, skipped) {
                    continue;
                }
                if code_unit_language(&declaration) == Language::CSharp
                    && csharp_implicit_entry_point(declaration_syntax, &declaration)
                {
                    continue;
                }
                if code_unit_language(&declaration) == Language::Cpp
                    && brokk_bifrost_cpp_analysis::analyzer::usages::cpp_graph::is_cpp_global_main(
                        analyzer,
                        &declaration,
                    )
                {
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

fn canonical_file_identity(file: &ProjectFile) -> PathBuf {
    let path = file.abs_path();
    path.canonicalize().unwrap_or(path)
}

#[cfg(test)]
mod tests {

    use crate::code_quality::dead_code_smells::PreciseInboundPreflightDecision;
    use brokk_bifrost_go::graph::resolver::GoPackageClauseProvider;

    use crate::code_quality::dead_code_smells::canonical_file_identity;

    use crate::code_quality::dead_code_smells::precise_inbound_preflight_decision;

    use brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_go_analysis::analyzer::go::GoAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::OverlayProject;

    use brokk_bifrost_core::analyzer::project::Project;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::model::ProjectFile;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    fn go_main_candidate(analyzer: &GoAnalyzer, file: &ProjectFile) -> CodeUnit {
        analyzer
            .declarations(file)
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "main")
            .unwrap_or_else(|| panic!("no Go main declaration in {}", file.rel_path().display()))
    }

    /// A candidate is called dead because no edge reaches it, so a pass whose
    /// canonical facts could not be read must make the evidence inconclusive
    /// rather than make every candidate look unreferenced.
    ///
    /// The native bucket had no input-authority preflight: the legacy pass
    /// owned `input_failure`, and routing a language to a native provider left
    /// the bucket projecting an empty graph over an unpublished workspace and
    /// reporting its live functions as dead. The Rust provider's own answer is
    /// covered end to end by
    /// `native_rust_usage_graph_reports_unavailable_canonical_facts_before_scanning`;
    /// this pins the bucket's side of it, that a reported failure stops the
    /// projection before any candidate is proved.
    #[test]
    fn native_dead_code_reports_unavailable_facts_instead_of_an_empty_graph() {
        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::languages::EdgePassId;

        use brokk_bifrost_analysis::analyzer::languages::LanguageEdgeFailure;

        use brokk_bifrost_analysis::analyzer::languages::NativeWorkspaceGraphProvider;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;

        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        struct UnreadableFacts(ProjectFile);
        impl NativeWorkspaceGraphProvider for UnreadableFacts {
            fn id(&self) -> EdgePassId {
                EdgePassId::Rust
            }

            fn input_failure(
                &self,
                _analyzer: &dyn IAnalyzer,
                _request_files: &[ProjectFile],
            ) -> Option<LanguageEdgeFailure> {
                Some(LanguageEdgeFailure {
                    reason: "canonical Rust facts are unavailable for live files",
                    files: vec![self.0.clone()],
                })
            }

            fn project(
                &self,
                _analyzer: &dyn IAnalyzer,
                _admitted_callers: &[ProjectFile],
                _cancellation: &CancellationToken,
            ) -> brokk_bifrost_analysis::analyzer::store::Result<
                SelectedWorkspaceUsageGraphProjectionOutcome,
            > {
                unreachable!("a reported input failure must stop the projection")
            }
        }

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"dead_preflight\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn target() {}\npub fn caller() { target(); }\n",
            )
            .build();
        let file = fixture.file("src/lib.rs");
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let candidates = analyzer
            .declarations(&file)
            .into_iter()
            .filter(|unit| unit.identifier() == "target")
            .collect::<Vec<_>>();
        assert_eq!(candidates.len(), 1);

        let provider = UnreadableFacts(file);
        let mut skipped = Vec::new();
        let findings = crate::code_quality::dead_code_smells::prove_native_candidates(
            &mut super::DeclarationSyntaxCache::new(&analyzer),
            &provider,
            &[Language::Rust],
            &candidates,
            10,
            2,
            &mut skipped,
        );
        assert!(
            findings.is_empty(),
            "an unreadable fact base proves nothing dead: {findings:#?}"
        );
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(
            skipped[0].contains("canonical Rust facts are unavailable for live files"),
            "{skipped:?}"
        );
        assert!(
            skipped[0].contains("evidence is inconclusive"),
            "{skipped:?}"
        );
    }

    #[test]
    fn lazy_rust_fact_publication_keeps_the_root_file_in_the_capture() {
        use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub fn unused() {}\n")
            .build();
        let file = fixture.file("src/lib.rs");
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let candidate = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "unused")
            .unwrap();
        let store = analyzer.analyzer_store();
        let oid = analyzer.live_path_snapshot().oid_for_path(&file).unwrap();
        let generation = store.current_generation("rust").unwrap();
        // Retain the live declaration while losing its canonical facts, as
        // the catch-up path sees after an interrupted publication.
        store.delete_rust_facts_for_test("rust");
        assert!(
            store
                .blobs_with_rust_facts("rust", generation, &[oid])
                .unwrap()
                .is_empty()
        );
        store.reset_parsed_blob_transaction_starts_for_test();
        let mut skipped = Vec::new();
        let (finding, reads) = capture_query_reads(&analyzer, || {
            let finding = super::bulk_graph_finding(
                &mut super::DeclarationSyntaxCache::new(&analyzer),
                &Default::default(),
                &candidate,
                super::GraphIncomingUsage::default(),
                &mut skipped,
            )
            .expect("the dead-code product consumes freshly published Rust visibility");
            assert!(
                store.parsed_blob_transaction_starts_for_test() > 0,
                "the capture must actually publish a parsed blob, not take a warm path"
            );
            finding
        });
        assert_eq!(finding.file, file);
        assert!(skipped.is_empty(), "{skipped:?}");
        assert!(
            store
                .blobs_with_rust_facts("rust", generation, &[oid])
                .unwrap()
                .contains(&oid)
        );
        assert!(
            reads
                .keys()
                .contains(&ReadKey::file(Language::Rust, "src/lib.rs", oid)),
            "the lazily parsed root must remain a captured dependency: {:?}",
            reads.keys()
        );
        assert_eq!(reads.unattributed_reads(), 0);
    }

    #[test]
    fn rust_dead_code_visibility_catches_up_missing_facts() {
        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
        let fixture = crate::inline_project::InlineTestProject::with_language(
            brokk_bifrost_core::analyzer::model::Language::Rust,
        )
        .file("src/lib.rs", "pub fn unused() {}\n")
        .build();
        let project = fixture.project_dyn();
        let context =
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context(
                project.as_ref(),
            )
            .unwrap();
        let store = std::sync::Arc::clone(&context.store);
        let analyzer = RustAnalyzer::new_with_config_store_context(
            project,
            brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            context,
            None,
        )
        .unwrap();
        let candidate = analyzer
            .declarations(&fixture.file("src/lib.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "unused")
            .unwrap();
        store.delete_rust_facts_for_test("rust");
        let mut skipped = Vec::new();
        assert!(
            crate::code_quality::dead_code_smells::bulk_graph_finding(
                &mut super::DeclarationSyntaxCache::new(&analyzer),
                &Default::default(),
                &candidate,
                crate::code_quality::dead_code_smells::GraphIncomingUsage::default(),
                &mut skipped
            )
            .is_some()
        );
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
    fn canonical_file_identity_ignores_equivalent_project_roots() {
        let temp = tempfile::tempdir().unwrap();
        let nested_root = temp.path().join("nested");
        std::fs::create_dir(&nested_root).unwrap();
        std::fs::write(nested_root.join("A.java"), "class A {}\n").unwrap();

        let from_workspace_root = ProjectFile::new(temp.path(), "nested/A.java");
        let from_nested_root = ProjectFile::new(&nested_root, "A.java");

        assert_ne!(from_workspace_root.rel_path(), from_nested_root.rel_path(),);
        assert_eq!(
            canonical_file_identity(&from_workspace_root),
            canonical_file_identity(&from_nested_root),
        );
    }

    #[test]
    #[hardwon("#2603: incomplete exact inbound evidence cannot prove a candidate dead")]
    fn precise_inbound_preflight_never_proves_absence_from_an_fqn_graph() {
        assert_eq!(
            precise_inbound_preflight_decision(true, false, 1, 1, 0),
            PreciseInboundPreflightDecision::SkipInconclusive
        );
        assert_eq!(
            precise_inbound_preflight_decision(false, false, 0, 1, 0),
            PreciseInboundPreflightDecision::SkipInconclusive
        );
        assert_eq!(
            precise_inbound_preflight_decision(false, false, 0, 1, 1),
            PreciseInboundPreflightDecision::SkipInconclusive
        );
        assert_eq!(
            precise_inbound_preflight_decision(false, true, 1, 1, 0),
            PreciseInboundPreflightDecision::SkipInconclusive
        );
        assert_eq!(
            precise_inbound_preflight_decision(false, false, 1, 1, 0),
            PreciseInboundPreflightDecision::RetireUsed
        );
    }

    #[test]
    #[hardwon(
        "#6090: the proof matched a member's owner-qualified short name against terminal identifiers"
    )]
    fn native_bulk_proof_requires_complete_and_proven_exact_inbound_inventory() {
        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::languages::EdgePassId;

        use brokk_bifrost_analysis::analyzer::languages::NativeWorkspaceGraphProvider;

        use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

        use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

        use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjection;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageCatalog;

        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        use brokk_bifrost_jvm_analysis::analyzer::java::JavaAnalyzer;

        use brokk_bifrost_core::hash::HashSet;

        use brokk_bifrost_core::analyzer::structural::edges::EdgeAxis;
        use std::collections::BTreeSet;

        struct EmptyNativeInventory {
            completeness: EdgeCompleteness,
            unproven: usize,
            unresolved_names: BTreeSet<String>,
        }
        impl NativeWorkspaceGraphProvider for EmptyNativeInventory {
            fn id(&self) -> EdgePassId {
                EdgePassId::Java
            }

            fn project(
                &self,
                analyzer: &dyn IAnalyzer,
                admitted_callers: &[ProjectFile],
                _cancellation: &CancellationToken,
            ) -> brokk_bifrost_analysis::analyzer::store::Result<
                SelectedWorkspaceUsageGraphProjectionOutcome,
            > {
                assert_eq!(
                    admitted_callers.len(),
                    2,
                    "empty source files remain admitted"
                );
                let mut nodes =
                    WorkspaceUsageCatalog::build_for_files(analyzer, admitted_callers).nodes;
                for node in &mut nodes {
                    node.unproven_inbound = self.unproven;
                }
                let projection = SelectedWorkspaceUsageGraphProjection {
                    raw_proven_inbound: vec![0; nodes.len()],
                    nodes,
                    edges: Vec::new(),
                    same_owner_edges: Vec::new(),
                    admitted_callers: HashSet::from_iter(admitted_callers.iter().cloned()),
                    skipped_callers: Default::default(),
                    build_selection_unavailable: None,
                    domain_discovery_failures: Vec::new(),
                    unresolved_names: Some(self.unresolved_names.clone()),
                    withheld_references: Vec::new(),
                    forward_completeness: self.completeness.clone(),
                    kind_projection_complete: self.completeness.is_complete(),
                    generation: analyzer.project().analysis_generation(),
                    reference_count: 0,
                    projected_edge_count: 0,
                    batch_count: 1,
                    root_binding_metrics: ResolutionBatchMetrics::default(),
                    resolved_ecosystems: vec![UsageEcosystem::Jvm],
                };
                Ok(if self.completeness.is_complete() {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection)
                } else {
                    SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection)
                })
            }
        }

        let fixture = InlineTestProject::with_language(Language::Java)
            .file("C.java", "class C { void unused() {} }\n")
            .file("Empty.java", "// No declarations or references.\n")
            .build();
        let analyzer = JavaAnalyzer::new(fixture.project_dyn());
        let candidate = analyzer
            .declarations(&fixture.file("C.java"))
            .into_iter()
            .find(|unit| unit.identifier() == "unused")
            .expect("unused method");
        assert_eq!(candidate.short_name(), "C.unused");
        let forward_gap = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ForwardResolutionIncomplete],
        };
        let withheld_edges = EdgeCompleteness::Incomplete {
            reasons: vec![
                EdgeIncompleteReason::ForwardAdmissionIncomplete,
                EdgeIncompleteReason::ForwardMetadataIncomplete,
                EdgeIncompleteReason::AxisUnsupported(EdgeAxis::OwnerClassification),
                EdgeIncompleteReason::AxisUnsupported(EdgeAxis::KindClassification),
            ],
        };
        for (completeness, unproven, nominated, expected_findings) in [
            (EdgeCompleteness::Complete, 0, false, 1),
            (EdgeCompleteness::Complete, 1, false, 0),
            // A forward-resolution gap that cannot name this candidate leaves
            // its proof standing: the unresolved reference can only add an
            // inbound edge, and not to a declaration its name does not reach.
            (forward_gap.clone(), 0, false, 1),
            // The same gap, when its name does reach this candidate.
            (forward_gap.clone(), 0, true, 0),
            // Edges withheld for known targets are attributed the same way.
            (withheld_edges.clone(), 0, false, 1),
            (withheld_edges.clone(), 0, true, 0),
            // A reason the projection cannot attribute per declaration still
            // disqualifies the whole pass.
            (
                EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::ReferenceEnumerationIncomplete],
                },
                0,
                false,
                0,
            ),
        ] {
            let provider = EmptyNativeInventory {
                completeness,
                unproven,
                // The route records terminal identifiers, never the
                // `C.unused` short name of a member.
                unresolved_names: if nominated {
                    BTreeSet::from(["unused".to_owned()])
                } else {
                    BTreeSet::new()
                },
            };
            let mut skipped = Vec::new();
            let findings = crate::code_quality::dead_code_smells::prove_native_candidates(
                &mut super::DeclarationSyntaxCache::new(&analyzer),
                &provider,
                &[Language::Java],
                std::slice::from_ref(&candidate),
                10,
                2,
                &mut skipped,
            );
            assert_eq!(findings.len(), expected_findings);
            assert_eq!(skipped.is_empty(), expected_findings == 1);
        }
    }

    #[test]
    fn native_exact_callers_do_not_rebind_colliding_names() {
        use brokk_bifrost_jvm_analysis::analyzer::java::JavaAnalyzer;
        use std::collections::BTreeMap;

        let source = "package p; class C { void caller() {} void target() {} }\n";
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("a/C.java", source)
            .file("b/C.java", source)
            .build();
        let analyzer = JavaAnalyzer::new(fixture.project_dyn());
        let find = |path: &str, name: &str| {
            analyzer
                .declarations(&fixture.file(path))
                .into_iter()
                .find(|unit| unit.identifier() == name)
                .expect("exact fixture declaration")
        };
        let candidate = find("a/C.java", "target");
        let own_caller = find("a/C.java", "caller");
        let foreign_caller = find("b/C.java", "caller");
        assert_eq!(own_caller.fq_name(), foreign_caller.fq_name());
        assert_ne!(own_caller.declaration_id(), foreign_caller.declaration_id());
        for (caller, misleading_name_match, external_count) in [
            (&own_caller, &foreign_caller, 0),
            (&foreign_caller, &own_caller, 1),
        ] {
            let usage = crate::code_quality::dead_code_smells::GraphIncomingUsage {
                total: 1,
                unproven_inbound: 0,
                callers: BTreeMap::from([(
                    crate::code_quality::dead_code_smells::GraphIncomingCaller::Declaration(
                        caller.clone(),
                    ),
                    1,
                )]),
            };
            let legacy_names =
                BTreeMap::from([(caller.fq_name(), vec![misleading_name_match.clone()])]);
            assert_eq!(
                crate::code_quality::dead_code_smells::external_usage_count(
                    &analyzer,
                    &legacy_names,
                    &candidate,
                    &usage
                ),
                external_count
            );
        }
    }

    #[test]
    fn native_rust_dead_code_separates_same_named_impl_members() {
        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        use brokk_bifrost_analysis::analyzer::languages::language_support_for_hook;

        let source = concat!(
            "struct Left;\n",
            "impl Left { fn target(&self) {} }\n",
            "struct Right;\n",
            "impl Right { fn target(&self) {} }\n",
            "fn caller(value: Left) { value.target(); }\n",
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"dead_impls\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let mut candidates = analyzer
            .all_declarations()
            .filter(|unit| unit.identifier() == "target")
            .collect::<Vec<_>>();
        candidates.sort_by_key(|candidate| {
            analyzer
                .ranges(candidate)
                .into_iter()
                .map(|range| range.start_line)
                .min()
                .expect("impl member range")
        });
        assert_eq!(candidates.len(), 2);

        let mut skipped = Vec::new();
        let support = language_support_for_hook(Language::Rust, "dead_code_needs_precise_scan")
            .expect("Rust language support");
        let findings = candidates
            .iter()
            .map(|candidate| {
                assert!(support.dead_code_needs_precise_scan(&analyzer, candidate));
                crate::code_quality::dead_code_smells::analyze_candidate(
                    &mut super::DeclarationSyntaxCache::new(&analyzer),
                    candidate,
                    10,
                    2,
                    &mut skipped,
                )
                .expect("complete native precise evidence produces a finding")
            })
            .collect::<Vec<_>>();

        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert_eq!(findings[0].total_usage_count, 1, "{findings:#?}");
        assert_eq!(findings[1].total_usage_count, 0, "{findings:#?}");
        assert_ne!(findings[0].start_line, findings[1].start_line);
    }

    #[test]
    fn native_rust_incomplete_inventory_keeps_unused_declaration_indeterminate() {
        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        use brokk_bifrost_rust_analysis::analyzer::rust::selected_shadow::selected_rust_native_usage_consumer_shadow;

        use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

        use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

        use brokk_bifrost_core::hash::HashSet;

        for incomplete in [false, true] {
            let source = if incomplete {
                // A module mount keeps the token tree unenumerable. A bare
                // `unknown_macro!()` no longer leaves the reference inventory
                // incomplete in item position either, now that an item-position
                // token tree is enumerated for references.
                "pub fn unused() {}\npub fn opaque() { unknown_macro! { mod generated; } }\n"
            } else {
                "pub fn unused() {}\n"
            };
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"dead_shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                )
                .file("src/lib.rs", source)
                .build();
            let file = fixture.file("src/lib.rs");
            let analyzer = RustAnalyzer::new(fixture.project_dyn());
            let candidate = analyzer
                .declarations(&file)
                .into_iter()
                .find(|unit| unit.is_function() && unit.identifier() == "unused")
                .expect("unused declaration");
            let range = analyzer
                .ranges(&candidate)
                .into_iter()
                .find(|range| !range.is_empty())
                .expect("declaration range");
            let outcome = selected_rust_native_usage_consumer_shadow(
                &analyzer,
                &candidate,
                &HashSet::from_iter([file]),
            );
            let GraphUsageOutcome::Resolved(result) = outcome else {
                panic!("native usage inventory must resolve: {outcome:?}");
            };
            assert!(
                result.all_hits().is_empty(),
                "unused declaration has no positive sites"
            );
            let diagnostics = match &result {
                FuzzyResult::Incomplete { diagnostics, .. } if incomplete => {
                    assert!(!diagnostics.is_empty());
                    Some(format!("{diagnostics:?}"))
                }
                FuzzyResult::Success { .. } if !incomplete => None,
                other => panic!("unexpected native completion: {other:?}"),
            };
            let mut skipped = Vec::new();
            let finding = crate::code_quality::dead_code_smells::analyze_candidate_usage_result(
                &mut super::DeclarationSyntaxCache::new(&analyzer),
                &candidate,
                Language::Rust,
                range,
                result,
                &mut skipped,
            );
            if let Some(diagnostics) = diagnostics {
                assert!(
                    finding.is_none(),
                    "incomplete absence cannot prove dead code"
                );
                assert_eq!(skipped.len(), 1);
                assert!(skipped[0].contains(&diagnostics), "{skipped:?}");
                assert!(skipped[0].contains("inconclusive"), "{skipped:?}");
            } else {
                assert_eq!(
                    finding
                        .expect("complete unused declaration")
                        .total_usage_count,
                    0
                );
                assert!(skipped.is_empty(), "{skipped:?}");
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "94224b15a07d: Go main detection must read the package clause when a trailing line comment follows it"
    )]
    fn go_main_entry_point_accepts_a_package_clause_with_a_trailing_comment() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/comments\n\ngo 1.24\n")
            .file(
                "cmd/app/main.go",
                "package main // command entry point\n\nfunc main() {}\n",
            )
            .build();
        let file = fixture.file("cmd/app/main.go");
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        let candidate = go_main_candidate(&analyzer, &file);
        let mut skipped = Vec::new();

        assert!(
            !crate::code_quality::dead_code_smells::is_dead_code_candidate(
                &analyzer,
                &candidate,
                &mut skipped
            )
        );
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "94224b15a07d: a fake package main inside a block comment must not turn a worker into a Go entry point"
    )]
    fn go_main_entry_point_ignores_a_block_comment_fake_package_in_worker() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/block-comments\n\ngo 1.24\n")
            .file(
                "worker.go",
                "package worker\n\n/*\npackage main\n*/\nfunc main() {}\n",
            )
            .build();
        let file = fixture.file("worker.go");
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        let candidate = go_main_candidate(&analyzer, &file);
        let mut skipped = Vec::new();

        assert!(
            crate::code_quality::dead_code_smells::is_dead_code_candidate(
                &analyzer,
                &candidate,
                &mut skipped
            )
        );
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "94224b15a07d: Go entry-point identity comes from the declared package, not a directory named main"
    )]
    fn go_main_entry_point_uses_declared_package_not_import_path() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/import-path\n\ngo 1.24\n")
            .file("main/worker.go", "package worker\n\nfunc main() {}\n")
            .build();
        let file = fixture.file("main/worker.go");
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        let candidate = go_main_candidate(&analyzer, &file);
        let mut skipped = Vec::new();

        assert!(
            candidate.package_name().ends_with("/main"),
            "fixture must put `main` only in the import path: {}",
            candidate.package_name()
        );
        assert!(
            crate::code_quality::dead_code_smells::is_dead_code_candidate(
                &analyzer,
                &candidate,
                &mut skipped
            )
        );
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "94224b15a07d: entry-point detection must use the active Go overlay package clause instead of stale disk text"
    )]
    fn go_main_entry_point_uses_overlay_package_clause_instead_of_disk_source() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/overlay\n\ngo 1.24\n")
            .file("entry.go", "package worker\n\nfunc main() {}\n")
            .build();
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        let file = fixture.file("entry.go");
        assert!(overlay.set(
            file.abs_path(),
            "package main\n\nfunc main() {}\n".to_owned(),
        ));
        let analyzer = GoAnalyzer::new(overlay as Arc<dyn Project>);
        let candidate = go_main_candidate(&analyzer, &file);
        let mut skipped = Vec::new();

        assert_eq!(analyzer.package_clause_of(&file).as_deref(), Some("main"));
        assert!(
            !crate::code_quality::dead_code_smells::is_dead_code_candidate(
                &analyzer,
                &candidate,
                &mut skipped
            )
        );
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "94224b15a07d: a missing Go package clause must remain inconclusive instead of fabricating main-package identity"
    )]
    fn go_main_entry_point_with_missing_package_clause_is_inconclusive() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/missing-clause\n\ngo 1.24\n")
            .file("main.go", "// no package clause\n\nfunc main() {}\n")
            .build();
        let file = fixture.file("main.go");
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        let candidate = go_main_candidate(&analyzer, &file);
        let mut skipped = Vec::new();

        assert!(
            !crate::code_quality::dead_code_smells::is_dead_code_candidate(
                &analyzer,
                &candidate,
                &mut skipped
            )
        );
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(
            skipped[0].contains("package clause") && skipped[0].contains("inconclusive"),
            "{skipped:?}"
        );
    }

    #[test]
    #[hardwon(
        "dce884c96143: quicksilver round 12 on brokk-bifrost-analysis: declaration visibility read words from annotations and bodies"
    )]
    fn declaration_visibility_uses_modifiers_in_each_language() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;
        use brokk_bifrost_cpp_analysis::analyzer::cpp::CppAnalyzer;
        use brokk_bifrost_jvm_analysis::analyzer::java::JavaAnalyzer;
        use brokk_bifrost_jvm_analysis::analyzer::scala::ScalaAnalyzer;
        for (language, path, source, expected) in [
            (
                Language::Java,
                "C.java",
                "class C { @Tag(\"public\") void F() {} }",
                false,
            ),
            (
                Language::Scala,
                "C.scala",
                "class C { def F(): String = \"private\" }",
                true,
            ),
            (
                Language::Cpp,
                "C.cpp",
                "[[deprecated(\"static\")]] void F() {}",
                true,
            ),
            (
                Language::Java,
                "C.java",
                "class C { public void F() {} }",
                true,
            ),
            (
                Language::Scala,
                "C.scala",
                "class C { private def F(): Int = 1 }",
                false,
            ),
            (Language::Cpp, "C.cpp", "static void F() {}", false),
        ] {
            let fixture = InlineTestProject::with_language(language)
                .file(path, source)
                .build();
            let analyzer: Box<dyn IAnalyzer> = match language {
                Language::Java => Box::new(JavaAnalyzer::new(fixture.project_dyn())),
                Language::Scala => Box::new(ScalaAnalyzer::new(fixture.project_dyn())),
                Language::Cpp => Box::new(CppAnalyzer::new(fixture.project_dyn())),
                _ => unreachable!(),
            };
            let unit = analyzer
                .declarations(&fixture.file(path))
                .into_iter()
                .find(|unit| unit.is_function() && unit.identifier() == "F")
                .unwrap();
            let actual = match language {
                Language::Java => super::java_public_like_declaration(
                    &mut super::DeclarationSyntaxCache::new(analyzer.as_ref()),
                    &unit,
                ),
                Language::Scala => super::scala_public_like_declaration(
                    &mut super::DeclarationSyntaxCache::new(analyzer.as_ref()),
                    &unit,
                ),
                Language::Cpp => super::cpp_public_like_declaration(
                    &mut super::DeclarationSyntaxCache::new(analyzer.as_ref()),
                    &unit,
                ),
                _ => unreachable!(),
            };
            assert_eq!(actual, expected, "{language:?}");
        }
        // Metadata is optional on CodeUnitIndex. Exercise the same real
        // declaration ranges through an index that supplies source and ranges
        // but leaves signature_metadata at its empty default.
        struct SourceOnlyAnalyzer {
            inner: Box<dyn IAnalyzer>,
            source_reads: std::sync::atomic::AtomicUsize,
        }
        impl CodeUnitIndex for SourceOnlyAnalyzer {
            fn project(&self) -> &dyn Project {
                self.inner.project()
            }
            fn languages(&self) -> std::collections::BTreeSet<Language> {
                self.inner.languages()
            }
            fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
                self.inner.all_declarations()
            }
            fn search_definitions(
                &self,
                pattern: &str,
                auto_quote: bool,
            ) -> std::collections::BTreeSet<CodeUnit> {
                self.inner.search_definitions(pattern, auto_quote)
            }
            fn enclosing_code_unit(
                &self,
                file: &ProjectFile,
                range: &super::Range,
            ) -> Option<CodeUnit> {
                self.inner.enclosing_code_unit(file, range)
            }
            fn enclosing_code_unit_for_lines(
                &self,
                file: &ProjectFile,
                start: usize,
                end: usize,
            ) -> Option<CodeUnit> {
                self.inner.enclosing_code_unit_for_lines(file, start, end)
            }
            fn get_skeleton(&self, unit: &CodeUnit) -> Option<String> {
                self.inner.get_skeleton(unit)
            }
            fn get_skeleton_header(&self, unit: &CodeUnit) -> Option<String> {
                self.inner.get_skeleton_header(unit)
            }
            fn get_sources(
                &self,
                unit: &CodeUnit,
                comments: bool,
            ) -> std::collections::BTreeSet<String> {
                self.inner.get_sources(unit, comments)
            }
            fn ranges_of(&self, unit: &CodeUnit) -> Vec<super::Range> {
                self.inner.ranges_of(unit)
            }
            fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
                self.source_reads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.inner.indexed_source(file)
            }
        }
        impl IAnalyzer for SourceOnlyAnalyzer {
            fn update(&self, _files: &std::collections::BTreeSet<ProjectFile>) -> Self {
                unimplemented!()
            }
            fn update_all(&self) -> Self {
                unimplemented!()
            }
            fn is_access_expression(&self, file: &ProjectFile, start: usize, end: usize) -> bool {
                self.inner.is_access_expression(file, start, end)
            }
            fn find_nearest_declaration(
                &self,
                file: &ProjectFile,
                start: usize,
                end: usize,
                name: &str,
            ) -> Option<brokk_bifrost_core::analyzer::model::DeclarationInfo> {
                self.inner.find_nearest_declaration(file, start, end, name)
            }
        }
        for (language, path, source) in [
            (
                Language::Java,
                "Target.java",
                "public class Target { public int x; private int hidden; }",
            ),
            (
                Language::Scala,
                "Target.scala",
                "class Target { val x: Int = 1; private val hidden: Int = 2 }",
            ),
            (
                Language::CSharp,
                "Target.cs",
                "public class Target { public int x; private int hidden; [NUnit.Framework.TestCase(1)] public void TestParser(int value) {} }",
            ),
        ] {
            let mut fixture = InlineTestProject::with_language(language).file(path, source);
            let mut paths = vec![path.to_owned()];
            for index in 1..=super::DECLARATION_SYNTAX_CACHE_FILES {
                let (path, source) = match language {
                    Language::Java => (
                        format!("Target{index}.java"),
                        format!(
                            "public class Target{index} {{ public int x; private int hidden; }}"
                        ),
                    ),
                    Language::Scala => (
                        format!("Target{index}.scala"),
                        format!(
                            "class Target{index} {{ val x: Int = 1; private val hidden: Int = 2 }}"
                        ),
                    ),
                    Language::CSharp => (
                        format!("Target{index}.cs"),
                        format!(
                            "public class Target{index} {{ public int x; private int hidden; }}"
                        ),
                    ),
                    _ => unreachable!(),
                };
                fixture = fixture.file(&path, &source);
                paths.push(path);
            }
            let fixture = fixture.build();
            let analyzer: Box<dyn IAnalyzer> = match language {
                Language::Java => Box::new(JavaAnalyzer::new(fixture.project_dyn())),
                Language::Scala => Box::new(ScalaAnalyzer::new(fixture.project_dyn())),
                Language::CSharp => Box::new(CSharpAnalyzer::new(fixture.project_dyn())),
                _ => unreachable!(),
            };
            let declarations = analyzer.declarations(&fixture.file(path));
            for (identifier, expected) in [("Target", true), ("x", true), ("hidden", false)] {
                let unit = declarations
                    .iter()
                    .find(|unit| {
                        unit.identifier() == identifier
                            && if identifier == "Target" {
                                unit.is_class()
                            } else {
                                unit.is_field()
                            }
                    })
                    .unwrap();
                let actual = match language {
                    Language::Java => super::java_public_like_declaration(
                        &mut super::DeclarationSyntaxCache::new(analyzer.as_ref()),
                        unit,
                    ),
                    Language::Scala => super::scala_public_like_declaration(
                        &mut super::DeclarationSyntaxCache::new(analyzer.as_ref()),
                        unit,
                    ),
                    Language::CSharp => super::csharp_public_like_declaration(
                        &mut super::DeclarationSyntaxCache::new(analyzer.as_ref()),
                        unit,
                    ),
                    _ => unreachable!(),
                };
                assert_eq!(
                    actual,
                    expected,
                    "{language:?} {identifier}, metadata: {:?}",
                    analyzer.signature_metadata(unit)
                );
            }
            let source_only = SourceOnlyAnalyzer {
                inner: analyzer,
                source_reads: std::sync::atomic::AtomicUsize::new(0),
            };
            for request in 1..=2 {
                let mut syntax = super::DeclarationSyntaxCache::new(&source_only);
                for _ in 0..3 {
                    for (identifier, expected) in [("Target", true), ("x", true), ("hidden", false)]
                    {
                        let unit = declarations
                            .iter()
                            .find(|unit| {
                                unit.identifier() == identifier
                                    && if identifier == "Target" {
                                        unit.is_class()
                                    } else {
                                        unit.is_field()
                                    }
                            })
                            .unwrap();
                        let actual = match language {
                            Language::Java => {
                                super::java_public_like_declaration(&mut syntax, unit)
                            }
                            Language::Scala => {
                                super::scala_public_like_declaration(&mut syntax, unit)
                            }
                            Language::CSharp => {
                                super::csharp_public_like_declaration(&mut syntax, unit)
                            }
                            _ => unreachable!(),
                        };
                        assert_eq!(actual, expected, "source-only {language:?} {identifier}");
                    }
                }
                if language == Language::CSharp {
                    let test = declarations
                        .iter()
                        .find(|unit| unit.is_function() && unit.identifier() == "TestParser")
                        .unwrap();
                    for _ in 0..3 {
                        assert!(super::csharp_implicit_entry_point(&mut syntax, test));
                    }
                }
                assert_eq!(syntax.files.len(), 1);
                assert!(syntax.files[0].1.as_ref().unwrap().root_node().is_some());
                assert_eq!(
                    source_only
                        .source_reads
                        .load(std::sync::atomic::Ordering::Relaxed),
                    request,
                    "one indexed-source read and parse per file per request"
                );
            }
            let mut syntax = super::DeclarationSyntaxCache::new(&source_only);
            let reads_before = source_only
                .source_reads
                .load(std::sync::atomic::Ordering::Relaxed);
            let mut file_units = Vec::new();
            for (index, path) in paths.iter().enumerate() {
                let units = source_only.inner.declarations(&fixture.file(path));
                let expected = units
                    .iter()
                    .map(|unit| match language {
                        Language::Java => super::java_public_like_declaration(
                            &mut super::DeclarationSyntaxCache::new(source_only.inner.as_ref()),
                            unit,
                        ),
                        Language::Scala => super::scala_public_like_declaration(
                            &mut super::DeclarationSyntaxCache::new(source_only.inner.as_ref()),
                            unit,
                        ),
                        Language::CSharp => super::csharp_public_like_declaration(
                            &mut super::DeclarationSyntaxCache::new(source_only.inner.as_ref()),
                            unit,
                        ),
                        _ => unreachable!(),
                    })
                    .collect::<Vec<_>>();
                file_units.push((units, expected));
                for (unit, expected) in file_units
                    .last()
                    .unwrap()
                    .0
                    .iter()
                    .zip(&file_units.last().unwrap().1)
                {
                    let actual = match language {
                        Language::Java => super::java_public_like_declaration(&mut syntax, unit),
                        Language::Scala => super::scala_public_like_declaration(&mut syntax, unit),
                        Language::CSharp => {
                            super::csharp_public_like_declaration(&mut syntax, unit)
                        }
                        _ => unreachable!(),
                    };
                    assert_eq!(actual, *expected, "bounded {language:?} {path} {unit:?}");
                    assert!(syntax.files.len() <= super::DECLARATION_SYNTAX_CACHE_FILES);
                }
                assert_eq!(
                    source_only
                        .source_reads
                        .load(std::sync::atomic::Ordering::Relaxed),
                    reads_before + index + 1,
                    "each file loads once on its first visit"
                );
            }
            // The first file was evicted. Refresh the second file, reload the
            // first, then revisit the second: true LRU must keep that recent hit.
            let mut expected_reads = reads_before + paths.len();
            for (index, reload) in [(1, false), (0, true), (1, false)] {
                let (units, expected) = &file_units[index];
                for (unit, expected) in units.iter().zip(expected) {
                    let actual = match language {
                        Language::Java => super::java_public_like_declaration(&mut syntax, unit),
                        Language::Scala => super::scala_public_like_declaration(&mut syntax, unit),
                        Language::CSharp => {
                            super::csharp_public_like_declaration(&mut syntax, unit)
                        }
                        _ => unreachable!(),
                    };
                    assert_eq!(actual, *expected, "eviction {language:?} {unit:?}");
                }
                expected_reads += usize::from(reload);
                assert_eq!(
                    source_only
                        .source_reads
                        .load(std::sync::atomic::Ordering::Relaxed),
                    expected_reads
                );
                assert_eq!(syntax.files.len(), super::DECLARATION_SYNTAX_CACHE_FILES);
            }
        }
    }

    #[test]
    #[hardwon(
        "dce884c96143: quicksilver round 12 on brokk-bifrost-analysis: comments and attribute strings fabricated declaration modifiers"
    )]
    fn csharp_modifier_evidence_ignores_comments_and_attribute_strings() {
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file(
                "Modifiers.cs",
                r#"
                class C {
                    public /* private */ void F() {}
                    [Description("static")] public void Main() {}
                }
                class D { public /* static */ void Main() {} }
                class E { public static void Main() {} }
            "#,
            )
            .build();
        let analyzer = CSharpAnalyzer::new(fixture.project_dyn());
        let declarations = analyzer.declarations(&fixture.file("Modifiers.cs"));
        let f = declarations
            .iter()
            .find(|unit| unit.identifier() == "F")
            .unwrap();
        assert!(super::csharp_public_like_declaration(
            &mut super::DeclarationSyntaxCache::new(&analyzer),
            f
        ));
        let mains = declarations
            .iter()
            .filter(|unit| unit.is_function() && unit.identifier() == "Main")
            .collect::<Vec<_>>();
        assert_eq!(mains.len(), 3);
        let mut syntax = super::DeclarationSyntaxCache::new(&analyzer);
        for main in mains {
            let static_main = main.fq_name().contains("E.");
            assert_eq!(
                super::csharp_implicit_entry_point(&mut syntax, main),
                static_main,
                "{}",
                main.fq_name()
            );
            assert_eq!(brokk_bifrost_csharp_analysis::analyzer::usages::csharp_graph::csharp_implicit_entry_point(
                &analyzer, main), static_main, "{}", main.fq_name());
        }
    }

    #[test]
    fn kotlin_dead_code_report_excludes_main_and_reports_unused_function() {
        use brokk_bifrost_jvm_analysis::analyzer::kotlin::KotlinAnalyzer;
        let fixture = InlineTestProject::with_language(Language::Kotlin)
            .file(
                "Program.kt",
                "package sample\nfun main() {}\nprivate fun unused() {}\n",
            )
            .build();
        let analyzer = KotlinAnalyzer::new(fixture.project_dyn());
        let declarations = analyzer.declarations(&fixture.file("Program.kt"));
        let main = declarations
            .iter()
            .find(|unit| unit.is_function() && unit.identifier() == "main")
            .unwrap();
        let unused = declarations
            .iter()
            .find(|unit| unit.is_function() && unit.identifier() == "unused")
            .unwrap();
        let result = super::report_dead_code_and_unused_abstraction_smells(
            &analyzer,
            super::ReportDeadCodeAndUnusedAbstractionSmellsParams {
                file_paths: vec!["Program.kt".to_string()],
                fq_names: vec![main.fq_name(), unused.fq_name()],
                min_score: 1,
                ..Default::default()
            },
        );
        assert!(
            result.report.contains(&format!("`{}`", unused.fq_name())),
            "{}",
            result.report
        );
        assert!(
            !result
                .report
                .contains(&format!("| `function` | `{}` |", main.fq_name())),
            "{}",
            result.report
        );
    }

    #[test]
    #[hardwon("#4271: NUnit TestCase methods must count as dead-code entry points")]
    fn csharp_nunit_testcase_entry_point_is_not_reported_as_dead_code() {
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file(
                "Tests.cs",
                "using NUnit.Framework;\n\
                 public class ArithmeticTests {\n\
                     [TestCase(1)]\n\
                     public void HandlesInput(int value) {}\n\
                 }\n",
            )
            .build();
        let file = fixture.file("Tests.cs");
        let analyzer = CSharpAnalyzer::new(fixture.project_dyn());
        let candidate = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "HandlesInput")
            .expect("NUnit test method should be indexed as a declaration");

        assert!(
            brokk_bifrost_csharp_analysis::analyzer::usages::csharp_graph::csharp_implicit_entry_point(
                &analyzer, &candidate
            )
        );

        let result = crate::code_quality::dead_code_smells::report_dead_code_and_unused_abstraction_smells(
            &analyzer,
            crate::code_quality::dead_code_smells::ReportDeadCodeAndUnusedAbstractionSmellsParams {
                file_paths: vec!["Tests.cs".into()],
                min_score: 1,
                ..Default::default()
            },
        );
        assert!(
            !result.report.contains("HandlesInput"),
            "NUnit test entry point appeared in dead-code report:\n{}",
            result.report
        );
    }
}

fn is_dead_code_candidate(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    skipped: &mut Vec<String>,
) -> bool {
    if code_unit.is_anonymous() {
        return false;
    }
    let language = code_unit_language(code_unit);
    if code_unit.is_synthetic() && language != Language::Scala {
        return false;
    }
    if language == Language::Go {
        match brokk_bifrost_go_analysis::go_implicit_entry_point(analyzer, code_unit) {
            Some(true) => return false,
            Some(false) => {}
            None => {
                skipped.push(format!(
                    "`{}`: Go package clause was unavailable for the main entry-point check; evidence is inconclusive",
                    code_unit.fq_name()
                ));
                return false;
            }
        }
    }
    if language == Language::Kotlin && kotlin_implicit_entry_point(analyzer, code_unit) {
        return false;
    }
    if brokk_bifrost_core::analyzer::model::SignatureMetadata::unit_is_declaration_only(
        &analyzer.signature_metadata(code_unit),
    ) {
        return false;
    }
    matches!(
        language,
        Language::Rust
            | Language::Python
            | Language::JavaScript
            | Language::TypeScript
            | Language::Java
            | Language::Scala
            | Language::Go
            | Language::CSharp
            | Language::Cpp
            | Language::Php
            | Language::Ruby
            | Language::Kotlin
    ) && (code_unit.is_function() || code_unit.is_class() || code_unit.is_field())
}

/// Whether `candidate` is a Kotlin/JVM program entry point invoked by the
/// runtime rather than from within the analyzed workspace: a top-level `fun
/// main()`/`fun main(args: Array<String>)` (never called from within the
/// workspace, so it would otherwise always read as zero-usage dead code), or
/// a `main` inside a singleton `object`/companion annotated `@JvmStatic`,
/// which the Kotlin compiler also recognizes as an entry point. An ordinary
/// class's instance method named `main` is neither shape and stays eligible
/// — unlike Go's exclusion, which keys off the enclosing file declaring
/// `package main`, Kotlin has no per-file entry-point marker, so the check
/// keys off the declaration's own shape instead: top-level (no owner) or
/// `@JvmStatic`.
fn kotlin_implicit_entry_point(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    if !candidate.is_function() || candidate.identifier() != "main" {
        return false;
    }
    if analyzer.parent_of(candidate).is_none() {
        return true;
    }
    kotlin_jvm_static_declaration(analyzer, candidate)
}

fn kotlin_jvm_static_declaration(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    let source = analyzer.get_source(candidate, true).unwrap_or_default();
    declaration_header(&source).contains("@JvmStatic")
}

fn analyze_candidate(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    candidate: &CodeUnit,
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Option<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    let language = code_unit_language(candidate);
    let range = candidate_range(analyzer, candidate)?;

    if graph_strategy_for(candidate).is_none() {
        skipped.push(format!(
            "`{}`: {} precise usage strategy is unavailable; evidence is inconclusive",
            candidate.fq_name(),
            language_label(language)
        ));
        return None;
    }

    let query = query_graph_usages(analyzer, candidate, usage_candidate_file_cap, usage_cap)?;
    analyze_candidate_query(
        declaration_syntax,
        candidate,
        range,
        query,
        usage_candidate_file_cap,
        skipped,
    )
}

fn candidate_range(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> Option<Range> {
    analyzer
        .ranges(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)
}

fn analyze_candidate_query(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    candidate: &CodeUnit,
    range: Range,
    query: GraphQueryResult,
    usage_candidate_file_cap: usize,
    skipped: &mut Vec<String>,
) -> Option<DeadCodeFinding> {
    let language = code_unit_language(candidate);
    if query.candidate_files_truncated {
        skipped.push(format!(
            "`{}`: usage candidate files exceeded cap {usage_candidate_file_cap}; evidence is inconclusive",
            candidate.fq_name()
        ));
        return None;
    }

    analyze_candidate_usage_result(
        declaration_syntax,
        candidate,
        language,
        range,
        query.result,
        skipped,
    )
}

fn analyze_candidate_usage_result(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    candidate: &CodeUnit,
    language: Language,
    range: Range,
    result: FuzzyResult,
    skipped: &mut Vec<String>,
) -> Option<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    let result = match language_support_for_hook(language, "dead_code_usage_result") {
        Some(support) => support.dead_code_usage_result(result),
        None => result,
    };
    let (hits, same_owner_count) = match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            let unproven_total: usize = unproven_total_by_overload.values().sum();
            if unproven_total > 0 {
                skipped.push(format!(
                    "`{}`: {unproven_total} structurally matching usage site(s) could not be proven or disproven; evidence is inconclusive",
                    candidate.fq_name()
                ));
                return None;
            }
            let all_hits: Vec<UsageHit> = hits_by_overload
                .into_values()
                .flat_map(BTreeSet::into_iter)
                .collect();
            // Same-owner (self/this receiver) sites are excluded from the external
            // surface, but their presence means the symbol IS referenced from its
            // own type — inconclusive, never confidently dead (#1138). This mirrors
            // the inverted builders' `record_unproven` routing for the languages
            // whose dead-code analysis runs through this per-symbol path (Rust
            // members, C++).
            let same_owner_count = all_hits
                .iter()
                .filter(|hit| hit.kind == UsageHitKind::SelfReceiver)
                .count();
            let external = all_hits
                .into_iter()
                .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
                .collect::<Vec<_>>();
            (external, same_owner_count)
        }
        FuzzyResult::Incomplete { diagnostics, .. } => {
            skipped.push(format!(
                "`{}`: usage analysis is incomplete: {diagnostics:?}; evidence is inconclusive",
                candidate.fq_name()
            ));
            return None;
        }
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

    // A symbol whose only references are same-owner (self/this receiver) calls is
    // inconclusive, not dead: the self-call is real evidence its externality could
    // not be disproven (#1138). Matches the inverted builders' `record_unproven`.
    if hits.is_empty() && same_owner_count > 0 {
        skipped.push(format!(
            "`{}`: {same_owner_count} same-owner (self/this receiver) usage site(s) could not be proven or disproven; evidence is inconclusive",
            candidate.fq_name()
        ));
        return None;
    }

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
    if language == Language::Scala && candidate.is_field() && external_hits.is_empty() {
        skipped.push(format!(
            "`{}`: Scala field usage evidence was inconclusive; precise field reads are not reported as dead code in this bulk slice",
            candidate.fq_name()
        ));
        return None;
    }

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

    // Visibility changes the interpretation of sparse evidence regardless of
    // whether the evidence came from the bulk graph or a precise search.
    let public_label = match language {
        Language::Go => {
            brokk_bifrost_go::declarations::go_identifier_is_exported(candidate.identifier())
                .then_some("exported")
        }
        Language::Java => {
            java_public_like_declaration(declaration_syntax, candidate).then_some("public")
        }
        Language::Scala => {
            scala_public_like_declaration(declaration_syntax, candidate).then_some("public")
        }
        Language::CSharp => {
            csharp_public_like_declaration(declaration_syntax, candidate).then_some("public")
        }
        Language::Cpp => {
            cpp_public_like_declaration(declaration_syntax, candidate).then_some("public")
        }
        Language::Php => (!php_method_candidate(analyzer, candidate)).then_some("public"),
        Language::Ruby => Some("public"),
        Language::Rust => {
            let rust = resolve_analyzer::<RustAnalyzer>(analyzer)
                .expect("precise Rust candidates have a Rust analyzer");
            match brokk_bifrost_rust::graph_support::is_rust_public_like_declaration(
                rust, candidate,
            ) {
                Ok(is_public) => is_public.then_some("public"),
                Err(error) => {
                    skipped.push(format!(
                        "`{}`: Rust canonical declaration visibility failed ({error:?}); evidence is inconclusive",
                        candidate.fq_name()
                    ));
                    return None;
                }
            }
        }
        Language::Python
        | Language::Kotlin
        | Language::JavaScript
        | Language::TypeScript
        | Language::None => None,
    };
    let (score, confidence, rationale) = if let Some(public_label) = public_label {
        public_surface_classification(
            non_self_hits.len(),
            declaration_lines,
            true,
            language,
            public_label,
        )
    } else {
        (score, confidence, rationale)
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

/// One bulk proof's candidates, with the routing memo the proof keeps across them.
struct DeadCodeBulkBucket {
    proof: &'static dyn DeadCodeBulkProof,
    memo: Box<dyn Any + Send>,
    candidates: Vec<CodeUnit>,
    precise_candidates: Vec<CodeUnit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreciseInboundPreflightDecision {
    RetireUsed,
    SkipInconclusive,
}

/// Decide what a conservative inbound preflight may do with a candidate that
/// was routed to the precise path. An FQN-keyed graph can prove that some
/// declaration with this name is used, but cannot prove which overload it is.
/// It therefore never produces a finding for a precise candidate.
fn precise_inbound_preflight_decision(
    ambiguous_fqn: bool,
    truncated: bool,
    usage_total: usize,
    usage_cap: usize,
    unproven_inbound: usize,
) -> PreciseInboundPreflightDecision {
    if ambiguous_fqn
        || truncated
        || usage_total > usage_cap
        || unproven_inbound > 0
        || usage_total == 0
    {
        PreciseInboundPreflightDecision::SkipInconclusive
    } else {
        PreciseInboundPreflightDecision::RetireUsed
    }
}

fn preflight_precise_candidates(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    proof: &'static dyn DeadCodeBulkProof,
    candidates: &[CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    if !matches!(
        proof.preflight(analyzer),
        DeadCodeBulkPreflight::Ready { files, .. } if files <= usage_candidate_file_cap
    ) {
        for candidate in candidates {
            if let Some(finding) = analyze_candidate(
                declaration_syntax,
                candidate,
                usage_candidate_file_cap,
                usage_cap,
                skipped,
            ) {
                findings.push(finding);
            }
        }
        return findings;
    }

    let Some(DeadCodeBulkEdges::Fqn(edges)) = proof.build(analyzer, candidates) else {
        for candidate in candidates {
            if let Some(finding) = analyze_candidate(
                declaration_syntax,
                candidate,
                usage_candidate_file_cap,
                usage_cap,
                skipped,
            ) {
                findings.push(finding);
            }
        }
        return findings;
    };

    let language = code_unit_language(&candidates[0]);
    let incoming = incoming_usage_by_callee(&edges);
    for candidate in candidates {
        let candidate_fqn = candidate.fq_name();
        let usage = incoming.get(&candidate_fqn).cloned().unwrap_or_default();
        let ambiguous_fqn = analyzer
            .get_definitions(&candidate_fqn)
            .into_iter()
            .filter(|definition| {
                code_unit_language(definition) == language
                    && !definition.is_synthetic()
                    && definition.is_function()
            })
            .take(2)
            .count()
            > 1;
        let decision = precise_inbound_preflight_decision(
            ambiguous_fqn,
            edges.truncated.contains_key(&candidate_fqn),
            usage.total,
            usage_cap,
            usage.unproven_inbound,
        );
        match decision {
            PreciseInboundPreflightDecision::RetireUsed => {}
            PreciseInboundPreflightDecision::SkipInconclusive => {
                if let Some(reason) = inbound_usage_inconclusive_reason(
                    &candidate_fqn,
                    edges.truncated.get(&candidate_fqn).copied(),
                    usage.total,
                    usage_cap,
                    usage.unproven_inbound,
                ) {
                    skipped.push(reason);
                } else {
                    skipped.push(format!(
                        "`{candidate_fqn}`: precise candidate inbound evidence cannot distinguish declarations sharing this FQN; evidence is inconclusive"
                    ));
                }
            }
        }
    }

    findings
}

/// Prove a bucket of candidates against its language family's whole-workspace edges.
///
/// The framework half of the dead-code carve-out: preflight, the file cap, the
/// could-not-be-built skip and the per-candidate truncation and unproven-inbound
/// diagnostics are the same for every language, and each of them reports through the
/// label the proof supplies. Everything the languages actually disagree about -- which
/// builder runs, what the cap is measured against, whether a concrete analyzer must be
/// resolved first -- lives behind [`DeadCodeBulkProof`].
fn prove_bulk_candidates(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    proof: &'static dyn DeadCodeBulkProof,
    candidates: &[CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    if candidates.is_empty() {
        return Vec::new();
    }

    let (label, files) = match proof.preflight(analyzer) {
        DeadCodeBulkPreflight::Ready { label, files } => (label, files),
        DeadCodeBulkPreflight::Unavailable(reason) => {
            for candidate in candidates {
                skipped.push(format!(
                    "`{}`: {reason}; evidence is inconclusive",
                    candidate.fq_name()
                ));
            }
            return Vec::new();
        }
    };

    if files > usage_candidate_file_cap {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: {label} usage graph candidate files exceeded cap {usage_candidate_file_cap} ({files} {label} files); evidence is inconclusive",
                candidate.fq_name()
            ));
        }
        return Vec::new();
    }

    let Some(edges) = proof.build(analyzer, candidates) else {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: {label} usage graph could not be built; evidence is inconclusive",
                candidate.fq_name()
            ));
        }
        return Vec::new();
    };

    match edges {
        DeadCodeBulkEdges::Fqn(edges) => {
            prove_fqn_candidates(declaration_syntax, &edges, candidates, usage_cap, skipped)
        }
        DeadCodeBulkEdges::Scoped(edges) => {
            prove_scoped_candidates(analyzer, edges, candidates, usage_cap, skipped)
        }
    }
}

fn prove_native_candidates(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    provider: &dyn NativeWorkspaceGraphProvider,
    languages: &[Language],
    candidates: &[CodeUnit],
    usage_candidate_file_cap: usize,
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    // Input authority before admission. A candidate is called dead because no
    // edge reaches it, so a pass whose canonical facts could not be read
    // projects an empty graph and every candidate in it reads as dead. That is
    // the one failure this report cannot afford to make silently.
    //
    // This report proves every candidate against the whole workspace, so its
    // request file set is every *analyzable* file of the pass's languages.
    // Publication readiness is part of the analyzed-file predicate, so a file
    // whose canonical facts were never published is missing from
    // `analyzed_files` for exactly the reason the preflight exists to report.
    let analyzable = analyzer
        .source_file_inventory()
        .rows
        .into_iter()
        .filter(|file| {
            languages.contains(&brokk_bifrost_core::analyzer::common::language_for_file(
                file,
            ))
        })
        .collect::<Vec<_>>();
    if let Some(failure) = provider.input_failure(analyzer, &analyzable) {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: {}; files: {:?}; evidence is inconclusive",
                candidate.fq_name(),
                failure.reason,
                failure.files
            ));
        }
        return Vec::new();
    }
    // A source that admission refused may reference any candidate: an
    // explained exclusion still leaves every candidate's inbound edges unknown.
    let excluded = match provider.excluded_sources(analyzer) {
        Ok(excluded) => excluded
            .into_iter()
            .map(|(file, reason)| format!("{} ({reason})", rel_path_string(&file)))
            .collect::<Vec<_>>(),
        Err(error) => vec![format!("source admission refusals unavailable: {error}")],
    };
    if !excluded.is_empty() {
        for candidate in candidates {
            skipped.push(format!(
                "`{}`: source admission refused files that may reference it: {excluded:?}; evidence is inconclusive",
                candidate.fq_name(),
            ));
        }
        return Vec::new();
    }
    // Admission is the analyzed listing: only a published file can contribute
    // an edge, and the preflight above has already reported any that cannot.
    // This proof reads only the edges into the candidates, so a file the
    // provider shows cannot reach any candidate's file is left out rather
    // than projected and discarded.
    let generation = analyzer.project().analysis_generation();
    let files = analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| {
            languages.contains(&brokk_bifrost_core::analyzer::common::language_for_file(
                file,
            ))
        })
        .collect::<Vec<_>>();
    let targets = candidates
        .iter()
        .map(|candidate| candidate.source().clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let files = match provider.callers_reaching(
        analyzer,
        &files,
        &targets,
        &brokk_bifrost_core::cancellation::CancellationToken::default(),
    ) {
        Ok(files) => files,
        Err(error) => {
            analyzer.record_query_failure(error.clone());
            for candidate in candidates {
                skipped.push(format!(
                    "`{}`: native usage graph callers could not be narrowed: {error}; evidence is inconclusive",
                    candidate.fq_name()
                ));
            }
            return Vec::new();
        }
    };
    if files.len() > usage_candidate_file_cap {
        // One reason per candidate, in the wording the bulk proofs use. A
        // consumer reads the report per symbol: an aggregate line leaves every
        // candidate in this bucket with no recorded reason at all.
        for candidate in candidates {
            let label = language_label(code_unit_language(candidate));
            skipped.push(format!(
                "`{}`: {label} usage graph candidate files exceeded cap {usage_candidate_file_cap} ({} pass files: {files:?}); evidence is inconclusive",
                candidate.fq_name(),
                files.len()
            ));
        }
        return Vec::new();
    }
    let projection = match provider.project(
        analyzer,
        &files,
        &brokk_bifrost_core::cancellation::CancellationToken::default(),
    ) {
        Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection)) => Ok(projection),
        // The forward gaps of one reference are attributed per declaration.
        // An unresolved binding can only *add* an inbound edge, and only to a
        // declaration its own name reaches. A receiver admission the route
        // could not decide, an owner it could not classify and a site with no
        // metadata each withhold an edge whose targets are already known. The
        // projection carries the names of all of them as `unresolved_names`,
        // or `None` when one has no readable name. A reference kind the route
        // could not classify withholds nothing: the edge is drawn, and this
        // proof counts edges of every kind. Every other reason -- above all an
        // incomplete reference enumeration, which can hide an edge to any
        // declaration -- still disqualifies the whole pass.
        //
        // Without this, one `input.saturating_sub(1)` anywhere in the pass
        // made every candidate inconclusive. Every real workspace contains a
        // call whose receiver the route cannot resolve, so the native bulk
        // bucket abstained on all of them.
        Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection))
            if projection.unresolved_names.is_some()
                && match &projection.forward_completeness {
                    // Only an inexact edge kind left the projection incomplete.
                    EdgeCompleteness::Complete => true,
                    EdgeCompleteness::Incomplete { reasons } => reasons.iter().all(|reason| {
                        languages.iter().any(|language| {
                            language_support_for_hook(*language, "dead_code_reason_is_scope")
                                .is_some_and(|support| {
                                    support.dead_code_reason_is_scope(reason)
                                        || support.dead_code_reason_is_attributed(reason)
                                })
                        }) || matches!(
                            reason,
                            EdgeIncompleteReason::ForwardResolutionIncomplete
                                | EdgeIncompleteReason::ForwardAdmissionIncomplete
                                | EdgeIncompleteReason::ForwardMetadataIncomplete
                                | EdgeIncompleteReason::AxisUnsupported(
                                    EdgeAxis::OwnerClassification | EdgeAxis::KindClassification
                                )
                        )
                    }),
                } =>
        {
            Ok(projection)
        }
        Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection)) => Err(format!(
            "native usage graph has incomplete forward semantics: {:?}; kind_projection_complete={}",
            projection.forward_completeness, projection.kind_projection_complete
        )),
        Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled) => {
            Err("native usage graph cancelled".into())
        }
        Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale) => {
            Err("native usage graph lost selected generation authority".into())
        }
        Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason)) => {
            Err(format!("native usage graph unavailable: {reason}"))
        }
        Err(error) => {
            analyzer.record_query_failure(error.clone());
            Err(format!("native usage graph failed: {error}"))
        }
    };
    let projection = match projection {
        Ok(projection)
            if projection.generation == generation
                && analyzer.project().analysis_generation() == generation =>
        {
            projection
        }
        outcome => {
            let reason = outcome.err().unwrap_or_else(|| {
                "workspace changed during native usage graph construction".into()
            });
            for candidate in candidates {
                skipped.push(format!(
                    "`{}`: {reason}; evidence is inconclusive",
                    candidate.fq_name()
                ));
            }
            return Vec::new();
        }
    };
    // Deliberately excluded callers have already had their names checked by
    // the report's outside-build veto. Every requested file must still have
    // an explicit admitted or skipped classification.
    projection.certify_callers(&files.into_iter().collect());
    let node_indices = projection
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (&node.key.id, index))
        .collect::<HashMap<_, _>>();
    let mut incoming = HashMap::default();
    for candidate in candidates {
        if let Some(&index) = node_indices.get(&candidate.declaration_id()) {
            let node = &projection.nodes[index];
            // GoNativeUsageStrategy::find_graph_usages uses CodeUnit::file_scope
            // as the precise route's fallback for a site without an enclosing
            // declaration. Score the same use the same way here: one non-same-owner
            // caller per distinct file, weighted by that file's site count.
            incoming.insert(
                index,
                GraphIncomingUsage {
                    total: node.proven_non_graph_inbound_by_file.values().sum(),
                    callers: node
                        .proven_non_graph_inbound_by_file
                        .iter()
                        .map(|(file, count)| {
                            (
                                GraphIncomingCaller::Declaration(CodeUnit::file_scope(
                                    file.clone(),
                                )),
                                *count,
                            )
                        })
                        .collect(),
                    ..Default::default()
                },
            );
        }
    }
    for edge in &projection.edges {
        let Some(usage) = incoming.get_mut(&edge.to) else {
            continue;
        };
        let count = edge.counts.total();
        if count == 0 {
            continue;
        }
        usage.total = usage
            .total
            .checked_add(count)
            .expect("native incoming count fits usize");
        *usage
            .callers
            .entry(GraphIncomingCaller::Declaration(
                projection.nodes[edge.from].primary.clone(),
            ))
            .or_default() += count;
    }
    let mut findings = Vec::new();
    for candidate in candidates {
        let Some(&index) = node_indices.get(&candidate.declaration_id()) else {
            skipped.push(format!("`{}`: native graph lacks the exact candidate declaration; evidence is inconclusive", candidate.fq_name()));
            continue;
        };
        // The names are terminal identifiers. A member's short name carries
        // its owner chain (`Builder.build`), so it never matched one.
        if projection.unresolved_names.as_ref().is_some_and(|names| {
            let name = strip_raw_identifier_prefix(candidate.terminal_name());
            if !names.contains(name) {
                return false;
            }
            // Withheld self references are not inbound usages, just as drawn
            // self edges are omitted by the canonical accumulator. Preserve a
            // name-only veto when the provider supplied no site attribution.
            let mut attributed = false;
            let possible = projection.withheld_references.iter().any(|reference| {
                use brokk_bifrost_analysis::analyzer::resolution::reference_vocabulary::WithheldCallee;
                let could_name = match &reference.callee {
                    WithheldCallee::Named(unresolved) => unresolved == name,
                    WithheldCallee::Declaration(target) => {
                        if strip_raw_identifier_prefix(target.terminal_name()) == name {
                            attributed = true;
                        }
                        target.declaration_id() == candidate.declaration_id()
                    }
                };
                if !could_name {
                    return false;
                }
                attributed = true;
                reference
                    .site
                    .enclosing
                    .as_ref()
                    .is_none_or(|caller| caller.declaration_id() != candidate.declaration_id())
            });
            possible || !attributed
        }) {
            skipped.push(format!(
                "`{}`: a reference the route could not fully project may reach this declaration's name, so an inbound edge to it may be missing; evidence is inconclusive",
                candidate.fq_name()
            ));
            incoming.remove(&index);
            continue;
        }
        let node = &projection.nodes[index];
        let usage = incoming
            .remove(&index)
            .expect("every admitted candidate has an inbound entry");
        if usage.total == 0
            && projection.same_owner_edges.iter().any(|edge| {
                edge.to == index
                    && (!edge.same_owner_sites.is_empty()
                        || !edge.unproven_same_owner_sites.is_empty())
            })
        {
            skipped.push(format!(
                "`{}`: same-owner usage is present; evidence is inconclusive",
                candidate.fq_name()
            ));
            continue;
        }
        if let Some(reason) = inbound_usage_inconclusive_reason(
            &candidate.fq_name(),
            node.truncated_inbound,
            usage.total,
            usage_cap,
            node.unproven_inbound,
        ) {
            skipped.push(reason);
            continue;
        }
        if node.unproven_inbound > 0 {
            // A proven inbound count the same node reports unproven sites
            // against is not a count this report may publish: the shared
            // reason above only covers a candidate with no proven site at all.
            skipped.push(unproven_inbound_inconclusive_reason(
                &candidate.fq_name(),
                node.unproven_inbound,
            ));
            continue;
        }
        if let Some(finding) = bulk_graph_finding(
            declaration_syntax,
            &BTreeMap::new(),
            candidate,
            usage,
            skipped,
        ) {
            findings.push(finding);
        }
    }
    findings
}

fn prove_fqn_candidates(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    edges: &UsageEdges,
    candidates: &[CodeUnit],
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    let language = code_unit_language(&candidates[0]);
    debug_assert!(
        candidates
            .iter()
            .all(|candidate| code_unit_language(candidate) == language),
        "an fqn-keyed bulk bucket holds exactly one language"
    );
    let incoming = incoming_usage_by_callee(edges);

    candidates
        .iter()
        .filter_map(|candidate| {
            let candidate_fqn = candidate.fq_name();
            let usage = incoming.get(&candidate_fqn).cloned().unwrap_or_default();
            if let Some(reason) = inbound_usage_inconclusive_reason(
                &candidate_fqn,
                edges.truncated.get(&candidate_fqn).copied(),
                usage.total,
                usage_cap,
                usage.unproven_inbound,
            ) {
                skipped.push(reason);
                return None;
            }
            let declarations_by_fqn = if usage.total == 0 {
                BTreeMap::new()
            } else {
                requested_declarations_by_fqn_for_language(
                    analyzer,
                    language,
                    usage.callers.keys().map(|caller| {
                        let GraphIncomingCaller::Name(name) = caller else {
                            unreachable!("legacy graph proof only has named callers")
                        };
                        name.as_str()
                    }),
                )
            };
            bulk_graph_finding(
                declaration_syntax,
                &declarations_by_fqn,
                candidate,
                usage,
                skipped,
            )
        })
        .collect()
}

fn inbound_usage_inconclusive_reason(
    candidate_fqn: &str,
    truncated_total: Option<usize>,
    usage_total: usize,
    usage_cap: usize,
    unproven_inbound: usize,
) -> Option<String> {
    if let Some(total_callsites) = truncated_total {
        return Some(format!(
            "`{candidate_fqn}`: too many workspace inbound call sites ({total_callsites}, limit {}); evidence is inconclusive",
            brokk_bifrost_analysis::analyzer::usages::inverted_edges::MAX_CALLSITES
        ));
    }
    if usage_total > usage_cap {
        return Some(format!(
            "`{candidate_fqn}`: too many workspace inbound call sites ({usage_total}, limit {usage_cap}); evidence is inconclusive"
        ));
    }
    if usage_total == 0 && unproven_inbound > 0 {
        return Some(unproven_inbound_inconclusive_reason(
            candidate_fqn,
            unproven_inbound,
        ));
    }
    None
}

fn unproven_inbound_inconclusive_reason(candidate_fqn: &str, unproven_inbound: usize) -> String {
    format!(
        "`{candidate_fqn}`: {unproven_inbound} structurally matching usage site(s) could not be proven or disproven; evidence is inconclusive"
    )
}

/// Score one bulk-proven candidate.
///
/// Selection by language, but not language dispatch: these are the report's own scoring
/// rules, and they differ in whether a language has a public-surface notion and how it is
/// tested, never in how the usage evidence was gathered.
fn bulk_graph_finding(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
    skipped: &mut Vec<String>,
) -> Option<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    let language = code_unit_language(candidate);
    match language {
        Language::Rust => {
            rust_graph_finding(analyzer, declarations_by_fqn, candidate, usage, skipped)
        }
        Language::Java => {
            java_graph_finding(declaration_syntax, declarations_by_fqn, candidate, usage)
        }
        Language::Scala => {
            scala_graph_finding(declaration_syntax, declarations_by_fqn, candidate, usage)
        }
        Language::Go => go_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::CSharp => {
            csharp_graph_finding(declaration_syntax, declarations_by_fqn, candidate, usage)
        }
        Language::Cpp => {
            cpp_graph_finding(declaration_syntax, declarations_by_fqn, candidate, usage)
        }
        Language::Php => php_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::Ruby => ruby_graph_finding(analyzer, declarations_by_fqn, candidate, usage),
        Language::Python => graph_finding_for_language(
            analyzer,
            Language::Python,
            declarations_by_fqn,
            candidate,
            usage,
        ),
        Language::Kotlin | Language::JavaScript | Language::TypeScript => {
            graph_finding_for_language(analyzer, language, declarations_by_fqn, candidate, usage)
        }
        Language::None => {
            unreachable!("{language:?} candidates never reach the fqn-keyed bulk proof")
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum GraphIncomingCaller {
    Name(String),
    Declaration(CodeUnit),
}

impl std::fmt::Display for GraphIncomingCaller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name(name) => formatter.write_str(name),
            Self::Declaration(unit) => formatter.write_str(unit.fq_name_str()),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct GraphIncomingUsage {
    total: usize,
    unproven_inbound: usize,
    callers: BTreeMap<GraphIncomingCaller, usize>,
}

/// Fold workspace edges into per-callee inbound usage: each callee's total inbound
/// weight and the per-caller weight. Shared by the Rust and per-language dead-code
/// passes, which differ only in how they build `edges`. Reads weights via
/// [`UsageEdges::edge_weights`], so it never touches per-edge call-site locations.
fn incoming_usage_by_callee(
    edges: &brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges,
) -> BTreeMap<String, GraphIncomingUsage> {
    let mut incoming: BTreeMap<String, GraphIncomingUsage> = BTreeMap::new();
    for (caller, callee, weight) in edges.edge_weights() {
        let usage = incoming.entry(callee.to_string()).or_default();
        usage.total += weight;
        usage
            .callers
            .entry(GraphIncomingCaller::Name(caller.to_string()))
            .or_insert(weight);
    }
    for (callee, total) in &edges.unproven_inbound {
        incoming
            .entry(callee.to_string())
            .or_default()
            .unproven_inbound += total;
    }
    incoming
}

/// Prove JS/TS candidates against `{file, fqn}`-keyed edges.
///
/// The only shape whose product carries per-node seed statuses, because a JS/TS export's
/// identity can fail to resolve in two distinguishable ways. `Ambiguous` and `Unseedable`
/// each get their own skip, and a candidate with no entry at all folds into the
/// unseedable arm rather than being treated as an error: a node the scoped build never
/// seeded is exactly a node whose seed could not be resolved.
fn prove_scoped_candidates(
    analyzer: &dyn IAnalyzer,
    result: JsTsScopedUsageEdges,
    candidates: &[CodeUnit],
    usage_cap: usize,
    skipped: &mut Vec<String>,
) -> Vec<DeadCodeFinding> {
    let JsTsScopedUsageEdges { edges, node_status } = result;
    let brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights {
        edges,
        truncated,
        unproven_inbound,
    } = edges;

    let declarations_by_key = scoped_declarations_by_key_for_languages(
        analyzer,
        &[Language::JavaScript, Language::TypeScript],
    );
    let mut incoming: BTreeMap<UsageNodeKey, ScopedGraphIncomingUsage> = BTreeMap::new();
    for ((caller, callee), weight) in edges {
        let usage = incoming.entry(callee).or_default();
        let weight = weight.total();
        usage.total += weight;
        usage.callers.entry(caller).or_insert(weight);
    }
    for (callee, total) in unproven_inbound {
        incoming.entry(callee).or_default().unproven_inbound += total;
    }

    candidates
        .iter()
        .filter_map(|candidate| {
            let candidate_key = UsageNodeKey::from_unit(candidate);
            match node_status.get(&candidate_key) {
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
            let usage = incoming.get(&candidate_key).cloned().unwrap_or_default();
            if let Some(reason) = inbound_usage_inconclusive_reason(
                &candidate.fq_name(),
                truncated.get(&candidate_key).copied(),
                usage.total,
                usage_cap,
                usage.unproven_inbound,
            ) {
                skipped.push(reason);
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
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
    skipped: &mut Vec<String>,
) -> Option<DeadCodeFinding> {
    if usage.total > 1 {
        return None;
    }
    // The Rust bulk proof resolves this analyzer in its preflight, so a candidate only
    // reaches scoring once it is known to be there.
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)
        .expect("the Rust bulk preflight resolved the Rust analyzer");

    let range = analyzer
        .ranges(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)?;
    let declaration_lines = span_lines(&range);
    let is_public = match brokk_bifrost_rust::graph_support::is_rust_public_like_declaration(
        rust, candidate,
    ) {
        Ok(is_public) => is_public,
        Err(error) => {
            skipped.push(format!(
                "`{}`: Rust canonical declaration visibility failed ({error:?}); evidence is inconclusive",
                candidate.fq_name()
            ));
            return None;
        }
    };
    let score = public_api_score(usage.total, declaration_lines, is_public);
    let confidence = public_api_confidence(usage.total, is_public);
    let evidence = graph_inbound_evidence(&usage);
    let rationale = rust_graph_rationale(usage.total, is_public);

    Some(build_graph_dead_code_finding(
        Language::Rust,
        candidate,
        range,
        usage.total,
        GraphFindingDetails {
            score,
            confidence,
            external_usage_count: external_usage_count(
                analyzer,
                declarations_by_fqn,
                candidate,
                &usage,
            ),
            evidence,
            rationale,
        },
    ))
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
        .ranges(candidate)
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

    Some(build_graph_dead_code_finding(
        language,
        candidate,
        range,
        usage.total,
        GraphFindingDetails {
            score,
            confidence,
            external_usage_count: external_usage_count(
                analyzer,
                declarations_by_fqn,
                candidate,
                &usage,
            ),
            evidence,
            rationale,
        },
    ))
}

fn java_graph_finding(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    public_surface_graph_finding(
        analyzer,
        Language::Java,
        declarations_by_fqn,
        candidate,
        usage,
        java_public_like_declaration(declaration_syntax, candidate),
        "public",
    )
}

fn scala_graph_finding(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    public_surface_graph_finding(
        analyzer,
        Language::Scala,
        declarations_by_fqn,
        candidate,
        usage,
        scala_public_like_declaration(declaration_syntax, candidate),
        "public",
    )
}

fn go_graph_finding(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    public_surface_graph_finding(
        analyzer,
        Language::Go,
        declarations_by_fqn,
        candidate,
        usage,
        brokk_bifrost_go::declarations::go_identifier_is_exported(candidate.identifier()),
        "exported",
    )
}

fn csharp_graph_finding(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    public_surface_graph_finding(
        analyzer,
        Language::CSharp,
        declarations_by_fqn,
        candidate,
        usage,
        csharp_public_like_declaration(declaration_syntax, candidate),
        "public",
    )
}

fn cpp_graph_finding(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    let analyzer = declaration_syntax.analyzer;
    public_surface_graph_finding(
        analyzer,
        Language::Cpp,
        declarations_by_fqn,
        candidate,
        usage,
        cpp_public_like_declaration(declaration_syntax, candidate),
        "public",
    )
}

fn php_graph_finding(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    if php_method_candidate(analyzer, candidate) {
        return php_method_graph_finding(analyzer, declarations_by_fqn, candidate, usage);
    }
    public_surface_graph_finding(
        analyzer,
        Language::Php,
        declarations_by_fqn,
        candidate,
        usage,
        true,
        "public",
    )
}

fn php_method_candidate(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> bool {
    candidate.is_function()
        && analyzer
            .parent_of(candidate)
            .is_some_and(|parent| parent.is_class())
}

fn php_method_graph_finding(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    if usage.total > 1 {
        return None;
    }

    let range = analyzer
        .ranges(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)?;
    let declaration_lines = span_lines(&range);
    let score = graph_score(usage.total, declaration_lines);
    let confidence = if usage.total == 0 { 0.95 } else { 0.75 };
    let evidence = graph_inbound_evidence(&usage);
    let rationale = if usage.total == 0 {
        "symbol has no usage evidence in PHP tree-sitter analysis and may be generated residue"
            .to_string()
    } else {
        "symbol has only one non-self caller in PHP tree-sitter analysis and may be a low-value abstraction"
            .to_string()
    };

    Some(build_graph_dead_code_finding(
        Language::Php,
        candidate,
        range,
        usage.total,
        GraphFindingDetails {
            score,
            confidence,
            external_usage_count: external_usage_count(
                analyzer,
                declarations_by_fqn,
                candidate,
                &usage,
            ),
            evidence,
            rationale,
        },
    ))
}

fn ruby_graph_finding(
    analyzer: &dyn IAnalyzer,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
) -> Option<DeadCodeFinding> {
    public_surface_graph_finding(
        analyzer,
        Language::Ruby,
        declarations_by_fqn,
        candidate,
        usage,
        true,
        "public",
    )
}

fn public_surface_graph_finding(
    analyzer: &dyn IAnalyzer,
    language: Language,
    declarations_by_fqn: &BTreeMap<String, Vec<CodeUnit>>,
    candidate: &CodeUnit,
    usage: GraphIncomingUsage,
    is_public: bool,
    public_label: &'static str,
) -> Option<DeadCodeFinding> {
    if usage.total > 1 {
        return None;
    }

    let range = analyzer
        .ranges(candidate)
        .into_iter()
        .filter(|range| !range.is_empty())
        .max_by_key(span_lines)?;
    let declaration_lines = span_lines(&range);
    let (score, confidence, rationale) = public_surface_classification(
        usage.total,
        declaration_lines,
        is_public,
        language,
        public_label,
    );
    let evidence = graph_inbound_evidence(&usage);

    Some(build_graph_dead_code_finding(
        language,
        candidate,
        range,
        usage.total,
        GraphFindingDetails {
            score,
            confidence,
            external_usage_count: external_usage_count(
                analyzer,
                declarations_by_fqn,
                candidate,
                &usage,
            ),
            evidence,
            rationale,
        },
    ))
}

#[derive(Clone, Debug, Default)]
struct ScopedGraphIncomingUsage {
    total: usize,
    callers: BTreeMap<UsageNodeKey, usize>,
    unproven_inbound: usize,
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

    Some(build_graph_dead_code_finding(
        language,
        candidate,
        range,
        usage.total,
        GraphFindingDetails {
            score,
            confidence,
            external_usage_count: scoped_external_usage_count(
                analyzer,
                declarations_by_key,
                candidate,
                &usage,
            ),
            evidence,
            rationale,
        },
    ))
}

fn graph_score(total_usage_count: usize, declaration_lines: usize) -> i32 {
    if total_usage_count == 0 {
        30 + (declaration_lines / 4).min(20) as i32
    } else {
        12 + (declaration_lines / 8).min(12) as i32
    }
}

fn public_surface_classification(
    total_usage_count: usize,
    declaration_lines: usize,
    is_public: bool,
    language: Language,
    public_label: &'static str,
) -> (i32, f64, String) {
    (
        public_api_score(total_usage_count, declaration_lines, is_public),
        public_api_confidence(total_usage_count, is_public),
        public_surface_rationale(
            total_usage_count,
            is_public,
            language_label(language),
            public_label,
        ),
    )
}

fn public_api_score(total_usage_count: usize, declaration_lines: usize, is_public: bool) -> i32 {
    match (total_usage_count, is_public) {
        (0, true) => 10 + (declaration_lines / 8).min(8) as i32,
        (0, false) => graph_score(total_usage_count, declaration_lines),
        (_, true) => 8 + (declaration_lines / 16).min(6) as i32,
        (_, false) => graph_score(total_usage_count, declaration_lines),
    }
}

fn public_api_confidence(total_usage_count: usize, is_public: bool) -> f64 {
    match (total_usage_count, is_public) {
        (0, true) => 0.55,
        (0, false) => 0.90,
        (_, true) => 0.45,
        (_, false) => 0.70,
    }
}

fn graph_inbound_evidence(usage: &GraphIncomingUsage) -> String {
    graph_inbound_evidence_for(
        usage.total,
        usage
            .callers
            .iter()
            .next()
            .map(|(caller, weight)| (caller, *weight)),
    )
}

fn scoped_graph_inbound_evidence(usage: &ScopedGraphIncomingUsage) -> String {
    graph_inbound_evidence_for(
        usage.total,
        usage
            .callers
            .iter()
            .next()
            .map(|(caller, weight)| (&caller.fqn, *weight)),
    )
}

fn graph_inbound_evidence_for<C: std::fmt::Display>(
    total: usize,
    caller: Option<(C, usize)>,
) -> String {
    if total == 0 {
        return "no non-self usages found".to_string();
    }
    match caller {
        Some((caller, 1)) => format!("one workspace inbound edge from {caller}"),
        Some((caller, weight)) => {
            format!("one workspace inbound caller: {caller} ({weight} references)")
        }
        None => "one workspace inbound edge".to_string(),
    }
}

fn rust_graph_rationale(total_usage_count: usize, is_public: bool) -> String {
    public_surface_rationale(total_usage_count, is_public, "Rust", "public")
}

fn public_surface_rationale(
    total_usage_count: usize,
    is_public: bool,
    language_label: &'static str,
    public_label: &'static str,
) -> String {
    match (total_usage_count, is_public) {
        (0, true) => {
            format!(
                "{public_label} {language_label} symbol is unreferenced in workspace; it may be untested public surface or consumed externally"
            )
        }
        (0, false) => {
            format!(
                "symbol has no workspace inbound usage evidence in {language_label} tree-sitter analysis and may be generated residue"
            )
        }
        (_, true) => {
            format!(
                "{public_label} {language_label} symbol has only one workspace inbound reference; it may be lightly tested public surface or consumed externally"
            )
        }
        (_, false) => {
            format!(
                "symbol has only one workspace inbound caller in {language_label} tree-sitter analysis and may be a low-value abstraction"
            )
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
            .entry(UsageNodeKey::from_unit(&declaration))
            .or_default()
            .push(declaration);
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
            caller_has_different_owner(analyzer, candidate, caller)
        })
        .map(|(_, weight)| *weight)
        .sum()
}

fn java_public_like_declaration(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    candidate: &CodeUnit,
) -> bool {
    let analyzer = declaration_syntax.analyzer;
    use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
    if let Some(visibility) = analyzer
        .signature_metadata(candidate)
        .iter()
        .filter_map(|metadata| metadata.callable_declared_visibility())
        .find(|visibility| *visibility != DeclaredVisibility::Unknown)
    {
        return visibility == DeclaredVisibility::Public;
    }
    declaration_node_matches(declaration_syntax, candidate, |node, _| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).any(|child| {
            child.kind() == "modifiers" && {
                let mut tokens = child.walk();
                child
                    .children(&mut tokens)
                    .any(|token| token.kind() == "public")
            }
        })
    })
}

fn scala_public_like_declaration(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    candidate: &CodeUnit,
) -> bool {
    let analyzer = declaration_syntax.analyzer;
    use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
    if let Some(visibility) = analyzer
        .signature_metadata(candidate)
        .iter()
        .filter_map(|metadata| metadata.callable_declared_visibility())
        .find(|visibility| *visibility != DeclaredVisibility::Unknown)
    {
        return visibility != DeclaredVisibility::Private;
    }
    !declaration_node_matches(declaration_syntax, candidate, |node, _| {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            let mut cursor = current.walk();
            for child in current.children(&mut cursor) {
                match child.kind() {
                    // A class's direct access_modifier belongs to its primary
                    // constructor, not to the class (Scala grammar).
                    "access_modifier" if current.kind() == "class_definition" => {}
                    "modifiers" | "access_modifier" => stack.push(child),
                    "private" => return true,
                    _ => {}
                }
            }
        }
        false
    })
}

fn csharp_public_like_declaration(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    candidate: &CodeUnit,
) -> bool {
    let analyzer = declaration_syntax.analyzer;
    use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
    if let Some(visibility) = analyzer
        .signature_metadata(candidate)
        .iter()
        .filter_map(|metadata| metadata.callable_declared_visibility())
        .find(|visibility| *visibility != DeclaredVisibility::Unknown)
    {
        return visibility != DeclaredVisibility::Private;
    }
    !declaration_node_matches(declaration_syntax, candidate, |node, source| {
        // Field units use variable-declarator ranges; accessibility belongs
        // to the enclosing member declaration, not to the individual name.
        let node = if candidate.is_field()
            && matches!(
                node.kind(),
                "identifier" | "variable_declarator" | "variable_declaration"
            ) {
            brokk_bifrost_core::analyzer::structural::adapter_helpers::nearest_ancestor(
                node,
                |kind| {
                    matches!(
                        kind,
                        "field_declaration"
                            | "event_field_declaration"
                            | "property_declaration"
                            | "event_declaration"
                            | "indexer_declaration"
                    )
                },
            )
            .unwrap_or(node)
        } else {
            node
        };
        brokk_bifrost_csharp_analysis::analyzer::usages::csharp_graph::csharp_has_modifier(
            source, node, "private",
        )
    })
}

fn csharp_implicit_entry_point(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    candidate: &CodeUnit,
) -> bool {
    use brokk_bifrost_csharp_analysis::analyzer::usages::csharp_graph::{
        csharp_implicit_entry_point_at_declaration, csharp_main_entry_point,
    };
    let analyzer = declaration_syntax.analyzer;
    candidate.is_function()
        && (csharp_main_entry_point(analyzer, candidate)
            || declaration_node_matches(declaration_syntax, candidate, |node, source| {
                csharp_implicit_entry_point_at_declaration(analyzer, candidate, node, source)
            }))
}

fn cpp_public_like_declaration(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    candidate: &CodeUnit,
) -> bool {
    candidate.is_class()
        || !declaration_node_matches(declaration_syntax, candidate, |node, source| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).any(|child| {
                child.kind() == "storage_class_specifier" && &source[child.byte_range()] == "static"
            })
        })
}

const DECLARATION_SYNTAX_CACHE_FILES: usize = 16;

// This cache belongs to one report invocation, with least-recently-used files
// first. Bound parsed trees as well as their source: a workspace-wide report
// must not retain every file's syntax until the request completes. Misses use
// the same cheap entries and eviction policy.
struct DeclarationSyntaxCache<'analyzer> {
    analyzer: &'analyzer dyn IAnalyzer,
    files: Vec<(
        ProjectFile,
        Option<brokk_bifrost_analysis::analyzer::declaration_range::DeclarationNameRangeContext>,
    )>,
}

impl<'analyzer> DeclarationSyntaxCache<'analyzer> {
    fn new(analyzer: &'analyzer dyn IAnalyzer) -> Self {
        Self {
            analyzer,
            files: Vec::new(),
        }
    }

    fn context(
        &mut self,
        file: &ProjectFile,
    ) -> Option<&brokk_bifrost_analysis::analyzer::declaration_range::DeclarationNameRangeContext>
    {
        use brokk_bifrost_analysis::analyzer::declaration_range::DeclarationNameRangeContext;
        let entry = if let Some(index) = self.files.iter().position(|(key, _)| key == file) {
            self.files.remove(index)
        } else {
            if self.files.len() == DECLARATION_SYNTAX_CACHE_FILES {
                // Drop the evicted tree before parsing the replacement.
                self.files.remove(0);
            }
            let context = self
                .analyzer
                .indexed_source(file)
                .map(|source| DeclarationNameRangeContext::new(file, source));
            (file.clone(), context)
        };
        self.files.push(entry);
        self.files.last().unwrap().1.as_ref()
    }
}

// Only full indexed source is parsed; never a rendered declaration fragment.
fn declaration_node_matches(
    declaration_syntax: &mut DeclarationSyntaxCache<'_>,
    candidate: &CodeUnit,
    predicate: impl Fn(tree_sitter::Node<'_>, &str) -> bool,
) -> bool {
    let analyzer = declaration_syntax.analyzer;
    use brokk_bifrost_core::analyzer::tree_walk::node_for_exact_range;
    let Some(context) = declaration_syntax.context(candidate.source()) else {
        return false;
    };
    let Some(root) = context.root_node() else {
        return false;
    };
    analyzer.ranges_of(candidate).into_iter().any(|range| {
        node_for_exact_range(root, &range).is_some_and(|node| predicate(node, context.content()))
    })
}

fn requested_declarations_by_fqn_for_language<'a, I>(
    analyzer: &dyn IAnalyzer,
    language: Language,
    fqns: I,
) -> BTreeMap<String, Vec<CodeUnit>>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut declarations: BTreeMap<String, Vec<CodeUnit>> = BTreeMap::new();
    for fqn in fqns {
        let definitions = analyzer
            .get_definitions(fqn)
            .into_iter()
            .filter(|unit| code_unit_language(unit) == language)
            .collect();
        declarations.insert(fqn.to_string(), definitions);
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
        .filter(|(caller, _)| match caller {
            GraphIncomingCaller::Name(name) => {
                edge_is_external(analyzer, declarations_by_fqn, name, candidate)
            }
            GraphIncomingCaller::Declaration(caller) => {
                caller_has_different_owner(analyzer, candidate, caller)
            }
        })
        .map(|(_, weight)| *weight)
        .sum()
}

fn caller_has_different_owner(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    caller: &CodeUnit,
) -> bool {
    let defining_owner = analyzer
        .parent_of(candidate)
        .unwrap_or_else(|| candidate.clone());
    let caller_owner = analyzer.parent_of(caller).unwrap_or_else(|| caller.clone());
    caller_owner != defining_owner
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
    let (candidates, candidate_files_truncated) =
        admit_graph_usage_files(analyzer, candidate, usage_candidate_file_cap);
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

fn admit_graph_usage_files(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    usage_candidate_file_cap: usize,
) -> (HashSet<ProjectFile>, bool) {
    let provider: FallbackCandidateProvider<
        ImportGraphCandidateProvider,
        TextSearchCandidateProvider,
    > = brokk_bifrost_analysis::analyzer::usages::candidates::default_provider();
    let mut candidates =
        language_support_for_hook(code_unit_language(candidate), "dead_code_reference_scope")
            .and_then(|support| support.dead_code_reference_scope(analyzer))
            .unwrap_or_else(|| provider.find_candidates(candidate, analyzer));
    let candidate_files_truncated = candidates.len() > usage_candidate_file_cap;
    if candidate_files_truncated {
        candidates = candidates
            .into_iter()
            .take(usage_candidate_file_cap)
            .collect();
    }
    (candidates, candidate_files_truncated)
}

fn query_graph_usage_batches(
    analyzer: &dyn IAnalyzer,
    candidates: &[&CodeUnit],
    file_cap: usize,
    usage_cap: usize,
) -> Vec<GraphQueryResult> {
    let admitted = candidates
        .iter()
        .map(|candidate| admit_graph_usage_files(analyzer, candidate, file_cap))
        .collect::<Vec<_>>();
    let cancellations = candidates
        .iter()
        .map(|_| CancellationToken::default())
        .collect::<Vec<_>>();
    let mut groups = HashMap::<&str, Vec<usize>>::default();
    for (index, candidate) in candidates.iter().enumerate() {
        groups
            .entry(candidate.terminal_name())
            .or_default()
            .push(index);
    }
    // Execute groups in first-candidate order, retaining each independent slot.
    let mut groups = groups.into_values().collect::<Vec<_>>();
    groups.sort_by_key(|indices| indices[0]);
    let mut results = candidates.iter().map(|_| None).collect::<Vec<_>>();
    for indices in groups {
        let strategy = graph_strategy_for(candidates[indices[0]])
            .expect("precise candidates have a usage strategy");
        let queries = indices
            .iter()
            .map(|&index| GraphUsageBatchQuery {
                overloads: std::slice::from_ref(candidates[index]),
                scope: UsageScanScope::with_cancellation(&admitted[index].0, &cancellations[index]),
                prepared: None,
            })
            .collect::<Vec<_>>();
        let answers = strategy.find_usages_batch(analyzer, &queries, usage_cap);
        assert_eq!(
            answers.len(),
            indices.len(),
            "one usage answer per independent query"
        );
        for (index, result) in indices.into_iter().zip(answers) {
            results[index] = Some(GraphQueryResult {
                candidate_files_truncated: admitted[index].1,
                result,
            });
        }
    }
    results
        .into_iter()
        .map(|result| result.expect("every candidate group was queried"))
        .collect()
}

/// Nine of the twelve languages answer here. Python and C++ are absent by design --
/// they prove their candidates through their bulk proofs -- and their supports keep
/// `DeadCodeSupport::strategy` at `None` so a candidate that does reach this path is
/// still skipped as inconclusive.
fn graph_strategy_for(candidate: &CodeUnit) -> Option<&'static dyn UsageAnalyzer> {
    language_support_for_hook(code_unit_language(candidate), "dead_code")?
        .dead_code()
        .strategy
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
        Language::Scala => "Scala",
        Language::Go => "Go",
        Language::CSharp => "C#",
        Language::Cpp => "C++",
        Language::Php => "PHP",
        Language::Ruby => "Ruby",
        Language::Kotlin => "Kotlin",
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
